#!/usr/bin/env python3
"""
gatekeeper.py — self-hosted replacement for the old Cloudflare Worker.

One endpoint, two methods, served at https://remote.joatverse.com/archie :

    GET  /archie   -> returns launcher.ps1 (contains no secrets; safe to be public)
    POST /archie   -> {"otp": "123456"} -> {"key": "tskey-auth-..."}

The POST path verifies a TOTP code and, only on success, asks the Tailscale API
for a single-use ephemeral auth key tagged tag:guest that expires in 5 minutes.

Stdlib only — no pip install, no venv. Runs as a Docker container
(`remote-gatekeeper`) and is reached by the cloudflared container by name,
`remote-gatekeeper:8787`, over the shared `joatverse_edge` docker network.

WHY BY NAME, NOT AN IP OR LOCALHOST:
  cloudflared runs inside its own container. "localhost" in its ingress config
  means that container, not archie — that is exactly why the existing
  test.joatverse.com -> localhost:3000 rule fails with "connection refused".
  A pinned container IP is equally wrong: Docker reassigns IPs in start order,
  so a daemon restart silently breaks it (see the Immich outage in
  homelab/networking/cloudflare-tunnel-origin-routing.md). A shared
  user-defined network with name-based resolution is the only form that
  survives both.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ── Config (all via environment; see gatekeeper.env.example) ─────────────────

# 0.0.0.0: inside the container this always binds a real, reachable address.
# docker-compose.yml does not need to override this, unlike the old
# host-bridge-gateway default this replaced.
BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0")
BIND_PORT = int(os.environ.get("BIND_PORT", "8787"))
ROUTE = os.environ.get("ROUTE", "/archie")

# The public URL baked into the served launcher.ps1 so it knows where to POST.
PUBLIC_URL = os.environ.get("PUBLIC_URL", "https://remote.joatverse.com/archie")

TOTP_SECRET = os.environ.get("TOTP_SECRET", "")

# Preferred: OAuth client scoped to auth_keys, owning tag:guest.
TS_OAUTH_CLIENT_ID = os.environ.get("TS_OAUTH_CLIENT_ID", "")
TS_OAUTH_CLIENT_SECRET = os.environ.get("TS_OAUTH_CLIENT_SECRET", "")
# Fallback: long-lived API key (works, but is a permanent key-minting credential).
TS_API_KEY = os.environ.get("TS_API_KEY", "")
# With OAuth, "-" means "the tailnet this client belongs to" — no need to name it.
TS_TAILNET = os.environ.get("TS_TAILNET", "-")

TS_TAG = os.environ.get("TS_TAG", "tag:guest")
KEY_TTL_SECONDS = int(os.environ.get("KEY_TTL_SECONDS", "300"))

# ── Rate limiting knobs ──────────────────────────────────────────────────────
# The old Worker "rate limited" with a 2-second sleep on failure. That does
# nothing: the sleeps are per-request, so N concurrent requests all sleep at
# once and N is unbounded. With a +/-1 step window, 3 codes out of 1,000,000
# are valid at any instant, so roughly 230k guesses inside one 30s window is a
# coin flip. That is well within reach of ordinary bandwidth. Real counters,
# below, are the actual fix.
FAIL_WINDOW = 300          # seconds of history each counter looks at
MAX_FAILS_PER_IP = 5       # failures from one IP in FAIL_WINDOW -> lock that IP
IP_LOCKOUT = 900           # how long that IP stays locked (seconds)
MAX_FAILS_GLOBAL = 20      # total failures in FAIL_WINDOW -> lock everyone
GLOBAL_LOCKOUT = 300       # backstop against a distributed / spoofed-IP attack

SCRIPT_DIR = Path(__file__).resolve().parent
LAUNCHER_PATH = SCRIPT_DIR / "launcher.ps1"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,  # `docker logs` / `docker compose logs` capture stdout
)
log = logging.getLogger("gatekeeper")


# ── TOTP ─────────────────────────────────────────────────────────────────────

def _b32decode(secret: str) -> bytes:
    """Decode a base32 TOTP secret, tolerating lowercase and missing padding."""
    s = secret.strip().replace(" ", "").upper()
    s += "=" * (-len(s) % 8)  # b32decode demands padding to a multiple of 8
    return base64.b32decode(s)


def _hotp(key: bytes, counter: int) -> str:
    """RFC 4226 HOTP: HMAC-SHA1 over the counter, then dynamic truncation."""
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


class OTPGate:
    """
    TOTP verification with replay protection.

    The replay half is the part the Worker was missing. A TOTP code stays valid
    for up to 90 seconds across the +/-1 step window. If someone captures the
    code you typed on an untrusted machine — keylogger, screen recorder, a
    camera over your shoulder — they can post it themselves before it expires
    and get their own VPN key. Remembering which counters have already been
    spent makes every code strictly single-use.
    """

    def __init__(self, secret: str, window: int = 1):
        self._key = _b32decode(secret)
        self._window = window
        self._consumed: set[int] = set()
        self._lock = threading.Lock()

    def verify(self, otp: str) -> tuple[bool, str]:
        now_counter = int(time.time()) // 30
        matched = None

        for delta in range(-self._window, self._window + 1):
            counter = now_counter + delta
            # compare_digest, not ==, so the comparison does not short-circuit
            # on the first wrong digit. The timing signal is impractical to
            # exploit across the internet, but the fix costs nothing.
            if hmac.compare_digest(otp, _hotp(self._key, counter)):
                matched = counter
                break

        if matched is None:
            return False, "invalid"

        with self._lock:
            if matched in self._consumed:
                return False, "replayed"
            self._consumed.add(matched)
            # Keep only counters that could still be inside a live window.
            cutoff = now_counter - (self._window + 1)
            self._consumed = {c for c in self._consumed if c >= cutoff}

        return True, "ok"


# ── Rate limiting ────────────────────────────────────────────────────────────

class RateLimiter:
    """Per-IP and global failure counters with lockouts. In-memory by design:
    a restart clearing the counters is acceptable, and it keeps this to one
    file with no database."""

    def __init__(self):
        self._ip_fails: dict[str, list[float]] = {}
        self._ip_locked_until: dict[str, float] = {}
        self._global_fails: list[float] = []
        self._global_locked_until = 0.0
        self._lock = threading.Lock()

    def check(self, ip: str) -> tuple[bool, str]:
        now = time.time()
        with self._lock:
            if now < self._global_locked_until:
                return False, "global lockout"
            if now < self._ip_locked_until.get(ip, 0):
                return False, "ip lockout"
        return True, ""

    def record_failure(self, ip: str) -> None:
        now = time.time()
        cutoff = now - FAIL_WINDOW
        with self._lock:
            fails = [t for t in self._ip_fails.get(ip, []) if t > cutoff]
            fails.append(now)
            self._ip_fails[ip] = fails
            if len(fails) >= MAX_FAILS_PER_IP:
                self._ip_locked_until[ip] = now + IP_LOCKOUT
                log.warning("LOCKOUT ip=%s for %ds (%d failures)", ip, IP_LOCKOUT, len(fails))

            self._global_fails = [t for t in self._global_fails if t > cutoff] + [now]
            if len(self._global_fails) >= MAX_FAILS_GLOBAL:
                self._global_locked_until = now + GLOBAL_LOCKOUT
                log.warning("GLOBAL LOCKOUT for %ds (%d failures in %ds)",
                            GLOBAL_LOCKOUT, len(self._global_fails), FAIL_WINDOW)

    def record_success(self, ip: str) -> None:
        with self._lock:
            self._ip_fails.pop(ip, None)
            self._ip_locked_until.pop(ip, None)


# ── Tailscale ────────────────────────────────────────────────────────────────

def _http_json(url: str, *, data: bytes | None, headers: dict, timeout: int = 15):
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _oauth_token() -> str:
    """Exchange the OAuth client for a short-lived access token.

    This is why OAuth beats a raw API key: the credential on disk can only mint
    auth keys for tag:guest, and what actually goes out on the wire is a token
    that expires on its own. A stolen API key, by contrast, keeps working until
    you notice and revoke it.
    """
    body = (
        f"client_id={urllib.parse.quote(TS_OAUTH_CLIENT_ID)}"
        f"&client_secret={urllib.parse.quote(TS_OAUTH_CLIENT_SECRET)}"
        f"&grant_type=client_credentials"
    ).encode()
    data = _http_json(
        "https://api.tailscale.com/api/v2/oauth/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return data["access_token"]


def mint_ephemeral_key() -> str | None:
    """Ask Tailscale for a single-use, ephemeral, pre-approved key.

    ephemeral=true is what makes the device delete itself from the tailnet once
    it disconnects — that is the "session closes on logout" behaviour, enforced
    by Tailscale rather than by the launcher script remembering to clean up.
    """
    try:
        if TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET:
            bearer = _oauth_token()
        elif TS_API_KEY:
            bearer = TS_API_KEY
        else:
            log.error("no Tailscale credential configured")
            return None

        payload = json.dumps({
            "capabilities": {
                "devices": {
                    "create": {
                        "reusable": False,
                        "ephemeral": True,
                        "preauthorized": True,
                        "tags": [TS_TAG],
                    }
                }
            },
            "expirySeconds": KEY_TTL_SECONDS,
            "description": "remote-access gatekeeper",
        }).encode()

        data = _http_json(
            f"https://api.tailscale.com/api/v2/tailnet/{TS_TAILNET}/keys",
            data=payload,
            headers={"Authorization": f"Bearer {bearer}",
                     "Content-Type": "application/json"},
        )
        return data.get("key")

    except urllib.error.HTTPError as e:
        log.error("tailscale api %s: %s", e.code, e.read()[:400].decode(errors="replace"))
    except Exception as e:
        log.error("tailscale api failed: %r", e)
    return None


# ── HTTP ─────────────────────────────────────────────────────────────────────

MAX_BODY = 1024  # a JSON blob with a 6-digit OTP; anything larger is abuse

gate: OTPGate
limiter = RateLimiter()


class Handler(BaseHTTPRequestHandler):
    server_version = "gatekeeper"
    sys_version = ""

    def log_message(self, fmt, *args):  # route access logs through our logger
        log.info("%s %s", self.client_ip(), fmt % args)

    def client_ip(self) -> str:
        """Real client IP.

        Every request arrives from the cloudflared container on the shared
        joatverse_edge network, so the socket peer is always cloudflared's own
        address there — not the real client — and useless for per-IP limiting.
        Cloudflare puts the true origin in CF-Connecting-IP. We trust that
        header only because the tunnel is the sole path in; the global
        lockout is the backstop if that assumption is ever wrong.
        """
        return self.headers.get("CF-Connecting-IP") or self.client_address[0]

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/") != ROUTE.rstrip("/"):
            self._send(404, {"error": "Not found"})
            return
        try:
            script = LAUNCHER_PATH.read_text(encoding="utf-8")
        except OSError as e:
            log.error("cannot read launcher: %r", e)
            self._send(500, {"error": "Launcher unavailable"})
            return

        # Single source of truth: the endpoint URL lives in config, not in
        # two files that can drift apart.
        script = script.replace("{{BACKEND_URL}}", PUBLIC_URL)

        # Serve CRLF. Windows PowerShell parses this text as one string via
        # `irm | iex`, and LF-only endings make multi-line constructs fragile
        # there. The launcher is ASCII-only by design (see its header), so
        # ascii() encoding is also a guard: if a non-ASCII character ever
        # sneaks back in, this raises here instead of producing mojibake on
        # the client.
        script = script.replace("\r\n", "\n").replace("\n", "\r\n")
        try:
            body = script.encode("ascii")
        except UnicodeEncodeError as e:
            log.error("launcher contains non-ASCII at pos %d — refusing to serve", e.start)
            self._send(500, {"error": "Launcher encoding error"})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        log.info("served launcher to %s", self.client_ip())

    def do_POST(self):
        ip = self.client_ip()

        if self.path.rstrip("/") != ROUTE.rstrip("/"):
            self._send(404, {"error": "Not found"})
            return

        allowed, why = limiter.check(ip)
        if not allowed:
            log.warning("BLOCKED ip=%s (%s)", ip, why)
            self._send(429, {"error": "Too many attempts. Try again later."})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                raise ValueError("bad length")
            otp = json.loads(self.rfile.read(length).decode())["otp"]
        except Exception:
            self._send(400, {"error": "Invalid request body"})
            return

        if not (isinstance(otp, str) and len(otp) == 6 and otp.isdigit()):
            self._send(400, {"error": "OTP must be 6 digits"})
            return

        ok, reason = gate.verify(otp)
        if not ok:
            limiter.record_failure(ip)
            log.warning("AUTH FAIL ip=%s reason=%s", ip, reason)
            self._send(401, {"error": "Invalid or already-used code"})
            return

        limiter.record_success(ip)
        log.info("AUTH OK ip=%s — minting key", ip)

        key = mint_ephemeral_key()
        if not key:
            self._send(502, {"error": "Failed to issue VPN key"})
            return

        log.info("KEY ISSUED ip=%s ttl=%ds tag=%s", ip, KEY_TTL_SECONDS, TS_TAG)
        self._send(200, {"key": key})


def main():
    global gate

    if not TOTP_SECRET:
        sys.exit("TOTP_SECRET is not set")
    if not (TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET) and not TS_API_KEY:
        sys.exit("no Tailscale credential set (OAuth client or TS_API_KEY)")
    if not LAUNCHER_PATH.exists():
        sys.exit(f"launcher not found at {LAUNCHER_PATH}")

    gate = OTPGate(TOTP_SECRET)

    auth_mode = "oauth" if TS_OAUTH_CLIENT_ID else "api-key"
    log.info("listening on %s:%d route=%s auth=%s tag=%s",
             BIND_HOST, BIND_PORT, ROUTE, auth_mode, TS_TAG)

    ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
