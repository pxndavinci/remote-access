# remote-access

SSH into **archie** from any untrusted Windows machine, with one command, no
VPN client pre-installed and no credential left behind.

```powershell
irm https://remote.joatverse.com/archie | iex
```

Enter the 6-digit Authy code → you land in a shell on archie. Type `exit` and
the machine is scrubbed: VPN down, device deleted from the tailnet, Tailscale
disabled until the next run.

---

## Flow

```
Windows box:  irm https://remote.joatverse.com/archie | iex
                    │
                    ├─ GET  /archie  ──► launcher.ps1 (no secrets, safe public)
                    │
              [type TOTP]
                    │
                    └─ POST /archie  {"otp":"123456"}
                            │
        Cloudflare edge ► cloudflared ► remote-gatekeeper:8787 ► gatekeeper.py
                            │                                  ├ TOTP verify (constant-time)
                            │                                  ├ replay cache (single-use codes)
                            │                                  ├ rate limit (per-IP + global)
                            │                                  └ Tailscale API ► ephemeral key
                            ◄── {"key":"tskey-auth-..."}
                    │
              tailscale up --authkey  ►  ssh pxanda@archie  (Tailscale SSH, no password)
                    │
              exit ► tailscale down/logout ► ephemeral device auto-deleted
```

## Files

| File | Role |
|---|---|
| `gatekeeper.py` | The whole backend. Stdlib only. Serves the launcher on GET, mints keys on POST. |
| `launcher.ps1` | What runs on the Windows box. Contains no secrets; `{{BACKEND_URL}}` is substituted at serve time. |
| `docker-compose.yml` | How it runs. Stock `python:3.13-slim` + read-only source mount — no image to build. |
| `gatekeeper.env.example` | Template for `gatekeeper.env` (chmod 600, gitignored). |

## Setup

**1. Tailscale OAuth client** — admin console → Settings → OAuth clients → Generate.
Scope `auth_keys` **write**, tags `tag:guest`. Copy the ID and secret.

**2. Secrets file**

```bash
cp gatekeeper.env.example gatekeeper.env
nano gatekeeper.env          # fill TOTP_SECRET + OAuth client
chmod 600 gatekeeper.env
```

**3. Run it**

```bash
docker compose up -d
docker compose logs -f
```

Editing `gatekeeper.py` or `launcher.ps1` needs only `docker compose restart` —
both are mounted, not baked into an image.

**4. Cloudflare tunnel ingress** — Zero Trust → Networks → Tunnels → your tunnel
→ Public Hostnames → Add:

| Field | Value |
|---|---|
| Subdomain | `remote` |
| Domain | `joatverse.com` |
| Service | `HTTP` → `remote-gatekeeper:8787` |

> **Use the container name, never an IP or `localhost`.** cloudflared shares
> the `joatverse_edge` network with this container and resolves the name via
> Docker's embedded DNS. `localhost` would mean the cloudflared container
> itself (that is why `test.joatverse.com → localhost:3000` returns
> "connection refused"), and a pinned container IP breaks the moment Docker
> reshuffles addresses on a daemon restart — which took Immich down on
> 2026-09-13.

**5. Verify**

```bash
curl -s https://remote.joatverse.com/archie | head -5     # through the tunnel
curl -s -XPOST https://remote.joatverse.com/archie -d '{"otp":"000000"}'
# -> {"error": "Invalid or already-used code"}
```

## Tailscale lifecycle on the Windows box

The launcher tracks whether *it* installed Tailscale, and cleans up to match:

| On arrival | On exit |
|---|---|
| Tailscale already installed | Signed out, ephemeral device deleted — **left installed** |
| Tailscale not installed | Installed silently via `msiexec /qn` (no dialogs), then **fully uninstalled** |

> **If Tailscale is already signed in on that machine, the launcher stops and
> asks before continuing.** `tailscale up --reset` replaces the active account,
> and there is no way to sign the original one back in afterwards. On a machine
> that is genuinely someone else's, answer `N`.

## Tailnet prerequisites (already configured)

- archie is tagged `tag:remote-server` and runs Tailscale SSH (`RunSSH: true`).
- The ACL grants `tag:guest` → `tag:remote-server` as user `pxanda`, auto-approved.
- Guest devices are created ephemeral, so they delete themselves on disconnect.

## What changed from the Cloudflare Workers version

| Was | Now | Why |
|---|---|---|
| `bit.ly` → GitHub Gist | `remote.joatverse.com` | A shortener account compromise meant arbitrary admin code execution on whatever machine ran the one-liner. That link is gone from the trust chain. |
| 2-second sleep on bad OTP | per-IP + global failure counters with lockout | The sleep throttled nothing — it was per-request, so concurrent requests all slept at once. With 3 valid codes out of 1,000,000 per window, brute force was genuinely reachable. |
| Codes reusable for ~90s | single-use (replay cache) | A code captured on the untrusted box (keylogger, screen recorder, shoulder surf) could be replayed before expiry. |
| `otp === code` | `hmac.compare_digest` | Not short-circuiting. Timing attacks over the internet are impractical here; the fix is free. |
| Password SSH | Tailscale SSH | The old flow typed your account password into a possibly-keylogged machine. Now nothing secret leaves that box — the WireGuard tunnel identity *is* the authentication. |
| Long-lived `TS_API_KEY` | OAuth client → short-lived tokens | A stolen API key mints VPN keys until you notice. The OAuth client is scoped to `auth_keys` for `tag:guest` only. |
| No logs | every attempt logged to journald | You would previously have had no idea you were being probed. |

## Known behaviour, not a bug

- **A valid code is consumed even if Tailscale then fails.** Verification marks
  the code spent before the API call. If minting 502s you wait ~30s for a fresh
  code. Un-consuming on failure would reopen the replay window; the trade is
  deliberate.
- **Rate-limit state is in memory.** Restarting the container clears lockouts.
  Acceptable for a single-file service with no database.
- **No Dockerfile.** `gatekeeper.py` imports nothing outside the stdlib, so
  there is no dependency layer worth building. The cost is that the image tag
  is not pinned to a digest — `docker compose pull` changes the Python
  underneath you. Acceptable here; worth revisiting if this grows deps.
- **`CF-Connecting-IP` is trusted** for per-IP limiting, because the tunnel is
  the only route in — the socket peer is always the cloudflared container and
  therefore useless. The global lockout is the backstop if that ever stops
  being true.
- **`StrictHostKeyChecking=accept-new` is intentional.** Under Tailscale SSH the
  peer is already authenticated cryptographically by WireGuard, so host-key
  TOFU is no longer the thing protecting the session.

## Residual risk

`irm | iex` as Administrator means total trust in the endpoint. Self-hosting it
on your own domain over TLS is the strongest available form of that bargain,
but it does not eliminate it: whoever controls `remote.joatverse.com` controls
what runs as admin on the machine you type that command into. Protect the
Cloudflare account accordingly.
