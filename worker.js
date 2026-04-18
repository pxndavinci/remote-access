// worker.js
// Deploy this to Cloudflare Workers
// Secrets to set via wrangler CLI (never hardcode here):
//   wrangler secret put TOTP_SECRET
//   wrangler secret put TS_API_KEY
//   wrangler secret put TS_TAILNET

function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const output = [];
  for (const char of base32.toUpperCase().replace(/=+$/, "")) {
    value = (value << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

// Replace the single generateTOTP call + comparison with this:
async function verifyTOTP(secret, otp) {
  const counter = Math.floor(Date.now() / 30000);
  for (const delta of [-1, 0, 1]) {
    const code = await generateTOTPForCounter(secret, counter + delta);
    if (otp === code) return true;
  }
  return false;
}

async function generateTOTPForCounter(secret, counter) {
  const key = await crypto.subtle.importKey(
    "raw", base32ToBytes(secret),
    { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const buf = new ArrayBuffer(8);
  new DataView(buf).setUint32(4, counter, false);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const offset = sig[19] & 0xf;
  const code =
    ((sig[offset] & 0x7f) << 24 | sig[offset+1] << 16 |
      sig[offset+2] << 8 | sig[offset+3]) % 1000000;
  return String(code).padStart(6, "0");
}

export default {
  async fetch(request, env) {

    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405,
        headers: { "Content-Type": "application/json" }
      });
    }

    let otp;
    try {
      ({ otp } = await request.json());
    } catch {
      return new Response(JSON.stringify({ error: "Invalid request body" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    if (!/^\d{6}$/.test(otp)) {
      return new Response(JSON.stringify({ error: "OTP must be 6 digits" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    const valid = await verifyTOTP(env.TOTP_SECRET, otp);
    if (!valid) {
      await new Promise(r => setTimeout(r, 2000));
      return new Response(JSON.stringify({ error: "Invalid OTP" }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }

    const tsRes = await fetch(
      `https://api.tailscale.com/api/v2/tailnet/${env.TS_TAILNET}/keys`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.TS_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          capabilities: {
            devices: {
              create: {
                reusable: false,
                ephemeral: true,
                preauthorized: true,
                tags: ["tag:guest"]
              }
            }
          },
          expirySeconds: 300
        })
      }
    );

    const tsData = await tsRes.json();
    if (!tsData.key) {
      return new Response(JSON.stringify({ error: "Failed to issue VPN key" }), {
        status: 502,
        headers: { "Content-Type": "application/json" }
      });
    }

    return new Response(JSON.stringify({ key: tsData.key }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
};
