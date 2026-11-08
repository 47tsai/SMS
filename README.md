# SMS Forwarder

Cloudflare Worker that accepts an authenticated JSON request from iOS Shortcuts and forwards it to Discord as an Embed.

## GitHub Actions deployment secrets

Configure these repository secrets:

- `CLOUDFLARE_API_TOKEN`: Cloudflare API token with permission to deploy Workers.
- `CLOUDFLARE_ACCOUNT_ID`: Cloudflare account ID.

Pushing changes to `main` deploys the Worker automatically.

## Cloudflare Worker runtime secrets

After the first successful deployment, open **Cloudflare Dashboard → Workers & Pages → sms-forwarder → Settings → Variables and Secrets** and add:

- `SMS_FORWARDER_API_KEY`: a long random key used to authenticate incoming requests.
- `DISCORD_WEBHOOK_URL`: the Discord webhook URL. Keep this secret.

Do not put the Discord webhook URL or API key in the source code, Shortcut text, or a public issue.

## Endpoint

- `GET /`: inbox UI (Chi Auth login required).
- `GET /health`: health check.
- `POST /` or `POST /sms`: forwards a message to Discord.

Send JSON with these fields:

```json
{
  "sender": "Service name",
  "message": "Example notification",
  "receivedAt": "2026-10-27 12:00:00"
}
```

Authenticate with the `X-API-Key` header set to the value of `SMS_FORWARDER_API_KEY`.

Successful response (D1 storage and Discord delivery are reported separately):

```json
{ "ok": true, "saved": true, "id": 12, "discord": { "ok": true, "status": 204 } }
```

If the message was saved to D1 but Discord rejected it, the response is HTTP 502 with `saved: true` and `discord: { "ok": false, "status": ..., "error": ... }` — a failed notification is never reported as success.

## Limits and behaviour

- **Rate limiting**: ingest (`POST /`, `POST /sms`) is limited to 30 requests per minute per client IP, and admin routes (`DELETE`, clear) share the same per-IP limit, via the `SMS_LIMITER` binding in `wrangler.toml` (`[[ratelimits]]`). Exceeding it returns HTTP 429. If the binding is missing at runtime the Worker logs and proceeds, so a limiter outage does not take down ingest.
- **Request body limit**: 32 KiB. Larger bodies are rejected with HTTP 413, whether or not the client sends a `Content-Length` header.
- **Payload validation**: the body must be a JSON object; `sender` (≤200 chars) and `message` (≤3500 chars, non-empty) must be strings. Invalid payloads return HTTP 400 instead of crashing with 500.
- **Idempotency**: a message is identified by the SHA-256 hash of `sender + message + receivedAt`. Retrying the same request (e.g. an iOS Shortcut retry) returns the existing record with `duplicate: true` and does not write a second row or send a second Discord notification. The hash is enforced by a `UNIQUE` index (`migrations/0002_idempotency_and_retention.sql`).
- **Long messages**: the full message is always sent to Discord (never truncated to an OTP or a summary). Messages longer than Discord's 1024-character embed field limit are split across several fields labelled `1/N`, `2/N`, … so the complete text arrives.
- **CORS and security headers**: the API only accepts the `https://sms.chi.qzz.io` origin; responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a Content-Security-Policy on the inbox page.
- **API key check**: the key is compared in constant time (SHA-256 digests first) instead of `===`.

## Retention: 30 days (D1 only)

Messages are kept in D1 for 30 days. Each row gets `expires_at = created_at + 30 days` (UTC, set by the database at insert time), and a daily cron trigger (03:00 Taipei, `0 19 * * *` UTC) deletes expired rows. Rows created before the 0002 migration have no `expires_at` and are deleted by `created_at` instead.

Timezone note: expiry is based on server-side ingestion time (`created_at`, UTC), **not** on `receivedAt`. `receivedAt` is a raw local-time string sent by the iOS Shortcut with no timezone attached, so it cannot be compared reliably.

**Discord copies are not deleted by this cleanup.** A message already delivered to Discord stays in the Discord channel; clearing D1 only removes the Worker's own copy. The inbox UI says the same when clearing messages.

## Tests

```sh
npm test   # node --test test/sms.test.mjs (Node built-in test runner, no dependencies)
```

The tests cover payload validation, Discord field splitting (including emoji), CSV formula escaping, the idempotency hash, and the full ingest flow against a mocked D1 and mocked Discord webhook, including duplicate retries, long messages, oversized bodies, rate limiting, and the 30-day cleanup.

The Worker does not intentionally log message content. Treat forwarded SMS as sensitive because messages can contain login codes.
