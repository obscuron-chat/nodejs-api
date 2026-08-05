<div align="center">
  <table border="1">
    <tr>
      <td align="center" style="padding: 20px;">
        <h3>📢 Domain & Email Migration Notice</h3>
        <p>From <b>May 14 th, 2026</b>, Obscuron will transition to new domains as <code>obscuron.chat</code> will not be renewed:</p>
        <p>🌐 <b>Website:</b> <a href="https://obscuron.faizath.com">obscuron.faizath.com</a> (formerly <i>obscuron.chat</i>)<br>
        ⚙️ <b>API:</b> <a href="https://obscuron-api.faizath.com">obscuron-api.faizath.com</a> (formerly <i>api.obscuron.chat</i>)<br>
        📧 <b>Email:</b> <a href="mailto:contact@obscuron.faizath.com">contact@obscuron.faizath.com</a> (formerly <i>contact@obscuron.chat</i>)<br>
        🛰️ <b>CDN:</b> <a>obscuron-cdn.faizath.com</a> (formerly <i>cdn.obscuron.chat</i>)<br>
        📈 <b>Status Pages:</b> <a href="https://status.faizath.com/status/obscuron">https://status.faizath.com/status/obscuron</a> (formerly <i>status.obscuron.chat</i>)
        </p>
      </td>
    </tr>
  </table>
</div>

# Obscuron API

Express, MongoDB, JWT, and WebSocket service for Obscuron, a web-based
end-to-end encrypted 1:1 chat product. The browser client lives in
[`../obscuron-web`](../obscuron-web).

The wire contract is documented in [`openapi.yaml`](openapi.yaml).

## What this service stores

**Public key bundles and ciphertext envelopes only.**

- Each account holds a validated `PublicKeyBundle`: a public ECDSA secp256k1
  signing key, a public X25519 encryption key, their key IDs, algorithm names,
  and a SHA3-256 fingerprint. Nothing else about the user's keys is stored.
  
- Each message is stored as an `EncryptedMessageEnvelope`: routing metadata plus
  an AES-256-GCM `ciphertext` blob. The collection has no field for
  message text, previews, or plaintext-derived hashes.
- **Private signing keys, private encryption keys, and `EncryptedKeyBundle`
  vault records never reach this API.** They are generated, encrypted, stored,
  exported, and used entirely in the browser. Requests
  carrying such a field are rejected at the validation boundary.
- The server cannot verify message signatures, because it never sees the signed
  inner transcript. Verification is the receiving client's job.
- **There is no server-side key recovery.** Losing the local vault without an
  exported backup means losing the identity; the only remedy is an identity
  reset that publishes fresh keys.
- Logs redact ciphertext, public keys, fingerprints, nonces, HKDF salts,
  authorization headers, and connection credentials.

## Requirements

- Node.js 22 or newer
- MongoDB 7 or newer (or Docker for the bundled Compose stack)
- Docker 24 or newer for container builds

## Setup

```bash
git clone https://github.com/obscuron/nodejs-api.git
cd nodejs-api
npm install
cp .env.example .env
```

Then edit `.env` and replace every value containing `replace_me`. Startup
validates the whole environment **before binding the port** and exits with code
1 and a redacted reason when a value is missing, malformed, insecure, or still
equal to a documented example. `.env` is gitignored; production values
come from the deployment secret manager, never from the repository or the image.


Every variable, its local example, and its production rule are listed in
[`.env.example`](.env.example). The ones worth calling out:

| Variable | Notes |
| --- | --- |
| `JWT_ACCESS_SECRET`, `REFRESH_TOKEN_SECRET` | At least 32 bytes each and must differ from each other. |
| `JWT_ACCESS_TTL` | Exactly `15m`. Access tokens are memory-only in the browser. |
| `REFRESH_COOKIE_NAME` | Must use the `__Host-` prefix; `__Host-obscuron_refresh` in production. |
| `BCRYPT_COST` | Exactly `12`. |
| `CORS_ALLOWED_ORIGINS`, `WS_ALLOWED_ORIGINS` | Exact allowlists. No wildcards, `null`, or trailing slashes. |
| `MESSAGE_RETENTION_DAYS` | 1–365, default 90. Sets the TTL on stored ciphertext. |

## Running

```bash
npm run dev     # nodemon, local development
npm start       # node index.js
```

With Docker Compose (API + MongoDB, matching production variable names):

```bash
docker compose up --build            # api + mongodb
docker compose --profile tools up     # also start mongo-express on :8081
docker compose config                 # validate the stack without starting it
```

`mongo-express` sits behind the `tools` profile and must never be exposed in
production.

## Testing and checks

```bash
npm run lint            # node --check over every source file
npm test                # node --test test/*.test.js
npm run test:coverage   # same suite with V8 coverage
npm audit --audit-level=high
docker compose config
```

The suite covers configuration validation, auth and refresh-token rotation,
audit events, the OpenAPI contract, repository behavior, the WebSocket protocol,
and the shared crypto fixtures in `test/fixtures/protocol/`.

## Endpoints

All responses use `{ "ok": true, "data": … }` or
`{ "ok": false, "error": { code, message, details, requestId } }`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness. No database access. |
| `GET` | `/readyz` | Readiness: MongoDB reachable, indexes ready, upgrades accepted. |
| `POST` | `/auth/register` | Create an account and publish its `PublicKeyBundle`. |
| `POST` | `/auth/login` | Authenticate and start a refresh-token family. |
| `POST` | `/auth/refresh` | Rotate the refresh cookie and mint a new access token. |
| `POST` | `/auth/logout` | Revoke the family, clear the cookie, close that user's sockets. |
| `GET` | `/me` | Read the authenticated public profile. |
| `PATCH` | `/me/profile` | Update display name and avatar URL. |
| `GET` | `/users` | Contact discovery with `q`, `cursor`, and `limit`. |
| `GET` | `/messages/:peer` | Retained ciphertext history, newest first. |
| `POST` | `/identity/reset` | Publish a replacement bundle and bump the identity epoch. |
| `GET` | `/ws` | Authenticated realtime socket (upgrade only). |

Example — register and then read the contact list:

```bash
curl -sX POST http://localhost:8080/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct horse battery staple","displayName":"Alice","publicKeyBundle":{ … }}'

curl -s 'http://localhost:8080/users?q=bo&limit=25' \
  -H 'Authorization: Bearer <accessToken>'
```

### WebSocket `/ws`

The socket accepts only exact `/ws` upgrades from an allowlisted `Origin`;
credentials in the query string are never trusted. The first client frame must
be `authenticate` within 5 seconds or the connection closes `4408
authentication_timeout`.

Event types: `authenticate`, `authenticated`, `message.send`, `message.ack`,
`message.new`, `message.delivered`, `error`.

The server derives the authoritative sender from the socket identity, persists
each envelope before acknowledging it, deduplicates by `messageId`, answers a
changed re-send with `MESSAGE_ID_CONFLICT`, and replays missed events after a
signed cursor. An unusable cursor returns `CURSOR_EXPIRED`, and the client falls
back to `GET /messages/:peer`. Close codes and their reason strings are listed
under `/ws` in [`openapi.yaml`](openapi.yaml).

Limits: 64 KiB frames, compression disabled, 60 messages per minute per user,
5 concurrent sockets per user, and a 30 second heartbeat that terminates a
connection after 2 missed pongs.

## Audit events

Security-relevant outcomes are written as single-line JSON records carrying a
timestamp, event name, request or connection id, username when authenticated,
source IP, origin, result, and a non-sensitive reason code. Values pass
through redaction before reaching the sink, so credentials and key material
cannot leak into logs.

Deployment and backup tooling emits its own events through the same writer:

```bash
node scripts/audit-event.js deploy.started
node scripts/audit-event.js backup.failed "snapshot timeout"
```

The complete allowed event list is in `src/audit.js`.

## Project structure

```
index.js                     # Bootstrap: load config, connect, listen
openapi.yaml                 # HTTP and WebSocket wire contract
compose.yml                  # Local API + MongoDB parity stack
scripts/audit-event.js       # Ops-side audit event emitter
src/
  audit.js                   # Security audit records
  auth.js                    # Registration, login, rotation, rate limits
  config.js                  # Strict startup environment validation
  cookies.js                 # Refresh cookie encode/decode
  db.js                      # Mongo connection, collection and index init
  envelope.js                # ok/error response envelopes and request ids
  realtime.js                # Authenticated /ws protocol and replay
  redaction.js               # Sensitive-field redaction
  validation.js              # Shared field and schema validation
  models/                    # Mongoose schemas and public serializers
  repositories/              # Mongo data access
  routes/                    # Express route registration
test/                        # node --test suite and protocol fixtures
```

## Notes

- MongoDB is the source of record for users, refresh sessions, and encrypted
  messages. Collections and named indexes are created at startup from a clean
  database; this release ships no migration path.
- Refresh tokens are opaque, rotating, and stored only as HMAC digests in an
  `HttpOnly; Secure; SameSite=Strict` cookie. Replaying a rotated token revokes
  the entire family.
- Stored messages expire via a TTL index, and queries additionally filter
  `expiresAt <= now` so expired records are never returned while the sweep is
  pending.
- Obscuron does **not** implement Double Ratchet, forward secrecy, or
  server-side key escrow, and makes no such claim.
