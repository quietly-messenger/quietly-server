# Quietly server

Server-side of [Quietly](https://github.com/quietly-messenger) — a messenger with Telegram-level UX and a Signal/Matrix-level security model. This repo is the home server: account and device registry, encrypted message store-and-forward, and (eventually) federation.

The server never sees plaintext. It stores and routes ciphertext and device keys, and that's it. All encryption/decryption happens on the client.

> **Status:** the MVP home server (accounts, devices, prekeys, delivery tokens,
> message store-and-forward, WebSocket delivery, PoW) is implemented per
> `api/v1/PROTOCOL.md`. The trust service and federation gateway are an
> **experimental first cut** — inbound verification only, described in
> `docs/FEDERATION.md` rather than the protocol spec. Not yet a stable release:
> the API and schema may still change.

## Contents

- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Getting started](#getting-started)
- [Project layout](#project-layout)
- [Configuration](#configuration)
- [API](#api)
- [Security](#security)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Architecture

At MVP, this server handles:

- **Account & device registry** — username-based accounts (no phone/email), per-device identity keys, signed prekeys, and one-time prekey batches for X3DH.
- **Message store-and-forward** — clients upload encrypted messages addressed to a specific recipient device; the server queues them until the device fetches and acks. Undelivered messages expire after ~30 days.
- **Push triggers** — wakes up a client via UnifiedPush or a persistent connection, without revealing anything about the message content.

Federation (trust service + gateway) ships as an experimental first cut, inbound-verification only. **Group messaging, encrypted media/attachments, calls, and encrypted backups are planned, not implemented** — they appear in the org-level plans and `CLIENT_DESIGN.md` as milestones, and have no endpoints or protocol chapters yet. The full protocol and architecture writeup lives in the [org-level docs](https://github.com/quietly-messenger).

## Tech stack

- **Go** — backend language
- **chi** — HTTP routing and middleware
- **PostgreSQL** — primary datastore
- **JSON** — wire format (protobuf is deferred, see `api/v1/PROTOCOL.md` §16)
- **Docker Compose** — local development and deployment

## Getting started

### Prerequisites

- Go 1.26.5
- Docker and Docker Compose
- `golang-migrate` CLI, installed as `migrate`:
  ```bash
  go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
  ```
  If your binary is named differently, override it: `make MIGRATE=your-name migrate-up`.

### Run the full stack with Docker

The easiest way to run everything — PostgreSQL, the home server, the trust
service, and the federation gateway — is Docker Compose. Build from the parent
directory that contains both `quietly-server` and `quietly-crypto` (the server's
`go.mod` references quietly-crypto via a local `replace`):

```bash
git clone https://github.com/quietly-messenger/quietly-server.git
git clone https://github.com/quietly-messenger/quietly-crypto.git
cd quietly-server
cp .env.example .env   # DATABASE_URL already points at the `postgres` service

docker compose up --build
```

This runs migrations and starts `server` on `:8080`. The trust service (`:8081`)
is internal to the Compose network, and the gateway (`:8082`) is bound to
localhost: terminate TLS in front before exposing either to peers. Set
`TRUST_ADMIN_TOKEN` in `.env` before starting.

### Run locally (without Docker)

```bash
git clone https://github.com/quietly-messenger/quietly-server.git
cd quietly-server
cp .env.example .env
```

**Edit `.env` before going further.** `DATABASE_URL` ships as a placeholder and will not connect as-is. For the local Compose setup, the matching value is:

```
DATABASE_URL=postgresql://quietly:quietly@localhost:5432/quietly?sslmode=disable
```

Compose reads the same `.env`, so if you change `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, or `POSTGRES_PORT`, keep `DATABASE_URL` consistent with them.

```bash
# start Postgres
docker compose up -d postgres

# run migrations
make migrate-up

# run the server
make run
```

The server listens on `:8080` by default (configurable, see below).

The server itself reads only the process environment; it never opens `.env`. Locally, the `Makefile` loads `.env` and exports it before running. In deployment, configuration comes from systemd `Environment=` or whatever supervisor you use — no `.env` file is involved.

### Common commands

```bash
make run          # run the server locally
make test         # run the test suite
make migrate-up   # apply pending migrations
make migrate-down # roll back the last migration
make lint         # run golangci-lint
```

The suite includes PostgreSQL integration tests (`internal/storage/postgres`). They apply the real migrations to a scratch schema and run **only when `DATABASE_URL` is set** — against the Compose Postgres locally, and against a service container in CI. Without it they skip, so `make test` works with no database running.

## Project layout

```
cmd/
  server/           home server entry point (wiring only)
  trust/            directory/trust service (CA)
  gateway/          federation gateway (S2S delivery)
internal/
  account/          account creation, PoW verification, username lookup
  device/           device registration, prekey management, delivery tokens
  message/          store-and-forward, TTL
  auth/             request signature verification middleware
  api/              JSON wire types + error model
  id/               UUIDv4 + monotonic ULID generation
  storage/          Store interface + postgres implementation
  storage/memory/   in-memory Store for tests and local runs
  ratelimit/        bounded token-bucket limiter (per-IP, bundle fetch)
  transport/http/   handlers, routes
  transport/ws/     WebSocket hub
  transport/tlsconfig/ TLS 1.3 configuration shared by the binaries
  federation/       S2S types + cert/signature/replay verification
  trust/            certificate authority with persisted state
  testutil/         signed-request and fixture helpers (tests only)
  config/           env-based configuration
migrations/         SQL schema migrations
docs/FEDERATION.md  federation design (first cut)
```

`internal/` holds anything that isn't meant to be imported outside this module. Handlers stay thin — parsing and responses only; business logic lives in the domain packages.

## Configuration

The server is configured entirely through environment variables. See `.env.example` for the full list. The essentials:

| Variable | Description | Default |
|---|---|---|
| `SERVER_ADDR` | listen address | `:8080` |
| `DATABASE_URL` | Postgres connection string | — |
| `MESSAGE_TTL_DAYS` | offline message expiry | `30` |
| `LOG_LEVEL` | `debug`/`info`/`warn`/`error` | `info` |
| `POW_DIFFICULTY` | account-creation proof-of-work leading zero bits (raise before public registration — §4.3) | `20` |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | terminate TLS 1.3 in-process (or leave unset behind a TLS proxy) | — |
| `BUNDLE_FETCH_PER_HOUR` | per-address prekey-bundle limit (bundle fetch is unauthenticated — §12.7) | `60` |
| `DELIVERY_JITTER_MS` | max server-side hold before a message is delivered (0 disables; partial timing mitigation — §17) | `0` |
| `REQUESTS_PER_MINUTE` | per-IP request limit for the HTTP surface | `120` |
| `TRUSTED_PROXIES` | IPs/CIDRs of reverse proxies whose `X-Forwarded-For` may key the per-IP limiter (empty: header always ignored — audit F-23) | empty |
| `WS_PING_INTERVAL_S` / `WS_IDLE_TIMEOUT_S` | WebSocket keepalive / idle close | `30` / `90` |
| `WS_ALLOWED_ORIGINS` | browser origins allowed on `/v1/ws` (native clients unaffected) | empty |

The trust service additionally uses `TRUST_ADMIN_TOKEN` (required — admin bearer token for issuing/revoking certificates), `TRUST_PRIVATE_KEY`, `TRUST_STATE_PATH`, and the gateway uses `TRUST_PUBLIC_KEY` and `TRUST_URL`.

**TLS.** `PROTOCOL.md` §1 requires HTTPS on every client connection. Either set `TLS_CERT_FILE`/`TLS_KEY_FILE` (TLS 1.3 is enforced) or run the server behind a TLS terminator such as Caddy or nginx. The same applies to `trust` and `gateway` for server-to-server links; the reference Compose setup keeps those internal/localhost-only until you configure certificates.

**Reverse proxies.** If a proxy sits in front of the server, set `TRUSTED_PROXIES` to its address(es) so the per-IP rate limiter keys on the forwarded client rather than the proxy. The server ignores `X-Forwarded-For` from any peer not listed there, because an arbitrary client can set that header.

**Deployment privacy.** Anything in front of the server — a reverse proxy, load balancer, or container platform — logs source IPs and request times unless you configure it not to. The protocol minimizes what the server *needs* to know; your logging configuration decides what it *keeps*. See `PROTOCOL.md` §17.

## API

**The normative specification is [`api/v1/PROTOCOL.md`](./api/v1/PROTOCOL.md).** It defines every byte on the wire — key formats, binary layouts, KDF inputs, error codes, and limits. Where this README and that document disagree, the specification is right.

Most requests are authenticated by having each device sign them with its Ed25519 identity key — there is no password and no session token. Message submission is the exception: it is unauthenticated by design, because a signature would identify the sender and defeat sealed sender. It is gated by a per-device delivery token instead.

Endpoints at MVP stage:

| Endpoint | Auth |
|---|---|
| `GET /v1/accounts/pow-params` | none |
| `POST /v1/accounts` | PoW + self-signed device 1 |
| `POST /v1/devices` | existing device |
| `GET /v1/devices` | device |
| `DELETE /v1/devices/{device_id}` | device |
| `GET /v1/users/{username}` | device |
| `GET /v1/devices/{user_id}/{device_id}/prekey-bundle` | device |
| `GET /v1/devices/{user_id}/{device_id}/delivery-token` | device |
| `POST /v1/devices/{device_id}/prekeys` | that device |
| `PUT /v1/devices/{device_id}/signed-prekey` | that device |
| `PUT /v1/devices/{device_id}/delivery-token` | that device |
| `PUT /v1/devices/{device_id}/push-endpoint` | that device |
| `POST /v1/messages` | **none** — delivery token |
| `GET /v1/messages` | device |
| `POST /v1/messages/{id}/ack` | device |
| `GET /v1/ws` | device |

JSON over HTTPS. Protobuf is a later optimization, once the schema stops moving.

## Security

The protocol's metadata register lives in `api/v1/PROTOCOL.md` §17. The deployment half — adversaries, the operator-facing checklist, and the gates before public registration — is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Roadmap

- [x] Account/device registration with PoW anti-abuse
- [x] Message store-and-forward with TTL cleanup
- [ ] Media upload/download for encrypted attachments
- [x] Realtime delivery over WebSocket
- [x] Federation gateway and trust service (inbound verification, first cut)
- [ ] Group messaging support
- [ ] Outbound federation (user → home-server directory, peer routing)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Issues and PRs are welcome, but given the security-sensitive nature of this project, please open an issue to discuss any change to the crypto-adjacent parts (auth, key storage, message envelopes) before sending a PR.

## License

AGPL-3.0 — see [LICENSE](./LICENSE).
