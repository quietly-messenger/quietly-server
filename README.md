# Quietly server

Server-side of [Quietly](https://github.com/quietly-messenger) — a messenger with Telegram-level UX and a Signal/Matrix-level security model. This repo is the home server: account and device registry, encrypted message store-and-forward, and (eventually) federation.

The server never sees plaintext. It stores and routes ciphertext, device keys, and encrypted media blobs, and that's it. All encryption/decryption happens on the client.

> **Status:** early development, no stable release yet. API and schema will change without notice until v1.

## Contents

- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Getting started](#getting-started)
- [Project layout](#project-layout)
- [Configuration](#configuration)
- [API](#api)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Architecture

At MVP, this server handles:

- **Account & device registry** — username-based accounts (no phone/email), per-device identity keys, signed prekeys, and one-time prekey batches for X3DH.
- **Message store-and-forward** — clients upload encrypted messages addressed to a specific recipient device; the server queues them until the device fetches and acks. Undelivered messages expire after ~30 days.
- **Media storage** — encrypted attachments, referenced by opaque IDs.
- **Push triggers** — wakes up a client via UnifiedPush or a persistent connection, without revealing anything about the message content.

Federation, the trust/CA service, and group messaging are planned for later stages and are not part of the current build. The full protocol and architecture writeup lives in the [org-level docs](https://github.com/quietly-messenger).

## Tech stack

- **Go** — backend language
- **chi** — HTTP routing and middleware
- **PostgreSQL** — primary datastore
- **Protobuf** — wire format for client-server and future server-server messages
- **Docker Compose** — local development environment

## Getting started

### Prerequisites

- Go 1.26.5
- Docker and Docker Compose
- `golang-migrate` CLI, installed as `migrate`:
  ```bash
  go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
  ```
  If your binary is named differently, override it: `make MIGRATE=your-name migrate-up`.

### Setup

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
docker compose up -d

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

## Project layout

```
cmd/server/        entry point, wiring only
internal/
  account/          account creation, PoW verification
  device/           device registration, prekey management
  message/          store-and-forward, TTL cleanup
  auth/             request signature verification
  storage/postgres/ concrete repository implementations
  transport/http/   handlers, routes, middleware
  config/           env-based configuration
migrations/         SQL schema migrations
api/                protobuf/openapi definitions
deploy/             Dockerfile, systemd units
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

## Roadmap

- [ ] Account/device registration with PoW anti-abuse
- [ ] Message store-and-forward with TTL cleanup
- [ ] Media upload/download for encrypted attachments
- [ ] Realtime delivery over WebSocket
- [ ] Federation gateway and trust service
- [ ] Group messaging support

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Issues and PRs are welcome, but given the security-sensitive nature of this project, please open an issue to discuss any change to the crypto-adjacent parts (auth, key storage, message envelopes) before sending a PR.

## License

AGPL-3.0 — see [LICENSE](./LICENSE).
