# Federation — first-cut design

`PROTOCOL.md` defers federation (§16 reserves only a `domain` field), so this is
a **provisional design**, not a normative spec. It will be frozen (and the S2S
domain strings moved into the shared `quietly-crypto/quietly` package) before
federation ships.

## Model

Every home server holds an Ed25519 identity key. A **Trust Service (CA)** issues
a certificate binding a server's domain to its public key, and publishes a
revocation list. Servers trust only certificates signed by the trust service.

| Component | Binary | Role |
|---|---|---|
| Trust Service | `cmd/trust` | Issues/revokes server certs; lists trusted servers |
| Federation Gateway | `cmd/gateway` | Receives signed S2S delivery requests, verifies, enqueues locally |

## Certificate

`ServerCert{ domain, public_key, signature }`, where `signature` is the trust
service's Ed25519 signature over `domain || 0x00 || public_key`
(`federation.SignCert` / `VerifyCert`).

## Delivery request

A gateway-to-gateway delivery carries the sender's certificate plus a signed
request:

```json
{
  "cert":   { "domain": "alice.example", "public_key": "...", "signature": "..." },
  "request": {
    "v": "quietly/1",
    "domain": "alice.example",
    "timestamp": 1785340800000,
    "nonce": "...",
    "recipient": { "user_id": "...", "device_id": 1 },
    "sealed": "...",
    "signature": "..."
  }
}
```

The request signature is the sender server's Ed25519 over
`"quietly/1 s2s" || 0x00 || domain || 0x00 || timestamp || 0x00 || nonce || 0x00 || SHA-256(sealed)`
(`SignedRequest.Sign` / `Verify`). The receiver verifies the cert against the
trust-service public key (and that it is not revoked), then the request
signature against the cert's public key, and only then enqueues the sealed blob.

## Not yet designed (explicit gaps)

- **User → home-server directory.** `user_id` is a globally-unique UUID, but
  there is no mapping from a federated `user_id` to its home server's domain.
  The trust service is a CA, not a directory; a directory (or domain-scoped
  usernames) is required before outbound routing works.
- **Outbound routing** on the sending side (which gateway to POST to).
- **Replay/rate limits** on the S2S channel.

Until these are resolved, federation is inbound-verification-only.
