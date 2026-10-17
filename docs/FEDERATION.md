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
(`SignedRequest.Sign` / `Verify`).

A gateway accepts a delivery only when **all** of the following hold
(`federation.VerifyDelivery`):

1. the certificate verifies against the trust-service public key;
2. the certificate's domain is not revoked in the trust service's current view
   (the gateway polls `GET /servers` every 30 s and **fails closed** at boot
   until the first successful poll);
3. the request's `domain` equals the certificate's `domain`;
4. `timestamp` is within ±5 minutes of local time (`federation.MaxClockSkew`);
5. the request signature verifies against the certificate's public key;
6. the `(domain, nonce)` pair has not been seen before within the window
   (in-memory replay cache; a gateway restart clears it, so the timestamp
   window is the backstop).

Only then is the sealed blob enqueued.

## Trust service operation

- Issuing (`POST /servers`) and revoking
  (`POST /servers/{domain}/revoke`) require
  `Authorization: Bearer $TRUST_ADMIN_TOKEN`. The service refuses to start
  without the token, so an exposed instance can never mint certificates
  anonymously.
- Issued certificates and revocations are persisted to `TRUST_STATE_PATH`
  (atomic write on every mutation) and reloaded at startup, so a restart cannot
  silently un-revoke a server.
- `GET /ca` and `GET /servers` are public (a directory is meant to be
  readable); they expose only public keys and revocation flags.
- `trust` and `gateway` must speak TLS 1.3 to peers (`TLS_CERT_FILE` /
  `TLS_KEY_FILE`, or a TLS terminator in front). The reference Compose file
  keeps `trust` internal and binds `gateway` to localhost until real peer TLS
  is configured.

## Not yet designed (explicit gaps)

- **User → home-server directory.** `user_id` is a globally-unique UUID, but
  there is no mapping from a federated `user_id` to its home server's domain.
  The trust service is a CA, not a directory; a directory (or domain-scoped
  usernames) is required before outbound routing works.
- **Outbound routing** on the sending side (which gateway to POST to).
- **S2S rate limits.** Replay is bounded (timestamp window + nonce cache), but
  there is no per-peer request budget yet.

Until these are resolved, federation is inbound-verification-only.
