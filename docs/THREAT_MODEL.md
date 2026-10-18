# Threat model

This is the deployment half of the metadata register in `api/v1/PROTOCOL.md`
§17. The protocol section states what the home server can observe; this
document names the adversaries, what each of them can and cannot do, and what
an operator must configure for the promises to hold.

## Assets

| Asset | Where it lives | Protected by |
|---|---|---|
| Message plaintext | client devices only | X3DH + Double Ratchet (§8–9), sealed sender (§10) |
| Identity private keys | client devices | never sent to the server; server holds public halves only |
| Ratchet / session state | client devices | client key store (SQLCipher or Keystore equivalent — client-side work, not yet implemented) |
| Queued message content | server DB, as ciphertext | E2EE; a server or DB compromise yields ciphertext and metadata, not plaintext |
| Delivery tokens | server DB, **plaintext** | nothing at rest (§6); compromise ⇒ spam rights for every device, recovered by rotation |
| Metadata (who↔whom, timing, sizes, IPs) | server DB + logs + operator infrastructure | minimized, **not** hidden (§17) |

## Adversaries

### 1. Passive network observer

Sees TLS metadata: which client connects to which server, when, and how much
traffic flows. Cannot read content (TLS + E2EE). A *global* passive adversary
who watches both ends can correlate conversations — §17 documents this as
accepted. Size padding (§16.1) and delivery jitter (§15) are partial
mitigations; cover traffic remains a reserved gap.

### 2. Malicious or compromised home server

Can read the full §17 register (per-message recipient, quantized size, and
timing; presence; IPs; and the source address/timing of first-contact fetches
— but not *which* device made them, §12.6–12.8), deny or delay service, drop
messages, and serve stale prekey bundles — substitution is eventually detected
by TOFU pinning and safety numbers (§2.0.1, §9.5), not by the crypto itself.
Cannot read content, forge a sender (inner ratchet + sealed sender), or learn
anything from a push wakeup.

### 3. Database compromise (dump, no process access)

Yields queued ciphertext, metadata, public keys, and **plaintext delivery
tokens**. Tokens allow spamming devices until they rotate (§6); they do not
decrypt anything. Session keys, ratchet state, and private identity keys never
exist on the server. The trust service's admin token is configuration, not
database state — keep it out of DB backups.

### 4. Malicious push provider

Sees that a wakeup was sent and the endpoint URL the device registered —
content-free by construction (`{"type":"wake"}`). Can suppress or delay
wakeups (availability), cannot read messages or learn senders. The endpoint
URL itself is device-chosen metadata the provider learns; register opaque,
rotatable topics (§12.12).

### 5. Malicious federated peer / CA

The federation trust anchor is the CA; compromising it can authorize bogus
peers, but cannot read content or impersonate a sender (the inner ratchet
authenticates, §10.4). Peers can only inject ciphertext that fails to decrypt.
Gateways verify certificates, live revocation (polled every 30 s, fail-closed
at boot), the ±5-minute timestamp window, and nonce replay
(`docs/FEDERATION.md`).

### 6. Compromised client device

The Double Ratchet heals *future* messages after a ratchet step (post-
compromise security), but everything stored on the device is exposed. Local
database encryption and key management are the client's responsibility and are
not yet implemented.

### 7. Abuser: bulk registration and anonymous submission

Account creation is gated by a stateless proof of work and per-IP throttling.
PoW is a speed bump, not a gate (§4.3): solves are bankable within the window.
Submission requires a recipient's delivery token (§6), so an anonymous sender
can only spam recipients whose tokens leaked or were fetched. Public
registration is gated on the checklist below.

### 8. The operator (self-hosting reality)

The operator controls the server, its logs, and its legal exposure. Quietly is
self-hosted, so the honest framing is "trust your (or your admin's) server
with metadata, never with content". Deployment reality is part of the model:
reverse proxies, load balancers, and container platforms log source IPs and
request times unless deliberately configured not to (§17).

## Deployment checklist

- [ ] TLS terminated — in-process (`TLS_CERT_FILE`/`TLS_KEY_FILE`, TLS 1.3) or
      by a terminator you control.
- [ ] `TRUST_ADMIN_TOKEN` set (the trust service refuses to start without it);
      no default credentials anywhere.
- [ ] PostgreSQL not exposed publicly; `sslmode=require` or stronger off-host.
- [ ] Proxy/platform access logs configured deliberately (retention, IP
      logging).
- [ ] Behind a reverse proxy: `TRUSTED_PROXIES` lists exactly those proxies, so
      `X-Forwarded-For` is honored only from them (without it the header is
      ignored and every request keys on the proxy's own address).
- [ ] Per-IP throttling (`REQUESTS_PER_MINUTE`) and the per-address bundle-fetch
      limiter (`BUNDLE_FETCH_PER_HOUR`) verified under load; the first-contact
      endpoints (§12.6–12.8) are unauthenticated and must stay behind them.
- [ ] Federation gateway reachable only as intended, with its per-peer delivery
      budget (`S2S_REQUESTS_PER_MINUTE`) sized for real peer traffic.
- [ ] `POW_DIFFICULTY` raised above the default, plus screening a proof of
      work cannot provide (CAPTCHA, invite gate), before opening registration.
- [ ] Backups treated like the database they copy (ciphertext + delivery
      tokens + metadata).
- [ ] `trust` internal-only; `gateway` behind TLS or bound to localhost until
      real peers exist.
- [ ] Federation requires `TRUST_URL` reachable at boot (the gateway fails
      closed otherwise) — monitor that dependency.

## Out of scope for v1 (not claimed)

Cover traffic; timing obfuscation beyond `delivery_jitter_ms` (which exists,
default 0); protection against a global passive adversary; quantum resistance;
formal verification; external audit (**required before public beta**, §17.1).
Size padding is implemented and specified in §16.1 — it removes the length
signal for compliant clients, and it is not server-enforced. When media,
calls, and backups land they each need a threat-model update — a TURN relay
sees IP pairs and traffic shape, media blobs leak sizes, and backup recovery
phrases become a new key-management surface.

## Gates before public registration

1. External review of the crypto core and protocol (§17.1).
2. Independent fuzzing and second known-answer vectors for X3DH, the ratchet,
   and the wire formats.
3. Registration abuse controls: raised difficulty, per-IP limits, and a
   CAPTCHA or invite gate.
4. Client key store (SQLCipher/Keystore) implemented and reviewed.
