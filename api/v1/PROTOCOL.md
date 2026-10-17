# Quietly Protocol v1

**Status:** draft — not yet tagged. Once tagged `api/v1.0.0`, any change to a defined field is a new version.

**Revision history**

| Date | Change |
|---|---|
| 2026-07-29 | Initial draft |
| 2026-07-29 | Security review fixes: XChaCha20-Poly1305 with random nonce and hedged ephemeral keys for sealed sender (§10.1); AD folded into the X3DH KDF (§8.1); honest statement of what the identity binding does and does not prove (§2); delivery-token fetch split from bundle fetch (§12.8); one-time prekey exhaustion mitigations (§7.2, §15); `device_id` widened to u16 (§1); recipient-state errors collapsed into `delivery_rejected` (§12.13) |

This document specifies every byte that crosses the network between a Quietly client and a Quietly home server. It is the single normative source for both `quietly-server` and `quietly-client`. Where an implementation disagrees with this document, this document is right.

The protocol version constant is **`quietly/1`**. It appears in every request and every envelope. A mismatch is a hard error on both sides, never a silent parse failure.

---

## Table of contents

1. [Conventions](#1-conventions)
2. [Identity model](#2-identity-model)
3. [Cryptographic primitives](#3-cryptographic-primitives)
4. [Proof of work](#4-proof-of-work)
5. [Request authentication](#5-request-authentication)
6. [Delivery tokens](#6-delivery-tokens)
7. [Prekey bundles](#7-prekey-bundles)
8. [X3DH](#8-x3dh)
9. [Double Ratchet message format](#9-double-ratchet-message-format)
10. [Sealed sender](#10-sealed-sender)
11. [Message envelope](#11-message-envelope)
12. [HTTP endpoints](#12-http-endpoints)
13. [WebSocket protocol](#13-websocket-protocol)
14. [Errors](#14-errors)
15. [Parameters and limits](#15-parameters-and-limits)
16. [Reserved for future versions](#16-reserved-for-future-versions)
17. [Known metadata leaks](#17-known-metadata-leaks)

---

## 1. Conventions

| Rule | Value |
|---|---|
| Transport | HTTPS 1.1 or 2, TLS 1.3 minimum |
| Request/response bodies | JSON, UTF-8, `Content-Type: application/json` |
| Binary values in JSON | base64url **without** padding (RFC 4648 §5, `-` and `_`, no `=`) |
| Binary values in binary layouts | raw bytes |
| Integers in binary layouts | big-endian, unsigned |
| Timestamps | Unix milliseconds, signed 64-bit integer |
| Base path | `/v1` |
| Unknown JSON fields | Ignored by receivers. Do not rely on rejection. |
| Missing required field | `invalid_payload` error, never a default value |

`user_id` is a UUIDv4 assigned by the server at account creation. In JSON it appears in canonical hyphenated string form; in binary layouts it is the raw 16 bytes. It is the routing identifier everywhere. Usernames are a lookup alias only and never appear in envelopes.

`device_id` is a server-assigned integer, `1..65535` (u16), unique per account and never reused after revocation. The range is wide because ids are burned permanently on revocation: a user who replaces devices regularly would exhaust a single byte over the lifetime of an account.

---

## 2. Identity model

An **account** is a username and a `user_id`. It carries no phone number, email, password, or other PII.

A **device** belongs to exactly one account and holds two long-term keypairs:

| Key | Algorithm | Purpose |
|---|---|---|
| `identity_key_dh` | X25519 | X3DH Diffie-Hellman, sealed sender decryption |
| `identity_key_sig` | Ed25519 | Signing prekeys, authenticating requests |

Two keys rather than one Curve25519 key with XEdDSA. This trades 32 bytes per device record for removing a hand-written key-conversion primitive from the crypto core.

The two are bound at registration by the **identity binding**: an Ed25519 signature, made with `identity_key_sig`, over the 32 raw bytes of `identity_key_dh`, with the domain-separation prefix from §3.3. A device record whose binding does not verify MUST be rejected.

### 2.0.1 What the identity binding does not prove

The binding is **one-directional**. It proves that whoever holds the private half of `identity_key_sig` asserts this `identity_key_dh`. It does **not** prove the converse, because X25519 keys cannot sign. Anyone can generate their own Ed25519 keypair and produce a valid binding over somebody else's published `identity_key_dh`.

Making the binding mutual would require signing with the X25519 key — that is XEdDSA, the primitive this design deliberately avoids. The residual risk is accepted, and the actual defence against key substitution is elsewhere:

- **Safety numbers** (§9.5) cover both identity keys, so any substitution changes the value both users compare out of band.
- **Trust on first use:** clients MUST pin a contact's identity keys on first session and warn on any later change, treating it as a potential attack rather than a routine event.
- **X3DH binds all four keys into the shared secret** (§8.1), so a tampered bundle yields a different `SK` and the session simply fails to establish, rather than establishing insecurely.

A server that substitutes an `identity_key_sig` cannot read messages — it does not hold the corresponding `identity_key_dh` private half, so `DH2` is beyond it. What it can do is prevent a session from establishing, which is a denial of service a malicious server can achieve anyway by dropping traffic.

Private keys never leave the device. There is no key escrow, no server-side key generation, and no path by which the server obtains a private key.

### 2.1 Device authorization

- **Device 1** is created atomically with the account (`POST /v1/accounts`) and self-signs its own registration.
- **Devices 2..N** are added by `POST /v1/devices`, a request authenticated by an **already-active device** of the same account. The body additionally carries the new device's self-signed identity binding, proving possession of the new private keys.

An account therefore cannot gain a device without an existing device consenting. There is no password-based recovery: losing every device to which an account is registered loses the account.

### 2.2 Revocation

Revocation is a soft delete. A revoked device keeps its row, stops appearing in lookups and prekey bundles, has its requests rejected with `device_revoked`, and has its queued messages deleted. Its `device_id` is never reissued.

---

## 3. Cryptographic primitives

| Purpose | Algorithm |
|---|---|
| Key agreement | X25519 |
| Signatures | Ed25519 |
| AEAD, ratchet messages | ChaCha20-Poly1305 (IETF, 96-bit derived nonce, 128-bit tag) |
| AEAD, sealed sender | XChaCha20-Poly1305 (192-bit random nonce, 128-bit tag) |
| Hash | SHA-256 |
| KDF | HKDF-SHA256 |
| Chain KDF | HMAC-SHA256 |
| Proof of work | SHA-256 |

Implementations MUST use their platform's reviewed implementations of these primitives. Quietly implements protocols, not primitives.

### 3.1 Randomness

All nonces, ephemeral keys, one-time prekeys, and delivery tokens come from the platform CSPRNG (`getrandom(2)` / `SecureRandom` / `std.crypto.random`). Never a seeded or user-space PRNG.

### 3.2 Key material handling

Private keys, chain keys, root keys, and message keys are zeroized when they go out of scope. Message keys are destroyed immediately after single use, except skipped keys held under §9.4.

### 3.3 Domain separation

Every KDF and every signature is domain-separated. These strings are ASCII, without a trailing NUL unless shown:

| Context | String |
|---|---|
| Identity binding signature | `quietly/1 identity-binding` |
| Signed prekey signature | `quietly/1 signed-prekey` |
| X3DH root secret | `quietly/1 x3dh` |
| Ratchet root chain | `quietly/1 ratchet-root` |
| Ratchet message key | `quietly/1 ratchet-msg` |
| Sealed sender | `quietly/1 sealed-sender` |
| Sealed sender ephemeral key | `quietly/1 sealed-ephemeral` |
| Safety number | `quietly/1 safety-number` |
| Proof of work | `quietly/1 pow` |

A signature is always computed over `domain_string || 0x00 || payload`. Reusing a key across contexts without its domain string is a protocol violation.

---

## 4. Proof of work

Account creation requires a proof of work. It is stateless: the server issues no challenge and stores no state.

### 4.1 Construction

```
preimage = "quietly/1 pow" || 0x00
        || username        || 0x00      (UTF-8, lowercased)
        || timestamp_ms    || 0x00      (decimal ASCII, no leading zeros)
        || nonce                        (decimal ASCII, no leading zeros)

digest = SHA-256(preimage)
```

The proof is valid when `digest` has at least `difficulty` leading zero **bits**, counting from the most significant bit of byte 0.

The client varies `nonce` from 0 upward until the condition holds. `timestamp_ms` is the client's clock at the start of solving.

### 4.2 Verification

The server MUST check, in this order:

1. `username` is syntactically valid (§15) — else `username_invalid`
2. `username` is not taken — else `username_taken`
3. `|now − timestamp_ms| ≤ pow_window_ms` — else `pow_stale`
4. Recomputed digest has ≥ `difficulty` leading zero bits — else `pow_invalid`

The username-taken check comes **before** PoW verification so a client is never made to spend CPU on a name it cannot have.

Difficulty is server configuration and may be raised without a client release. Clients MUST fetch it from `GET /v1/accounts/pow-params` immediately before solving.

### 4.3 What this does and does not do

It raises the cost of bulk account creation. It does not prevent a determined attacker with hardware from registering many accounts, and it is not a substitute for rate limiting. It exists because identity is username-only and there is no phone number to make accounts expensive.

Two consequences are normative for deployments:

- The proof is **stateless and bankable**. It is only bounded by `pow_window_ms`, so one solve can be submitted repeatedly within the window and solves can be stockpiled in advance. Difficulty alone therefore cannot bound the registration rate: per-IP throttling (§15) is mandatory, and deployments open to public registration SHOULD raise `difficulty` well above the default and add screening a proof of work cannot provide (an external CAPTCHA, an invite gate, or manual approval).
- A server-issued, short-lived challenge nonce that binds each solve to a recent issuance — removing the stockpiling and replay window — is reserved for v2 (§16). Until then, difficulty is a speed bump, not a gate.

---

## 5. Request authentication

There are no passwords, no bearer tokens, and no sessions. Each authenticated request is signed by the device's `identity_key_sig`. The server holds only public keys; a full database compromise yields no credential that can impersonate a device.

### 5.1 Canonical string

```
canonical = METHOD || "\n"
         || PATH   || "\n"
         || TIMESTAMP || "\n"
         || NONCE  || "\n"
         || SHA256_HEX(body)
```

- `METHOD` — uppercase, e.g. `POST`
- `PATH` — path **including** query string, exactly as sent, no normalization, e.g. `/v1/messages?limit=50`
- `TIMESTAMP` — Unix milliseconds, decimal ASCII
- `NONCE` — the header value verbatim (base64url of 16 random bytes)
- `SHA256_HEX(body)` — lowercase hex of the SHA-256 of the raw request body; for an empty body, the SHA-256 of the empty string: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

The signature is Ed25519 over `"quietly/1 request" || 0x00 || canonical`.

### 5.2 Headers

```
X-Quietly-Version:   quietly/1
X-Quietly-Device:    <user_id>.<device_id>
X-Quietly-Timestamp: <unix ms, decimal>
X-Quietly-Nonce:     <base64url, 16 bytes>
X-Quietly-Signature: <base64url, 64 bytes>
```

Example:

```
X-Quietly-Version: quietly/1
X-Quietly-Device: 7c9e6679-7425-40de-944b-e07fc1f90ae7.1
X-Quietly-Timestamp: 1785340800000
X-Quietly-Nonce: qtFT7cJ2mVvJ7t0RJHYy9w
X-Quietly-Signature: 3sT9Yk...Qw
```

### 5.3 Verification

The server MUST reject when, each with its own error code:

| Condition | Code |
|---|---|
| Any required header missing or malformed | `signature_missing` |
| `X-Quietly-Version` ≠ `quietly/1` | `version_mismatch` |
| Device unknown | `device_unknown` |
| Device revoked | `device_revoked` |
| `|now − timestamp| > auth_skew_ms` | `timestamp_out_of_window` |
| Nonce seen within the cache window | `nonce_replayed` |
| Signature does not verify | `signature_invalid` |

The nonce cache holds entries for `auth_skew_ms × 2`, which bounds it: a nonce older than the skew window is already rejected by the timestamp check.

### 5.4 Which endpoints are authenticated

| Endpoint | Authentication |
|---|---|
| `GET /v1/accounts/pow-params` | none |
| `POST /v1/accounts` | self-signed by the new device 1, plus PoW |
| `POST /v1/messages` | **none** — delivery token instead (§6) |
| everything else | signed by an active device |

`POST /v1/messages` is deliberately unauthenticated. Signing it would reveal the sender to the server and defeat sealed sender.

---

## 6. Delivery tokens

Because message submission is unauthenticated, something must stop the server being an open relay. That is the **delivery token**: 32 random bytes generated by each device and published in its prekey bundle.

- The server stores the token itself, because it must hand it to senders (§7.2, §12.8), and keeps `SHA-256(token)` only for verification. That is **plaintext at rest**: a database dump yields every token and lets its holder spam every device. Rotating the token invalidates every harvested copy; that is the recovery path, and it costs each honest contact one cheap refetch (§12.8, no key material). A token grants no ability to read anything.
- A sender obtains a recipient's token when it fetches the prekey bundle, and caches it for the lifetime of the session.
- The token is presented on every message submission as `X-Quietly-Delivery-Token`.
- A device may rotate its token at any time (`PUT /v1/devices/{device_id}/delivery-token`). Rotation invalidates every cached copy.
- A sender whose token is rejected refetches it from `GET /v1/devices/{user_id}/{device_id}/delivery-token` (§12.8) and retries once. This endpoint returns **only the token** and does **not** consume a one-time prekey.

The token fetch is deliberately a separate endpoint from the prekey bundle. If rotation forced a full bundle refetch, then anyone who could provoke a rotation could drain a victim's one-time prekeys through their own legitimate contacts — turning a spam nuisance into the key-exhaustion attack of §7.2.1. Rotation costs each contact one cheap request and no key material.

A token authorizes *sending to* a device. It is not a secret that protects content — content is protected by the ratchet — and possessing it grants no ability to read anything.

### 6.1 Anti-abuse consequences

The server cannot rate-limit by sender, because it does not know the sender. Rate limiting on submission is therefore **per recipient device** and **per source IP**. A recipient being spammed by someone holding its token rotates the token; that is the recovery path, and it costs every legitimate contact one bundle refetch.

This trade is deliberate: sender anonymity from the server is worth a weaker abuse story at a scale of a few users. It MUST be revisited before public registration.

---

## 7. Prekey bundles

A sender fetches a bundle to establish a session with one recipient device.

### 7.1 Registration payload

Device registration publishes:

```json
{
  "identity_key_dh": "TxGa0k9y...",
  "identity_key_sig": "9dRk2mQp...",
  "identity_binding": "L2vXq8...",
  "signed_prekey": {
    "id": 1,
    "public_key": "Kp9wZa2R...",
    "signature": "7Yt3nB..."
  },
  "one_time_prekeys": [
    { "id": 1, "public_key": "aQ2mVx9L..." },
    { "id": 2, "public_key": "bR3nWy0M..." }
  ],
  "delivery_token": "u4Kd9Xp2..."
}
```

- `identity_binding` — Ed25519 over `"quietly/1 identity-binding" || 0x00 || identity_key_dh`
- `signed_prekey.signature` — Ed25519 over `"quietly/1 signed-prekey" || 0x00 || id_be32 || public_key`
- Prekey ids are unsigned 32-bit, unique per device, never reused
- `one_time_prekeys` carries `otp_batch_size` entries at registration (§15)

The server MUST verify both signatures before storing. It MUST NOT accept a registration whose binding or signed-prekey signature fails.

### 7.2 Bundle response

```json
{
  "v": "quietly/1",
  "user_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "device_id": 1,
  "identity_key_dh": "TxGa0k9y...",
  "identity_key_sig": "9dRk2mQp...",
  "identity_binding": "L2vXq8...",
  "signed_prekey": { "id": 1, "public_key": "Kp9wZa2R...", "signature": "7Yt3nB..." },
  "one_time_prekey": { "id": 42, "public_key": "cS4oXz1N..." },
  "delivery_token": "u4Kd9Xp2...",
  "one_time_prekeys_remaining": 57
}
```

- The server consumes the returned one-time prekey **atomically** and never returns it again to a *different* requester. Concurrent fetches for the same device MUST receive different prekeys, and neither may fail.
- When the batch is exhausted, `one_time_prekey` is `null` and the session proceeds with the signed prekey only. This is a weaker but valid X3DH; it MUST NOT be an error.
- `one_time_prekeys_remaining` lets the owning device know when to replenish (§15).

### 7.2.1 One-time prekey exhaustion

An attacker who repeatedly fetches bundles for a target device drains its one-time prekeys. Once drained, every subsequent session with that device — including sessions with honest users — establishes on the signed prekey alone.

This is a real loss, and it must be stated precisely. The Double Ratchet's forward secrecy **within** an established session is unaffected. What is lost is forward secrecy of the **initial** secret: a session established without a one-time prekey can be reconstructed by an adversary who later compromises both `identity_key_dh` and the signed prekey private half for that window. With a one-time prekey, which is deleted on use, it cannot.

Four mandatory mitigations:

1. **Per-requester rate limit** on bundle fetch (`bundle_fetch_per_hour`). Bundle fetch is authenticated, so the server always knows who is draining and can act.
2. **Per-pair idempotency.** Repeat fetches by the same requester for the same target device within `otp_idempotency_window_h` return the **same** one-time prekey rather than consuming another. A session needs exactly one bundle; retries, reinstalls, and rotations must not cost key material.
3. **Low-prekey signalling.** When a device's count falls below `otp_replenish_threshold`, the server pushes a `prekeys_low` frame (§13.2) to that device if connected. Replenishment must not wait for the next app launch.
4. **Short signed prekey lifetime.** `spk_rotation_days` is 3, bounding the window in which an exhausted device is exposed.

A device that stays offline long enough to be drained and not replenish remains exposed until it reconnects. That is inherent to the design and is documented in §17 rather than solved.

The client MUST verify `identity_binding` and `signed_prekey.signature` against `identity_key_sig` before using a bundle. A server that tampers with a bundle is caught here, not later.

### 7.3 Signed prekey rotation

A device rotates its signed prekey every `spk_rotation_days`; the server nudges it with a `spk_rotate` frame (§13.2) once the current key is that old, and bundles always return the current key. Because X3DH responders decrypt with their *private* signed prekey, keeping the retired key valid for `spk_grace_days` is a **responder-side** obligation: the device MUST retain the retired signed prekey's private half for `spk_grace_days` and accept inbound initiations that name it by `signed_prekey.id`, so a bundle fetched just before rotation still works. The server cannot enforce this — it holds only public keys — but it is part of the client contract.

---

## 8. X3DH

Session establishment between an initiator A and a responder device B.

### 8.1 Initiator

Given B's bundle, A generates an ephemeral X25519 keypair `EK_A` and computes:

```
DH1 = X25519(IK_A_dh_priv, SPK_B_pub)
DH2 = X25519(EK_A_priv,    IK_B_dh_pub)
DH3 = X25519(EK_A_priv,    SPK_B_pub)
DH4 = X25519(EK_A_priv,    OPK_B_pub)     // omitted when no one-time prekey
```

```
F  = 0xFF repeated 32 times
SK = HKDF-SHA256(
       ikm  = F || DH1 || DH2 || DH3 [|| DH4],
       salt = 32 zero bytes,
       info = "quietly/1 x3dh" || 0x00 || SHA-256(AD),
       len  = 32)
```

`AD` is the 128-byte associated data of §8.2 and is therefore computed **before** `SK`.

Folding `SHA-256(AD)` into the KDF binds all four identity keys — both DH keys and both signing keys — into the shared secret itself, not merely into the AEAD associated data. Without this, the signing keys would participate in no key derivation at all, and substituting one would produce a session that derives a *valid-looking* `SK` and fails only later at decryption. With it, any substitution changes `SK` directly, so the failure is a key-agreement failure and is reasoned about as one.

All DH outputs are zeroized immediately after `SK` is derived.

### 8.2 Associated data

```
AD = IK_A_dh || IK_A_sig || IK_B_dh || IK_B_sig      (128 bytes)
```

`AD` binds all four identity keys into every message of the session and is a permanent part of session state. Including the signing keys, not just the DH keys, is what makes AD-1's two-key identity safe against substitution of either half.

### 8.3 Responder

B receives an initial message (§9.2) carrying `IK_A_dh`, `IK_A_sig`, `EK_A`, `spk_id`, and `otpk_id`. It looks up the referenced private keys, computes the same four DH values with roles reversed, derives the identical `SK` and `AD`, and initializes its ratchet.

If `otpk_id` refers to a prekey B has already consumed or never had, B MUST attempt the three-DH derivation. If that also fails to authenticate, the message is dropped.

**Responder session store (normative).** A responder MUST keep at most one live session per peer device — keyed on `(sender_user_id, sender_device_id)` — and MUST deduplicate on envelope `id` before establishing anything. Delivery is at-least-once (§11.2), so an initial message whose ack was lost will be redelivered; it must be decrypted against the session that already processed it (which rejects the consumed message key, and the client discards the duplicate silently) rather than by running the responder derivation again. A second responder session for the same peer forks the ratchet and strands everything the first session produces. Establish a fresh session only when none exists for that peer, or when the peer presents a new identity key (§2.0.1).

### 8.4 Initialization

`SK` becomes the initial root key. The initiator immediately performs a DH ratchet step against `SPK_B_pub` to derive its first sending chain, per §9.1. The one-time prekey is deleted by B on successful decryption.

---

## 9. Double Ratchet message format

### 9.1 Key derivation

Root chain, on every DH ratchet step:

```
rk_new || ck_new = HKDF-SHA256(
    ikm  = X25519(dh_priv, dh_pub_remote),
    salt = rk_current,
    info = "quietly/1 ratchet-root",
    len  = 64)
```

Symmetric chain, per message:

```
mk       = HMAC-SHA256(ck, 0x01)
ck_next  = HMAC-SHA256(ck, 0x02)
```

Message key expansion:

```
key || nonce = HKDF-SHA256(
    ikm  = mk,
    salt = 32 zero bytes,
    info = "quietly/1 ratchet-msg",
    len  = 44)          // 32-byte ChaCha20 key, 12-byte nonce
```

Each message key is used exactly once. The nonce is derived, never a counter, which removes any possibility of reuse across a ratchet step.

### 9.2 Wire layouts

All ratchet messages are binary. They appear only inside the sealed sender layer (§10) and are never visible to the server.

**Header** (40 bytes):

```
offset  size  field
0       32    ratchet_public_key      X25519
32      4     pn                      previous chain length, u32 BE
36      4     n                       message number in chain, u32 BE
```

**Normal message:**

```
offset  size  field
0       1     version  = 0x01
1       1     type     = 0x02  (normal)
2       40    header
42      var   ciphertext (ChaCha20-Poly1305, includes 16-byte tag)
```

**Initial (X3DH) message:**

```
offset  size  field
0       1     version  = 0x01
1       1     type     = 0x01  (initial)
2       32    IK_A_dh
34      32    IK_A_sig
66      32    EK_A
98      4     spk_id     u32 BE
102     4     otpk_id    u32 BE, 0 = none used
106     40    header
146     var   ciphertext
```

### 9.3 AEAD parameters

```
AAD = AD || header_bytes
```

`AD` is the 128 bytes from §8.2; `header_bytes` is the 40-byte header exactly as it appears on the wire. Encryption is ChaCha20-Poly1305 with the key and nonce from §9.1.

Decryption failure MUST NOT advance any ratchet state. A failed message is dropped and surfaced to the user as undecryptable; the session continues unchanged. This property is what makes forged messages a nuisance rather than a denial of service.

### 9.4 Skipped messages

When a message arrives with `n` greater than the expected counter, the receiver derives and stores the intermediate message keys so the gap can be filled later.

Two limits are mandatory:

- `max_skip_per_chain` — the largest gap accepted within one chain
- `max_skipped_chains` — how many previous chains retain skipped keys

Exceeding either is a protocol error (`skip_limit_exceeded`, local to the client), not an allocation. Without these limits a peer can request an unbounded number of derivations with a single message.

Skipped keys are deleted on use and when their chain is evicted.

### 9.5 Safety number

```
fp(party) = SHA-256("quietly/1 safety-number" || 0x00 || user_id || IK_dh || IK_sig)
```

truncated to 30 bytes, rendered as 12 groups of 5 decimal digits. The displayed safety number is `fp(lower) || fp(higher)`, where the two fingerprints are ordered by byte-wise comparison so both parties compute the identical value regardless of who initiated.

The safety number covers both identity keys. It is per **user pair**, computed over the identity keys of the devices in the session; when a user has multiple devices, the UI shows one entry per peer device.

---

## 10. Sealed sender

The server learns who a message is *for*. It must not learn who it is *from*.

Every ratchet message is wrapped in a layer encrypted to the recipient device's `identity_key_dh` using a fresh ephemeral key. The sender's identity lives inside that layer.

### 10.1 Sealing

The ephemeral key is **hedged**: derived from fresh randomness mixed with the sender's long-term private key and a hash of the payload, rather than taken raw from the CSPRNG.

```
E_priv = HKDF-SHA256(
    ikm  = random_32 || IK_A_dh_priv || SHA-256(sealed_payload),
    salt = 32 zero bytes,
    info = "quietly/1 sealed-ephemeral",
    len  = 32)                                  // clamped as an X25519 scalar

E_pub  = X25519_base(E_priv)
dh     = X25519(E_priv, IK_B_dh)

nonce  = random_24                              // 192-bit, from the CSPRNG

key = HKDF-SHA256(
    ikm  = dh,
    salt = E_pub || IK_B_dh,
    info = "quietly/1 sealed-sender",
    len  = 32)

AAD = recipient_user_id (16 bytes) || recipient_device_id (u16 BE)
ct  = XChaCha20-Poly1305(key, nonce, sealed_payload, AAD)

sealed_blob = 0x01 || E_pub (32) || nonce (24) || ct
```

Two properties this buys, both deliberate:

**The nonce is independent of the key.** Earlier drafts derived key and nonce from the same HKDF output, so a repeated ephemeral key repeated both at once — the catastrophic case. With a separate random 192-bit nonce, a repeated ephemeral key is survivable: the same key under different nonces is safe. XChaCha20's nonce is large enough that random generation is safe without coordination.

**The ephemeral key survives a degraded CSPRNG.** Mixing in `IK_A_dh_priv` and the payload hash means that even if `random_32` repeats — a stuck RNG, a cloned VM, a device restored from a snapshot — two different messages still produce different ephemeral keys. Only an identical payload to the identical recipient with identical randomness collides, and that produces an identical ciphertext, which leaks nothing new.

Including `E_pub` and the recipient's identity key in the HKDF salt binds the derived key to this exact ephemeral-recipient pair. `E_priv`, `dh`, and `random_32` are zeroized immediately.

### 10.2 Sealed payload

Fixed binary layout — deliberately not JSON. This is parsed by the crypto core with the recipient's private key, before any authentication of the sender exists, so the parser must be trivially bounds-checkable.

```
offset  size  field
0       1     version = 0x01
1       16    sender_user_id           raw UUID bytes
17      2     sender_device_id         u16 BE
19      1     session_type             0x00 = pairwise
20      16    group_id                 all zero at v1
36      1     msg_type                 0x01 initial, 0x02 normal
37      4     inner_len                u32 BE
41      var   inner                    ratchet message, §9.2
```

Fixed 41-byte prefix. A payload shorter than 41 bytes, or whose `inner_len` disagrees with the remaining length, is discarded without further parsing.

`session_type` and `group_id` are inside the sealed layer, not the envelope, so the server cannot see whether a message is 1:1 or group when groups arrive in v2.

### 10.3 Opening

The recipient:

1. Checks `sealed_blob[0] == 0x01` and that the blob is at least `1 + 32 + 24 + 16` bytes, else discard
2. Reads `E_pub` and `nonce`, and derives the key from `E_pub` and its own `identity_key_dh` private key
3. Decrypts with XChaCha20-Poly1305; failure means discard, with no state change and no error to the sender
4. Parses the payload with strict bounds checks
5. Reads `sender_user_id` and `sender_device_id`, and looks up that session
6. Decrypts the inner ratchet message

### 10.4 Sender authenticity

There is **no server-issued sender certificate** in v1. The claimed sender in the payload is unverified at that layer; authenticity comes entirely from the inner ratchet.

The reasoning: a forged claim of being Alice fails at step 6, because the attacker cannot produce a message that authenticates under Alice's session. For an initial message, X3DH's `AD` binds Alice's identity keys, so a forgery fails to authenticate there instead.

Clients MUST therefore:

- Treat the claimed sender as **untrusted** until the inner decryption succeeds
- Verify that `IK_A_dh` / `IK_A_sig` in an initial message match the registered keys of the claimed sender, and warn on mismatch as an identity change (§2, safety numbers)
- Never display, notify, or store a message whose inner decryption has not succeeded as being from the claimed sender

The residual risk is nuisance: anyone holding a delivery token can cause undecryptable-message noise attributed to nobody. It cannot produce a message that appears to come from a real contact. Sender certificates are the mitigation if this becomes a problem, and are a candidate for v2.

---

## 11. Message envelope

The only structure the server sees. It contains no sender, no message type, no session type, and no group identity.

**Submitted** by the sender:

```json
{
  "v": "quietly/1",
  "recipient": { "user_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "device_id": 1 },
  "sealed": "AQ3kR9wY..."
}
```

**Returned** to the recipient, with server-assigned fields added:

```json
{
  "v": "quietly/1",
  "id": "01JQ8Z4K7VXN2M9P0T3RWY6C5B",
  "recipient": { "user_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "device_id": 1 },
  "sealed": "AQ3kR9wY...",
  "server_ts": 1785340801234,
  "ttl_expires_at": 1787932801234
}
```

`id` is a server-generated ULID, monotonic per server, used for ack and for stable ordering of the queue. `id`, `server_ts`, and `ttl_expires_at` are response-only; a client that sends them has them ignored.

### 11.1 Fan-out

A message to a user with N active devices is N independent envelopes, each with its own session, its own ratchet state, and its own sealed layer. The server performs no fan-out and correlates nothing. The sender is responsible for enumerating the recipient's devices via `GET /v1/users/{username}`.

### 11.2 Delivery semantics

Delivery is **at-least-once**. A message is deleted only when acked; if an ack is lost, the message is redelivered. Clients MUST deduplicate on envelope `id`, and MUST tolerate the same ratchet message arriving twice — the second copy will fail to decrypt because its message key is consumed, and MUST be discarded silently rather than shown as an error.

Ordering within a device queue is by `id`. Ordering *within a conversation* is the client's job, using the ratchet counters.

---

## 12. HTTP endpoints

### 12.1 `GET /v1/accounts/pow-params`

Unauthenticated. Fetched immediately before solving.

```json
{ "v": "quietly/1", "algorithm": "sha256-leading-zero-bits", "difficulty": 20, "window_ms": 300000 }
```

### 12.2 `POST /v1/accounts`

Unauthenticated except for PoW; self-signed by the device being created. Creates the account and device 1 atomically.

Request:

```json
{
  "v": "quietly/1",
  "username": "alice",
  "pow": { "timestamp_ms": 1785340800000, "nonce": 91847362 },
  "device": { "identity_key_dh": "...", "identity_key_sig": "...", "identity_binding": "...",
              "signed_prekey": { "id": 1, "public_key": "...", "signature": "..." },
              "one_time_prekeys": [ { "id": 1, "public_key": "..." } ],
              "delivery_token": "..." }
}
```

Response `201`:

```json
{ "v": "quietly/1", "user_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "device_id": 1, "username": "alice" }
```

Errors: `username_invalid`, `username_taken`, `pow_stale`, `pow_invalid`, `signature_invalid`, `rate_limited`.

### 12.3 `POST /v1/devices`

Authenticated by an **existing active device**. Body is the registration payload of §7.1.

Response `201`: `{ "v": "quietly/1", "device_id": 2 }`

Errors: `device_limit_reached`, `signature_invalid`, `invalid_payload`.

### 12.4 `GET /v1/devices`

Authenticated. Lists the account's devices.

```json
{ "v": "quietly/1", "devices": [
  { "device_id": 1, "created_at": 1785340800000, "revoked": false },
  { "device_id": 2, "created_at": 1785427200000, "revoked": false } ] }
```

### 12.5 `DELETE /v1/devices/{device_id}`

Authenticated by any active device of the account. Revokes per §2.2. Revoking the last active device is permitted and orphans the account permanently; the client MUST warn before doing so.

Response `204`.

### 12.6 `GET /v1/users/{username}`

Authenticated. Resolves a username to its routing identity and active devices.

```json
{ "v": "quietly/1", "user_id": "7c9e6679-...", "username": "bob", "devices": [ 1, 3 ] }
```

Errors: `user_not_found`. The response for a nonexistent username is byte-identical to that for a reserved or deleted one.

### 12.7 `GET /v1/devices/{user_id}/{device_id}/prekey-bundle`

Authenticated. Returns §7.2 and consumes one one-time prekey.

Errors: `user_not_found`, `device_unknown`, `device_revoked`, `rate_limited`.

### 12.8 `GET /v1/devices/{user_id}/{device_id}/delivery-token`

Authenticated. Returns only the recipient device's current delivery token. **Consumes no one-time prekey** (§6, §7.2.1).

```json
{ "v": "quietly/1", "user_id": "7c9e6679-...", "device_id": 1, "delivery_token": "u4Kd9Xp2..." }
```

Errors: `user_not_found`, `device_unknown`, `device_revoked`, `rate_limited`.

Callers use this on `delivery_rejected` (§12.13) before falling back to a full bundle fetch. A sender with a live session needs a fresh token, not a fresh session.

### 12.9 `POST /v1/devices/{device_id}/prekeys`

Authenticated by that device. Appends one-time prekeys.

```json
{ "v": "quietly/1", "one_time_prekeys": [ { "id": 101, "public_key": "..." } ] }
```

Response `200`: `{ "v": "quietly/1", "one_time_prekeys_remaining": 120 }`

Errors: `prekey_id_conflict`, `prekey_limit_exceeded`.

### 12.10 `PUT /v1/devices/{device_id}/signed-prekey`

Authenticated by that device. Rotates per §7.3. Body is the `signed_prekey` object. Response `200`.

### 12.11 `PUT /v1/devices/{device_id}/delivery-token`

Authenticated by that device. Body `{ "v": "quietly/1", "delivery_token": "..." }`. Response `200`. Previous tokens stop working immediately.

### 12.12 `PUT /v1/devices/{device_id}/push-endpoint`

Authenticated by that device. Registers a UnifiedPush endpoint for wakeups.

```json
{ "v": "quietly/1", "endpoint": "https://ntfy.example/abc123" }
```

`null` unregisters. The endpoint MUST be an `https://` URL whose host is a public name or address; loopback, private, link-local (including cloud metadata addresses), and credential-bearing URLs are rejected with `invalid_payload`. The server treats the endpoint as opaque and sends only a content-free wakeup (§13.3); it never follows redirects when delivering one.

### 12.13 `POST /v1/messages`

**Unauthenticated.** Requires `X-Quietly-Delivery-Token` and `X-Quietly-Version`. Body is the submitted envelope of §11.

Response `202`: `{ "v": "quietly/1", "id": "01JQ8Z4K7VXN2M9P0T3RWY6C5B", "server_ts": 1785340801234 }`

Errors about the **request**: `payload_too_large`, `rate_limited`, `version_mismatch`, `invalid_payload`.

Errors about the **recipient**: exactly one code, `delivery_rejected` (403), covering *all* of — token absent, token wrong, token rotated, device unknown, device revoked, account deleted.

This endpoint is unauthenticated, so distinguishing those cases would hand any anonymous caller an oracle over the state of somebody else's device. Anyone who ever held a token could learn that a device had been revoked. The server MUST therefore:

- return the identical body and status for every recipient-state failure
- avoid distinguishable fast paths where practical: the implementation performs the same token comparison for an existing device and a missing one, but internal work still differs (a database hit versus a miss), so timing MUST be treated as non-authoritative rather than claimed constant. `user_id` secrecy is what raises the cost of enumeration.

A client receiving `delivery_rejected` refetches the delivery token (§12.8), and if that also fails, refetches the bundle (§12.7). Both are authenticated, so they may return a precise cause without creating an oracle.

### 12.14 `GET /v1/messages`

Authenticated. Returns queued messages for the calling device, oldest first.

Query: `limit` (default 100, max `fetch_limit_max`).

Only messages whose release time has arrived (`not_before <= now`, §15
`delivery_jitter_ms`) are returned; a message held by the delivery-jitter
window surfaces on the first fetch after that time. Ordering stays
`(server_ts, id)` and `remaining` reflects undelivered messages not yet
returned by this response.

```json
{ "v": "quietly/1", "messages": [ /* envelopes per §11 */ ], "remaining": 0 }
```

### 12.15 `POST /v1/messages/{id}/ack`

Authenticated. Deletes the message. Acking an unknown or already-acked id returns `204` — ack is idempotent, because a client retrying after a lost response must not see an error.

Response `204`. Errors: `forbidden` if the message is not addressed to the calling device.

---

## 13. WebSocket protocol

### 13.1 Connection

`GET /v1/ws`, upgraded, authenticated by the §5 headers on the upgrade request. The signed `PATH` is `/v1/ws` and the body hash is that of the empty string.

Browser `Origin` headers are validated against a server-side allow-list; requests without an `Origin` header (native clients) rely on the §5 signature alone. This closes cross-site WebSocket hijacking for any future web client.

On connect the server delivers nothing automatically. The client fetches its backlog via §12.13, then relies on the socket for new arrivals. This keeps backlog handling in exactly one code path.

### 13.2 Frames

JSON text frames, each with a `type`.

Server → client:

```json
{ "type": "message",      "v": "quietly/1", "envelope": { /* §11 */ } }
{ "type": "prekeys_low",  "v": "quietly/1", "one_time_prekeys_remaining": 12 }
{ "type": "spk_rotate",   "v": "quietly/1" }
{ "type": "error",        "v": "quietly/1", "code": "...", "message": "..." }
```

`prekeys_low` is sent when the device's one-time prekey count falls below `otp_replenish_threshold`, so replenishment happens immediately rather than at the next app launch (§7.2.1). The client responds by uploading a fresh batch via §12.9.

`spk_rotate` is sent when the device's current signed prekey is at least `spk_rotation_days` old (§7.2.1 mitigation 4). The client rotates via §12.10 at the next opportunity, keeping the retired key valid for inbound sessions for `spk_grace_days` (§7.3).

Client → server:

```json
{ "type": "ack",  "v": "quietly/1", "id": "01JQ8Z4K7VXN2M9P0T3RWY6C5B" }
{ "type": "ping", "v": "quietly/1" }
```

Server → client: `{ "type": "pong", "v": "quietly/1" }`

Acking over the socket is equivalent to §12.14. Clients ping every `ws_ping_interval_s`; a server seeing no traffic for `ws_idle_timeout_s` closes the connection.

### 13.3 Push wakeups

When a message is queued for a device with no live socket, the server sends a wakeup to that device's registered UnifiedPush endpoint. The wakeup body is:

```json
{ "v": "quietly/1", "type": "wake" }
```

Nothing else. No sender, no recipient, no message id, no count. The push provider is untrusted infrastructure and learns only that *some* device it has an endpoint for has *something* waiting.

A failed push MUST NOT delete or alter the queued message.

---

## 14. Errors

All errors are JSON with a stable machine-readable `code`. Clients branch on `code` and never on `message`, which is human-facing and may change.

```json
{ "v": "quietly/1", "code": "pow_invalid", "message": "proof of work does not meet required difficulty" }
```

| Code | HTTP | Meaning |
|---|---|---|
| `version_mismatch` | 400 | Protocol version unsupported |
| `invalid_payload` | 400 | Malformed body or missing required field |
| `username_invalid` | 400 | Username fails syntax rules |
| `username_taken` | 409 | Username already registered |
| `pow_invalid` | 400 | Proof of work below required difficulty |
| `pow_stale` | 400 | Proof of work timestamp outside window |
| `signature_missing` | 401 | Auth headers absent or malformed |
| `signature_invalid` | 401 | Signature does not verify |
| `timestamp_out_of_window` | 401 | Clock skew exceeded |
| `nonce_replayed` | 401 | Nonce already used |
| `device_unknown` | 404 | No such device |
| `device_revoked` | 403 | Device has been revoked |
| `device_limit_reached` | 409 | Account already has the maximum devices |
| `forbidden` | 403 | Authenticated, but not permitted on this resource |
| `user_not_found` | 404 | No such username or user_id |
| `prekey_id_conflict` | 409 | Prekey id already used by this device |
| `prekey_limit_exceeded` | 409 | Stored prekeys would exceed the cap |
| `delivery_token_invalid` | 403 | Token absent, wrong, or rotated — **authenticated endpoints only** |
| `delivery_rejected` | 403 | `POST /v1/messages` only: recipient unreachable. Deliberately does not say why (§12.13) |
| `payload_too_large` | 413 | Sealed blob exceeds the ceiling |
| `rate_limited` | 429 | Too many requests; `Retry-After` set |
| `internal_error` | 500 | Server fault; safe to retry with backoff |

Error responses MUST NOT leak whether a username exists beyond what `user_not_found` states, and MUST NOT vary in *observable* timing in a way that distinguishes a missing account from a wrong signature. Internal branches may differ (database hit versus miss); network jitter is not a substitute for care, and servers SHOULD keep such paths as uniform as is practical.

---

## 15. Parameters and limits

| Parameter | Value | Notes |
|---|---|---|
| `username` syntax | 3–32 chars, `[a-z0-9_]` | lowercased for uniqueness |
| `max_devices_per_account` | 5 | active devices; `device_id` range 1–65535, never reused |
| `otp_batch_size` | 100 | uploaded at registration |
| `otp_replenish_threshold` | 20 | client tops up below this |
| `otp_max_stored` | 200 | server cap per device |
| `sealed_blob_max` | 64 KiB | text-only milestone; `payload_too_large` above |
| `delivery_jitter_ms` | 0 | max randomized hold before a message is fetchable/notifiable (0 disables; hard cap 5000) — §17, TASK-001 B |
| `message_ttl_days` | 30 | undelivered messages expire |
| `auth_skew_ms` | ±60 000 | request timestamp window |
| `nonce_cache_ms` | 120 000 | twice the skew window |
| `pow_difficulty` | 20 bits | server config, raisable without a client release; raise well above this before opening public registration (§4.3) |
| `pow_window_ms` | ±300 000 | solving takes time |
| `spk_rotation_days` | 3 | signed prekey rotation; short to bound §7.2.1 exposure |
| `spk_grace_days` | 3 | previous signed prekey stays valid |
| `bundle_fetch_per_hour` | 60 | per requesting device, across all targets |
| `otp_idempotency_window_h` | 24 | repeat fetch by the same requester for the same target returns the same prekey |
| `sealed_nonce_bytes` | 24 | XChaCha20-Poly1305, random per message |
| `max_skip_per_chain` | 1 000 | client-side ratchet limit |
| `max_skipped_chains` | 5 | client-side ratchet limit |
| `fetch_limit_max` | 500 | `GET /v1/messages` |
| `ws_ping_interval_s` | 30 | client-initiated |
| `ws_idle_timeout_s` | 90 | server closes after silence |
| `delivery_token_bytes` | 32 | stored as SHA-256 |

Every value marked as server config MUST be readable by clients where they need it (`pow_difficulty` via §12.1) or fail safely when exceeded.

---

## 16. Reserved for future versions

Reserved now so that adding them is not a breaking change:

- **`session_type`** (§10.2) — `0x00` pairwise. Group sessions take `0x01`.
- **`group_id`** (§10.2) — 16 bytes, all zero at v1.
- **Sender certificates** (§10.4) — would add a signed sender assertion inside the sealed payload.
- **Server-issued PoW challenges** (§4) — a short-lived challenge nonce binding each solve to a recent issuance, closing the stockpiling window.
- **Traffic shaping** (§16.1) — size padding is specified; cover traffic remains reserved.
- **Federation** — `user_id` is globally unique as a UUID, so a future `domain` field on the envelope routes cross-server without changing identity.
- **Protobuf** — the JSON shapes here map one-to-one; the binary layouts (§9, §10) are already final and would be unaffected.

Anything not listed here is not reserved. Adding it later is a version bump.

### 16.1 Size padding (specified)

The client pads every message's app content so the sealed blob the server
stores has one of a fixed set of sizes, removing the message-length signal
(§17). This is specified rather than merely reserved because the padding format
is shared client code — not a server-visible wire field.

Buckets (final sealed-blob size, ascending):

```
512 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB
```

The 64 KiB bucket respects `sealed_blob_max` for both message kinds.

Padding is applied *inside* the ratchet ciphertext — to the app content, before
encryption — so the frozen §9/§10 wire layouts are untouched and no known-answer
test changes. The framed app content is:

```
u32 BE original_len || payload || 0x00 padding
```

`original_len` is the unpadded app-content length; padding bytes are zero. A
decoder MUST fail closed on a truncated frame, an `original_len` larger than
the remaining bytes, or a non-zero padding tail. The target bucket is the
smallest one whose size is at least

```
original_len + 4 (frame) + kind_overhead
```

where `kind_overhead` is 172 bytes for a normal message (`0x02`) and 276 bytes
for an initial message (`0x01`) — the fixed §9/§10 overheads. Initial and
normal messages therefore remain distinguishable by their ~104-byte overhead
difference; this is accepted and must not be "fixed" by merging the two
families.

Padding is implemented once in `quietly-crypto` (`protocol.PadToBucket` /
`Unpad`, and `ffi.quietly_pad_payload` / `quietly_unpad_payload`) and MUST NOT
be re-implemented in any client. The server never parses the framing; it only
ever observes sealed-blob lengths that land in the bucket set.

Cover traffic (fixed-rate decoy submissions) is **not** implemented and remains
a documented residual in §17.

---

## 17. Known metadata leaks

Stated plainly, because a protocol that pretends to leak nothing is worse than one that documents what it does.

The server **can** observe:

- Which device fetched a prekey bundle for which device, and when. **This reveals who is starting a conversation with whom**, at session start. Sealed sender hides the sender of every subsequent message but not this first act.
- The recipient of every message, its quantized size (one of the five §16.1 padding buckets), and its timing. Traffic analysis over recipient and timing is the primary residual attack; message size is no longer a continuous signal.
- Which devices are connected by WebSocket, and when — an online-presence signal, even though presence is never exposed via the API.
- The IP address of every request, including unauthenticated submissions.
- The push endpoint URL a device registers: the push provider (and anything on the path to it) learns that URL, including any identity a client embeds in it. Clients SHOULD register opaque, rotatable topics and treat the endpoint as provider-visible metadata (§12.12).

The server **cannot** observe:

- Message content, or anything derived from it.
- The sender of any message (§10).
- Whether a message is 1:1 or group, once groups exist (§10.2).
- Anything from the push wakeup (§13.3), which is why the push provider is untrusted infrastructure rather than a trusted component.

Not addressed, and not claimed: cover traffic, or protection against a global passive adversary correlating both ends. Size padding (§16.1) removes the length signal. Delivery jitter (§15 `delivery_jitter_ms`) inserts a server-side randomized hold between enqueue and delivery, which weakens upload↔delivery timing correlation; it is a **partial** mitigation, not a fix: a *client-side* delay before upload is a no-op against a network observer (it moves the observable event itself — both ends shift together, so the correlation gap is unchanged), and with no cover traffic a low-traffic deployment remains trivially correlatable. The remaining signals are *who* talks to *whom* and *when*.

Deployment reality belongs on this list too. Any reverse proxy, load balancer, TLS terminator, or container platform in front of the home server **logs source IP addresses and request times unless explicitly configured not to**. The register above describes the protocol, not the deployment; an operator's logging configuration is part of the metadata story, and self-hosting is only as private as the box it runs on.

### 17.1 Accepted residual risks

Stated so they are decisions rather than oversights:

| Risk | Why it is accepted |
|---|---|
| Identity binding proves only one direction (§2.0.1) | The mutual version needs XEdDSA, which AD-1 avoids. Safety numbers and TOFU pinning are the real defence. |
| A drained, offline device stays exposed (§7.2.1) | It cannot replenish until it reconnects. Bounded by `spk_rotation_days`. |
| No sender-based rate limiting (§6.1) | Inherent to sealed sender. Per-recipient and per-IP limits only. Must be revisited before public registration. |
| Delivery tokens are plaintext at rest (§6) | The server must return them to senders, so a database compromise yields spam rights for every device. Rotation invalidates harvested copies; content is never at risk. |
| No sender certificates (§10.4) | Inner ratchet authenticates the sender. Cost is undecryptable-message noise, not impersonation. |
| Hand-written protocol implementation | Mitigated by test vectors and property tests, not by external audit. **No third-party review has been done.** Required before any public beta. |
| Initial vs normal messages differ by ~104 B of overhead (§16.1) | Accepted: padding quantizes to the bucket set but does not merge the two message families. |
| Size padding adds ~4 KiB worst-case for messages near the top of a bucket (§16.1) | Accepted as the cost of removing the length signal; buckets are configurable client-side. |
| Delivery jitter is partial (§15) | Accepted: a randomized server-side hold weakens but does not break timing correlation. Cover traffic is a separate, later task. |
