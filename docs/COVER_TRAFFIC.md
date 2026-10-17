# Cover traffic — design note

Status: **reserved, not implemented** (TASK-001 A out-of-scope deliverable).
This is the honest record of the shape it would take, so §16/§17 can point at a
real design rather than a vague "later".

## What it buys

Size padding (§16.1) removes the length signal and delivery jitter (§15) blurs
timing, but a network observer who sees *when* a client submits still learns
that *something real* was sent. Cover traffic replaces "submit on activity"
with "submit at a constant rate", so the server (and any observer) sees a
fixed-rate stream of padded envelopes and cannot tell real messages from
decoys.

## Shape

- Each device submits a padded envelope at a **fixed cadence** (client policy,
  not a protocol constant). When there is a real message, it occupies the next
  slot; otherwise the slot carries a **cover envelope**.
- A cover envelope is a normal sealed message addressed to the device's own
  account (self-addressed), using its own delivery token. It is byte-wise
  indistinguishable from a real message to the server — same envelope shape,
  same padding bucket, same authentication surface (§12.13). The inner content
  marks it as a decoy so the device drops it on receipt.

## Interactions to resolve before building

- **Delivery tokens / anti-abuse.** Self-addressed cover reuses the device's
  own token, so it costs nothing extra under §6's spam bound. Sending cover to
  *other* recipients would burn their tokens and is out of scope.
- **Rate limiting.** Cover raises per-IP and per-recipient request volume; the
  per-IP limiter (§15) and the bundle-fetch limiter must budget for the
  cadence, or cover must have its own allowance. A low-traffic deployment with
  few devices still produces only a few slots per minute — an observer can
  count *devices*, just not *messages*.
- **Battery.** Constant-rate transmission is the dominant client cost (radio
  wake-ups). It must be a user-togglable setting (likely Wi-Fi-only by
  default), and the cadence is a per-device policy, not a server parameter.

## Explicit non-goals

This note does not cover mixnets, onion-style routing, or hiding *which server*
a client talks to — those are separate, larger designs. Cover traffic only
hides the presence and timing of real messages behind a constant client-side
stream.
