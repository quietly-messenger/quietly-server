// Package federation implements the server-to-server protocol and the
// trust-service certificate model (PROTOCOL.md §16, which reserves the design;
// the detailed S2S spec is a first cut documented in docs/FEDERATION.md).
//
// A home server holds an Ed25519 identity key and a certificate signed by the
// trust service binding its domain to that key. S2S requests are signed by the
// sender server and verified by the receiver against the sender's certificate.
package federation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

// DomainS2S is the domain-separation string for S2S signatures. It is a draft;
// when the S2S spec is finalized it belongs in the shared `quietly` package.
const DomainS2S = "quietly/1 s2s"

// ServerCert binds a server domain to its Ed25519 public key, signed by the
// trust service. NotAfter is the expiry as Unix milliseconds; a certificate
// must be renewed (re-issued) before then and verifiers refuse it afterwards,
// with MaxClockSkew of grace for clock drift (audit F-03 residual).
type ServerCert struct {
	Domain    string `json:"domain"`
	PublicKey Bytes  `json:"public_key"`
	NotAfter  int64  `json:"not_after"`
	Signature Bytes  `json:"signature"`
}

// Bytes is base64url-encoded binary.
type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	dec, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	*b = dec
	return nil
}

// certPayload is the canonical bytes a cert signs:
// domain || 0x00 || public key || 0x00 || not_after (big-endian Unix ms). The
// expiry is inside the signed payload, so it cannot be extended without the
// trust service's key.
func certPayload(c ServerCert) []byte {
	out := make([]byte, 0, len(c.Domain)+1+len(c.PublicKey)+1+8)
	out = append(out, c.Domain...)
	out = append(out, 0x00)
	out = append(out, c.PublicKey...)
	out = append(out, 0x00)
	out = binary.BigEndian.AppendUint64(out, uint64(c.NotAfter))
	return out
}

// SignCert issues a certificate with the trust service's signing key, valid
// until notAfter.
func SignCert(tsPriv []byte, domain string, serverPub []byte, notAfter time.Time) (ServerCert, error) {
	cert := ServerCert{Domain: domain, PublicKey: serverPub, NotAfter: notAfter.UnixMilli()}
	sig, err := cryptocore.SignIdentity(tsPriv, certPayload(cert))
	if err != nil {
		return ServerCert{}, err
	}
	cert.Signature = sig
	return cert, nil
}

// VerifyCert checks a certificate against the trust service's public key and
// the verifier's clock: the signature must verify and the certificate must
// still be valid. MaxClockSkew of grace past NotAfter absorbs drift between
// the issuing and verifying hosts; a missing expiry (NotAfter <= 0) is
// malformed and rejected.
func VerifyCert(tsPub []byte, c ServerCert, now time.Time) bool {
	if len(c.PublicKey) != cryptocore.IdentityPublicKeySize || len(c.Signature) != cryptocore.SignatureSize {
		return false
	}
	if c.NotAfter <= 0 || now.UnixMilli() > c.NotAfter+MaxClockSkew.Milliseconds() {
		return false
	}
	return cryptocore.VerifyIdentitySignature(tsPub, certPayload(c), c.Signature)
}

// Recipient mirrors the C2S recipient.
type Recipient struct {
	UserID   string `json:"user_id"`
	DeviceID int    `json:"device_id"`
}

// SignedRequest is an S2S message-routing request signed by the sending server.
type SignedRequest struct {
	Version   string    `json:"v"`
	Domain    string    `json:"domain"`
	Timestamp int64     `json:"timestamp"`
	Nonce     string    `json:"nonce"`
	Recipient Recipient `json:"recipient"`
	Sealed    Bytes     `json:"sealed"`
	Signature Bytes     `json:"signature"`
}

// canonical builds the bytes a SignedRequest signs.
func (r SignedRequest) canonical() []byte {
	h := sha256.Sum256(r.Sealed)
	out := []byte(DomainS2S)
	out = append(out, 0x00)
	out = append(out, r.Domain...)
	out = append(out, 0x00)
	out = append(out, fmt.Sprintf("%d", r.Timestamp)...)
	out = append(out, 0x00)
	out = append(out, r.Nonce...)
	out = append(out, 0x00)
	out = append(out, fmt.Sprintf("%x", h)...)
	return out
}

// Sign signs the request with the sending server's identity key.
func (r *SignedRequest) Sign(serverPriv []byte) error {
	sig, err := cryptocore.SignIdentity(serverPriv, r.canonical())
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// Verify checks the request signature against the sending server's public key.
func (r SignedRequest) Verify(serverPub []byte) bool {
	if len(r.Signature) != cryptocore.SignatureSize {
		return false
	}
	return cryptocore.VerifyIdentitySignature(serverPub, r.canonical(), r.Signature)
}

// DeliveryRequest is an S2S delivery: the sender's certificate plus the signed
// request, so a receiver can verify without a separate registry round-trip.
type DeliveryRequest struct {
	Cert    ServerCert    `json:"cert"`
	Request SignedRequest `json:"request"`
}

// MaxClockSkew bounds how far a delivery timestamp may be from local time. It
// complements the nonce replay check: a captured delivery stays replayable
// forever without both (audit F-03).
const MaxClockSkew = 5 * time.Minute

// VerifyDelivery checks that the certificate is valid (against the trust
// service public key, including its expiry) and not revoked, that the request
// comes from the certified domain, that its timestamp is fresh, that its
// signature verifies against the certificate's public key, and — when replay
// is non-nil — that its nonce has not been seen. replay(domain, nonce) must
// return true only on the first sighting of a nonce.
func VerifyDelivery(tsPub []byte, revoked func(domain string) bool, replay func(domain, nonce string) bool, now time.Time, d DeliveryRequest) bool {
	if !VerifyCert(tsPub, d.Cert, now) {
		return false
	}
	if revoked != nil && revoked(d.Cert.Domain) {
		return false
	}
	if d.Request.Domain != d.Cert.Domain {
		return false
	}
	ts := time.UnixMilli(d.Request.Timestamp)
	if skew := now.Sub(ts); skew > MaxClockSkew || -skew > MaxClockSkew {
		return false
	}
	if !d.Request.Verify(d.Cert.PublicKey) {
		return false
	}
	if replay != nil && !replay(d.Cert.Domain, d.Request.Nonce) {
		return false
	}
	return true
}
