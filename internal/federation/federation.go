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
	"encoding/json"
	"fmt"
	"time"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"
)

// DomainS2S is the domain-separation string for S2S signatures. It is a draft;
// when the S2S spec is finalized it belongs in the shared `quietly` package.
const DomainS2S = "quietly/1 s2s"

// ServerCert binds a server domain to its Ed25519 public key, signed by the
// trust service.
type ServerCert struct {
	Domain    string `json:"domain"`
	PublicKey Bytes  `json:"public_key"`
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

// certPayload is the canonical bytes a cert signs: domain || 0x00 || public key.
func certPayload(c ServerCert) []byte {
	out := make([]byte, 0, len(c.Domain)+1+len(c.PublicKey))
	out = append(out, c.Domain...)
	out = append(out, 0x00)
	out = append(out, c.PublicKey...)
	return out
}

// SignCert issues a certificate with the trust service's signing key.
func SignCert(tsPriv []byte, domain string, serverPub []byte) (ServerCert, error) {
	sig, err := cryptocore.SignIdentity(tsPriv, certPayload(ServerCert{Domain: domain, PublicKey: serverPub}))
	if err != nil {
		return ServerCert{}, err
	}
	return ServerCert{Domain: domain, PublicKey: serverPub, Signature: sig}, nil
}

// VerifyCert checks a certificate against the trust service's public key.
func VerifyCert(tsPub []byte, c ServerCert) bool {
	if len(c.PublicKey) != cryptocore.IdentityPublicKeySize || len(c.Signature) != cryptocore.SignatureSize {
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
// service public key) and not revoked, that the request comes from the
// certified domain, that its timestamp is fresh, that its signature verifies
// against the certificate's public key, and — when replay is non-nil — that its
// nonce has not been seen. replay(domain, nonce) must return true only on the
// first sighting of a nonce.
func VerifyDelivery(tsPub []byte, revoked func(domain string) bool, replay func(domain, nonce string) bool, now time.Time, d DeliveryRequest) bool {
	if !VerifyCert(tsPub, d.Cert) {
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
