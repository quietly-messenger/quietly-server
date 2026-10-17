// Package trust implements the Directory/Trust Service: a certificate
// authority that issues, lists, and revokes home-server certificates
// (PROTOCOL.md §16, README §2.4).
package trust

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/federation"
)

// CA is the trust-service authority. It holds its own Ed25519 signing key and
// an in-memory registry of issued certificates and revocations.
type CA struct {
	mu      sync.Mutex
	tsPub   []byte
	tsPriv  []byte
	certs   map[string]federation.ServerCert
	revoked map[string]bool
}

// New builds a CA from the trust service's Ed25519 keypair.
func New(tsPriv, tsPub []byte) *CA {
	return &CA{
		tsPriv:  tsPriv,
		tsPub:   tsPub,
		certs:   map[string]federation.ServerCert{},
		revoked: map[string]bool{},
	}
}

// PublicKey returns the trust service's public key.
func (ca *CA) PublicKey() []byte { return ca.tsPub }

// Issue signs and records a certificate for a server domain.
func (ca *CA) Issue(domain string, serverPub []byte) (federation.ServerCert, error) {
	cert, err := federation.SignCert(ca.tsPriv, domain, serverPub)
	if err != nil {
		return federation.ServerCert{}, err
	}
	ca.mu.Lock()
	ca.certs[domain] = cert
	ca.revoked[domain] = false
	ca.mu.Unlock()
	return cert, nil
}

// Revoke marks a domain's certificate revoked.
func (ca *CA) Revoke(domain string) {
	ca.mu.Lock()
	ca.revoked[domain] = true
	ca.mu.Unlock()
}

// IsRevoked reports whether a domain is revoked.
func (ca *CA) IsRevoked(domain string) bool {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.revoked[domain]
}

// VerifyDelivery verifies an S2S delivery request against this CA.
func (ca *CA) VerifyDelivery(d federation.DeliveryRequest, replay func(domain, nonce string) bool, now time.Time) bool {
	return federation.VerifyDelivery(ca.tsPub, ca.IsRevoked, replay, now, d)
}

// Certs returns a snapshot of issued certificates with their revocation state.
func (ca *CA) Certs() map[string]bool {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	out := make(map[string]bool, len(ca.certs))
	for d := range ca.certs {
		out[d] = ca.revoked[d]
	}
	return out
}

// state is the on-disk form of the CA registry.
type state struct {
	Certs   map[string]federation.ServerCert `json:"certs"`
	Revoked map[string]bool                  `json:"revoked"`
}

// Load restores issued certificates and revocations from path. A missing file
// leaves the CA empty (first boot).
func (ca *CA) Load(path string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if s.Certs != nil {
		ca.certs = s.Certs
	}
	if s.Revoked != nil {
		ca.revoked = s.Revoked
	}
	return nil
}

// Save writes the CA registry to path atomically, so a restart cannot lose
// issued certificates or revocations (audit F-03).
func (ca *CA) Save(path string) error {
	ca.mu.Lock()
	b, err := json.MarshalIndent(state{Certs: ca.certs, Revoked: ca.revoked}, "", "  ")
	ca.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
