package trust_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"

	"github.com/quietly-messenger/quietly-server/internal/federation"
	"github.com/quietly-messenger/quietly-server/internal/trust"
)

func signedDelivery(t *testing.T, domain string, serverPriv []byte, now time.Time) federation.SignedRequest {
	t.Helper()
	req := federation.SignedRequest{
		Version:   "quietly/1",
		Domain:    domain,
		Timestamp: now.UnixMilli(),
		Nonce:     "nonce",
		Recipient: federation.Recipient{UserID: "7c9e6679-7425-40de-944b-e07fc1f90ae7", DeviceID: 1},
		Sealed:    []byte("sealed"),
	}
	if err := req.Sign(serverPriv); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestCAIssueVerifyRevoke(t *testing.T) {
	ts, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ca := trust.New(ts.PrivateKey, ts.PublicKey, 24*time.Hour)

	server, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := ca.Issue("a.example", server.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(24 * time.Hour).UnixMilli(); cert.NotAfter != want {
		t.Fatalf("issued cert NotAfter = %d, want %d (now + validity)", cert.NotAfter, want)
	}

	d := federation.DeliveryRequest{
		Cert:    cert,
		Request: signedDelivery(t, "a.example", server.PrivateKey, now),
	}
	if !ca.VerifyDelivery(d, nil, now) {
		t.Fatal("issued delivery rejected")
	}

	// Past its validity the certificate is refused even though the request
	// itself is fresh (audit F-03 residual).
	later := now.Add(48 * time.Hour)
	expired := federation.DeliveryRequest{
		Cert:    cert,
		Request: signedDelivery(t, "a.example", server.PrivateKey, later),
	}
	if ca.VerifyDelivery(expired, nil, later) {
		t.Fatal("expired certificate accepted")
	}

	ca.Revoke("a.example")
	if ca.VerifyDelivery(d, nil, now) {
		t.Fatal("revoked delivery accepted")
	}
	if !ca.IsRevoked("a.example") {
		t.Fatal("IsRevoked reports false after Revoke")
	}
}

// TestCARenewal covers the renewal path: re-issuing a domain before expiry
// replaces the certificate with one that lives longer and verifies.
func TestCARenewal(t *testing.T) {
	ts, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ca := trust.New(ts.PrivateKey, ts.PublicKey, 24*time.Hour)
	server, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	first, err := ca.Issue("a.example", server.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := ca.Issue("a.example", server.PublicKey, now.Add(12*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if renewed.NotAfter <= first.NotAfter {
		t.Fatalf("renewal did not extend expiry: %d then %d", first.NotAfter, renewed.NotAfter)
	}
	if ca.IsRevoked("a.example") {
		t.Fatal("renewal must clear revocation for the domain")
	}
	at := now.Add(36 * time.Hour) // past the old expiry, before the new one
	d := federation.DeliveryRequest{
		Cert:    renewed,
		Request: signedDelivery(t, "a.example", server.PrivateKey, at),
	}
	if !ca.VerifyDelivery(d, nil, at) {
		t.Fatal("renewed certificate rejected")
	}
}

func TestCAPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	ts, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ca := trust.New(ts.PrivateKey, ts.PublicKey, 24*time.Hour)
	server, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := ca.Issue("a.example", server.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	ca.Revoke("dead.example")
	ca.Issue("b.example", server.PublicKey, now)
	if err := ca.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Fresh CA (as after a restart) must keep certificates and revocations.
	restored := trust.New(ts.PrivateKey, ts.PublicKey, 24*time.Hour)
	if err := restored.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !restored.IsRevoked("dead.example") {
		t.Fatal("revocation lost across restart")
	}
	d := federation.DeliveryRequest{
		Cert:    cert,
		Request: signedDelivery(t, "a.example", server.PrivateKey, now),
	}
	if !restored.VerifyDelivery(d, nil, now) {
		t.Fatal("issued certificate lost across restart")
	}
	later := now.Add(48 * time.Hour)
	expired := federation.DeliveryRequest{
		Cert:    cert,
		Request: signedDelivery(t, "a.example", server.PrivateKey, later),
	}
	if restored.VerifyDelivery(expired, nil, later) {
		t.Fatal("persisted certificate never expires")
	}
}

func TestCALoadMissingFileIsFresh(t *testing.T) {
	ts, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ca := trust.New(ts.PrivateKey, ts.PublicKey, 24*time.Hour)
	if err := ca.Load(filepath.Join(t.TempDir(), "does-not-exist.json")); err != nil {
		t.Fatalf("missing state file must be a fresh start: %v", err)
	}
}
