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
	ca := trust.New(ts.PrivateKey, ts.PublicKey)

	server, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue("a.example", server.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	d := federation.DeliveryRequest{
		Cert:    cert,
		Request: signedDelivery(t, "a.example", server.PrivateKey, now),
	}
	if !ca.VerifyDelivery(d, nil, now) {
		t.Fatal("issued delivery rejected")
	}

	ca.Revoke("a.example")
	if ca.VerifyDelivery(d, nil, now) {
		t.Fatal("revoked delivery accepted")
	}
	if !ca.IsRevoked("a.example") {
		t.Fatal("IsRevoked reports false after Revoke")
	}
}

func TestCAPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	ts, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ca := trust.New(ts.PrivateKey, ts.PublicKey)
	server, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue("a.example", server.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ca.Revoke("dead.example")
	ca.Issue("b.example", server.PublicKey)
	if err := ca.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Fresh CA (as after a restart) must keep certificates and revocations.
	restored := trust.New(ts.PrivateKey, ts.PublicKey)
	if err := restored.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !restored.IsRevoked("dead.example") {
		t.Fatal("revocation lost across restart")
	}
	now := time.Now()
	d := federation.DeliveryRequest{
		Cert:    cert,
		Request: signedDelivery(t, "a.example", server.PrivateKey, now),
	}
	if !restored.VerifyDelivery(d, nil, now) {
		t.Fatal("issued certificate lost across restart")
	}
}

func TestCALoadMissingFileIsFresh(t *testing.T) {
	ts, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ca := trust.New(ts.PrivateKey, ts.PublicKey)
	if err := ca.Load(filepath.Join(t.TempDir(), "does-not-exist.json")); err != nil {
		t.Fatalf("missing state file must be a fresh start: %v", err)
	}
}
