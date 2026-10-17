package federation_test

import (
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"

	"github.com/quietly-messenger/quietly-server/internal/federation"
)

func newDelivery(t *testing.T, now time.Time) (tsPub, tsPriv []byte, d federation.DeliveryRequest) {
	t.Helper()
	ts, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := federation.SignCert(ts.PrivateKey, "a.example", server.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	req := federation.SignedRequest{
		Version:   "quietly/1",
		Domain:    "a.example",
		Timestamp: now.UnixMilli(),
		Nonce:     "nonce-1",
		Recipient: federation.Recipient{UserID: "7c9e6679-7425-40de-944b-e07fc1f90ae7", DeviceID: 1},
		Sealed:    []byte("sealed-bytes"),
	}
	if err := req.Sign(server.PrivateKey); err != nil {
		t.Fatal(err)
	}
	return ts.PublicKey, ts.PrivateKey, federation.DeliveryRequest{Cert: cert, Request: req}
}

func TestVerifyDeliveryAcceptsValidRequest(t *testing.T) {
	now := time.Now()
	tsPub, _, d := newDelivery(t, now)
	if !federation.VerifyDelivery(tsPub, nil, nil, now, d) {
		t.Fatal("valid delivery rejected")
	}
}

func TestVerifyDeliveryRejectsTampering(t *testing.T) {
	now := time.Now()
	tsPub, _, d := newDelivery(t, now)

	t.Run("stale timestamp", func(t *testing.T) {
		if federation.VerifyDelivery(tsPub, nil, nil, now.Add(federation.MaxClockSkew+time.Minute), d) {
			t.Fatal("stale timestamp accepted")
		}
	})
	t.Run("future timestamp", func(t *testing.T) {
		if federation.VerifyDelivery(tsPub, nil, nil, now.Add(-(federation.MaxClockSkew + time.Minute)), d) {
			t.Fatal("future timestamp accepted")
		}
	})
	t.Run("revoked domain", func(t *testing.T) {
		revoked := func(domain string) bool { return domain == "a.example" }
		if federation.VerifyDelivery(tsPub, revoked, nil, now, d) {
			t.Fatal("revoked domain accepted")
		}
	})
	t.Run("tampered sealed blob", func(t *testing.T) {
		bad := d
		bad.Request.Sealed = []byte("different-bytes")
		if federation.VerifyDelivery(tsPub, nil, nil, now, bad) {
			t.Fatal("tampered payload accepted")
		}
	})
	t.Run("domain mismatch between cert and request", func(t *testing.T) {
		bad := d
		bad.Request.Domain = "b.example"
		if federation.VerifyDelivery(tsPub, nil, nil, now, bad) {
			t.Fatal("mismatched request domain accepted")
		}
	})
	t.Run("wrong trust key", func(t *testing.T) {
		other, err := cryptocore.GenerateIdentityKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if federation.VerifyDelivery(other.PublicKey, nil, nil, now, d) {
			t.Fatal("cert accepted under a different trust key")
		}
	})
}

func TestVerifyDeliveryReplayProtection(t *testing.T) {
	now := time.Now()
	tsPub, _, d := newDelivery(t, now)

	seen := map[string]bool{}
	replay := func(domain, nonce string) bool {
		key := domain + "|" + nonce
		if seen[key] {
			return false
		}
		seen[key] = true
		return true
	}
	if !federation.VerifyDelivery(tsPub, nil, replay, now, d) {
		t.Fatal("first delivery rejected")
	}
	if federation.VerifyDelivery(tsPub, nil, replay, now, d) {
		t.Fatal("replayed delivery accepted")
	}
}

func TestVerifyCertRejectsMalformed(t *testing.T) {
	ts, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := federation.SignCert(ts.PrivateKey, "a.example", server.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !federation.VerifyCert(ts.PublicKey, cert) {
		t.Fatal("valid cert rejected")
	}
	short := cert
	short.Signature = short.Signature[:32]
	if federation.VerifyCert(ts.PublicKey, short) {
		t.Fatal("short signature accepted")
	}
	moved := cert
	moved.Domain = "b.example"
	if federation.VerifyCert(ts.PublicKey, moved) {
		t.Fatal("domain swap accepted")
	}
}
