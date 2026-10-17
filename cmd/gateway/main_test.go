package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-crypto/cryptocore"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/federation"
	"github.com/quietly-messenger/quietly-server/internal/ratelimit"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

type fakeDeliveryStore struct {
	m   *storage.Message
	err error
	n   int
}

func (f *fakeDeliveryStore) EnqueueMessage(_ context.Context, m *storage.Message) error {
	if f.err != nil {
		return f.err
	}
	f.m = m
	f.n++
	return nil
}

func delivery(sealed []byte) federation.DeliveryRequest {
	d := federation.DeliveryRequest{}
	d.Request.Recipient.UserID = "11111111-2222-4333-8444-555555555555"
	d.Request.Recipient.DeviceID = 1
	d.Request.Sealed = sealed
	return d
}

// TestEnqueueDeliveryEnforcesEnvelopeLimits pins audit F-25: the gateway must
// apply the same envelope rules as message.Submit — a federated peer must not
// be able to queue blobs larger than SealedBlobMax (the body cap alone allows
// 256 KiB) or messages with a different lifetime than §15 promises.
func TestEnqueueDeliveryEnforcesEnvelopeLimits(t *testing.T) {
	limits := config.DefaultLimits()
	limits.MessageTTLDays = 7
	limits.SealedBlobMax = 8

	now := time.Now()
	ctx := context.Background()

	t.Run("oversized blob is rejected", func(t *testing.T) {
		store := &fakeDeliveryStore{}
		err := enqueueDelivery(ctx, store, limits, delivery(make([]byte, limits.SealedBlobMax+1)), now)
		if ae := api.AsAPIError(err); ae == nil || ae.Code != api.CodePayloadTooLarge {
			t.Fatalf("error = %v, want payload_too_large", err)
		}
		if store.m != nil {
			t.Fatal("oversized blob reached storage")
		}
	})

	t.Run("empty blob is rejected", func(t *testing.T) {
		store := &fakeDeliveryStore{}
		err := enqueueDelivery(ctx, store, limits, delivery(nil), now)
		if ae := api.AsAPIError(err); ae == nil || ae.Code != api.CodeInvalidPayload {
			t.Fatalf("error = %v, want invalid_payload", err)
		}
	})

	t.Run("blob at the limit gets the configured TTL", func(t *testing.T) {
		store := &fakeDeliveryStore{}
		if err := enqueueDelivery(ctx, store, limits, delivery(make([]byte, limits.SealedBlobMax)), now); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if store.m == nil {
			t.Fatal("message was not stored")
		}
		if want := now.Add(7 * 24 * time.Hour); !store.m.TTLExpiresAt.Equal(want) {
			t.Fatalf("TTLExpiresAt = %v, want %v (configured TTL, not a hardcoded 30 days)", store.m.TTLExpiresAt, want)
		}
		if !store.m.ServerTS.Equal(now) {
			t.Fatalf("ServerTS = %v, want %v", store.m.ServerTS, now)
		}
	})

	t.Run("storage failure surfaces as a plain error", func(t *testing.T) {
		store := &fakeDeliveryStore{err: errors.New("db down")}
		err := enqueueDelivery(ctx, store, limits, delivery([]byte("sealed!!")), now)
		if err == nil || api.AsAPIError(err) != nil {
			t.Fatalf("error = %v, want a non-API error", err)
		}
	})
}

// deliverFixture wires a deliverHandler around a signed, verifiable delivery.
type deliverFixture struct {
	handler  *deliverHandler
	store    *fakeDeliveryStore
	delivery federation.DeliveryRequest
}

func newDeliverFixture(t *testing.T, perMinute int, certExpiry time.Time) *deliverFixture {
	t.Helper()
	ts, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server, err := cryptocore.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := federation.SignCert(ts.PrivateKey, "a.example", server.PublicKey, certExpiry)
	if err != nil {
		t.Fatal(err)
	}
	d := federation.DeliveryRequest{
		Cert: cert,
		Request: federation.SignedRequest{
			Version:   "quietly/1",
			Domain:    "a.example",
			Timestamp: now.UnixMilli(),
			Nonce:     "nonce-1",
			Recipient: federation.Recipient{UserID: "7c9e6679-7425-40de-944b-e07fc1f90ae7", DeviceID: 1},
			Sealed:    []byte("sealed"),
		},
	}
	if err := d.Request.Sign(server.PrivateKey); err != nil {
		t.Fatal(err)
	}
	st := &fakeDeliveryStore{}
	// Refill rate 0: the budget never regenerates, so the tests do not depend
	// on wall-clock timing.
	return &deliverFixture{
		handler: &deliverHandler{
			tsPub:   ts.PublicKey,
			revoked: &revocationCache{},
			replay:  func(string, string) bool { return true },
			store:   st,
			limits:  config.DefaultLimits(),
			limiter: ratelimit.New(0, perMinute, 100),
		},
		store:    st,
		delivery: d,
	}
}

func (f *deliverFixture) post(t *testing.T, remote, xff string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(f.delivery)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/deliver", bytes.NewReader(body))
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

// TestDeliverRateLimitIsPerPeerAddress pins the F-03 residual: /deliver is
// metered per direct peer address, and a spoofed X-Forwarded-For cannot mint a
// fresh bucket (the F-23 class of bug must not reappear on the S2S surface).
func TestDeliverRateLimitIsPerPeerAddress(t *testing.T) {
	f := newDeliverFixture(t, 1, time.Now().Add(time.Hour))

	if got := f.post(t, "203.0.113.9:4444", "").Code; got != http.StatusAccepted {
		t.Fatalf("first request status = %d, want 202", got)
	}
	if got := f.post(t, "203.0.113.9:4444", "9.9.9.9").Code; got != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429 (spoofed XFF must not reset the bucket)", got)
	}
	if f.store.n != 1 {
		t.Fatalf("store received %d messages, want 1 (throttled request must not enqueue)", f.store.n)
	}

	// A different peer has its own budget.
	if got := f.post(t, "203.0.113.10:4444", "").Code; got != http.StatusAccepted {
		t.Fatalf("other peer status = %d, want 202", got)
	}
	if f.store.n != 2 {
		t.Fatalf("store received %d messages, want 2", f.store.n)
	}
}

// TestDeliverRejectsExpiredCert ties the F-03 expiry work to the live handler
// path: an expired certificate is refused before enqueueing.
func TestDeliverRejectsExpiredCert(t *testing.T) {
	f := newDeliverFixture(t, 10, time.Now().Add(-time.Hour))
	if got := f.post(t, "203.0.113.9:4444", "").Code; got != http.StatusForbidden {
		t.Fatalf("expired certificate status = %d, want 403", got)
	}
	if f.store.n != 0 {
		t.Fatal("expired delivery reached storage")
	}
}
