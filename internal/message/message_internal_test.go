package message

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/storage"
	"github.com/quietly-messenger/quietly-server/internal/storage/memory"
)

// newAlice builds a store plus an account/device whose delivery token matches
// `token`, so Submit accepts it. (testutil cannot be imported here: it imports
// this package.)
func newAlice(t *testing.T, token []byte) (*memory.Store, *storage.Device) {
	t.Helper()
	store := memory.New()
	hash := sha256.Sum256(token)
	_, dev, err := store.CreateAccountWithDevice(context.Background(), "alice", &storage.Device{
		IdentityKeyDH:     make([]byte, 32),
		IdentityKeySig:    make([]byte, 32),
		IdentityBinding:   make([]byte, 64),
		SignedPreKey:      make([]byte, 32),
		SignedPreKeySig:   make([]byte, 64),
		DeliveryToken:     token,
		DeliveryTokenHash: hash[:],
	}, nil)
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	return store, dev
}

func TestSubmitAppliesJitter(t *testing.T) {
	token := []byte("tok")
	store, alice := newAlice(t, token)
	limits := config.DefaultLimits()
	limits.DeliveryJitterMs = 5000
	// Deterministic full hold: rng(n) = n-1, so NotBefore = now + 5000ms.
	svc := &Service{store: store, limits: limits, jitter: func(n int) int { return n - 1 }}

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	m, err := svc.Submit(context.Background(), api.MessageSubmit{
		V:         api.Version,
		Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.ID},
		Sealed:    make([]byte, 16),
	}, token, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(5000 * time.Millisecond); !m.NotBefore.Equal(want) {
		t.Fatalf("NotBefore = %v, want %v (full jitter)", m.NotBefore, want)
	}
	if !m.ServerTS.Equal(now) {
		t.Fatalf("ServerTS = %v, want %v (jitter must not move the enqueue time)", m.ServerTS, now)
	}
}

func TestSubmitZeroJitterKeepsCurrentBehavior(t *testing.T) {
	token := []byte("tok")
	store, alice := newAlice(t, token)
	svc := New(store, config.DefaultLimits()) // DeliveryJitterMs == 0

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	m, err := svc.Submit(context.Background(), api.MessageSubmit{
		V:         api.Version,
		Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.ID},
		Sealed:    make([]byte, 16),
	}, token, now)
	if err != nil {
		t.Fatal(err)
	}
	if !m.NotBefore.Equal(now) {
		t.Fatalf("NotBefore = %v, want %v (jitter 0)", m.NotBefore, now)
	}
}

func TestFetchRespectsNotBefore(t *testing.T) {
	token := []byte("tok")
	store, alice := newAlice(t, token)
	limits := config.DefaultLimits()
	limits.DeliveryJitterMs = 1000
	svc := &Service{store: store, limits: limits, jitter: func(n int) int { return n - 1 }}

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	if _, err := svc.Submit(context.Background(), api.MessageSubmit{
		V:         api.Version,
		Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.ID},
		Sealed:    make([]byte, 16),
	}, token, now); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	resp, err := svc.Fetch(ctx, alice.UserID, alice.ID, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 0 {
		t.Fatalf("fetch before release returned %d messages, want 0", len(resp.Messages))
	}

	resp, err = svc.Fetch(ctx, alice.UserID, alice.ID, now.Add(time.Second), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("fetch after release returned %d messages, want 1", len(resp.Messages))
	}
}
