package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/storage"
)

// TestPrunePreKeyIssuances covers the F-02 residual in the in-memory store:
// records older than the cutoff are dropped, fresh ones survive, and the
// returned count reflects what was removed.
func TestPrunePreKeyIssuances(t *testing.T) {
	s := New()
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	s.SetNow(func() time.Time { return now })

	oldKey := storage.OneTimePreKey{ID: 7, PublicKey: []byte{1, 2, 3}}
	freshKey := storage.OneTimePreKey{ID: 8, PublicKey: []byte{4, 5, 6}}
	if err := s.RecordPreKeyIssuance(ctx, "alice", 1, "bob", 1, oldKey); err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	if err := s.RecordPreKeyIssuance(ctx, "alice", 1, "carol", 1, freshKey); err != nil {
		t.Fatal(err)
	}

	n, err := s.PrunePreKeyIssuances(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d records, want 1", n)
	}
	if _, _, err := s.GetPreKeyIssuance(ctx, "alice", 1, "bob", 1); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired issuance error = %v, want ErrNotFound", err)
	}
	got, at, err := s.GetPreKeyIssuance(ctx, "alice", 1, "carol", 1)
	if err != nil {
		t.Fatalf("fresh issuance: %v", err)
	}
	if got.ID != freshKey.ID || !at.Equal(now) {
		t.Fatalf("fresh issuance = %+v at %v, want id %d at %v", got, at, freshKey.ID, now)
	}
}
