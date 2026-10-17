package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/storage"
)

// TestMessagesRespectNotBefore covers the TASK-001 B fetch/pending split.
func TestMessagesRespectNotBefore(t *testing.T) {
	s := New()
	ctx := context.Background()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

	s.messages["past"] = &storage.Message{ID: "past", RecipientUserID: "u", RecipientDeviceID: 1, NotBefore: now.Add(-time.Hour)}
	s.messages["future"] = &storage.Message{ID: "future", RecipientUserID: "u", RecipientDeviceID: 1, NotBefore: now.Add(time.Hour)}

	future, err := s.PendingMessages(ctx, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(future) != 1 || future[0].ID != "future" {
		t.Fatalf("PendingMessages = %v, want [future]", idsOf(future))
	}

	due, err := s.ListMessages(ctx, "u", 1, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].ID != "past" {
		t.Fatalf("ListMessages = %v, want [past]", idsOf(due))
	}
}

func idsOf(ms []storage.Message) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.ID)
	}
	return out
}

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
	w1 := now.Truncate(24 * time.Hour)
	if err := s.RecordPreKeyIssuance(ctx, "bob", 1, w1, oldKey); err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	w2 := now.Truncate(24 * time.Hour)
	if err := s.RecordPreKeyIssuance(ctx, "carol", 1, w2, freshKey); err != nil {
		t.Fatal(err)
	}

	n, err := s.PrunePreKeyIssuances(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d records, want 1", n)
	}
	if _, _, err := s.GetPreKeyIssuance(ctx, "bob", 1, w1); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired issuance error = %v, want ErrNotFound", err)
	}
	got, at, err := s.GetPreKeyIssuance(ctx, "carol", 1, w2)
	if err != nil {
		t.Fatalf("fresh issuance: %v", err)
	}
	if got.ID != freshKey.ID || !at.Equal(now) {
		t.Fatalf("fresh issuance = %+v at %v, want id %d at %v", got, at, freshKey.ID, now)
	}
}
