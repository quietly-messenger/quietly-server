package notify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/storage"
	"github.com/quietly-messenger/quietly-server/internal/storage/memory"
	"github.com/quietly-messenger/quietly-server/internal/testutil"
)

func env(id string) api.Envelope { return api.Envelope{ID: id} }

// cursorStore is a PendingStore that honors the (not_before, id) keyset
// cursor over a fixed slice and counts calls — the permanent regression for
// audit F-28 (Recover must advance the cursor, not re-read the head).
type cursorStore struct {
	msgs  []storage.Message
	calls int
}

func (f *cursorStore) PendingMessages(_ context.Context, now time.Time, afterNotBefore time.Time, afterID string, limit int) ([]storage.Message, error) {
	f.calls++
	var out []storage.Message
	for _, m := range f.msgs {
		if !m.NotBefore.After(now) {
			continue
		}
		if m.NotBefore.Before(afterNotBefore) {
			continue
		}
		if m.NotBefore.Equal(afterNotBefore) && m.ID <= afterID {
			continue
		}
		out = append(out, m)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// countingStore wraps a real store and counts PendingMessages calls.
type countingStore struct {
	inner PendingStore
	calls int
}

func (c *countingStore) PendingMessages(ctx context.Context, now time.Time, afterNotBefore time.Time, afterID string, limit int) ([]storage.Message, error) {
	c.calls++
	return c.inner.PendingMessages(ctx, now, afterNotBefore, afterID, limit)
}

func TestScheduleDeliversImmediatelyWhenDue(t *testing.T) {
	var got []string
	s := &Scheduler{
		deliver: func(u string, d int, e api.Envelope) { got = append(got, u) },
		cap:     10,
		now:     func() time.Time { return time.Unix(100, 0) },
	}
	s.Schedule("u1", 1, env("m1"), time.Unix(99, 0)) // already due
	if len(got) != 1 || got[0] != "u1" {
		t.Fatalf("immediate delivery = %v, want [u1]", got)
	}
}

func TestScheduleQueuesUntilRelease(t *testing.T) {
	var got []string
	s := &Scheduler{
		deliver: func(u string, d int, e api.Envelope) { got = append(got, u) },
		cap:     10,
		now:     func() time.Time { return time.Unix(100, 0) },
	}
	s.Schedule("u1", 1, env("m1"), time.Unix(110, 0))
	if len(got) != 0 {
		t.Fatal("delivered before release time")
	}
	s.drain(time.Unix(105, 0))
	if len(got) != 0 {
		t.Fatal("delivered before release time (drain at 105)")
	}
	s.drain(time.Unix(110, 0))
	if len(got) != 1 || got[0] != "u1" {
		t.Fatalf("delivery = %v, want [u1]", got)
	}
	// The queue is now empty: a further drain is a no-op.
	s.drain(time.Unix(200, 0))
	if len(got) != 1 {
		t.Fatalf("re-delivered after drain: %v", got)
	}
}

func TestScheduleDropsWhenFull(t *testing.T) {
	now := time.Unix(100, 0)
	s := &Scheduler{
		deliver: func(u string, d int, e api.Envelope) {},
		cap:     2,
		now:     func() time.Time { return now },
	}
	for i := 0; i < 100; i++ {
		s.Schedule("u", i, env("m"), time.Unix(200, 0)) // all future
	}
	s.mu.Lock()
	n := len(s.items)
	s.mu.Unlock()
	if n != 2 {
		t.Fatalf("queue length = %d, want cap 2 (must be bounded)", n)
	}
}

func TestRecoverSchedulesFutureMessages(t *testing.T) {
	var got []string
	s := &Scheduler{
		deliver: func(u string, d int, e api.Envelope) { got = append(got, u) },
		cap:     100,
		now:     func() time.Time { return time.Unix(100, 0) },
	}
	store := &cursorStore{msgs: []storage.Message{
		{ID: "m1", RecipientUserID: "u1", RecipientDeviceID: 1, NotBefore: time.Unix(110, 0)},
		{ID: "m2", RecipientUserID: "u2", RecipientDeviceID: 2, NotBefore: time.Unix(120, 0)},
	}}
	if err := s.Recover(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("recovered notifications delivered early: %v", got)
	}
	s.drain(time.Unix(115, 0))
	if len(got) != 1 || got[0] != "u1" {
		t.Fatalf("drain at 115 = %v, want [u1]", got)
	}
	s.drain(time.Unix(125, 0))
	if len(got) != 2 {
		t.Fatalf("drain at 125 = %v, want [u1 u2]", got)
	}
}

// TestRecoverPaginatesBacklog is the permanent regression for audit F-28: a
// backlog larger than Recover's batch (1000) must be walked with a keyset
// cursor — every message scheduled exactly once, in a linear number of store
// calls, instead of re-reading the same head forever.
func TestRecoverPaginatesBacklog(t *testing.T) {
	base := time.Unix(1000, 0)
	msgs := make([]storage.Message, 2500)
	for i := range msgs {
		msgs[i] = storage.Message{
			ID:                fmt.Sprintf("m%04d", i),
			RecipientUserID:   "u",
			RecipientDeviceID: 1,
			NotBefore:         base.Add(time.Duration(i) * time.Second),
		}
	}
	s := &Scheduler{
		deliver: func(u string, d int, e api.Envelope) {},
		cap:     len(msgs),
		now:     func() time.Time { return time.Unix(0, 0) },
	}
	store := &cursorStore{msgs: msgs}
	if err := s.Recover(context.Background(), store); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	queued := len(s.items)
	s.mu.Unlock()
	if queued != len(msgs) {
		t.Fatalf("queued %d notifications, want %d (each recovered exactly once)", queued, len(msgs))
	}
	if store.calls != 3 { // 1000 + 1000 + 500
		t.Fatalf("store calls = %d, want 3 (cursor must advance, not re-read the head)", store.calls)
	}
}

// TestRecoverRealStoreBacklog is the real-store half of the F-28 regression: a
// 1200-row backlog sharing one release time must be walked in linear queries,
// queue the tail (not just the first batch), and deliver every envelope
// exactly once — the audit repro measured 1367 queries / 11x wakeups / 200
// stranded messages.
func TestRecoverRealStoreBacklog(t *testing.T) {
	store := memory.New()
	limits := testutil.Limits()
	target := testutil.NewAccount(t, store, limits, "backlog")
	ctx := context.Background()
	now := time.Now()
	when := now.Add(time.Hour).Truncate(time.Millisecond)

	const total = 1200
	for i := 0; i < total; i++ {
		m := &storage.Message{
			RecipientUserID:   target.UserID,
			RecipientDeviceID: target.DeviceID,
			Sealed:            []byte{byte(i)},
			ServerTS:          now,
			NotBefore:         when, // one release time: the id tiebreak carries the cursor
			TTLExpiresAt:      now.Add(2 * time.Hour),
		}
		if err := store.EnqueueMessage(ctx, m); err != nil {
			t.Fatal(err)
		}
	}

	var delivered []string
	s := &Scheduler{
		deliver: func(userID string, deviceID int, e api.Envelope) { delivered = append(delivered, e.ID) },
		cap:     total,
		now:     func() time.Time { return now },
	}
	counted := &countingStore{inner: store}
	if err := s.Recover(ctx, counted); err != nil {
		t.Fatal(err)
	}
	if counted.calls != 2 { // 1000 + 200 (short page ends the walk)
		t.Fatalf("store calls = %d, want 2", counted.calls)
	}

	s.mu.Lock()
	queued := len(s.items)
	s.mu.Unlock()
	if queued != total {
		t.Fatalf("queued = %d, want %d (the tail must be scheduled)", queued, total)
	}

	s.drain(when)
	if len(delivered) != total {
		t.Fatalf("delivered %d wakeups, want %d", len(delivered), total)
	}
	seen := map[string]int{}
	for _, id := range delivered {
		seen[id]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("envelope %s delivered %d times", id, n)
		}
	}
}

func TestNewAndClose(t *testing.T) {
	s := New(func(u string, d int, e api.Envelope) {}, 10)
	done := make(chan struct{})
	go func() {
		s.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close hung")
	}
}
