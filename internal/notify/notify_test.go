package notify

import (
	"context"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

func env(id string) api.Envelope { return api.Envelope{ID: id} }

type fakePending struct {
	msgs []storage.Message
	err  error
}

func (f *fakePending) PendingMessages(context.Context, time.Time, int) ([]storage.Message, error) {
	return f.msgs, f.err
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
	store := &fakePending{msgs: []storage.Message{
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
