// Package notify schedules message-delivery notifications so they fire no
// earlier than a message's release time (§15 delivery_jitter_ms, TASK-001 B).
//
// It is a single goroutine with a bounded min-heap of pending notifications
// drained on a fixed sweep interval — never one goroutine per message — so a
// burst of submitted messages cannot pin unbounded goroutines or memory.
// Notifications are best-effort hints: a dropped or lost notification only
// delays the wakeup, because the device still fetches its queue on connect.
//
// With jitter enabled, deliveries are serialized on the sweep goroutine, so
// one slow (half-open) socket can delay every notification queued behind it
// (audit F-35). This is accepted while the default `delivery_jitter_ms` is 0
// (deliveries then happen on the submit path, as before the delta); revisit
// with a bounded worker pool if the jitter default is ever raised.
package notify

import (
	"container/heap"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

// Deliver sends one notification: a WS frame to a connected device, or a push
// wakeup to an offline one (see ws.Hub.NotifyMessage).
type Deliver func(userID string, deviceID int, env api.Envelope)

// PendingStore is the storage subset Recover needs.
type PendingStore interface {
	PendingMessages(ctx context.Context, now time.Time, afterNotBefore time.Time, afterID string, limit int) ([]storage.Message, error)
}

// DefaultSweep is how often the scheduler checks for due notifications. The
// task's suggested bound (250–500 ms).
const DefaultSweep = 250 * time.Millisecond

type entry struct {
	when     time.Time
	userID   string
	deviceID int
	env      api.Envelope
}

type entries []entry

func (e entries) Len() int { return len(e) }
func (e entries) Less(i, j int) bool {
	if !e[i].when.Equal(e[j].when) {
		return e[i].when.Before(e[j].when)
	}
	if e[i].userID != e[j].userID {
		return e[i].userID < e[j].userID
	}
	if e[i].deviceID != e[j].deviceID {
		return e[i].deviceID < e[j].deviceID
	}
	return e[i].env.ID < e[j].env.ID
}
func (e entries) Swap(i, j int) { e[i], e[j] = e[j], e[i] }
func (e *entries) Push(x any)   { *e = append(*e, x.(entry)) }
func (e *entries) Pop() any     { old := *e; n := len(old); it := old[n-1]; *e = old[:n-1]; return it }

// Scheduler holds pending notifications until their release time.
type Scheduler struct {
	mu      sync.Mutex
	deliver Deliver
	cap     int
	now     func() time.Time
	sweep   time.Duration
	items   entries

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// New builds a scheduler with the given capacity (max queued notifications)
// and starts its sweep goroutine. Close must be called to stop it.
func New(deliver Deliver, cap int) *Scheduler {
	s := &Scheduler{
		deliver: deliver,
		cap:     cap,
		now:     time.Now,
		sweep:   DefaultSweep,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go s.run()
	return s
}

// Schedule delivers immediately when the release time has already arrived, and
// otherwise queues the notification (dropping it if the queue is full).
func (s *Scheduler) Schedule(userID string, deviceID int, env api.Envelope, when time.Time) {
	if !when.After(s.now()) {
		s.deliver(userID, deviceID, env)
		return
	}
	s.mu.Lock()
	if len(s.items) >= s.cap {
		s.mu.Unlock()
		slog.Debug("notification queue full; dropping wakeup", "user", userID, "device", deviceID)
		return
	}
	heap.Push(&s.items, entry{when: when, userID: userID, deviceID: deviceID, env: env})
	s.mu.Unlock()
}

// drain delivers every notification whose release time has arrived. Exported
// only for tests and for Recover's synchronous check; the run loop drives it
// on the sweep interval.
func (s *Scheduler) drain(now time.Time) {
	s.mu.Lock()
	var due []entry
	for len(s.items) > 0 && !s.items[0].when.After(now) {
		due = append(due, heap.Pop(&s.items).(entry))
	}
	s.mu.Unlock()
	for _, e := range due {
		s.deliver(e.userID, e.deviceID, e.env)
	}
}

func (s *Scheduler) run() {
	defer close(s.done)
	t := time.NewTicker(s.sweep)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.drain(s.now())
		}
	}
}

// Close stops the sweep goroutine.
func (s *Scheduler) Close() {
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done
	})
}

// Recover re-schedules notifications for messages that were still unreleased
// at the previous shutdown (not_before > now), so a restart does not strand
// them. Pages advance a keyset cursor over (not_before, id), so the walk is
// linear in the backlog size and terminates even when the pending set does not
// drain (audit F-28). The notification queue is bounded, so an overwhelming
// backlog still drops the overflow (as with any in-process notification).
func (s *Scheduler) Recover(ctx context.Context, store PendingStore) error {
	const batch = 1000
	var afterNotBefore time.Time
	var afterID string
	for {
		msgs, err := store.PendingMessages(ctx, s.now(), afterNotBefore, afterID, batch)
		if err != nil {
			return err
		}
		if len(msgs) == 0 {
			return nil
		}
		for _, m := range msgs {
			s.Schedule(m.RecipientUserID, m.RecipientDeviceID, EnvelopeFor(m), m.NotBefore)
		}
		last := msgs[len(msgs)-1]
		afterNotBefore, afterID = last.NotBefore, last.ID
		if len(msgs) < batch {
			return nil
		}
	}
}

// EnvelopeFor converts a stored message into its wire envelope (§11).
func EnvelopeFor(m storage.Message) api.Envelope {
	return api.Envelope{
		V:            api.Version,
		ID:           m.ID,
		Recipient:    api.Recipient{UserID: m.RecipientUserID, DeviceID: m.RecipientDeviceID},
		Sealed:       m.Sealed,
		ServerTS:     m.ServerTS.UnixMilli(),
		TTLExpiresAt: m.TTLExpiresAt.UnixMilli(),
	}
}
