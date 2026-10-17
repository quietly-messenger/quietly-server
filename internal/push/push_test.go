package push

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/storage"
)

type fakeStore struct {
	mu      sync.Mutex
	device  *storage.Device
	cleared bool
}

func (f *fakeStore) GetDevice(context.Context, string, int) (*storage.Device, error) {
	return f.device, nil
}

func (f *fakeStore) UpdatePushEndpoint(_ context.Context, _ string, _ int, ep *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ep == nil {
		f.cleared = true
	}
	return nil
}

func (f *fakeStore) isCleared() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cleared
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestEnqueueDoesNotBlockOnFullQueue pins audit F-26: the notify path must
// never wait on the wake queue. With no worker draining it, the queue fills on
// the first call and every later call must drop instead of blocking.
func TestEnqueueDoesNotBlockOnFullQueue(t *testing.T) {
	d := &Dispatcher{queue: make(chan wake, 1)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			d.Enqueue("user", i)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Enqueue blocked on a full queue")
	}
	if len(d.queue) != 1 {
		t.Fatalf("queue length = %d, want 1 (excess wakes are dropped, not appended)", len(d.queue))
	}
}

// TestQueuedWakeIsProcessed proves the worker pool drains queued wakes and
// that per-device failure retirement still runs through it: the fake endpoint
// always fails, so one processed wake with maxFailures=1 must clear it.
func TestQueuedWakeIsProcessed(t *testing.T) {
	endpoint := "https://push.example/topic"
	st := &fakeStore{device: &storage.Device{PushEndpoint: &endpoint}}
	d := NewDispatcher(st)
	d.maxFailures = 1
	d.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("push endpoint unreachable")
	})}

	d.Enqueue("user-1", 1)

	deadline := time.Now().Add(5 * time.Second)
	for !st.isCleared() {
		if time.Now().After(deadline) {
			t.Fatal("queued wake was never processed (worker pool is not draining)")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
