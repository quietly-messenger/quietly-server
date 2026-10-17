package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

func TestBurstThenRefill(t *testing.T) {
	l := New(10, 3, 100) // 10 tokens/s, burst 3
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("burst token %d denied", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("4th request allowed before refill")
	}
	time.Sleep(150 * time.Millisecond) // ~1.5 tokens
	if !l.Allow("a") {
		t.Fatal("request denied after refill")
	}
	if l.Allow("a") {
		t.Fatal("second request allowed with <1 token available")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(1, 1, 100)
	if !l.Allow("a") {
		t.Fatal("a denied")
	}
	if l.Allow("a") {
		t.Fatal("a allowed twice")
	}
	if !l.Allow("b") {
		t.Fatal("b should have its own bucket")
	}
}

func TestEntryCountIsBounded(t *testing.T) {
	l := New(1, 1, 10)
	for i := 0; i < 1000; i++ {
		l.Allow("key-" + strconv.Itoa(i))
	}
	l.mu.Lock()
	n := len(l.entries)
	order := l.lru.Len()
	l.mu.Unlock()
	if n != 10 || order != 10 {
		t.Fatalf("entries=%d lru=%d, want 10/10 (eviction must bound memory)", n, order)
	}
}

func TestEvictionKeepsRecentKeys(t *testing.T) {
	l := New(1, 1, 2)
	l.Allow("old")
	l.Allow("middle")
	l.Allow("new") // evicts "old"
	l.mu.Lock()
	_, hasOld := l.entries["old"]
	_, hasNew := l.entries["new"]
	l.mu.Unlock()
	if hasOld {
		t.Fatal("oldest key was not evicted")
	}
	if !hasNew {
		t.Fatal("newest key was evicted")
	}
}

// TestEvictionIsLRU pins the audit F-23 hardening: a key that is still being
// used must outlive newer one-off keys, so a flood of spoofed keys cannot
// evict (and thereby reset the buckets of) active clients. Eviction is
// observed through behavior, not internals: a key whose bucket was drained
// starts a fresh burst only if it was actually evicted.
func TestEvictionIsLRU(t *testing.T) {
	l := New(0, 2, 2) // burst 2, no refill: drained buckets stay empty

	if !l.Allow("active") || !l.Allow("active") {
		t.Fatal("active key should have two burst tokens")
	}
	if l.Allow("active") {
		t.Fatal("active key should be drained")
	}
	// "oneoff" is inserted after "active", draining both of its tokens too.
	if !l.Allow("oneoff") || !l.Allow("oneoff") {
		t.Fatal("oneoff key should have two burst tokens")
	}

	// Touching "active" makes it the most recently used key; "oneoff" becomes
	// the least recently used.
	if l.Allow("active") {
		t.Fatal("drained key refilled without eviction")
	}
	// A third key forces one eviction: "oneoff", not "active".
	l.Allow("third")

	if l.Allow("active") {
		t.Fatal("active key was evicted and got a fresh burst (FIFO-style eviction)")
	}
	if !l.Allow("oneoff") {
		t.Fatal("least recently used key was not evicted (bucket did not reset)")
	}
}
