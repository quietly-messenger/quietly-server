package message_test

import (
	"context"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/message"
	"github.com/quietly-messenger/quietly-server/internal/storage/memory"
	"github.com/quietly-messenger/quietly-server/internal/testutil"
)

func newFixture(t *testing.T) (*memory.Store, *message.Service, config.Limits, *testutil.Fixture, *testutil.Fixture) {
	t.Helper()
	store := memory.New()
	limits := testutil.Limits()
	alice := testutil.NewAccount(t, store, limits, "alice")
	bob := testutil.NewAccount(t, store, limits, "bob")
	return store, message.New(store, limits), limits, alice, bob
}

func TestSubmitValidatesPayload(t *testing.T) {
	_, svc, limits, alice, _ := newFixture(t)
	ctx := context.Background()

	_, err := svc.Submit(ctx, api.MessageSubmit{
		V:         api.Version,
		Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.DeviceID},
		Sealed:    nil,
	}, alice.Token, time.Now())
	if code := errCode(t, err); code != api.CodeInvalidPayload {
		t.Fatalf("empty sealed: code=%q err=%v", code, err)
	}

	_, err = svc.Submit(ctx, api.MessageSubmit{
		V:         api.Version,
		Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.DeviceID},
		Sealed:    make([]byte, limits.SealedBlobMax+1),
	}, alice.Token, time.Now())
	if code := errCode(t, err); code != api.CodePayloadTooLarge {
		t.Fatalf("oversized sealed: code=%q err=%v", code, err)
	}

	_, err = svc.Submit(ctx, api.MessageSubmit{
		V:         api.Version,
		Recipient: api.Recipient{UserID: "not-a-uuid", DeviceID: 1},
		Sealed:    make([]byte, 32),
	}, alice.Token, time.Now())
	if code := errCode(t, err); code != api.CodeDeliveryRejected {
		t.Fatalf("bad recipient uuid: code=%q err=%v", code, err)
	}
}

// TestSubmitCollapsesRecipientFailures is the §12.13 anti-oracle requirement:
// wrong token, unknown user, unknown device, and revoked device must all look
// identical — same code (and HTTP status) with no distinguishing detail.
func TestSubmitCollapsesRecipientFailures(t *testing.T) {
	store, svc, _, alice, _ := newFixture(t)
	ctx := context.Background()

	if err := store.RevokeDevice(ctx, alice.UserID, alice.DeviceID); err != nil {
		t.Fatal(err)
	}

	type probe struct {
		name  string
		req   api.MessageSubmit
		token []byte
	}
	probes := []probe{
		{"wrong token", api.MessageSubmit{
			V:         api.Version,
			Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.DeviceID},
			Sealed:    make([]byte, 32),
		}, make([]byte, len(alice.Token))},
		{"unknown user", api.MessageSubmit{
			V:         api.Version,
			Recipient: api.Recipient{UserID: "00000000-0000-4000-8000-000000000000", DeviceID: 1},
			Sealed:    make([]byte, 32),
		}, alice.Token},
		{"unknown device", api.MessageSubmit{
			V:         api.Version,
			Recipient: api.Recipient{UserID: alice.UserID, DeviceID: 9},
			Sealed:    make([]byte, 32),
		}, alice.Token},
		{"revoked device", api.MessageSubmit{
			V:         api.Version,
			Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.DeviceID},
			Sealed:    make([]byte, 32),
		}, alice.Token},
	}

	var codes []api.ErrorCode
	var messages []string
	for _, p := range probes {
		_, err := svc.Submit(ctx, p.req, p.token, time.Now())
		ae := api.AsAPIError(err)
		if ae == nil {
			t.Fatalf("%s: expected delivery_rejected, got %v", p.name, err)
		}
		if ae.Code != api.CodeDeliveryRejected {
			t.Fatalf("%s: code=%q, want delivery_rejected", p.name, ae.Code)
		}
		codes = append(codes, ae.Code)
		messages = append(messages, ae.Error())
	}
	for i := range messages {
		if messages[i] != messages[0] {
			t.Fatalf("failure messages differ (oracle): %q vs %q", messages[i], messages[0])
		}
	}
}

func TestNotBefore(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

	if got := message.NotBefore(now, 0, nil); !got.Equal(now) {
		t.Fatalf("NotBefore(0) = %v, want %v", got, now)
	}
	if got := message.NotBefore(now, -5, nil); !got.Equal(now) {
		t.Fatalf("NotBefore(-5) = %v, want %v", got, now)
	}
	full := func(n int) int { return n - 1 } // max of [0, jitterMs]
	if got := message.NotBefore(now, 1000, full); !got.Equal(now.Add(time.Second)) {
		t.Fatalf("NotBefore(full) = %v, want %v", got, now.Add(time.Second))
	}
	zero := func(n int) int { return 0 }
	if got := message.NotBefore(now, 1000, zero); !got.Equal(now) {
		t.Fatalf("NotBefore(zero) = %v, want %v", got, now)
	}
}

func TestFetchDefaultsTo100AndCapsAtMax(t *testing.T) {
	_, svc, limits, alice, _ := newFixture(t)
	ctx := context.Background()
	base := time.Now()

	for i := 0; i < 105; i++ {
		if _, err := svc.Submit(ctx, api.MessageSubmit{
			V:         api.Version,
			Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.DeviceID},
			Sealed:    make([]byte, 16),
		}, alice.Token, base.Add(time.Duration(i-105)*time.Millisecond)); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}

	// No limit: §12.14 default of 100, with remaining=1 signalling more.
	resp, err := svc.Fetch(ctx, alice.UserID, alice.DeviceID, time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 100 {
		t.Fatalf("default fetch returned %d, want 100", len(resp.Messages))
	}
	if resp.Remaining != 1 {
		t.Fatalf("remaining=%d, want 1", resp.Remaining)
	}
	// Messages are oldest first.
	if resp.Messages[0].ServerTS >= resp.Messages[99].ServerTS {
		t.Fatal("messages not ordered oldest first")
	}

	// Above fetch_limit_max is clamped, not an error.
	resp, err = svc.Fetch(ctx, alice.UserID, alice.DeviceID, time.Now(), limits.FetchLimitMax+1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 105 {
		t.Fatalf("clamped fetch returned %d, want 105", len(resp.Messages))
	}

	// Explicit limit is honored.
	resp, err = svc.Fetch(ctx, alice.UserID, alice.DeviceID, time.Now(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Messages) != 3 || resp.Remaining != 1 {
		t.Fatalf("limit fetch: n=%d remaining=%d", len(resp.Messages), resp.Remaining)
	}
}

func TestAckIsIdempotentAndScopedToRecipient(t *testing.T) {
	store, svc, _, alice, bob := newFixture(t)
	ctx := context.Background()

	m, err := svc.Submit(ctx, api.MessageSubmit{
		V:         api.Version,
		Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.DeviceID},
		Sealed:    make([]byte, 32),
	}, alice.Token, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Bob cannot ack Alice's message.
	err = svc.Ack(ctx, bob.UserID, bob.DeviceID, m.ID)
	if code := errCode(t, err); code != api.CodeForbidden {
		t.Fatalf("foreign ack: code=%q err=%v", code, err)
	}

	// Alice acks: ok, and acking again is still ok (idempotent).
	if err := svc.Ack(ctx, alice.UserID, alice.DeviceID, m.ID); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if err := svc.Ack(ctx, alice.UserID, alice.DeviceID, m.ID); err != nil {
		t.Fatalf("re-ack: %v", err)
	}
	// Unknown id is also fine.
	if err := svc.Ack(ctx, alice.UserID, alice.DeviceID, "01JQ8Z4K7VXN2M9P0T3RWY6C5B"); err != nil {
		t.Fatalf("ack unknown: %v", err)
	}

	list, err := store.ListMessages(ctx, alice.UserID, alice.DeviceID, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("message survived ack: %v", list)
	}
}

func TestDeleteExpiredMessages(t *testing.T) {
	store, svc, limits, alice, _ := newFixture(t)
	ctx := context.Background()

	if _, err := svc.Submit(ctx, api.MessageSubmit{
		V:         api.Version,
		Recipient: api.Recipient{UserID: alice.UserID, DeviceID: alice.DeviceID},
		Sealed:    make([]byte, 32),
	}, alice.Token, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Nothing expired yet.
	if n, err := store.DeleteExpiredMessages(ctx, time.Now()); err != nil || n != 0 {
		t.Fatalf("early cleanup n=%d err=%v", n, err)
	}
	// Past the TTL: deleted.
	future := time.Now().Add(time.Duration(limits.MessageTTLDays+1) * 24 * time.Hour)
	n, err := store.DeleteExpiredMessages(ctx, future)
	if err != nil || n != 1 {
		t.Fatalf("cleanup n=%d err=%v, want 1", n, err)
	}
}

func errCode(t *testing.T, err error) api.ErrorCode {
	t.Helper()
	if err == nil {
		return ""
	}
	if ae := api.AsAPIError(err); ae != nil {
		return ae.Code
	}
	t.Fatalf("non-API error: %v", err)
	return ""
}
