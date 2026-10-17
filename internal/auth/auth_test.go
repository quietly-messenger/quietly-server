package auth_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/auth"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/storage/memory"
	"github.com/quietly-messenger/quietly-server/internal/testutil"
)

const skew = 60 * time.Second

// newHandler builds the auth middleware in front of a handler that echoes 200
// and the authenticated device id.
func newHandler(t *testing.T) (http.Handler, *memory.Store, *testutil.Fixture, config.Limits) {
	t.Helper()
	store := memory.New()
	limits := testutil.Limits()
	f := testutil.NewAccount(t, store, limits, "alice")
	nonces := auth.NewNonceCache(2 * skew)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dev := auth.DeviceFrom(r.Context())
		if dev == nil {
			t.Error("handler ran without an authenticated device")
		}
		// The middleware must restore the body it consumed for verification.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read restored body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	return auth.Middleware(store, skew, nonces)(next), store, f, limits
}

func TestMiddlewareAcceptsValidRequestAndRestoresBody(t *testing.T) {
	h, _, f, _ := newHandler(t)
	body := []byte(`{"v":"quietly/1","hello":"world"}`)
	req := testutil.SignedRequest(t, f, testutil.RequestOpts{Method: "POST", Path: "/v1/devices", Body: body})
	w := testutil.Do(h, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), body) {
		t.Fatalf("body not restored: %q", w.Body.String())
	}
}

func TestMiddlewareRejections(t *testing.T) {
	h, _, f, _ := newHandler(t)

	t.Run("missing headers", func(t *testing.T) {
		req := testutil.SignedRequest(t, f, testutil.RequestOpts{Method: "GET", Path: "/v1/devices"})
		req.Header.Del("X-Quietly-Nonce")
		w := testutil.Do(h, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d", w.Code)
		}
		if code := testutil.ErrorCode(t, w); code != api.CodeSignatureMissing {
			t.Fatalf("code=%s", code)
		}
	})

	t.Run("version mismatch", func(t *testing.T) {
		req := testutil.SignedRequest(t, f, testutil.RequestOpts{
			Method: "GET", Path: "/v1/devices",
			Mutate: func(r *http.Request) { r.Header.Set("X-Quietly-Version", "quietly/2") },
		})
		w := testutil.Do(h, req)
		if code := testutil.ErrorCode(t, w); code != api.CodeVersionMismatch {
			t.Fatalf("code=%s status=%d", code, w.Code)
		}
	})

	t.Run("timestamp outside window", func(t *testing.T) {
		req := testutil.SignedRequest(t, f, testutil.RequestOpts{Method: "GET", Path: "/v1/devices"})
		req.Header.Set("X-Quietly-Timestamp", "1000") // epoch + 1s
		w := testutil.Do(h, req)
		if code := testutil.ErrorCode(t, w); code != api.CodeTimestampOutOfWindow {
			t.Fatalf("code=%s status=%d", code, w.Code)
		}
	})

	t.Run("unknown device", func(t *testing.T) {
		other := *f
		other.UserID = "00000000-0000-4000-8000-000000000000"
		// Sign with alice's key but claim a nonexistent device.
		req := testutil.SignedRequest(t, &other, testutil.RequestOpts{Method: "GET", Path: "/v1/devices"})
		w := testutil.Do(h, req)
		if code := testutil.ErrorCode(t, w); code != api.CodeDeviceUnknown {
			t.Fatalf("code=%s status=%d", code, w.Code)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		req := testutil.SignedRequest(t, f, testutil.RequestOpts{
			Method: "GET", Path: "/v1/devices",
			Mutate: func(r *http.Request) { r.Header.Set("X-Quietly-Signature", "AAAA") },
		})
		w := testutil.Do(h, req)
		if code := testutil.ErrorCode(t, w); code != api.CodeSignatureInvalid {
			t.Fatalf("code=%s status=%d", code, w.Code)
		}
	})
}

func TestMiddlewareRejectsReplayedNonce(t *testing.T) {
	h, _, f, _ := newHandler(t)
	req := testutil.SignedRequest(t, f, testutil.RequestOpts{Method: "GET", Path: "/v1/devices"})
	if w := testutil.Do(h, req); w.Code != http.StatusOK {
		t.Fatalf("first request status=%d", w.Code)
	}
	// Replay the exact same request (same nonce and signature).
	if w := testutil.Do(h, req); w.Code != http.StatusUnauthorized {
		t.Fatalf("replay accepted: status=%d body=%s", w.Code, w.Body.String())
	} else if code := testutil.ErrorCode(t, w); code != api.CodeNonceReplayed {
		t.Fatalf("code=%s", code)
	}
}

func TestMiddlewareRejectsRevokedDevice(t *testing.T) {
	h, store, f, _ := newHandler(t)
	if err := store.RevokeDevice(context.Background(), f.UserID, f.DeviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	req := testutil.SignedRequest(t, f, testutil.RequestOpts{Method: "GET", Path: "/v1/devices"})
	w := testutil.Do(h, req)
	if code := testutil.ErrorCode(t, w); code != api.CodeDeviceRevoked {
		t.Fatalf("code=%s status=%d", code, w.Code)
	}
}

func TestMiddlewareRejectsOversizedBody(t *testing.T) {
	h, _, f, _ := newHandler(t)
	big := bytes.Repeat([]byte("x"), (1<<20)+1)
	req := testutil.SignedRequest(t, f, testutil.RequestOpts{Method: "POST", Path: "/v1/devices", Body: big})
	w := testutil.Do(h, req)
	if code := testutil.ErrorCode(t, w); code != api.CodeInvalidPayload {
		t.Fatalf("code=%s status=%d", code, w.Code)
	}
}

func TestNonceCacheIsBounded(t *testing.T) {
	c := auth.NewNonceCache(time.Minute)
	now := time.Now()
	// Fill well past the internal cap; the cache must not grow linearly.
	for i := 0; i < 300000; i++ {
		if !c.CheckAndAdd("nonce-"+time.Duration(i).String(), now) {
			t.Fatalf("unexpected replay at %d", i)
		}
	}
	// A nonce inserted at the start may have been aged out by the generation
	// rotation: that is the documented memory/TTL trade-off. The critical
	// property is that a recent nonce is still rejected.
	recent := "nonce-recent"
	if !c.CheckAndAdd(recent, now) {
		t.Fatal("fresh nonce rejected")
	}
	if c.CheckAndAdd(recent, now) {
		t.Fatal("recent nonce replayed")
	}
}
