package http_test

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-crypto/pow"

	"github.com/quietly-messenger/quietly-server/internal/account"
	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/auth"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/device"
	"github.com/quietly-messenger/quietly-server/internal/message"
	"github.com/quietly-messenger/quietly-server/internal/storage/memory"
	"github.com/quietly-messenger/quietly-server/internal/testutil"
	transporthttp "github.com/quietly-messenger/quietly-server/internal/transport/http"
	"github.com/quietly-messenger/quietly-server/internal/transport/ws"
)

func newRouter(t *testing.T, limits config.Limits) (http.Handler, *memory.Store) {
	t.Helper()
	store := memory.New()
	devSvc := device.New(store, limits)
	acctSvc := account.New(store, devSvc, limits)
	msgSvc := message.New(store, limits)
	hub := ws.NewHub(ws.Options{})
	srv := transporthttp.NewServer(acctSvc, devSvc, msgSvc, limits, hub)
	nonces := auth.NewNonceCache(2 * time.Minute)
	return srv.Router(store, time.Minute, nonces), store
}

// createAccountHTTP exercises POST /v1/accounts through the router.
func createAccountHTTP(t *testing.T, h http.Handler, limits config.Limits, username string) *testutil.Fixture {
	t.Helper()
	ik, reg := testutil.Registration(t, limits.DeliveryTokenBytes, 1, 2, 3)
	ts := time.Now().UnixMilli()
	body := testutil.JSONBody(t, api.AccountRequest{
		V:        api.Version,
		Username: username,
		POW:      api.POW{TimestampMs: ts, Nonce: pow.Solve(username, ts, limits.PowDifficulty)},
		Device:   reg,
	})
	req := testutil.Do(h, mustRequest(t, http.MethodPost, "/v1/accounts", body))
	if req.Code != http.StatusCreated {
		t.Fatalf("create account status=%d body=%s", req.Code, req.Body.String())
	}
	resp := testutil.Decode[api.AccountResponse](t, req)
	return &testutil.Fixture{UserID: resp.UserID, DeviceID: resp.DeviceID, Keys: ik, Token: reg.DeliveryToken, Reg: reg}
}

func TestEndToEndAccountDeviceMessageFlow(t *testing.T) {
	limits := testutil.Limits()
	h, store := newRouter(t, limits)

	alice := createAccountHTTP(t, h, limits, "alice")
	bob := testutil.NewAccount(t, store, limits, "bob")

	// pow-params.
	w := testutil.Do(h, mustRequest(t, http.MethodGet, "/v1/accounts/pow-params", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("pow-params status=%d", w.Code)
	}

	// Username lookup (authenticated).
	w = testutil.Do(h, testutil.SignedRequest(t, alice, testutil.RequestOpts{
		Method: http.MethodGet, Path: "/v1/users/bob",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("lookup status=%d body=%s", w.Code, w.Body.String())
	}
	if got := testutil.Decode[api.UserResponse](t, w); got.UserID != bob.UserID {
		t.Fatalf("lookup user_id=%s want %s", got.UserID, bob.UserID)
	}

	// Device list.
	w = testutil.Do(h, testutil.SignedRequest(t, alice, testutil.RequestOpts{
		Method: http.MethodGet, Path: "/v1/devices",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("list devices status=%d", w.Code)
	}
	if got := testutil.Decode[api.DevicesResponse](t, w); len(got.Devices) != 1 {
		t.Fatalf("devices=%v", got.Devices)
	}

	// Bundle fetch: consumes a prekey, then is idempotent for the same pair.
	bundlePath := "/v1/devices/" + bob.UserID + "/1/prekey-bundle"
	w = testutil.Do(h, testutil.SignedRequest(t, alice, testutil.RequestOpts{
		Method: http.MethodGet, Path: bundlePath,
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("bundle status=%d body=%s", w.Code, w.Body.String())
	}
	first := testutil.Decode[api.BundleResponse](t, w)
	if first.OneTimePrekey == nil {
		t.Fatal("bundle had no one-time prekey")
	}
	w = testutil.Do(h, testutil.SignedRequest(t, alice, testutil.RequestOpts{
		Method: http.MethodGet, Path: bundlePath,
	}))
	again := testutil.Decode[api.BundleResponse](t, w)
	if again.OneTimePrekey == nil || again.OneTimePrekey.ID != first.OneTimePrekey.ID {
		t.Fatalf("bundle fetch not idempotent: %v vs %v", again.OneTimePrekey, first.OneTimePrekey)
	}

	// Submit a message to bob using his delivery token (unauthenticated).
	submit := testutil.JSONBody(t, api.MessageSubmit{
		V:         api.Version,
		Recipient: api.Recipient{UserID: bob.UserID, DeviceID: bob.DeviceID},
		Sealed:    []byte("sealed-bytes"),
	})
	req := mustRequest(t, http.MethodPost, "/v1/messages", submit)
	req.Header.Set("X-Quietly-Version", api.Version)
	req.Header.Set("X-Quietly-Delivery-Token", string(bob.Token))
	w = testutil.Do(h, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit status=%d body=%s", w.Code, w.Body.String())
	}
	submitted := testutil.Decode[api.MessageSubmitResponse](t, w)

	// Bob fetches and acks.
	w = testutil.Do(h, testutil.SignedRequest(t, bob, testutil.RequestOpts{
		Method: http.MethodGet, Path: "/v1/messages",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("fetch status=%d", w.Code)
	}
	fetched := testutil.Decode[api.MessagesResponse](t, w)
	if len(fetched.Messages) != 1 || fetched.Messages[0].ID != submitted.ID {
		t.Fatalf("fetched=%+v", fetched.Messages)
	}

	w = testutil.Do(h, testutil.SignedRequest(t, bob, testutil.RequestOpts{
		Method: http.MethodPost, Path: "/v1/messages/" + submitted.ID + "/ack",
	}))
	if w.Code != http.StatusNoContent {
		t.Fatalf("ack status=%d body=%s", w.Code, w.Body.String())
	}
	w = testutil.Do(h, testutil.SignedRequest(t, bob, testutil.RequestOpts{
		Method: http.MethodGet, Path: "/v1/messages",
	}))
	if got := testutil.Decode[api.MessagesResponse](t, w); len(got.Messages) != 0 {
		t.Fatalf("messages after ack: %+v", got.Messages)
	}
}

func TestHandlerRejections(t *testing.T) {
	limits := testutil.Limits()
	h, store := newRouter(t, limits)

	t.Run("body version mismatch", func(t *testing.T) {
		alice := testutil.NewAccount(t, store, limits, "alice")
		body := testutil.JSONBody(t, api.DeviceRequest{V: "quietly/2"})
		w := testutil.Do(h, testutil.SignedRequest(t, alice, testutil.RequestOpts{
			Method: http.MethodPost, Path: "/v1/devices", Body: body,
		}))
		if code := testutil.ErrorCode(t, w); code != api.CodeVersionMismatch {
			t.Fatalf("code=%s status=%d body=%s", code, w.Code, w.Body.String())
		}
	})

	t.Run("missing body version is a mismatch", func(t *testing.T) {
		alice := testutil.NewAccount(t, store, limits, "alice2")
		body := []byte(`{"one_time_prekeys":[]}`)
		w := testutil.Do(h, testutil.SignedRequest(t, alice, testutil.RequestOpts{
			Method: http.MethodPost, Path: "/v1/devices/" + itoa(alice.DeviceID) + "/prekeys", Body: body,
		}))
		if code := testutil.ErrorCode(t, w); code != api.CodeVersionMismatch {
			t.Fatalf("code=%s status=%d", code, w.Code)
		}
	})

	t.Run("oversized content-length", func(t *testing.T) {
		alice := testutil.NewAccount(t, store, limits, "alice3")
		body := testutil.JSONBody(t, api.DeviceRequest{V: api.Version})
		req := testutil.SignedRequest(t, alice, testutil.RequestOpts{
			Method: http.MethodPost, Path: "/v1/devices", Body: body,
		})
		req.ContentLength = (1 << 20) + 1
		w := testutil.Do(h, req)
		if code := testutil.ErrorCode(t, w); code != api.CodePayloadTooLarge {
			t.Fatalf("code=%s status=%d", code, w.Code)
		}
	})

	t.Run("push endpoint must be https and public", func(t *testing.T) {
		alice := testutil.NewAccount(t, store, limits, "alice4")
		for _, endpoint := range []string{
			"http://ntfy.example/abc",
			"https://127.0.0.1/x",
			"https://169.254.169.254/latest/meta-data/",
			"https://localhost:8080/x",
			"https://user:pass@ntfy.example/x",
		} {
			body := testutil.JSONBody(t, api.PushEndpointUpdate{V: api.Version, Endpoint: endpoint})
			w := testutil.Do(h, testutil.SignedRequest(t, alice, testutil.RequestOpts{
				Method: http.MethodPut, Path: "/v1/devices/" + itoa(alice.DeviceID) + "/push-endpoint", Body: body,
			}))
			if code := testutil.ErrorCode(t, w); code != api.CodeInvalidPayload {
				t.Fatalf("endpoint %q: code=%s status=%d", endpoint, code, w.Code)
			}
		}
		good := testutil.JSONBody(t, api.PushEndpointUpdate{V: api.Version, Endpoint: "https://ntfy.example/abc123"})
		w := testutil.Do(h, testutil.SignedRequest(t, alice, testutil.RequestOpts{
			Method: http.MethodPut, Path: "/v1/devices/" + itoa(alice.DeviceID) + "/push-endpoint", Body: good,
		}))
		if w.Code != http.StatusOK {
			t.Fatalf("valid endpoint status=%d body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("cannot act on another device id", func(t *testing.T) {
		alice := testutil.NewAccount(t, store, limits, "alice5")
		body := testutil.JSONBody(t, api.PrekeysRequest{V: api.Version})
		w := testutil.Do(h, testutil.SignedRequest(t, alice, testutil.RequestOpts{
			Method: http.MethodPost, Path: "/v1/devices/" + itoa(alice.DeviceID+1) + "/prekeys", Body: body,
		}))
		if code := testutil.ErrorCode(t, w); code != api.CodeForbidden {
			t.Fatalf("code=%s status=%d", code, w.Code)
		}
	})
}

func TestPerIPRateLimit(t *testing.T) {
	limits := testutil.Limits()
	limits.RequestsPerMinute = 2
	h, _ := newRouter(t, limits)

	for i := 0; i < 3; i++ {
		w := testutil.Do(h, mustRequest(t, http.MethodGet, "/v1/accounts/pow-params", nil))
		if i < 2 && w.Code != http.StatusOK {
			t.Fatalf("request %d status=%d", i, w.Code)
		}
		if w.Code == http.StatusTooManyRequests {
			if w.Header().Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
			if code := testutil.ErrorCode(t, w); code != api.CodeRateLimited {
				t.Fatalf("code=%s", code)
			}
			return
		}
	}
	t.Fatal("third request was not rate limited")
}

func mustRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, path, r)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return req
}

func itoa(n int) string { return strconv.Itoa(n) }
