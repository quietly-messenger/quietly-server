// Package testutil builds signed requests, accounts, and devices for tests.
// It is imported only by _test files.
package testutil

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	qcauth "github.com/quietly-messenger/quietly-crypto/auth"
	"github.com/quietly-messenger/quietly-crypto/cryptocore"
	"github.com/quietly-messenger/quietly-crypto/identity"
	"github.com/quietly-messenger/quietly-crypto/pow"

	"github.com/quietly-messenger/quietly-server/internal/account"
	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/device"
	"github.com/quietly-messenger/quietly-server/internal/message"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

// Limits returns §15 defaults with a trivial PoW so tests stay fast.
func Limits() config.Limits {
	l := config.DefaultLimits()
	l.PowDifficulty = 4
	return l
}

// Fixture is a registered account/device with the private keys a test client
// would hold.
type Fixture struct {
	UserID   string
	DeviceID int
	Keys     *identity.IdentityKeys
	Token    []byte
	Reg      api.DeviceRegistration
}

// Registration builds a correctly signed device registration with the given
// one-time-prekey ids.
func Registration(t *testing.T, tokenBytes int, prekeyIDs ...uint32) (*identity.IdentityKeys, api.DeviceRegistration) {
	t.Helper()
	ik, err := identity.GenerateIdentityKeys()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	spk, err := cryptocore.GeneratePreKey()
	if err != nil {
		t.Fatalf("generate spk: %v", err)
	}
	binding, err := identity.SignIdentityBinding(ik.SigPriv, ik.DHPub)
	if err != nil {
		t.Fatalf("sign binding: %v", err)
	}
	spkSig, err := identity.SignSignedPreKey(ik.SigPriv, 1, spk.PublicKey)
	if err != nil {
		t.Fatalf("sign spk: %v", err)
	}
	token := make([]byte, tokenBytes)
	if err := cryptocore.RandomBytes(token); err != nil {
		t.Fatalf("token: %v", err)
	}
	reg := api.DeviceRegistration{
		IdentityKeyDH:   ik.DHPub,
		IdentityKeySig:  ik.SigPub,
		IdentityBinding: binding,
		SignedPreKey: api.SignedPreKey{
			ID:        1,
			PublicKey: spk.PublicKey,
			Signature: spkSig,
		},
		DeliveryToken: token,
	}
	for _, id := range prekeyIDs {
		pk, err := cryptocore.GeneratePreKey()
		if err != nil {
			t.Fatalf("generate prekey: %v", err)
		}
		reg.OneTimePrekeys = append(reg.OneTimePrekeys, api.PreKey{ID: id, PublicKey: pk.PublicKey})
	}
	return ik, reg
}

// NewAccount creates an account through the real service path (PoW included)
// and returns the fixture.
func NewAccount(t *testing.T, store storage.Store, limits config.Limits, username string, prekeyIDs ...uint32) *Fixture {
	t.Helper()
	if len(prekeyIDs) == 0 {
		prekeyIDs = []uint32{1, 2, 3, 4, 5}
	}
	svc := account.New(store, device.New(store, limits), limits)
	ik, reg := Registration(t, limits.DeliveryTokenBytes, prekeyIDs...)
	ts := time.Now().UnixMilli()
	resp, err := svc.Create(context.Background(), api.AccountRequest{
		V:        api.Version,
		Username: username,
		POW:      api.POW{TimestampMs: ts, Nonce: pow.Solve(username, ts, limits.PowDifficulty)},
		Device:   reg,
	})
	if err != nil {
		t.Fatalf("create account %q: %v", username, err)
	}
	return &Fixture{UserID: resp.UserID, DeviceID: resp.DeviceID, Keys: ik, Token: reg.DeliveryToken, Reg: reg}
}

// AddDevice registers an additional device for an existing account.
func AddDevice(t *testing.T, store storage.Store, limits config.Limits, userID string, prekeyIDs ...uint32) *Fixture {
	t.Helper()
	if len(prekeyIDs) == 0 {
		prekeyIDs = []uint32{1, 2, 3}
	}
	svc := device.New(store, limits)
	ik, reg := Registration(t, limits.DeliveryTokenBytes, prekeyIDs...)
	resp, err := svc.Create(context.Background(), userID, reg)
	if err != nil {
		t.Fatalf("add device: %v", err)
	}
	return &Fixture{UserID: userID, DeviceID: resp.DeviceID, Keys: ik, Token: reg.DeliveryToken, Reg: reg}
}

// NewMessageService builds a message service for a store.
func NewMessageService(store storage.Store, limits config.Limits) *message.Service {
	return message.New(store, limits)
}

// JSONBody marshals v, failing the test on error.
func JSONBody(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return b
}

// RequestOpts carries the fields of a signed request.
type RequestOpts struct {
	Method string
	Path   string // includes query string
	Body   []byte
	// Mutate runs after headers are set, so tests can corrupt one of them.
	Mutate func(*http.Request)
}

// SignedRequest builds a device-authenticated request with a fresh
// timestamp/nonce, or a deliberately broken one when Mutate is set.
func SignedRequest(t *testing.T, f *Fixture, o RequestOpts) *http.Request {
	t.Helper()
	req := httptest.NewRequest(o.Method, o.Path, bytes.NewReader(o.Body))
	ts := time.Now().UnixMilli()
	nonce, err := qcauth.NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	sig, err := qcauth.SignRequest(f.Keys.SigPriv, o.Method, o.Path, ts, nonce, o.Body)
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}
	req.Header.Set("X-Quietly-Version", api.Version)
	req.Header.Set("X-Quietly-Device", f.UserID+"."+itoa(f.DeviceID))
	req.Header.Set("X-Quietly-Timestamp", itoa64(ts))
	req.Header.Set("X-Quietly-Nonce", nonce)
	req.Header.Set("X-Quietly-Signature", b64(sig))
	if o.Mutate != nil {
		o.Mutate(req)
	}
	return req
}

// Do runs a request through a handler and returns the recorder.
func Do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// Decode unmarshals a response body into T.
func Decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %T: %v (body %q)", out, err, w.Body.String())
	}
	return out
}

// ErrorCode extracts the §14 error code from a recorder.
func ErrorCode(t *testing.T, w *httptest.ResponseRecorder) api.ErrorCode {
	t.Helper()
	return Decode[api.ErrorResponse](t, w).Code
}

func itoa(n int) string { return strconv.Itoa(n) }

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
