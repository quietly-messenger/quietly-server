package ws_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/transport/ws"
)

func serve(t *testing.T, hub *ws.Hub, userID string, deviceID int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hub.ServeWS(w, r, userID, deviceID)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dial(t *testing.T, srv *httptest.Server, header http.Header) (*websocket.Conn, error) {
	t.Helper()
	u := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, _, err := websocket.DefaultDialer.Dial(u, header)
	return c, err
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestNotifyFallsBackToWakeWhenOffline(t *testing.T) {
	hub := ws.NewHub(ws.Options{})
	var wakes atomic.Int32
	hub.SetWake(func(userID string, deviceID int) {
		if userID == "u1" && deviceID == 1 {
			wakes.Add(1)
		}
	})

	hub.NotifyMessage("u1", 1, api.Envelope{V: api.Version, ID: "m1"})
	if wakes.Load() != 1 {
		t.Fatalf("wake calls=%d, want 1", wakes.Load())
	}
}

func TestServeWSDeliversReplacesAndAcks(t *testing.T) {
	hub := ws.NewHub(ws.Options{PingInterval: time.Hour, IdleTimeout: time.Minute})
	var acks atomic.Int32
	hub.SetAck(func(userID string, deviceID int, id string) error {
		if userID == "u1" && deviceID == 1 && id == "env-1" {
			acks.Add(1)
		}
		return nil
	})
	srv := serve(t, hub, "u1", 1)

	first, err := dial(t, srv, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	waitFor(t, "first connection registered", func() bool { return hub.Connected("u1", 1) })

	// A message reaches the live socket.
	hub.NotifyMessage("u1", 1, api.Envelope{V: api.Version, ID: "env-1"})
	var f ws.Frame
	_ = first.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := first.ReadJSON(&f); err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if f.Type != "message" || f.Envelope == nil || f.Envelope.ID != "env-1" {
		t.Fatalf("unexpected frame: %+v", f)
	}

	// A second connection for the same device replaces the first.
	second, err := dial(t, srv, nil)
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer second.Close()
	waitFor(t, "second connection registered", func() bool { return hub.Connected("u1", 1) })
	_ = first.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := first.ReadMessage(); err == nil {
		t.Fatal("first connection was not closed by the replacement")
	}

	// Acks over the socket reach the callback.
	if err := second.WriteJSON(ws.Frame{Type: "ack", V: api.Version, ID: "env-1"}); err != nil {
		t.Fatalf("write ack: %v", err)
	}
	waitFor(t, "ack callback", func() bool { return acks.Load() == 1 })

	// Unsupported frame types get an error frame back.
	if err := second.WriteJSON(ws.Frame{Type: "bogus", V: api.Version}); err != nil {
		t.Fatalf("write bogus: %v", err)
	}
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	var errFrame ws.Frame
	if err := second.ReadJSON(&errFrame); err != nil {
		t.Fatalf("read error frame: %v", err)
	}
	if errFrame.Type != "error" || errFrame.Code != string(api.CodeInvalidPayload) {
		t.Fatalf("unexpected error frame: %+v", errFrame)
	}
}

func TestIdleTimeoutEvictsSocketAndWakes(t *testing.T) {
	hub := ws.NewHub(ws.Options{PingInterval: 50 * time.Millisecond, IdleTimeout: 150 * time.Millisecond})
	var wakes atomic.Int32
	hub.SetWake(func(string, int) { wakes.Add(1) })
	srv := serve(t, hub, "u1", 1)

	c, err := dial(t, srv, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	waitFor(t, "connection registered", func() bool { return hub.Connected("u1", 1) })

	// The client never reads or answers pings, so the server must drop it.
	waitFor(t, "idle eviction", func() bool { return !hub.Connected("u1", 1) })

	// With the socket gone, notifications fall through to the wake path.
	hub.NotifyMessage("u1", 1, api.Envelope{V: api.Version, ID: "m"})
	if wakes.Load() != 1 {
		t.Fatalf("wake calls=%d, want 1", wakes.Load())
	}
}

func TestOriginAllowList(t *testing.T) {
	hub := ws.NewHub(ws.Options{AllowedOrigins: []string{"https://app.example"}})
	srv := serve(t, hub, "u1", 1)

	// Native clients send no Origin.
	c, err := dial(t, srv, nil)
	if err != nil {
		t.Fatalf("originless dial rejected: %v", err)
	}
	c.Close()

	// Allow-listed browser origin.
	c, err = dial(t, srv, http.Header{"Origin": []string{"https://app.example"}})
	if err != nil {
		t.Fatalf("allow-listed origin rejected: %v", err)
	}
	c.Close()

	// Any other browser origin is refused (cross-site WebSocket hijacking).
	if _, err := dial(t, srv, http.Header{"Origin": []string{"https://evil.example"}}); err == nil {
		t.Fatal("foreign origin accepted")
	}

	// Default hub: always refuse browser origins.
	strict := ws.NewHub(ws.Options{})
	strictSrv := serve(t, strict, "u1", 1)
	if _, err := dial(t, strictSrv, http.Header{"Origin": []string{"https://app.example"}}); err == nil {
		t.Fatal("default hub accepted a browser origin")
	}
}

func TestMarshalFrame(t *testing.T) {
	remaining := 7
	b, err := ws.MarshalFrame(ws.Frame{Type: "prekeys_low", V: api.Version, OneTimePrekeysRemaining: &remaining})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"one_time_prekeys_remaining":7`) ||
		!strings.Contains(string(b), `"type":"prekeys_low"`) {
		t.Fatalf("frame json=%s", b)
	}
}
