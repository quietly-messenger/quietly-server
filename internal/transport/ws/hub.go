// Package ws implements the realtime delivery channel (PROTOCOL.md §13).
package ws

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/quietly-messenger/quietly-server/internal/api"
)

const (
	// writeTimeout bounds a single frame write (audit F-08).
	writeTimeout = 10 * time.Second
	// readLimit bounds a client→server frame; §13.2 frames are tiny.
	readLimit = 8 << 10
)

// Options configures the connection lifecycle (PROTOCOL.md §15:
// ws_ping_interval_s, ws_idle_timeout_s).
type Options struct {
	PingInterval   time.Duration // server control-ping cadence
	IdleTimeout    time.Duration // close after this long without traffic
	AllowedOrigins []string      // browser Origin allow-list; empty = native clients only
}

func (o Options) withDefaults() Options {
	if o.PingInterval <= 0 {
		o.PingInterval = 30 * time.Second
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 90 * time.Second
	}
	return o
}

// Frame is a server→client or client→server WebSocket message (§13.2).
type Frame struct {
	Type                    string        `json:"type"`
	V                       string        `json:"v"`
	Envelope                *api.Envelope `json:"envelope,omitempty"`
	OneTimePrekeysRemaining *int          `json:"one_time_prekeys_remaining,omitempty"`
	Code                    string        `json:"code,omitempty"`
	Message                 string        `json:"message,omitempty"`
	ID                      string        `json:"id,omitempty"`
}

type key struct {
	userID   string
	deviceID int
}

type conn struct {
	ws  *websocket.Conn
	hub *Hub
	k   key
	mu  sync.Mutex
}

func (c *conn) write(f Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := c.ws.WriteJSON(f); err != nil {
		// The socket is dead: evict it so the next notification falls through
		// to the push-wakeup path (audit F-08).
		c.hub.evict(c.k, c)
		return err
	}
	return nil
}

// Hub routes frames to connected devices.
type Hub struct {
	mu       sync.Mutex
	conns    map[key]*conn
	upgrader websocket.Upgrader
	opts     Options
	ack      func(userID string, deviceID int, id string) error
	wake     func(userID string, deviceID int)
}

// NewHub builds an empty hub.
func NewHub(opts Options) *Hub {
	opts = opts.withDefaults()
	return &Hub{
		conns: map[key]*conn{},
		opts:  opts,
		upgrader: websocket.Upgrader{
			CheckOrigin: checkOrigin(opts.AllowedOrigins),
		},
	}
}

// checkOrigin accepts native clients (which send no Origin header) and any
// browser origin on the allow-list (audit F-18).
func checkOrigin(allowed []string) func(*http.Request) bool {
	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		origin = strings.TrimRight(origin, "/")
		for _, a := range allowed {
			if strings.EqualFold(origin, strings.TrimRight(a, "/")) {
				return true
			}
		}
		return false
	}
}

// SetAck wires the message-ack callback (so an ack frame over the socket is
// equivalent to POST /v1/messages/{id}/ack).
func (h *Hub) SetAck(fn func(userID string, deviceID int, id string) error) {
	h.ack = fn
}

// SetWake wires the push-wakeup callback, invoked when a frame is targeted at a
// device with no live socket (PROTOCOL.md §13.3).
func (h *Hub) SetWake(fn func(userID string, deviceID int)) {
	h.wake = fn
}

// Connected reports whether a device has a live socket.
func (h *Hub) Connected(userID string, deviceID int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[key{userID: userID, deviceID: deviceID}] != nil
}

func (h *Hub) evict(k key, c *conn) {
	h.mu.Lock()
	if h.conns[k] == c {
		delete(h.conns, k)
	}
	h.mu.Unlock()
}

// ServeWS upgrades the connection and runs the read loop for an authenticated
// device.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request, userID string, deviceID int) {
	c, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	k := key{userID: userID, deviceID: deviceID}
	cn := &conn{ws: c, hub: h, k: k}

	c.SetReadLimit(readLimit)
	_ = c.SetReadDeadline(time.Now().Add(h.opts.IdleTimeout))
	c.SetPongHandler(func(string) error {
		return c.SetReadDeadline(time.Now().Add(h.opts.IdleTimeout))
	})

	h.mu.Lock()
	old := h.conns[k]
	h.conns[k] = cn
	h.mu.Unlock()
	if old != nil {
		// One live socket per device: retire the previous one instead of
		// leaking its read loop (audit F-08).
		_ = old.ws.Close()
	}

	done := make(chan struct{})
	go func() {
		t := time.NewTicker(h.opts.PingInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				// Control ping (not a JSON frame): keeps the peer and any
				// middlebox alive and drives the pong handler above.
				if err := c.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout)); err != nil {
					_ = c.Close()
					return
				}
			}
		}
	}()

	defer close(done)
	defer func() {
		h.evict(k, cn)
		_ = c.Close()
	}()

	for {
		var f Frame
		if err := c.ReadJSON(&f); err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(h.opts.IdleTimeout))
		switch f.Type {
		case "ping":
			_ = cn.write(Frame{Type: "pong", V: api.Version})
		case "pong":
			// Control-frame pongs are handled by the pong handler; tolerate a
			// redundant JSON one.
		case "ack":
			if h.ack != nil && f.ID != "" {
				if err := h.ack(userID, deviceID, f.ID); err != nil {
					slog.Debug("ws ack failed", "error", err)
				}
			}
		default:
			_ = cn.write(Frame{
				Type:    "error",
				V:       api.Version,
				Code:    string(api.CodeInvalidPayload),
				Message: "unsupported frame type",
			})
		}
	}
}

// NotifyMessage sends a message envelope to a connected device, or triggers a
// push wakeup if the device is offline or its socket just failed (audit F-08).
func (h *Hub) NotifyMessage(userID string, deviceID int, env api.Envelope) {
	h.mu.Lock()
	c := h.conns[key{userID: userID, deviceID: deviceID}]
	h.mu.Unlock()
	if c != nil {
		if err := c.write(Frame{Type: "message", V: api.Version, Envelope: &env}); err == nil {
			return
		}
	}
	if h.wake != nil {
		h.wake(userID, deviceID)
	}
}

// NotifyPrekeysLow sends a prekeys_low frame to a connected device (§7.2.1).
func (h *Hub) NotifyPrekeysLow(userID string, deviceID int, remaining int) {
	h.mu.Lock()
	c := h.conns[key{userID: userID, deviceID: deviceID}]
	h.mu.Unlock()
	if c == nil {
		return
	}
	_ = c.write(Frame{Type: "prekeys_low", V: api.Version, OneTimePrekeysRemaining: &remaining})
}

// NotifySPKRotate nudges a connected device whose signed prekey is older than
// spk_rotation_days (§7.2.1 mitigation 4, audit F-02).
func (h *Hub) NotifySPKRotate(userID string, deviceID int) {
	h.mu.Lock()
	c := h.conns[key{userID: userID, deviceID: deviceID}]
	h.mu.Unlock()
	if c == nil {
		return
	}
	_ = c.write(Frame{Type: "spk_rotate", V: api.Version})
}

// MarshalFrame encodes a frame for tests.
func MarshalFrame(f Frame) ([]byte, error) { return json.Marshal(f) }
