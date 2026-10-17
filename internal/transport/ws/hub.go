// Package ws implements the realtime delivery channel (PROTOCOL.md §13).
package ws

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/quietly-messenger/quietly-server/internal/api"
)

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
	ws *websocket.Conn
	mu sync.Mutex
}

func (c *conn) write(f Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.WriteJSON(f)
}

// Hub routes frames to connected devices.
type Hub struct {
	mu       sync.Mutex
	conns    map[key]*conn
	upgrader websocket.Upgrader
	ack      func(userID string, deviceID int, id string) error
	wake     func(userID string, deviceID int)
}

// NewHub builds an empty hub.
func NewHub() *Hub {
	return &Hub{
		conns: map[key]*conn{},
		upgrader: websocket.Upgrader{
			CheckOrigin: func(*http.Request) bool { return true },
		},
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

// ServeWS upgrades the connection and runs the read loop for an authenticated
// device.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request, userID string, deviceID int) {
	c, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	k := key{userID: userID, deviceID: deviceID}
	cn := &conn{ws: c}

	h.mu.Lock()
	h.conns[k] = cn
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		if h.conns[k] == cn {
			delete(h.conns, k)
		}
		h.mu.Unlock()
		_ = c.Close()
	}()

	for {
		var f Frame
		if err := c.ReadJSON(&f); err != nil {
			return
		}
		switch f.Type {
		case "ping":
			_ = cn.write(Frame{Type: "pong", V: api.Version})
		case "ack":
			if h.ack != nil && f.ID != "" {
				if err := h.ack(userID, deviceID, f.ID); err != nil {
					slog.Debug("ws ack failed", "error", err)
				}
			}
		}
	}
}

// NotifyMessage sends a message envelope to a connected device, or triggers a
// push wakeup if the device is offline.
func (h *Hub) NotifyMessage(userID string, deviceID int, env api.Envelope) {
	h.mu.Lock()
	c := h.conns[key{userID: userID, deviceID: deviceID}]
	h.mu.Unlock()
	if c == nil {
		if h.wake != nil {
			h.wake(userID, deviceID)
		}
		return
	}
	_ = c.write(Frame{Type: "message", V: api.Version, Envelope: &env})
}

// NotifyPrekeysLow sends a prekeys_low frame to a connected device.
func (h *Hub) NotifyPrekeysLow(userID string, deviceID int, remaining int) {
	h.mu.Lock()
	c := h.conns[key{userID: userID, deviceID: deviceID}]
	h.mu.Unlock()
	if c == nil {
		return
	}
	_ = c.write(Frame{Type: "prekeys_low", V: api.Version, OneTimePrekeysRemaining: &remaining})
}

// MarshalFrame encodes a frame for tests.
func MarshalFrame(f Frame) ([]byte, error) { return json.Marshal(f) }
