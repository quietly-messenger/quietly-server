// Package http wires the HTTP routes to the domain services.
package http

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/quietly-messenger/quietly-server/internal/account"
	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/auth"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/device"
	"github.com/quietly-messenger/quietly-server/internal/message"
	"github.com/quietly-messenger/quietly-server/internal/push"
	"github.com/quietly-messenger/quietly-server/internal/ratelimit"
	"github.com/quietly-messenger/quietly-server/internal/storage"
	"github.com/quietly-messenger/quietly-server/internal/transport/ws"
)

// Server bundles the domain services and configuration for the HTTP handlers.
type Server struct {
	accounts       *account.Service
	devices        *device.Service
	messages       *message.Service
	limits         config.Limits
	hub            *ws.Hub
	notify         Notifier
	ipLimiter      *ratelimit.Limiter
	bundleLimiter  *ratelimit.Limiter
	trustedProxies []*net.IPNet
}

// Notifier delivers a message notification no earlier than `when`. A nil
// Notifier (in tests) means immediate delivery via the hub.
type Notifier func(userID string, deviceID int, env api.Envelope, when time.Time)

// NewServer builds the handler bundle. trustedProxies lists the peers whose
// X-Forwarded-For header may be honored for rate-limit keying (empty: never).
// notify (may be nil) receives each message notification with its release
// time; it defaults to immediate hub delivery.
func NewServer(accounts *account.Service, devices *device.Service, messages *message.Service, limits config.Limits, hub *ws.Hub, notify Notifier, trustedProxies []*net.IPNet) *Server {
	if notify == nil {
		notify = func(userID string, deviceID int, env api.Envelope, _ time.Time) {
			hub.NotifyMessage(userID, deviceID, env)
		}
	}
	return &Server{
		accounts:       accounts,
		devices:        devices,
		messages:       messages,
		limits:         limits,
		hub:            hub,
		notify:         notify,
		ipLimiter:      ratelimit.New(float64(limits.RequestsPerMinute)/60.0, limits.RequestsPerMinute, 10000),
		bundleLimiter:  ratelimit.New(float64(limits.BundleFetchPerHour)/3600.0, limits.BundleFetchPerHour, 10000),
		trustedProxies: trustedProxies,
	}
}

// Router builds the chi router with all routes and middleware.
func (s *Server) Router(store auth.DeviceStore, authSkew time.Duration, nonces *auth.NonceCache) http.Handler {
	r := chi.NewRouter()
	authMW := auth.Middleware(store, authSkew, nonces)
	r.Use(s.rateLimit)

	r.Route("/v1", func(r chi.Router) {
		r.Get("/accounts/pow-params", s.powParams)
		r.Post("/accounts", s.createAccount)

		// Device-authenticated routes.
		r.Group(func(r chi.Router) {
			r.Use(authMW)
			r.Post("/devices", s.registerDevice)
			r.Get("/devices", s.listDevices)
			r.Delete("/devices/{device_id}", s.revokeDevice)
			r.Get("/users/{username}", s.lookupUser)
			r.Get("/devices/{user_id}/{device_id}/prekey-bundle", s.preKeyBundle)
			r.Get("/devices/{user_id}/{device_id}/delivery-token", s.deliveryToken)
			r.Post("/devices/{device_id}/prekeys", s.addPreKeys)
			r.Put("/devices/{device_id}/signed-prekey", s.updateSignedPreKey)
			r.Put("/devices/{device_id}/delivery-token", s.updateDeliveryToken)
			r.Put("/devices/{device_id}/push-endpoint", s.updatePushEndpoint)
			r.Get("/messages", s.fetchMessages)
			r.Post("/messages/{id}/ack", s.ackMessage)
			r.Get("/ws", s.websocket)
		})

		// Message submission is unauthenticated; gated by delivery token.
		r.Post("/messages", s.submitMessage)
	})

	return r
}

func (s *Server) powParams(w http.ResponseWriter, r *http.Request) {
	api.WriteJSON(w, http.StatusOK, s.accounts.POWParams())
}

// rateLimit is the per-IP middleware (audit F-01). The key comes from
// clientIP, which only trusts X-Forwarded-For from configured proxies.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ipLimiter.Allow("ip:" + s.clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			api.WriteError(w, api.Errorf(api.CodeRateLimited, "rate limited"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the client address used to key the per-IP rate limiter.
//
// X-Forwarded-For is honored only when the direct peer (RemoteAddr) is a
// configured trusted proxy: any client can set the header, so trusting it from
// an arbitrary peer is a rate-limit off switch (audit F-23). With a trusted
// peer, the chain is walked from the right, skipping trusted hops, and the
// first untrusted address wins — entries further left are attacker-supplied
// whenever the proxy appends to, rather than overwrites, the header.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(host)
	if remote == nil || !s.trustedProxy(remote) {
		return host
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			// A malformed hop invalidates everything to its left; fall back to
			// the proxy address so the key stays server-chosen, not
			// attacker-chosen.
			return host
		}
		if !s.trustedProxy(ip) {
			return ip.String()
		}
	}
	// Empty chain, or every hop was itself a trusted proxy: the origin address
	// is not observable, so key conservatively on the direct peer.
	return host
}

func (s *Server) trustedProxy(ip net.IP) bool {
	for _, n := range s.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	var req api.AccountRequest
	if err := decodeJSON(w, r, &req); err != nil {
		api.WriteError(w, err)
		return
	}
	resp, err := s.accounts.Create(r.Context(), req)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusCreated, resp)
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	var req api.DeviceRequest
	if err := decodeJSON(w, r, &req); err != nil {
		api.WriteError(w, err)
		return
	}
	resp, err := s.devices.Register(r.Context(), dev.UserID, req.Device)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusCreated, resp)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	resp, err := s.devices.List(r.Context(), dev.UserID)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	deviceID, err := pathInt(r, "device_id")
	if err != nil {
		api.WriteError(w, err)
		return
	}
	if err := s.devices.Revoke(r.Context(), dev.UserID, deviceID); err != nil {
		api.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) lookupUser(w http.ResponseWriter, r *http.Request) {
	resp, err := s.accounts.Lookup(r.Context(), chi.URLParam(r, "username"))
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) preKeyBundle(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	if !s.bundleLimiter.Allow("bundle:" + dev.UserID + ":" + strconv.Itoa(dev.ID)) {
		w.Header().Set("Retry-After", "3600")
		api.WriteError(w, api.Errorf(api.CodeRateLimited, "bundle fetch limit reached"))
		return
	}
	deviceID, err := pathInt(r, "device_id")
	if err != nil {
		api.WriteError(w, err)
		return
	}
	resp, spkRotatedAt, err := s.devices.PreKeyBundle(r.Context(), dev.UserID, dev.ID, chi.URLParam(r, "user_id"), deviceID)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	targetUserID := chi.URLParam(r, "user_id")
	// If the fetch drove the target below the replenish threshold, warn the
	// target device (§7.2.1 mitigation 3; audit F-02).
	if resp.OneTimePrekeysRemaining < s.limits.OTPReplenishThreshold {
		s.hub.NotifyPrekeysLow(targetUserID, deviceID, resp.OneTimePrekeysRemaining)
	}
	// Nudge the target when its signed prekey is overdue for rotation
	// (§7.2.1 mitigation 4; audit F-02).
	if time.Since(spkRotatedAt) > time.Duration(s.limits.SPKRotationDays)*24*time.Hour {
		s.hub.NotifySPKRotate(targetUserID, deviceID)
	}
	api.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) deliveryToken(w http.ResponseWriter, r *http.Request) {
	deviceID, err := pathInt(r, "device_id")
	if err != nil {
		api.WriteError(w, err)
		return
	}
	resp, err := s.devices.DeliveryToken(r.Context(), chi.URLParam(r, "user_id"), deviceID)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) addPreKeys(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	if err := requireOwnDevice(r, dev); err != nil {
		api.WriteError(w, err)
		return
	}
	var req api.PrekeysRequest
	if err := decodeJSON(w, r, &req); err != nil {
		api.WriteError(w, err)
		return
	}
	resp, err := s.devices.AddPreKeys(r.Context(), dev.UserID, dev.ID, req)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	if resp.OneTimePrekeysRemaining < s.limits.OTPReplenishThreshold {
		s.hub.NotifyPrekeysLow(dev.UserID, dev.ID, resp.OneTimePrekeysRemaining)
	}
	api.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) updateSignedPreKey(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	if err := requireOwnDevice(r, dev); err != nil {
		api.WriteError(w, err)
		return
	}
	var req api.SignedPrekeyRequest
	if err := decodeJSON(w, r, &req); err != nil {
		api.WriteError(w, err)
		return
	}
	if err := s.devices.UpdateSignedPreKey(r.Context(), dev.UserID, dev.ID, req); err != nil {
		api.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) updateDeliveryToken(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	if err := requireOwnDevice(r, dev); err != nil {
		api.WriteError(w, err)
		return
	}
	var req api.DeliveryTokenUpdate
	if err := decodeJSON(w, r, &req); err != nil {
		api.WriteError(w, err)
		return
	}
	if err := s.devices.RotateDeliveryToken(r.Context(), dev.UserID, dev.ID, req.DeliveryToken); err != nil {
		api.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) updatePushEndpoint(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	if err := requireOwnDevice(r, dev); err != nil {
		api.WriteError(w, err)
		return
	}
	var req api.PushEndpointUpdate
	if err := decodeJSON(w, r, &req); err != nil {
		api.WriteError(w, err)
		return
	}
	var endpoint *string
	if req.Endpoint != "" {
		if err := push.ValidateEndpoint(req.Endpoint); err != nil {
			api.WriteError(w, api.Errorf(api.CodeInvalidPayload, "invalid push endpoint: %s", err))
			return
		}
		endpoint = &req.Endpoint
	}
	if err := s.devices.UpdatePushEndpoint(r.Context(), dev.UserID, dev.ID, endpoint); err != nil {
		api.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) submitMessage(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Quietly-Version") != api.Version {
		api.WriteError(w, api.Errorf(api.CodeVersionMismatch, "version mismatch"))
		return
	}
	token := []byte(r.Header.Get("X-Quietly-Delivery-Token"))
	var req api.MessageSubmit
	if err := decodeJSON(w, r, &req); err != nil {
		api.WriteError(w, err)
		return
	}
	m, err := s.messages.Submit(r.Context(), req, token, time.Now())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	env := api.Envelope{
		V:            api.Version,
		ID:           m.ID,
		Recipient:    req.Recipient,
		Sealed:       m.Sealed,
		ServerTS:     m.ServerTS.UnixMilli(),
		TTLExpiresAt: m.TTLExpiresAt.UnixMilli(),
	}
	if s.notify != nil {
		s.notify(req.Recipient.UserID, req.Recipient.DeviceID, env, m.NotBefore)
	}
	api.WriteJSON(w, http.StatusAccepted, &api.MessageSubmitResponse{V: api.Version, ID: m.ID, ServerTS: m.ServerTS.UnixMilli()})
}

func (s *Server) fetchMessages(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	limit := 0 // service default: §12.14's 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	resp, err := s.messages.Fetch(r.Context(), dev.UserID, dev.ID, time.Now(), limit)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) ackMessage(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	if err := s.messages.Ack(r.Context(), dev.UserID, dev.ID, chi.URLParam(r, "id")); err != nil {
		api.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) websocket(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	s.hub.ServeWS(w, r, dev.UserID, dev.ID)
}

// requireOwnDevice rejects requests where the authenticated device does not
// match the {device_id} path parameter.
func requireOwnDevice(r *http.Request, dev *storage.Device) error {
	deviceID, err := pathInt(r, "device_id")
	if err != nil {
		return err
	}
	if dev.ID != deviceID {
		return api.Errorf(api.CodeForbidden, "not this device")
	}
	return nil
}

func pathInt(r *http.Request, name string) (int, error) {
	n, err := strconv.Atoi(chi.URLParam(r, name))
	if err != nil || n < 1 || n > 65535 {
		return 0, api.Errorf(api.CodeInvalidPayload, "invalid %s", name)
	}
	return n, nil
}

// maxRequestBody bounds every JSON request body.
const maxRequestBody = 1 << 20 // 1 MiB

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	// Reject oversized bodies before decoding (audit F-12); chunked requests
	// (ContentLength < 0) still fall back to the LimitReader.
	if r.ContentLength > maxRequestBody {
		return api.Errorf(api.CodePayloadTooLarge, "request body too large")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody+1))
	if err := dec.Decode(dst); err != nil {
		return api.Errorf(api.CodeInvalidPayload, "invalid JSON body")
	}
	// §1: `v` appears in every request; a mismatch is a hard error (audit
	// F-17). Reflection keeps this check in one place for all body types.
	if v, ok := structVersion(dst); ok && v != api.Version {
		return api.Errorf(api.CodeVersionMismatch, "version mismatch")
	}
	return nil
}

// structVersion returns the `v` field of a decoded request struct; ok is false
// when the type has no such field.
func structVersion(dst any) (string, bool) {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return "", false
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return "", false
	}
	f := v.FieldByName("V")
	if !f.IsValid() || f.Kind() != reflect.String {
		return "", false
	}
	return f.String(), true
}
