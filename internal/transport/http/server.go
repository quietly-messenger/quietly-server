// Package http wires the HTTP routes to the domain services.
package http

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/quietly-messenger/quietly-server/internal/account"
	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/auth"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/device"
	"github.com/quietly-messenger/quietly-server/internal/message"
	"github.com/quietly-messenger/quietly-server/internal/storage"
	"github.com/quietly-messenger/quietly-server/internal/transport/ws"
)

// Server bundles the domain services and configuration for the HTTP handlers.
type Server struct {
	accounts *account.Service
	devices  *device.Service
	messages *message.Service
	limits   config.Limits
	hub      *ws.Hub
}

// NewServer builds the handler bundle.
func NewServer(accounts *account.Service, devices *device.Service, messages *message.Service, limits config.Limits, hub *ws.Hub) *Server {
	return &Server{accounts: accounts, devices: devices, messages: messages, limits: limits, hub: hub}
}

// Router builds the chi router with all routes and middleware.
func (s *Server) Router(store auth.DeviceStore, authSkew time.Duration, nonces *auth.NonceCache) http.Handler {
	r := chi.NewRouter()
	authMW := auth.Middleware(store, authSkew, nonces)

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

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	var req api.AccountRequest
	if err := decodeJSON(w, r, &req); err != nil {
		api.WriteError(w, err)
		return
	}
	if req.V != api.Version {
		api.WriteError(w, api.Errorf(api.CodeVersionMismatch, "version mismatch"))
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
	deviceID, err := pathInt(r, "device_id")
	if err != nil {
		api.WriteError(w, err)
		return
	}
	resp, err := s.devices.PreKeyBundle(r.Context(), chi.URLParam(r, "user_id"), deviceID)
	if err != nil {
		api.WriteError(w, err)
		return
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
	if s.hub != nil {
		s.hub.NotifyMessage(req.Recipient.UserID, req.Recipient.DeviceID, env)
	}
	api.WriteJSON(w, http.StatusAccepted, &api.MessageSubmitResponse{V: api.Version, ID: m.ID, ServerTS: m.ServerTS.UnixMilli()})
}

func (s *Server) fetchMessages(w http.ResponseWriter, r *http.Request) {
	dev := auth.DeviceFrom(r.Context())
	limit := s.limits.FetchLimitMax
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	resp, err := s.messages.Fetch(r.Context(), dev.UserID, dev.ID, limit)
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

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(dst); err != nil {
		return api.Errorf(api.CodeInvalidPayload, "invalid JSON body")
	}
	return nil
}
