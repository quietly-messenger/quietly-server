// Command gateway is the Federation Gateway: it receives signed server-to-server
// delivery requests, verifies them against the trust service, and enqueues the
// message locally (docs/FEDERATION.md).
//
// Deliveries are verified for certificate validity, revocation, timestamp
// freshness, signature, and nonce replay (audit F-03), and revocation state is
// polled live from the trust service.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/auth"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/federation"
	"github.com/quietly-messenger/quietly-server/internal/message"
	"github.com/quietly-messenger/quietly-server/internal/ratelimit"
	"github.com/quietly-messenger/quietly-server/internal/storage"
	"github.com/quietly-messenger/quietly-server/internal/storage/postgres"
	"github.com/quietly-messenger/quietly-server/internal/transport/tlsconfig"
)

const (
	maxBodyBytes   = 256 << 10
	revocationPoll = 30 * time.Second
)

// revocationCache holds the trust service's revocation view.
type revocationCache struct {
	mu      sync.RWMutex
	revoked map[string]bool
}

func (rc *revocationCache) isRevoked(domain string) bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.revoked[domain]
}

// refresh fetches GET /servers from the trust service and replaces the cache.
func (rc *revocationCache) refresh(client *http.Client, base string) error {
	u := strings.TrimRight(base, "/") + "/servers"
	resp, err := client.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("trust service returned " + resp.Status)
	}
	var body struct {
		Servers map[string]bool `json:"servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	rc.mu.Lock()
	rc.revoked = body.Servers
	rc.mu.Unlock()
	return nil
}

// deliveryStore is the storage subset /deliver needs.
type deliveryStore interface {
	EnqueueMessage(ctx context.Context, m *storage.Message) error
}

// enqueueDelivery applies §12.13's envelope rules and §15's limits before
// storing a federated delivery, exactly as message.Submit does on the C2S
// path: a peer must not be able to queue envelopes larger or longer-lived
// than the protocol promises (audit F-25).
func enqueueDelivery(ctx context.Context, store deliveryStore, limits config.Limits, d federation.DeliveryRequest, now time.Time) error {
	if err := message.ValidateSealed(limits, d.Request.Sealed); err != nil {
		return err
	}
	m := &storage.Message{
		RecipientUserID:   d.Request.Recipient.UserID,
		RecipientDeviceID: d.Request.Recipient.DeviceID,
		Sealed:            d.Request.Sealed,
		ServerTS:          now,
		TTLExpiresAt:      now.Add(time.Duration(limits.MessageTTLDays) * 24 * time.Hour),
	}
	return store.EnqueueMessage(ctx, m)
}

// defaultS2SRequestsPerMinute bounds delivery requests per peer IP per minute
// unless S2S_REQUESTS_PER_MINUTE overrides it. Peers authenticate before a
// delivery is enqueued, but authentication itself (Ed25519 verification plus
// hashing the body) is the CPU a flood spends, so the budget gates both
// unauthenticated and authenticated traffic (audit F-03 residual).
const defaultS2SRequestsPerMinute = 300

// s2sRequestsPerMinute reads S2S_REQUESTS_PER_MINUTE, failing loud on an
// invalid value: silently falling back would leave the budget at the default
// while the operator believes it is configured.
func s2sRequestsPerMinute() int {
	v := os.Getenv("S2S_REQUESTS_PER_MINUTE")
	if v == "" {
		return defaultS2SRequestsPerMinute
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		slog.Error("S2S_REQUESTS_PER_MINUTE must be a positive number", "value", v)
		os.Exit(1)
	}
	return n
}

// deliverHandler serves POST /deliver.
type deliverHandler struct {
	tsPub   []byte
	revoked *revocationCache
	replay  func(domain, nonce string) bool
	store   deliveryStore
	limits  config.Limits
	limiter *ratelimit.Limiter
}

func (h *deliverHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.limiter.Allow(peerKey(r)) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var d federation.DeliveryRequest
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !federation.VerifyDelivery(h.tsPub, h.revoked.isRevoked, h.replay, time.Now(), d) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := enqueueDelivery(r.Context(), h.store, h.limits, d, time.Now()); err != nil {
		if ae := api.AsAPIError(err); ae != nil {
			http.Error(w, ae.Message, ae.Status)
			return
		}
		slog.Error("enqueue", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// peerKey is the rate-limit key for the direct peer address. X-Forwarded-For
// is deliberately ignored here for the same reason the HTTP server ignores it
// from untrusted peers (audit F-23): any sender can set the header, so
// honoring it would hand a flooder a fresh bucket per request. Behind a TLS
// terminator every peer shares one bucket, which still bounds total cost.
func peerKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host
}

func main() {
	ctx := context.Background()

	tsPub, err := base64.RawURLEncoding.DecodeString(os.Getenv("TRUST_PUBLIC_KEY"))
	if err != nil || len(tsPub) == 0 {
		slog.Error("TRUST_PUBLIC_KEY required")
		os.Exit(1)
	}
	trustURL := os.Getenv("TRUST_URL")
	if trustURL == "" {
		trustURL = "http://trust:8081"
	}

	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		slog.Error("database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	store := postgres.New(pool)
	limits := config.LoadLimits()
	revoked := &revocationCache{}
	trustClient := &http.Client{Timeout: 10 * time.Second}
	// Fail closed at boot: without the revocation view, deliveries must not be
	// accepted (audit F-03).
	if err := revoked.refresh(trustClient, trustURL); err != nil {
		slog.Error("fetch revocation list", "url", trustURL, "error", err)
		os.Exit(1)
	}
	go func() {
		t := time.NewTicker(revocationPoll)
		defer t.Stop()
		for range t.C {
			if err := revoked.refresh(trustClient, trustURL); err != nil {
				slog.Warn("revocation refresh failed", "error", err)
			}
		}
	}()

	nonces := auth.NewNonceCache(2 * federation.MaxClockSkew)
	replay := func(domain, nonce string) bool {
		return nonces.CheckAndAdd(domain+"\x00"+nonce, time.Now())
	}

	mux := http.NewServeMux()
	perMinute := s2sRequestsPerMinute()
	mux.Handle("/deliver", &deliverHandler{
		tsPub:   tsPub,
		revoked: revoked,
		replay:  replay,
		store:   store,
		limits:  limits,
		limiter: ratelimit.New(float64(perMinute)/60.0, perMinute, 10000),
	})

	addr := os.Getenv("GATEWAY_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8082"
	}
	tlsCfg, err := tlsconfig.FromEnv()
	if err != nil {
		slog.Error("tls", "error", err)
		os.Exit(1)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         tlsCfg,
	}
	slog.Info("gateway listening", "addr", addr, "tls", tlsCfg != nil, "trust", trustURL)
	if tlsCfg != nil {
		err = srv.ListenAndServeTLS("", "")
	} else {
		slog.Warn("TLS not configured; federation links must terminate TLS in front of the gateway")
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("gateway", "error", err)
		os.Exit(1)
	}
}
