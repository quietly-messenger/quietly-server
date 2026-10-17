// Command trust is the Directory/Trust Service: a certificate authority that
// issues, lists, and revokes home-server certificates (docs/FEDERATION.md).
//
// Issuing and revoking require the operator's admin token (TRUST_ADMIN_TOKEN);
// the service refuses to start without one, so an exposed instance can never
// mint certificates anonymously (audit F-03). CA state is persisted to
// TRUST_STATE_PATH so restarts keep issued certificates and revocations.
package main

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/quietly-messenger/quietly-server/internal/federation"
	"github.com/quietly-messenger/quietly-server/internal/transport/tlsconfig"
	"github.com/quietly-messenger/quietly-server/internal/trust"
)

const maxBodyBytes = 64 << 10

func main() {
	adminToken := os.Getenv("TRUST_ADMIN_TOKEN")
	if adminToken == "" {
		slog.Error("TRUST_ADMIN_TOKEN is required: refusing to run an unauthenticated CA")
		os.Exit(1)
	}

	priv, pub, err := loadKey()
	if err != nil {
		slog.Error("trust key", "error", err)
		os.Exit(1)
	}

	statePath := os.Getenv("TRUST_STATE_PATH")
	if statePath == "" {
		statePath = "trust-state.json"
	}
	// Certificates carry an expiry (audit F-03 residual). 90 days by default;
	// renewing is re-issuing before the old certificate lapses.
	validity := trust.DefaultCertValidity
	if days := os.Getenv("TRUST_CERT_DAYS"); days != "" {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			slog.Error("TRUST_CERT_DAYS must be a positive number of days", "value", days)
			os.Exit(1)
		}
		validity = time.Duration(n) * 24 * time.Hour
	}
	ca := trust.New(priv, pub, validity)
	if err := ca.Load(statePath); err != nil {
		slog.Error("load CA state", "path", statePath, "error", err)
		os.Exit(1)
	}
	save := func() {
		if err := ca.Save(statePath); err != nil {
			slog.Error("save CA state", "path", statePath, "error", err)
		}
	}

	r := chi.NewRouter()
	requireAdmin := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			got := req.Header.Get("Authorization")
			want := "Bearer " + adminToken
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin token required"})
				return
			}
			next.ServeHTTP(w, req)
		})
	}
	limitBody := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			req.Body = http.MaxBytesReader(w, req.Body, maxBodyBytes)
			next.ServeHTTP(w, req)
		})
	}

	r.Get("/ca", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"v": "quietly/1", "public_key": federation.Bytes(pub)})
	})
	r.Get("/servers", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"v": "quietly/1", "servers": ca.Certs()})
	})
	r.Group(func(r chi.Router) {
		r.Use(requireAdmin)
		r.Use(limitBody)
		r.Post("/servers", func(w http.ResponseWriter, req *http.Request) {
			var body struct {
				Domain    string           `json:"domain"`
				PublicKey federation.Bytes `json:"public_key"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.Domain == "" || len(body.PublicKey) == 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			cert, err := ca.Issue(body.Domain, body.PublicKey, time.Now())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
				return
			}
			save()
			writeJSON(w, http.StatusCreated, cert)
		})
		r.Post("/servers/{domain}/revoke", func(w http.ResponseWriter, req *http.Request) {
			ca.Revoke(chi.URLParam(req, "domain"))
			save()
			w.WriteHeader(http.StatusNoContent)
		})
	})

	addr := os.Getenv("TRUST_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8081"
	}
	tlsCfg, err := tlsconfig.FromEnv()
	if err != nil {
		slog.Error("tls", "error", err)
		os.Exit(1)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         tlsCfg,
	}
	slog.Info("trust service listening", "addr", addr, "tls", tlsCfg != nil, "state", statePath)
	if tlsCfg != nil {
		err = srv.ListenAndServeTLS("", "")
	} else {
		slog.Warn("TLS not configured; bind the trust service to a private network or terminate TLS in front of it")
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("trust service", "error", err)
		os.Exit(1)
	}
}

func loadKey() (priv, pub []byte, err error) {
	s := os.Getenv("TRUST_PRIVATE_KEY")
	if s == "" {
		// No persistent key provided: generate an ephemeral one (dev only).
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, nil, err
		}
		slog.Warn("TRUST_PRIVATE_KEY not set; using an ephemeral key (dev only)")
		return priv, pub, nil
	}
	priv, err = base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, nil, os.ErrInvalid
	}
	pub = ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	return priv, pub, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
