// Command trust is the Directory/Trust Service: a certificate authority that
// issues, lists, and revokes home-server certificates (docs/FEDERATION.md).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"github.com/quietly-messenger/quietly-server/internal/federation"
	"github.com/quietly-messenger/quietly-server/internal/trust"
)

func main() {
	priv, pub, err := loadKey()
	if err != nil {
		slog.Error("trust key", "error", err)
		os.Exit(1)
	}
	ca := trust.New(priv, pub)

	r := chi.NewRouter()
	r.Get("/ca", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"v": "quietly/1", "public_key": federation.Bytes(pub)})
	})
	r.Get("/servers", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"v": "quietly/1", "servers": ca.Certs()})
	})
	r.Post("/servers", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Domain    string           `json:"domain"`
			PublicKey federation.Bytes `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		cert, err := ca.Issue(req.Domain, req.PublicKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
			return
		}
		writeJSON(w, http.StatusCreated, cert)
	})
	r.Post("/servers/{domain}/revoke", func(w http.ResponseWriter, r *http.Request) {
		ca.Revoke(chi.URLParam(r, "domain"))
		w.WriteHeader(http.StatusNoContent)
	})

	addr := os.Getenv("TRUST_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8081"
	}
	slog.Info("trust service listening", "addr", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
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
