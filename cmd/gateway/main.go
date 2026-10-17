// Command gateway is the Federation Gateway: it receives signed server-to-server
// delivery requests, verifies them against the trust service, and enqueues the
// message locally (docs/FEDERATION.md).
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quietly-messenger/quietly-server/internal/federation"
	"github.com/quietly-messenger/quietly-server/internal/storage"
	"github.com/quietly-messenger/quietly-server/internal/storage/postgres"
	"github.com/quietly-messenger/quietly-server/internal/trust"
)

func main() {
	ctx := context.Background()

	tsPub, err := base64.RawURLEncoding.DecodeString(os.Getenv("TRUST_PUBLIC_KEY"))
	if err != nil || len(tsPub) == 0 {
		slog.Error("TRUST_PUBLIC_KEY required")
		os.Exit(1)
	}

	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		slog.Error("database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	store := postgres.New(pool)
	ca := trust.New(nil, tsPub) // CA with a public key only, for verification

	http.HandleFunc("/deliver", func(w http.ResponseWriter, r *http.Request) {
		var d federation.DeliveryRequest
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if !ca.VerifyDelivery(d) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		m := &storage.Message{
			RecipientUserID:   d.Request.Recipient.UserID,
			RecipientDeviceID: d.Request.Recipient.DeviceID,
			Sealed:            d.Request.Sealed,
			ServerTS:          time.Now(),
			TTLExpiresAt:      time.Now().Add(30 * 24 * time.Hour),
		}
		if err := store.EnqueueMessage(r.Context(), m); err != nil {
			slog.Error("enqueue", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})

	addr := os.Getenv("GATEWAY_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8082"
	}
	slog.Info("gateway listening", "addr", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		slog.Error("gateway", "error", err)
		os.Exit(1)
	}
}
