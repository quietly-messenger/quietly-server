package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quietly-messenger/quietly-server/internal/account"
	"github.com/quietly-messenger/quietly-server/internal/auth"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/device"
	"github.com/quietly-messenger/quietly-server/internal/message"
	"github.com/quietly-messenger/quietly-server/internal/push"
	"github.com/quietly-messenger/quietly-server/internal/storage"
	"github.com/quietly-messenger/quietly-server/internal/storage/postgres"
	transporthttp "github.com/quietly-messenger/quietly-server/internal/transport/http"
	"github.com/quietly-messenger/quietly-server/internal/transport/ws"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		slog.Error("database ping", "error", err)
		os.Exit(1)
	}

	store := postgres.New(pool)
	limits := cfg.Limits

	deviceSvc := device.New(store, limits)
	accountSvc := account.New(store, deviceSvc, limits)
	messageSvc := message.New(store, limits)

	hub := ws.NewHub()
	hub.SetAck(func(userID string, deviceID int, id string) error {
		return messageSvc.Ack(context.Background(), userID, deviceID, id)
	})
	hub.SetWake(func(userID string, deviceID int) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d, err := store.GetDevice(ctx, userID, deviceID)
		if err != nil || d.PushEndpoint == nil {
			return
		}
		if err := push.Wake(ctx, http.DefaultClient, *d.PushEndpoint); err != nil {
			slog.Debug("push wake", "error", err)
		}
	})

	srv := transporthttp.NewServer(accountSvc, deviceSvc, messageSvc, limits, hub)
	nonces := auth.NewNonceCache(time.Duration(limits.AuthSkewMs*2) * time.Millisecond)
	handler := srv.Router(store, time.Duration(limits.AuthSkewMs)*time.Millisecond, nonces)

	addr := netAddr(cfg)
	httpServer := &http.Server{Addr: addr, Handler: handler}

	go ttlCleanup(ctx, store, time.Hour)

	go func() {
		slog.Info("listening", "addr", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

func netAddr(cfg *config.Config) string {
	return cfg.ServerAddress + ":" + strconv.Itoa(cfg.ServerPort)
}

// ttlCleanup periodically deletes expired undelivered messages (§15:
// message_ttl_days).
func ttlCleanup(ctx context.Context, store *postgres.Store, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := store.DeleteExpiredMessages(ctx, time.Now())
			if err != nil {
				slog.Warn("ttl cleanup", "error", err)
				continue
			}
			if n > 0 {
				slog.Info("ttl cleanup", "deleted", n)
			}
		}
	}
}

var _ storage.Store = (*postgres.Store)(nil)
