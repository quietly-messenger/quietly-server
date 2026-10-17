package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/federation"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

type fakeDeliveryStore struct {
	m   *storage.Message
	err error
}

func (f *fakeDeliveryStore) EnqueueMessage(_ context.Context, m *storage.Message) error {
	if f.err != nil {
		return f.err
	}
	f.m = m
	return nil
}

func delivery(sealed []byte) federation.DeliveryRequest {
	d := federation.DeliveryRequest{}
	d.Request.Recipient.UserID = "11111111-2222-4333-8444-555555555555"
	d.Request.Recipient.DeviceID = 1
	d.Request.Sealed = sealed
	return d
}

// TestEnqueueDeliveryEnforcesEnvelopeLimits pins audit F-25: the gateway must
// apply the same envelope rules as message.Submit — a federated peer must not
// be able to queue blobs larger than SealedBlobMax (the body cap alone allows
// 256 KiB) or messages with a different lifetime than §15 promises.
func TestEnqueueDeliveryEnforcesEnvelopeLimits(t *testing.T) {
	limits := config.DefaultLimits()
	limits.MessageTTLDays = 7
	limits.SealedBlobMax = 8

	now := time.Now()
	ctx := context.Background()

	t.Run("oversized blob is rejected", func(t *testing.T) {
		store := &fakeDeliveryStore{}
		err := enqueueDelivery(ctx, store, limits, delivery(make([]byte, limits.SealedBlobMax+1)), now)
		if ae := api.AsAPIError(err); ae == nil || ae.Code != api.CodePayloadTooLarge {
			t.Fatalf("error = %v, want payload_too_large", err)
		}
		if store.m != nil {
			t.Fatal("oversized blob reached storage")
		}
	})

	t.Run("empty blob is rejected", func(t *testing.T) {
		store := &fakeDeliveryStore{}
		err := enqueueDelivery(ctx, store, limits, delivery(nil), now)
		if ae := api.AsAPIError(err); ae == nil || ae.Code != api.CodeInvalidPayload {
			t.Fatalf("error = %v, want invalid_payload", err)
		}
	})

	t.Run("blob at the limit gets the configured TTL", func(t *testing.T) {
		store := &fakeDeliveryStore{}
		if err := enqueueDelivery(ctx, store, limits, delivery(make([]byte, limits.SealedBlobMax)), now); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if store.m == nil {
			t.Fatal("message was not stored")
		}
		if want := now.Add(7 * 24 * time.Hour); !store.m.TTLExpiresAt.Equal(want) {
			t.Fatalf("TTLExpiresAt = %v, want %v (configured TTL, not a hardcoded 30 days)", store.m.TTLExpiresAt, want)
		}
		if !store.m.ServerTS.Equal(now) {
			t.Fatalf("ServerTS = %v, want %v", store.m.ServerTS, now)
		}
	})

	t.Run("storage failure surfaces as a plain error", func(t *testing.T) {
		store := &fakeDeliveryStore{err: errors.New("db down")}
		err := enqueueDelivery(ctx, store, limits, delivery([]byte("sealed!!")), now)
		if err == nil || api.AsAPIError(err) != nil {
			t.Fatalf("error = %v, want a non-API error", err)
		}
	})
}
