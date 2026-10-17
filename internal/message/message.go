// Package message implements encrypted message store-and-forward with TTL
// (PROTOCOL.md §11, §12.13–12.15).
package message

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"math/rand/v2"
	"time"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

// Service handles message operations.
type Service struct {
	store  storage.Store
	limits config.Limits
	jitter func(n int) int // returns an int in [0,n); nil means uniform
}

// New builds a message service.
func New(store storage.Store, limits config.Limits) *Service {
	return &Service{store: store, limits: limits, jitter: func(n int) int { return rand.IntN(n) }}
}

// NotBefore computes a message's release time: the enqueue time plus a uniform
// hold in [0, jitterMs] ms (inclusive). jitterMs <= 0 returns now unchanged.
// rng(n) must return an int in [0, n); nil uses a uniform default. This is the
// single code path for both C2S submission and the federation gateway
// (TASK-001 B).
func NotBefore(now time.Time, jitterMs int, rng func(n int) int) time.Time {
	if jitterMs <= 0 {
		return now
	}
	if rng == nil {
		rng = func(n int) int { return rand.IntN(n) }
	}
	return now.Add(time.Duration(rng(jitterMs+1)) * time.Millisecond)
}

func tokenHash(token []byte) []byte {
	h := sha256.Sum256(token)
	return h[:]
}

// DefaultFetchLimit is the GET /v1/messages default when no limit is given
// (PROTOCOL.md §12.14).
const DefaultFetchLimit = 100

// ValidateSealed applies the §12.13 envelope rules to a sealed blob: it must
// be non-empty and no larger than §15's SealedBlobMax. It is shared by C2S
// submission and the federation gateway, which must enforce the same per-
// message bounds a recipient queue promises (audit F-25).
func ValidateSealed(limits config.Limits, sealed []byte) error {
	if len(sealed) == 0 {
		return api.Errorf(api.CodeInvalidPayload, "sealed blob is empty")
	}
	if len(sealed) > limits.SealedBlobMax {
		return api.Errorf(api.CodePayloadTooLarge, "sealed blob exceeds limit")
	}
	return nil
}

// Submit stores an encrypted envelope for a recipient, gated by the recipient's
// delivery token (§12.13). All recipient-state failures collapse to a single
// delivery_rejected error to avoid an oracle. It returns the stored message.
func (s *Service) Submit(ctx context.Context, req api.MessageSubmit, token []byte, now time.Time) (*storage.Message, error) {
	if err := ValidateSealed(s.limits, req.Sealed); err != nil {
		return nil, err
	}
	if !validUUID(req.Recipient.UserID) {
		return nil, api.Errorf(api.CodeDeliveryRejected, "delivery rejected")
	}

	d, err := s.store.GetDevice(ctx, req.Recipient.UserID, req.Recipient.DeviceID)
	if err != nil || d.RevokedAt != nil {
		return nil, api.Errorf(api.CodeDeliveryRejected, "delivery rejected")
	}
	if subtle.ConstantTimeCompare(tokenHash(token), d.DeliveryTokenHash) != 1 {
		return nil, api.Errorf(api.CodeDeliveryRejected, "delivery rejected")
	}

	m := &storage.Message{
		RecipientUserID:   req.Recipient.UserID,
		RecipientDeviceID: req.Recipient.DeviceID,
		Sealed:            req.Sealed,
		ServerTS:          now,
		NotBefore:         NotBefore(now, s.limits.DeliveryJitterMs, s.jitter),
		TTLExpiresAt:      now.Add(time.Duration(s.limits.MessageTTLDays) * 24 * time.Hour),
	}
	if err := s.store.EnqueueMessage(ctx, m); err != nil {
		return nil, api.Errorf(api.CodeInternalError, "enqueue failed")
	}
	return m, nil
}

// Fetch returns the queued messages for a device, oldest first (§12.14). Only
// messages whose release time has arrived (not_before <= now) are returned
// (§15 delivery_jitter_ms).
func (s *Service) Fetch(ctx context.Context, userID string, deviceID int, now time.Time, limit int) (*api.MessagesResponse, error) {
	if limit <= 0 {
		limit = DefaultFetchLimit
	}
	if limit > s.limits.FetchLimitMax {
		limit = s.limits.FetchLimitMax
	}
	// Fetch one extra to know whether more remain.
	msgs, err := s.store.ListMessages(ctx, userID, deviceID, now, limit+1)
	if err != nil {
		return nil, api.Errorf(api.CodeInternalError, "message fetch failed")
	}
	resp := &api.MessagesResponse{V: api.Version}
	for i, m := range msgs {
		if i >= limit {
			resp.Remaining = 1
			break
		}
		resp.Messages = append(resp.Messages, api.Envelope{
			V:            api.Version,
			ID:           m.ID,
			Recipient:    api.Recipient{UserID: m.RecipientUserID, DeviceID: m.RecipientDeviceID},
			Sealed:       m.Sealed,
			ServerTS:     m.ServerTS.UnixMilli(),
			TTLExpiresAt: m.TTLExpiresAt.UnixMilli(),
		})
	}
	return resp, nil
}

// Ack deletes a delivered message, idempotently (§12.15).
func (s *Service) Ack(ctx context.Context, userID string, deviceID int, id string) error {
	err := s.store.AckMessage(ctx, userID, deviceID, id)
	switch err {
	case nil, storage.ErrNotFound:
		return nil // idempotent: unknown or already-acked
	case storage.ErrForbidden:
		return api.Errorf(api.CodeForbidden, "message not addressed to this device")
	default:
		return api.Errorf(api.CodeInternalError, "ack failed")
	}
}

// validUUID reports whether s has the canonical UUID string form.
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}
