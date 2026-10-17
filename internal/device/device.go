// Package device implements device registration, prekey management, and the
// signed-prekey/delivery-token lifecycle (PROTOCOL.md §7).
package device

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/quietly-messenger/quietly-crypto/identity"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

// Service handles device operations.
type Service struct {
	store  storage.Store
	limits config.Limits
}

// New builds a device service.
func New(store storage.Store, limits config.Limits) *Service {
	return &Service{store: store, limits: limits}
}

// VerifyRegistration validates key sizes and verifies the identity-binding and
// signed-prekey signatures of a registration payload (§7.1).
func VerifyRegistration(reg api.DeviceRegistration, tokenBytes int) error {
	bundle := identity.PreKeyBundle{
		IdentityKeyDH:         reg.IdentityKeyDH,
		IdentityKeySig:        reg.IdentityKeySig,
		IdentityBinding:       reg.IdentityBinding,
		SignedPreKeyID:        reg.SignedPreKey.ID,
		SignedPreKey:          reg.SignedPreKey.PublicKey,
		SignedPreKeySignature: reg.SignedPreKey.Signature,
	}
	if err := bundle.Verify(); err != nil {
		return api.Errorf(api.CodeSignatureInvalid, "registration signature invalid")
	}
	if len(reg.DeliveryToken) != tokenBytes {
		return api.Errorf(api.CodeInvalidPayload, "delivery token must be %d bytes", tokenBytes)
	}
	seen := make(map[uint32]bool, len(reg.OneTimePrekeys))
	for _, p := range reg.OneTimePrekeys {
		if p.ID == 0 || seen[p.ID] {
			return api.Errorf(api.CodePrekeyIDConflict, "duplicate or zero prekey id")
		}
		seen[p.ID] = true
		if len(p.PublicKey) != 32 {
			return api.Errorf(api.CodeInvalidPayload, "prekey public key must be 32 bytes")
		}
	}
	return nil
}

func tokenHash(token []byte) []byte {
	h := sha256.Sum256(token)
	return h[:]
}

// Register creates a new device for an existing user, enforcing the device
// limit (§12.3).
func (s *Service) Register(ctx context.Context, userID string, reg api.DeviceRegistration) (*api.DeviceResponse, error) {
	if err := VerifyRegistration(reg, s.limits.DeliveryTokenBytes); err != nil {
		return nil, err
	}
	n, err := s.store.CountActiveDevices(ctx, userID)
	if err != nil {
		return nil, api.Errorf(api.CodeInternalError, "device count failed")
	}
	if n >= s.limits.MaxDevicesPerAccount {
		return nil, api.Errorf(api.CodeDeviceLimitReached, "device limit reached")
	}
	return s.Create(ctx, userID, reg)
}

// Create creates a device without the active-device limit check (used for
// device 1 at account creation).
func (s *Service) Create(ctx context.Context, userID string, reg api.DeviceRegistration) (*api.DeviceResponse, error) {
	d, prekeys, err := s.PrepareDevice(userID, reg)
	if err != nil {
		return nil, err
	}
	created, err := s.store.CreateDevice(ctx, d, prekeys)
	if err != nil {
		if err == storage.ErrConflict {
			return nil, api.Errorf(api.CodePrekeyIDConflict, "prekey id conflict")
		}
		return nil, api.Errorf(api.CodeInternalError, "device creation failed")
	}
	return &api.DeviceResponse{V: api.Version, DeviceID: created.ID}, nil
}

// PrepareDevice verifies a registration and builds the storage device and
// prekeys without persisting them.
func (s *Service) PrepareDevice(userID string, reg api.DeviceRegistration) (*storage.Device, []storage.OneTimePreKey, error) {
	if err := VerifyRegistration(reg, s.limits.DeliveryTokenBytes); err != nil {
		return nil, nil, err
	}
	d := &storage.Device{
		UserID:            userID,
		IdentityKeyDH:     reg.IdentityKeyDH,
		IdentityKeySig:    reg.IdentityKeySig,
		IdentityBinding:   reg.IdentityBinding,
		SignedPreKeyID:    reg.SignedPreKey.ID,
		SignedPreKey:      reg.SignedPreKey.PublicKey,
		SignedPreKeySig:   reg.SignedPreKey.Signature,
		DeliveryToken:     reg.DeliveryToken,
		DeliveryTokenHash: tokenHash(reg.DeliveryToken),
	}
	var prekeys []storage.OneTimePreKey
	for _, p := range reg.OneTimePrekeys {
		prekeys = append(prekeys, storage.OneTimePreKey{ID: p.ID, PublicKey: p.PublicKey})
	}
	return d, prekeys, nil
}

// List returns the account's devices (§12.4).
func (s *Service) List(ctx context.Context, userID string) (*api.DevicesResponse, error) {
	devices, err := s.store.ListDevices(ctx, userID)
	if err != nil {
		return nil, api.Errorf(api.CodeInternalError, "device list failed")
	}
	out := api.DevicesResponse{V: api.Version}
	for _, d := range devices {
		out.Devices = append(out.Devices, api.DeviceInfo{
			DeviceID:  d.ID,
			CreatedAt: d.CreatedAt.UnixMilli(),
			Revoked:   d.RevokedAt != nil,
		})
	}
	return &out, nil
}

// Revoke soft-deletes a device (§2.2, §12.5).
func (s *Service) Revoke(ctx context.Context, userID string, deviceID int) error {
	if err := s.store.RevokeDevice(ctx, userID, deviceID); err != nil {
		if err == storage.ErrNotFound {
			return api.Errorf(api.CodeDeviceUnknown, "device unknown")
		}
		return api.Errorf(api.CodeInternalError, "revoke failed")
	}
	return nil
}

// OTPIdempotencyWindow is the per-pair one-time-prekey re-fetch window
// (PROTOCOL.md §15: otp_idempotency_window_h = 24). The server's janitor uses
// it to prune older issuance records (audit F-02 residual).
const OTPIdempotencyWindow = 24 * time.Hour

// PreKeyBundle returns the recipient's bundle, consuming one one-time prekey
// (§7.2, §12.7). The request is unauthenticated, so idempotency is keyed per
// (target, 24 h window): every fetch for the same target in the same window
// returns the same prekey, and the requester is never recorded (TASK-001 C,
// §7.2.1). It also reports when the target's signed prekey was installed so
// the caller can nudge the device when rotation is due (§7.2.1 mitigation 4).
func (s *Service) PreKeyBundle(ctx context.Context, targetUserID string, targetDeviceID int, now time.Time) (*api.BundleResponse, time.Time, error) {
	d, err := s.store.GetDevice(ctx, targetUserID, targetDeviceID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, time.Time{}, api.Errorf(api.CodeDeviceUnknown, "device unknown")
		}
		return nil, time.Time{}, api.Errorf(api.CodeInternalError, "device lookup failed")
	}
	if d.RevokedAt != nil {
		return nil, time.Time{}, api.Errorf(api.CodeDeviceRevoked, "device revoked")
	}

	windowStart := now.Truncate(OTPIdempotencyWindow)
	var otpk *storage.OneTimePreKey
	if prev, _, err := s.store.GetPreKeyIssuance(ctx, targetUserID, targetDeviceID, windowStart); err == nil {
		otpk = prev
	} else {
		otpk, err = s.store.TakeOneTimePreKey(ctx, targetUserID, targetDeviceID)
		if err != nil && err != storage.ErrNotFound {
			return nil, time.Time{}, api.Errorf(api.CodeInternalError, "prekey fetch failed")
		}
		if otpk != nil {
			if err := s.store.RecordPreKeyIssuance(ctx, targetUserID, targetDeviceID, windowStart, *otpk); err != nil {
				return nil, time.Time{}, api.Errorf(api.CodeInternalError, "prekey issuance failed")
			}
		}
	}

	remaining, err := s.store.CountAvailablePreKeys(ctx, targetUserID, targetDeviceID)
	if err != nil {
		return nil, time.Time{}, api.Errorf(api.CodeInternalError, "prekey count failed")
	}

	resp := &api.BundleResponse{
		V:                       api.Version,
		UserID:                  targetUserID,
		DeviceID:                targetDeviceID,
		IdentityKeyDH:           d.IdentityKeyDH,
		IdentityKeySig:          d.IdentityKeySig,
		IdentityBinding:         d.IdentityBinding,
		SignedPreKey:            api.SignedPreKey{ID: d.SignedPreKeyID, PublicKey: d.SignedPreKey, Signature: d.SignedPreKeySig},
		DeliveryToken:           d.DeliveryToken,
		OneTimePrekeysRemaining: remaining,
	}
	if otpk != nil {
		resp.OneTimePrekey = &api.PreKey{ID: otpk.ID, PublicKey: otpk.PublicKey}
	}
	return resp, d.SignedPreKeyRotatedAt, nil
}

// DeliveryToken returns the recipient device's current delivery token (§12.8).
func (s *Service) DeliveryToken(ctx context.Context, userID string, deviceID int) (*api.DeliveryTokenResponse, error) {
	d, err := s.store.GetDevice(ctx, userID, deviceID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, api.Errorf(api.CodeDeviceUnknown, "device unknown")
		}
		return nil, api.Errorf(api.CodeInternalError, "device lookup failed")
	}
	if d.RevokedAt != nil {
		return nil, api.Errorf(api.CodeDeviceRevoked, "device revoked")
	}
	return &api.DeliveryTokenResponse{
		V:             api.Version,
		UserID:        userID,
		DeviceID:      deviceID,
		DeliveryToken: d.DeliveryToken,
	}, nil
}

// AddPreKeys appends one-time prekeys (§12.9).
func (s *Service) AddPreKeys(ctx context.Context, userID string, deviceID int, req api.PrekeysRequest) (*api.PrekeysResponse, error) {
	seen := make(map[uint32]bool, len(req.OneTimePrekeys))
	var prekeys []storage.OneTimePreKey
	for _, p := range req.OneTimePrekeys {
		if p.ID == 0 || seen[p.ID] {
			return nil, api.Errorf(api.CodePrekeyIDConflict, "duplicate or zero prekey id")
		}
		seen[p.ID] = true
		if len(p.PublicKey) != 32 {
			return nil, api.Errorf(api.CodeInvalidPayload, "prekey public key must be 32 bytes")
		}
		prekeys = append(prekeys, storage.OneTimePreKey{ID: p.ID, PublicKey: p.PublicKey})
	}

	remaining, err := s.store.CountAvailablePreKeys(ctx, userID, deviceID)
	if err != nil {
		return nil, api.Errorf(api.CodeInternalError, "prekey count failed")
	}
	if remaining+len(prekeys) > s.limits.OTPMaxStored {
		return nil, api.Errorf(api.CodePrekeyLimitExceeded, "prekey limit exceeded")
	}
	if err := s.store.AddOneTimePreKeys(ctx, userID, deviceID, prekeys); err != nil {
		if err == storage.ErrConflict {
			return nil, api.Errorf(api.CodePrekeyIDConflict, "prekey id conflict")
		}
		return nil, api.Errorf(api.CodeInternalError, "prekey add failed")
	}
	return &api.PrekeysResponse{V: api.Version, OneTimePrekeysRemaining: remaining + len(prekeys)}, nil
}

// UpdateSignedPreKey rotates the signed prekey (§12.10).
func (s *Service) UpdateSignedPreKey(ctx context.Context, userID string, deviceID int, req api.SignedPrekeyRequest) error {
	if err := s.verifySignedPreKey(ctx, userID, deviceID, req.SignedPrekey); err != nil {
		return err
	}
	if err := s.store.UpdateSignedPreKey(ctx, userID, deviceID, req.SignedPrekey.ID, req.SignedPrekey.PublicKey, req.SignedPrekey.Signature); err != nil {
		if err == storage.ErrNotFound {
			return api.Errorf(api.CodeDeviceUnknown, "device unknown")
		}
		return api.Errorf(api.CodeInternalError, "signed prekey update failed")
	}
	return nil
}

// RotateDeliveryToken replaces the delivery token (§12.11).
func (s *Service) RotateDeliveryToken(ctx context.Context, userID string, deviceID int, token []byte) error {
	if len(token) != s.limits.DeliveryTokenBytes {
		return api.Errorf(api.CodeInvalidPayload, "delivery token must be %d bytes", s.limits.DeliveryTokenBytes)
	}
	if err := s.store.UpdateDeliveryToken(ctx, userID, deviceID, token, tokenHash(token)); err != nil {
		if err == storage.ErrNotFound {
			return api.Errorf(api.CodeDeviceUnknown, "device unknown")
		}
		return api.Errorf(api.CodeInternalError, "token update failed")
	}
	return nil
}

// UpdatePushEndpoint registers or clears a push endpoint (§12.12).
func (s *Service) UpdatePushEndpoint(ctx context.Context, userID string, deviceID int, endpoint *string) error {
	if err := s.store.UpdatePushEndpoint(ctx, userID, deviceID, endpoint); err != nil {
		if err == storage.ErrNotFound {
			return api.Errorf(api.CodeDeviceUnknown, "device unknown")
		}
		return api.Errorf(api.CodeInternalError, "push endpoint update failed")
	}
	return nil
}

func (s *Service) verifySignedPreKey(ctx context.Context, userID string, deviceID int, spk api.SignedPreKey) error {
	d, err := s.store.GetDevice(ctx, userID, deviceID)
	if err != nil {
		return api.Errorf(api.CodeDeviceUnknown, "device unknown")
	}
	if len(spk.PublicKey) != 32 || len(spk.Signature) != 64 {
		return api.Errorf(api.CodeInvalidPayload, "signed prekey must be 32 bytes with a 64-byte signature")
	}
	if !identity.VerifySignedPreKey(d.IdentityKeySig, spk.ID, spk.PublicKey, spk.Signature) {
		return api.Errorf(api.CodeSignatureInvalid, "signed-prekey signature invalid")
	}
	return nil
}
