// Package account implements account creation with proof-of-work anti-abuse
// and username validation (PROTOCOL.md §2, §4, §12.1–12.2).
package account

import (
	"context"
	"time"

	"github.com/quietly-messenger/quietly-crypto/pow"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/config"
	"github.com/quietly-messenger/quietly-server/internal/device"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

// Service handles account operations.
type Service struct {
	store   storage.Store
	devices *device.Service
	limits  config.Limits
}

// New builds an account service.
func New(store storage.Store, devices *device.Service, limits config.Limits) *Service {
	return &Service{store: store, devices: devices, limits: limits}
}

// POWParams returns the proof-of-work parameters a client needs before solving
// (§12.1).
func (s *Service) POWParams() api.POWParams {
	return api.POWParams{
		V:          api.Version,
		Algorithm:  "sha256-leading-zero-bits",
		Difficulty: s.limits.PowDifficulty,
		WindowMs:   s.limits.PowWindowMs,
	}
}

// Create validates the username and proof of work, then creates the account and
// device 1 atomically (§12.2).
func (s *Service) Create(ctx context.Context, req api.AccountRequest) (*api.AccountResponse, error) {
	if !validUsername(req.Username) {
		return nil, api.Errorf(api.CodeUsernameInvalid, "username must be 3-32 chars of [a-z0-9_]")
	}

	// Check availability before spending any work on PoW (§4.2).
	if _, err := s.store.GetUserByUsername(ctx, req.Username); err == nil {
		return nil, api.Errorf(api.CodeUsernameTaken, "username taken")
	} else if err != storage.ErrNotFound {
		return nil, api.Errorf(api.CodeInternalError, "username lookup failed")
	}

	now := time.Now().UnixMilli()
	if d := now - req.POW.TimestampMs; d > int64(s.limits.PowWindowMs) || -d > int64(s.limits.PowWindowMs) {
		return nil, api.Errorf(api.CodePowStale, "proof of work stale")
	}
	if !pow.Verify(req.Username, req.POW.TimestampMs, req.POW.Nonce, s.limits.PowDifficulty) {
		return nil, api.Errorf(api.CodePowInvalid, "proof of work does not meet difficulty")
	}

	// Create user + device 1 atomically (audit F-10): a failure here must not
	// leave an account with no device.
	d, prekeys, err := s.devices.PrepareDevice("", req.Device)
	if err != nil {
		return nil, err
	}
	createdUser, createdDevice, err := s.store.CreateAccountWithDevice(ctx, req.Username, d, prekeys)
	if err != nil {
		if err == storage.ErrConflict {
			return nil, api.Errorf(api.CodeUsernameTaken, "username taken")
		}
		return nil, api.Errorf(api.CodeInternalError, "account creation failed")
	}
	return &api.AccountResponse{
		V:        api.Version,
		UserID:   createdUser.ID,
		DeviceID: createdDevice.ID,
		Username: createdUser.Username,
	}, nil
}

// Lookup resolves a username to its routing identity and active devices (§12.6).
func (s *Service) Lookup(ctx context.Context, username string) (*api.UserResponse, error) {
	user, err := s.store.GetUserByUsername(ctx, username)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, api.Errorf(api.CodeUserNotFound, "user not found")
		}
		return nil, api.Errorf(api.CodeInternalError, "user lookup failed")
	}
	devices, err := s.store.ListDevices(ctx, user.ID)
	if err != nil {
		return nil, api.Errorf(api.CodeInternalError, "device list failed")
	}
	resp := &api.UserResponse{V: api.Version, UserID: user.ID, Username: user.Username}
	for _, d := range devices {
		if d.RevokedAt == nil {
			resp.Devices = append(resp.Devices, d.ID)
		}
	}
	return resp, nil
}

func validUsername(s string) bool {
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}
