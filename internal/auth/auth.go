// Package auth implements request authentication (PROTOCOL.md §5): the
// middleware that verifies each authenticated request's signature, timestamp,
// and nonce, and stashes the authenticated device in the request context.
package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	qcauth "github.com/quietly-messenger/quietly-crypto/auth"
	"github.com/quietly-messenger/quietly-crypto/quietly"

	"github.com/quietly-messenger/quietly-server/internal/api"
	"github.com/quietly-messenger/quietly-server/internal/storage"
)

// DeviceStore is the subset of storage the middleware needs.
type DeviceStore interface {
	GetDevice(ctx context.Context, userID string, deviceID int) (*storage.Device, error)
}

// maxBodyBytes bounds the request body read for signature verification.
const maxBodyBytes = 1 << 20 // 1 MiB

// NonceCache rejects replayed nonces within the auth window (§5.3).
type NonceCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	nonces map[string]time.Time
}

// NewNonceCache returns a cache that remembers a nonce for ttl.
func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{ttl: ttl, nonces: make(map[string]time.Time)}
}

// CheckAndAdd reports whether nonce is fresh (not seen within the window) and
// records it if so.
func (c *NonceCache) CheckAndAdd(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.nonces[nonce]; ok && now.Before(exp) {
		return false
	}
	if len(c.nonces) >= 8192 {
		for n, exp := range c.nonces {
			if now.After(exp) {
				delete(c.nonces, n)
			}
		}
	}
	c.nonces[nonce] = now.Add(c.ttl)
	return true
}

// Middleware returns an http middleware that authenticates each request,
// attaching the device to the request context on success.
func Middleware(store DeviceStore, authSkew time.Duration, nonces *NonceCache) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dev, err := authenticate(r, store, authSkew, nonces)
			if err != nil {
				api.WriteError(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithDevice(r.Context(), dev)))
		})
	}
}

func authenticate(r *http.Request, store DeviceStore, authSkew time.Duration, nonces *NonceCache) (*storage.Device, error) {
	version := r.Header.Get("X-Quietly-Version")
	deviceHdr := r.Header.Get("X-Quietly-Device")
	timestampHdr := r.Header.Get("X-Quietly-Timestamp")
	nonce := r.Header.Get("X-Quietly-Nonce")
	sigHdr := r.Header.Get("X-Quietly-Signature")

	if version == "" || deviceHdr == "" || timestampHdr == "" || nonce == "" || sigHdr == "" {
		return nil, api.Errorf(api.CodeSignatureMissing, "missing X-Quietly-* headers")
	}
	if version != quietly.Version {
		return nil, api.Errorf(api.CodeVersionMismatch, "unsupported protocol version")
	}

	userID, deviceID, err := parseDeviceHeader(deviceHdr)
	if err != nil {
		return nil, api.Errorf(api.CodeSignatureInvalid, "malformed X-Quietly-Device header")
	}

	timestampMS, err := strconv.ParseInt(timestampHdr, 10, 64)
	if err != nil {
		return nil, api.Errorf(api.CodeSignatureInvalid, "malformed X-Quietly-Timestamp")
	}
	if d := time.Since(time.UnixMilli(timestampMS)); d > authSkew || -d > authSkew {
		return nil, api.Errorf(api.CodeTimestampOutOfWindow, "timestamp outside window")
	}
	if !nonces.CheckAndAdd(nonce, time.Now()) {
		return nil, api.Errorf(api.CodeNonceReplayed, "nonce replayed")
	}

	dev, err := store.GetDevice(r.Context(), userID, deviceID)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, api.Errorf(api.CodeDeviceUnknown, "device unknown")
		}
		return nil, api.Errorf(api.CodeInternalError, "device lookup failed")
	}
	if dev.RevokedAt != nil {
		return nil, api.Errorf(api.CodeDeviceRevoked, "device revoked")
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, api.Errorf(api.CodeInternalError, "read body failed")
	}
	if len(body) > maxBodyBytes {
		return nil, api.Errorf(api.CodeInvalidPayload, "body too large")
	}
	// Restore the body for the handler.
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	sig, err := base64.RawURLEncoding.DecodeString(sigHdr)
	if err != nil {
		return nil, api.Errorf(api.CodeSignatureInvalid, "malformed signature")
	}
	if !qcauth.VerifyRequest(dev.IdentityKeySig, r.Method, r.URL.RequestURI(), timestampMS, nonce, body, sig) {
		return nil, api.Errorf(api.CodeSignatureInvalid, "signature does not verify")
	}
	return dev, nil
}

func parseDeviceHeader(h string) (string, int, error) {
	i := strings.LastIndexByte(h, '.')
	if i <= 0 || i == len(h)-1 {
		return "", 0, fmt.Errorf("malformed device header")
	}
	id, err := strconv.Atoi(h[i+1:])
	if err != nil || id < 1 || id > 65535 {
		return "", 0, fmt.Errorf("malformed device id")
	}
	return h[:i], id, nil
}

type ctxKey struct{}

// WithDevice attaches the authenticated device to the context.
func WithDevice(ctx context.Context, d *storage.Device) context.Context {
	return context.WithValue(ctx, ctxKey{}, d)
}

// DeviceFrom returns the authenticated device, or nil.
func DeviceFrom(ctx context.Context) *storage.Device {
	d, _ := ctx.Value(ctxKey{}).(*storage.Device)
	return d
}
