package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Bytes is a binary value encoded as base64url without padding (PROTOCOL.md §1).
type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	return []byte(`"` + base64.RawURLEncoding.EncodeToString(b) + `"`), nil
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("base64url: %w", err)
	}
	dec, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("base64url: %w", err)
	}
	*b = Bytes(dec)
	return nil
}

// POWParams is the response to GET /v1/accounts/pow-params (§12.1).
type POWParams struct {
	V          string `json:"v"`
	Algorithm  string `json:"algorithm"`
	Difficulty int    `json:"difficulty"`
	WindowMs   int    `json:"window_ms"`
}

// POW is the proof-of-work field of POST /v1/accounts (§12.2).
type POW struct {
	TimestampMs int64  `json:"timestamp_ms"`
	Nonce       uint64 `json:"nonce"`
}

// PreKey is a one-time prekey entry (§7.1).
type PreKey struct {
	ID        uint32 `json:"id"`
	PublicKey Bytes  `json:"public_key"`
}

// SignedPreKey is the signed prekey object (§7.1).
type SignedPreKey struct {
	ID        uint32 `json:"id"`
	PublicKey Bytes  `json:"public_key"`
	Signature Bytes  `json:"signature"`
}

// DeviceRegistration is the device registration payload (§7.1).
type DeviceRegistration struct {
	IdentityKeyDH   Bytes        `json:"identity_key_dh"`
	IdentityKeySig  Bytes        `json:"identity_key_sig"`
	IdentityBinding Bytes        `json:"identity_binding"`
	SignedPreKey    SignedPreKey `json:"signed_prekey"`
	OneTimePrekeys  []PreKey     `json:"one_time_prekeys"`
	DeliveryToken   Bytes        `json:"delivery_token"`
}

// AccountRequest is POST /v1/accounts (§12.2).
type AccountRequest struct {
	V        string             `json:"v"`
	Username string             `json:"username"`
	POW      POW                `json:"pow"`
	Device   DeviceRegistration `json:"device"`
}

// AccountResponse is the 201 from POST /v1/accounts (§12.2).
type AccountResponse struct {
	V        string `json:"v"`
	UserID   string `json:"user_id"`
	DeviceID int    `json:"device_id"`
	Username string `json:"username"`
}

// DeviceRequest is POST /v1/devices (§12.3); the body is a registration payload.
type DeviceRequest struct {
	V      string             `json:"v"`
	Device DeviceRegistration `json:"device"`
}

// DeviceResponse is the 201 from POST /v1/devices (§12.3).
type DeviceResponse struct {
	V        string `json:"v"`
	DeviceID int    `json:"device_id"`
}

// DeviceInfo is an entry in GET /v1/devices (§12.4).
type DeviceInfo struct {
	DeviceID  int   `json:"device_id"`
	CreatedAt int64 `json:"created_at"`
	Revoked   bool  `json:"revoked"`
}

// DevicesResponse is GET /v1/devices (§12.4).
type DevicesResponse struct {
	V       string       `json:"v"`
	Devices []DeviceInfo `json:"devices"`
}

// UserResponse is GET /v1/users/{username} (§12.6).
type UserResponse struct {
	V        string `json:"v"`
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Devices  []int  `json:"devices"`
}

// BundleResponse is GET /v1/devices/{user_id}/{device_id}/prekey-bundle (§7.2).
type BundleResponse struct {
	V                       string       `json:"v"`
	UserID                  string       `json:"user_id"`
	DeviceID                int          `json:"device_id"`
	IdentityKeyDH           Bytes        `json:"identity_key_dh"`
	IdentityKeySig          Bytes        `json:"identity_key_sig"`
	IdentityBinding         Bytes        `json:"identity_binding"`
	SignedPreKey            SignedPreKey `json:"signed_prekey"`
	OneTimePrekey           *PreKey      `json:"one_time_prekey"`
	DeliveryToken           Bytes        `json:"delivery_token"`
	OneTimePrekeysRemaining int          `json:"one_time_prekeys_remaining"`
}

// DeliveryTokenResponse is GET /v1/devices/{id}/delivery-token (§12.8).
type DeliveryTokenResponse struct {
	V             string `json:"v"`
	UserID        string `json:"user_id"`
	DeviceID      int    `json:"device_id"`
	DeliveryToken Bytes  `json:"delivery_token"`
}

// PrekeysRequest is POST /v1/devices/{id}/prekeys (§12.9).
type PrekeysRequest struct {
	V              string   `json:"v"`
	OneTimePrekeys []PreKey `json:"one_time_prekeys"`
}

// PrekeysResponse is the 200 from POST /v1/devices/{id}/prekeys (§12.9).
type PrekeysResponse struct {
	V                       string `json:"v"`
	OneTimePrekeysRemaining int    `json:"one_time_prekeys_remaining"`
}

// SignedPrekeyRequest is PUT /v1/devices/{id}/signed-prekey (§12.10).
type SignedPrekeyRequest struct {
	V            string       `json:"v"`
	SignedPrekey SignedPreKey `json:"signed_prekey"`
}

// DeliveryTokenUpdate is PUT /v1/devices/{id}/delivery-token (§12.11).
type DeliveryTokenUpdate struct {
	V             string `json:"v"`
	DeliveryToken Bytes  `json:"delivery_token"`
}

// PushEndpointUpdate is PUT /v1/devices/{id}/push-endpoint (§12.12).
type PushEndpointUpdate struct {
	V        string `json:"v"`
	Endpoint string `json:"endpoint"`
}

// Recipient identifies a target device (§11).
type Recipient struct {
	UserID   string `json:"user_id"`
	DeviceID int    `json:"device_id"`
}

// MessageSubmit is POST /v1/messages (§11, §12.13).
type MessageSubmit struct {
	V         string    `json:"v"`
	Recipient Recipient `json:"recipient"`
	Sealed    Bytes     `json:"sealed"`
}

// MessageSubmitResponse is the 202 from POST /v1/messages (§12.13).
type MessageSubmitResponse struct {
	V        string `json:"v"`
	ID       string `json:"id"`
	ServerTS int64  `json:"server_ts"`
}

// Envelope is the stored/returned message envelope (§11).
type Envelope struct {
	V            string    `json:"v"`
	ID           string    `json:"id"`
	Recipient    Recipient `json:"recipient"`
	Sealed       Bytes     `json:"sealed"`
	ServerTS     int64     `json:"server_ts"`
	TTLExpiresAt int64     `json:"ttl_expires_at"`
}

// MessagesResponse is GET /v1/messages (§12.14).
type MessagesResponse struct {
	V         string     `json:"v"`
	Messages  []Envelope `json:"messages"`
	Remaining int        `json:"remaining"`
}
