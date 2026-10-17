// Package api holds the client-server wire types and the error model
// (PROTOCOL.md §14). Handlers parse into and serialize from these types; the
// storage layer uses its own internal types.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/quietly-messenger/quietly-crypto/quietly"
)

// Version is the protocol version echoed in every response.
const Version = quietly.Version

// ErrorCode is a stable machine-readable error code (§14).
type ErrorCode string

const (
	CodeVersionMismatch      ErrorCode = "version_mismatch"
	CodeInvalidPayload       ErrorCode = "invalid_payload"
	CodeUsernameInvalid      ErrorCode = "username_invalid"
	CodeUsernameTaken        ErrorCode = "username_taken"
	CodePowInvalid           ErrorCode = "pow_invalid"
	CodePowStale             ErrorCode = "pow_stale"
	CodeSignatureMissing     ErrorCode = "signature_missing"
	CodeSignatureInvalid     ErrorCode = "signature_invalid"
	CodeTimestampOutOfWindow ErrorCode = "timestamp_out_of_window"
	CodeNonceReplayed        ErrorCode = "nonce_replayed"
	CodeDeviceUnknown        ErrorCode = "device_unknown"
	CodeDeviceRevoked        ErrorCode = "device_revoked"
	CodeDeviceLimitReached   ErrorCode = "device_limit_reached"
	CodeForbidden            ErrorCode = "forbidden"
	CodeUserNotFound         ErrorCode = "user_not_found"
	CodePrekeyIDConflict     ErrorCode = "prekey_id_conflict"
	CodePrekeyLimitExceeded  ErrorCode = "prekey_limit_exceeded"
	CodeDeliveryTokenInvalid ErrorCode = "delivery_token_invalid"
	CodeDeliveryRejected     ErrorCode = "delivery_rejected"
	CodePayloadTooLarge      ErrorCode = "payload_too_large"
	CodeRateLimited          ErrorCode = "rate_limited"
	CodeInternalError        ErrorCode = "internal_error"
)

// HTTPStatus maps an error code to its HTTP status (§14).
func (c ErrorCode) HTTPStatus() int {
	switch c {
	case CodeUsernameTaken, CodeDeviceLimitReached, CodePrekeyIDConflict, CodePrekeyLimitExceeded:
		return http.StatusConflict
	case CodeDeliveryRejected, CodeForbidden, CodeDeliveryTokenInvalid:
		return http.StatusForbidden
	case CodeDeviceUnknown, CodeUserNotFound:
		return http.StatusNotFound
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case CodeSignatureMissing, CodeSignatureInvalid, CodeTimestampOutOfWindow, CodeNonceReplayed:
		return http.StatusUnauthorized
	case CodeInternalError:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// APIError is an error carrying a stable code and an HTTP status.
type APIError struct {
	Code    ErrorCode
	Message string
	Status  int
}

func (e *APIError) Error() string { return e.Message }

// Errorf builds an APIError with the code's default HTTP status.
func Errorf(code ErrorCode, format string, args ...any) *APIError {
	return &APIError{Code: code, Message: fmt.Sprintf(format, args...), Status: code.HTTPStatus()}
}

// ErrorResponse is the JSON error body (§14).
type ErrorResponse struct {
	V       string    `json:"v"`
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

// WriteJSON writes v as a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes an APIError as the §14 JSON error body.
func WriteError(w http.ResponseWriter, err error) {
	var ae *APIError
	if errors.As(err, &ae) {
		WriteJSON(w, ae.Status, ErrorResponse{V: Version, Code: ae.Code, Message: ae.Message})
		return
	}
	WriteJSON(w, http.StatusInternalServerError, ErrorResponse{
		V: Version, Code: CodeInternalError, Message: "internal_error",
	})
}

// AsAPIError unwraps err into an *APIError, or nil if it is not one.
func AsAPIError(err error) *APIError {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae
	}
	return nil
}
