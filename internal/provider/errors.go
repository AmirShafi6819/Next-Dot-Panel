package provider

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable, safe-to-display error category (Design Spec §8.5).
// Raw transport errors never reach the client; the code does.
type ErrorCode string

const (
	CodeDNS                ErrorCode = "DNS_ERROR"
	CodeNetworkUnreachable ErrorCode = "NETWORK_UNREACHABLE"
	CodeTimeout            ErrorCode = "TIMEOUT"
	CodeAuthentication     ErrorCode = "AUTHENTICATION_FAILED"
	CodeHostKeyMismatch    ErrorCode = "HOST_KEY_MISMATCH"
	CodeHostKeyUnknown     ErrorCode = "HOST_KEY_UNKNOWN"
	CodePermissionDenied   ErrorCode = "PERMISSION_DENIED"
	CodeServerOffline      ErrorCode = "SERVER_OFFLINE"
	CodeInvalidConfig      ErrorCode = "INVALID_CONFIGURATION"
	CodeProtocol           ErrorCode = "PROTOCOL_ERROR"
	CodeResourceExhausted  ErrorCode = "RESOURCE_EXHAUSTED"
	CodeUnsupported        ErrorCode = "UNSUPPORTED"
	CodeUnknown            ErrorCode = "UNKNOWN_ERROR"
)

// Error wraps a provider failure with a stable code.
type Error struct {
	Code ErrorCode
	Op   string
	Err  error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("provider: %s: %s", e.Op, e.Code)
	}
	return fmt.Sprintf("provider: %s: %s: %v", e.Op, e.Code, e.Err)
}

// Unwrap exposes the underlying error for errors.Is/As.
func (e *Error) Unwrap() error { return e.Err }

// NewError builds a coded provider error.
func NewError(code ErrorCode, op string, err error) *Error {
	return &Error{Code: code, Op: op, Err: err}
}

// CodeOf extracts the code from an error, defaulting to UNKNOWN_ERROR.
func CodeOf(err error) ErrorCode {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	var hk *HostKeyError
	if errors.As(err, &hk) {
		return hk.Code
	}
	return CodeUnknown
}

// HostKeyError is returned when host-key verification fails. It carries the
// fingerprint so the UI can present a trust prompt, and never the key material
// of a different host.
type HostKeyError struct {
	Code        ErrorCode // CodeHostKeyUnknown or CodeHostKeyMismatch
	Host        string
	Algorithm   string // key type, e.g. ssh-ed25519
	Fingerprint string // SHA256:<base64> of the presented key
	Expected    string // SHA256:<base64> of the pinned key, for a mismatch
	PublicKey   []byte // marshaled presented key, for an explicit trust step
}

// Error implements the error interface.
func (e *HostKeyError) Error() string {
	if e.Code == CodeHostKeyMismatch {
		return fmt.Sprintf("provider: host key mismatch for %s: expected %s, got %s", e.Host, e.Expected, e.Fingerprint)
	}
	return fmt.Sprintf("provider: unknown host key for %s: %s", e.Host, e.Fingerprint)
}

// IsUnknownHostKey reports whether err is an unknown-host-key failure.
func IsUnknownHostKey(err error) bool {
	var hk *HostKeyError
	return errors.As(err, &hk) && hk.Code == CodeHostKeyUnknown
}

// IsHostKeyMismatch reports whether err is a changed-host-key failure.
func IsHostKeyMismatch(err error) bool {
	var hk *HostKeyError
	return errors.As(err, &hk) && hk.Code == CodeHostKeyMismatch
}
