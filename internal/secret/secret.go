// Package secret provides a string type that resists accidental disclosure.
//
// Design Spec §6.1: credential material is wrapped in Secret so that leaking it
// becomes a failing test or a compile-time error rather than a review
// oversight. Secret deliberately has no String, Format, or MarshalJSON
// methods; the only ways out are Reveal (explicit, greppable) and Redacted.
package secret

import (
	"errors"
	"fmt"
	"strings"
)

// redacted is what every incidental rendering of a Secret produces.
const redacted = "[REDACTED]"

// Secret holds sensitive material. The zero value is an empty secret.
type Secret struct {
	value string
	set   bool
}

// New wraps a plaintext string.
func New(v string) Secret {
	return Secret{value: v, set: true}
}

// NewBytes wraps a byte slice, taking a copy so later mutation of the caller's
// slice cannot alter the stored secret.
func NewBytes(v []byte) Secret {
	return Secret{value: string(v), set: true}
}

// Empty returns an unset secret.
func Empty() Secret { return Secret{} }

// IsSet reports whether a value is present, without revealing it.
func (s Secret) IsSet() bool { return s.set && s.value != "" }

// Reveal returns the plaintext. Callers should scope the result as narrowly as
// possible and never store it beyond the operation that needs it.
func (s Secret) Reveal() string { return s.value }

// RevealBytes returns the plaintext as a byte slice.
func (s Secret) RevealBytes() []byte { return []byte(s.value) }

// Len reports the length of the secret without revealing it.
func (s Secret) Len() int { return len(s.value) }

// String implements fmt.Stringer with a redacted value, so that any accidental
// formatting (including %v and %s) cannot leak the plaintext.
func (s Secret) String() string { return redacted }

// GoString covers %#v formatting.
func (s Secret) GoString() string { return redacted }

// MarshalJSON refuses to serialise. If a Secret ever reaches a response DTO,
// this fails loudly instead of silently publishing a credential.
func (s Secret) MarshalJSON() ([]byte, error) {
	return nil, errors.New("secret: refusing to marshal a Secret to JSON")
}

// MarshalText refuses to serialise into YAML, TOML, or similar encoders.
func (s Secret) MarshalText() ([]byte, error) {
	return nil, errors.New("secret: refusing to marshal a Secret to text")
}

// UnmarshalJSON allows decoding into a Secret (for request DTOs) while still
// preventing the reverse.
func (s *Secret) UnmarshalJSON(b []byte) error {
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		s.value = string(b[1 : len(b)-1])
		s.set = true
		return nil
	}
	return errors.New("secret: expected a JSON string")
}

// Clear overwrites the in-memory value. Go's garbage collector may already
// have copied the string, so this reduces but does not eliminate exposure; it
// is a defence-in-depth measure, not a guarantee.
func (s *Secret) Clear() {
	s.value = ""
	s.set = false
}

// Equal reports whether two secrets hold the same value without exposing
// either through a formatting path.
func (s Secret) Equal(other Secret) bool { return s.value == other.value }

// RedactKeys lists environment and field names whose values must never appear
// in logs. Matching is case-insensitive and substring-based so that
// "db_password", "PASSWORD_HASH", and "sshPrivateKey" are all caught.
var RedactKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"private_key",
	"privatekey",
	"authorization",
	"cookie",
	"credential",
	"encryption_key",
	"passphrase",
	"api_key",
	"apikey",
}

// LooksSensitive reports whether a field name should be redacted in log output.
func LooksSensitive(fieldName string) bool {
	name := strings.ToLower(fieldName)
	for _, k := range RedactKeys {
		if strings.Contains(name, k) {
			return true
		}
	}
	return false
}

// Redact replaces a value with a placeholder when the field name looks
// sensitive. It is used by the logging layer for free-form attributes.
func Redact(fieldName, value string) string {
	if LooksSensitive(fieldName) {
		return redacted
	}
	return value
}

// Format renders a secret for display, optionally showing a short prefix so an
// operator can identify which key is configured without exposing it.
func (s Secret) Format(showPrefix int) string {
	if !s.IsSet() {
		return "(unset)"
	}
	if showPrefix <= 0 || showPrefix >= len(s.value) {
		return redacted
	}
	return fmt.Sprintf("%s… (%d bytes)", s.value[:showPrefix], len(s.value))
}
