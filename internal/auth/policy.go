package auth

import (
	"errors"
	"strings"
)

// MinPasswordLength is the policy floor (Design Spec section 11.1). Length
// beats composition: no symbol-class rules are imposed.
const MinPasswordLength = 12

// Password policy errors. They carry no user input, so they are safe to map
// onto an API error envelope.
var (
	ErrPasswordTooShort  = errors.New("auth: password is too short")
	ErrPasswordTooCommon = errors.New("auth: password is too common")
)

// ValidatePassword enforces the password policy: a minimum length and a
// rejection of the most common passwords. It deliberately allows password
// managers and paste, and imposes no arbitrary character-class requirements.
func ValidatePassword(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if _, common := commonPasswords[strings.ToLower(password)]; common {
		return ErrPasswordTooCommon
	}
	return nil
}
