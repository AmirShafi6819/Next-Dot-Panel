package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Session tokens are opaque 256-bit values from crypto/rand. Only their
// SHA-256 is stored, so a database leak does not yield usable tokens
// (Design Spec section 11.4).
const sessionTokenBytes = 32

// sessionIDBytes is the random part of a session id; the id is not secret
// (it appears in URLs and audit records) but must be unguessable enough that
// it cannot be enumerated.
const sessionIDBytes = 16

// csrfTokenBytes is the double-submit CSRF token size.
const csrfTokenBytes = 32

var tokenEncoding = base64.RawURLEncoding

// newSessionToken returns a fresh opaque token and the SHA-256 hash to store.
func newSessionToken() (token string, hash []byte, err error) {
	buf := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("auth: generate session token: %w", err)
	}
	token = tokenEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// hashSessionToken hashes a presented token for lookup.
func hashSessionToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// newSessionID returns a session identifier such as ses_<random>.
func newSessionID() (string, error) {
	buf := make([]byte, sessionIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate session id: %w", err)
	}
	return "ses_" + tokenEncoding.EncodeToString(buf), nil
}

// newCSRFToken returns a fresh double-submit token. The token is not secret in
// the same sense as a session token; it only has to be unpredictable and
// compared server-side against the cookie echo (Design Spec section 28.2).
func newCSRFToken() (string, error) {
	buf := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate csrf token: %w", err)
	}
	return tokenEncoding.EncodeToString(buf), nil
}
