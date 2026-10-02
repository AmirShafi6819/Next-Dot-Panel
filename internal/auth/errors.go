package auth

import "errors"

// Sentinel errors. The HTTP layer maps these onto error codes and statuses;
// nothing else in the codebase should string-match them.
var (
	// ErrInvalidCredentials is returned for every failed login, regardless of
	// whether the username exists, the password was wrong, or the account is
	// disabled. The distinction is never exposed (Design Spec section 11.3).
	ErrInvalidCredentials = errors.New("auth: invalid credentials")

	// ErrUnauthenticated is returned when a session token is missing, unknown,
	// expired, idle-expired or revoked.
	ErrUnauthenticated = errors.New("auth: not authenticated")

	// ErrNotFound is returned when an object does not exist, or exists but is
	// not visible to the actor. Both cases are deliberately indistinguishable
	// so a caller cannot probe for other users' session ids (IDOR).
	ErrNotFound = errors.New("auth: not found")

	// ErrPasswordUnchanged is returned when a password change repeats the
	// current password.
	ErrPasswordUnchanged = errors.New("auth: new password matches the current password")

	// ErrPasswordHash indicates a stored hash that cannot be parsed. It is an
	// internal fault, never a user error.
	ErrPasswordHash = errors.New("auth: stored password hash is unusable")
)
