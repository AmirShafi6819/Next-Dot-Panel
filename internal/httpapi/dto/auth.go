package dto

import (
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
)

// LoginRequest is POST /api/v1/auth/login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// User is the public projection of an account. It never carries a password
// hash or any credential material.
type User struct {
	ID                 int64      `json:"id"`
	Username           string     `json:"username"`
	DisplayName        string     `json:"display_name"`
	IsActive           bool       `json:"is_active"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}

// FromUser projects a domain user onto the wire format.
func FromUser(u domain.User) User {
	return User{
		ID:                 int64(u.ID),
		Username:           u.Username,
		DisplayName:        u.DisplayName,
		IsActive:           u.IsActive,
		MustChangePassword: u.MustChangePassword,
		LastLoginAt:        u.LastLoginAt,
		CreatedAt:          u.CreatedAt,
	}
}

// Session is the public projection of a session.
type Session struct {
	ID         string     `json:"id"`
	IP         string     `json:"ip,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ReauthAt   *time.Time `json:"reauth_at,omitempty"`
	// Current marks the session making the request.
	Current bool `json:"current"`
}

// FromSession projects a domain session onto the wire format. currentSessionID
// is the caller's own session id, used to set Current.
func FromSession(s domain.Session, currentSessionID string) Session {
	return Session{
		ID:         s.ID,
		IP:         s.IP,
		UserAgent:  s.UserAgent,
		CreatedAt:  s.CreatedAt,
		LastSeenAt: s.LastSeenAt,
		ExpiresAt:  s.ExpiresAt,
		ReauthAt:   s.ReauthAt,
		Current:    s.ID == currentSessionID,
	}
}

// LoginResponse is returned by a successful login. The CSRF token is also set
// as a cookie; it is echoed here for clients that prefer to read the body.
type LoginResponse struct {
	User                      User    `json:"user"`
	Session                   Session `json:"session"`
	CSRFToken                 string  `json:"csrf_token"`
	DefaultCredentialsWarning bool    `json:"default_credentials_warning"`
}

// MeResponse is GET /api/v1/auth/me.
type MeResponse struct {
	User                      User     `json:"user"`
	Permissions               []string `json:"permissions"`
	DefaultCredentialsWarning bool     `json:"default_credentials_warning"`
}

// SessionsResponse is GET /api/v1/auth/sessions.
type SessionsResponse struct {
	Sessions []Session `json:"sessions"`
}

// ChangePasswordRequest is POST /api/v1/auth/password. The current password is
// required: a sensitive change is always re-authenticated.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ReauthRequest is POST /api/v1/auth/reauth.
type ReauthRequest struct {
	Password string `json:"password"`
}

// ReauthResponse is returned after a successful re-authentication.
type ReauthResponse struct {
	ReauthAt time.Time `json:"reauth_at"`
}
