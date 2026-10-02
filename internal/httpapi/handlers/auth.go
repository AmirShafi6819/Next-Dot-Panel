package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
)

// maxAuthBodyBytes caps request bodies on the auth endpoints. They carry a
// username and password, nothing larger.
const maxAuthBodyBytes = 4 << 10

// Auth serves the authentication and session endpoints (Design Spec §11, §13).
type Auth struct {
	Service *auth.Service
	Log     *logging.Logger
	// Secure marks the cookies Secure; it must be true whenever the panel is
	// served over HTTPS (production).
	Secure bool
}

// Login implements POST /api/v1/auth/login.
func (h *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request",
			"Both username and password are required.", nil)
		return
	}

	res, err := h.Service.Login(r.Context(), auth.LoginInput{
		Username:  req.Username,
		Password:  req.Password,
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: logging.RequestID(r.Context()),
	})
	if err != nil {
		h.writeAuthError(w, r, err)
		return
	}

	h.setSessionCookies(w, res.Token, res.CSRFToken, res.Session.ExpiresAt)

	actor := auth.Actor{UserID: res.User.ID, Username: res.User.Username, SessionID: res.Session.ID}
	warn := false
	if profile, perr := h.Service.Profile(r.Context(), actor); perr == nil {
		warn = profile.DefaultCredentialsWarning
	}
	dto.WriteJSON(w, http.StatusOK, dto.LoginResponse{
		User:                      dto.FromUser(res.User),
		Session:                   dto.FromSession(res.Session, res.Session.ID),
		CSRFToken:                 res.CSRFToken,
		DefaultCredentialsWarning: warn,
	})
}

// Logout implements POST /api/v1/auth/logout.
func (h *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.Logout(r.Context(), actor, h.meta(r)); err != nil {
		h.writeAuthError(w, r, err)
		return
	}
	h.clearSessionCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

// Me implements GET /api/v1/auth/me.
func (h *Auth) Me(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	profile, err := h.Service.Profile(r.Context(), actor)
	if err != nil {
		h.writeAuthError(w, r, err)
		return
	}
	perms := make([]string, 0, len(actor.Permissions))
	for _, p := range actor.Permissions {
		perms = append(perms, string(p))
	}
	dto.WriteJSON(w, http.StatusOK, dto.MeResponse{
		User:                      dto.FromUser(profile.User),
		Permissions:               perms,
		DefaultCredentialsWarning: profile.DefaultCredentialsWarning,
	})
}

// ChangePassword implements POST /api/v1/auth/password.
func (h *Auth) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req dto.ChangePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.ChangePassword(r.Context(), actor, req.CurrentPassword, req.NewPassword, h.meta(r)); err != nil {
		h.writeAuthError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Reauthenticate implements POST /api/v1/auth/reauth.
func (h *Auth) Reauthenticate(w http.ResponseWriter, r *http.Request) {
	var req dto.ReauthRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	at, err := h.Service.Reauthenticate(r.Context(), actor, req.Password, h.meta(r))
	if err != nil {
		h.writeAuthError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusOK, dto.ReauthResponse{ReauthAt: at})
}

// Sessions implements GET /api/v1/auth/sessions.
func (h *Auth) Sessions(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	sessions, err := h.Service.ListSessions(r.Context(), actor)
	if err != nil {
		h.writeAuthError(w, r, err)
		return
	}
	out := make([]dto.Session, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, dto.FromSession(s, actor.SessionID))
	}
	dto.WriteJSON(w, http.StatusOK, dto.SessionsResponse{Sessions: out})
}

// RevokeSession implements DELETE /api/v1/auth/sessions/{id}.
func (h *Auth) RevokeSession(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.Service.RevokeSession(r.Context(), actor, id, h.meta(r)); err != nil {
		h.writeAuthError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (h *Auth) setSessionCookies(w http.ResponseWriter, token, csrf string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- attributes are set below; Secure tracks the deployment scheme.
		Name:     middleware.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		MaxAge:   maxAge,
	})
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- deliberately readable by the frontend; Secure tracks the scheme.
		Name:     middleware.CSRFCookieName,
		Value:    csrf,
		Path:     "/",
		HttpOnly: false, // the frontend must read this one
		Secure:   h.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		MaxAge:   maxAge,
	})
}

func (h *Auth) clearSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{middleware.SessionCookieName, middleware.CSRFCookieName} {
		http.SetCookie(w, &http.Cookie{ // #nosec G124 -- clearing cookies; attributes mirror the set path.
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: name == middleware.SessionCookieName,
			Secure:   h.Secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
	}
}

func (h *Auth) meta(r *http.Request) auth.RequestMeta {
	return auth.RequestMeta{
		RequestID: logging.RequestID(r.Context()),
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
	}
}

// writeAuthError maps auth sentinel errors onto the error envelope. Anything
// unmapped is a 500 with a generic message; the detail is logged, not sent.
func (h *Auth) writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		dto.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials",
			"The username or password is incorrect.", nil)
	case errors.Is(err, auth.ErrUnauthenticated):
		dto.WriteError(w, r, http.StatusUnauthorized, "unauthenticated",
			"Authentication is required for this endpoint.", nil)
	case errors.Is(err, auth.ErrNotFound):
		dto.WriteError(w, r, http.StatusNotFound, "not_found",
			"The requested resource does not exist.", nil)
	case errors.Is(err, auth.ErrPasswordTooShort):
		dto.WriteError(w, r, http.StatusBadRequest, "password_too_short",
			"The new password is too short.", map[string]any{"min_length": auth.MinPasswordLength})
	case errors.Is(err, auth.ErrPasswordTooCommon):
		dto.WriteError(w, r, http.StatusBadRequest, "password_too_common",
			"That password is too common. Choose a less predictable one.", nil)
	case errors.Is(err, auth.ErrPasswordUnchanged):
		dto.WriteError(w, r, http.StatusBadRequest, "password_unchanged",
			"The new password must differ from the current one.", nil)
	default:
		if h.Log != nil {
			h.Log.Error(r.Context(), "auth request failed", "error", err)
		}
		dto.WriteError(w, r, http.StatusInternalServerError, "internal_error",
			"An internal error occurred.", nil)
	}
}

// decodeJSON reads a bounded JSON body, writing the standard error envelope on
// failure. It returns false when the response has already been written.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body := http.MaxBytesReader(w, r.Body, maxAuthBodyBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", "A JSON body is required.", nil)
			return false
		}
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", "The request body is not valid JSON.", nil)
		return false
	}
	return true
}

// clientIP extracts the peer address. Proxy headers are ignored until the
// trusted-proxy middleware lands: a spoofable X-Forwarded-For is worse than
// the socket address for login history.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
