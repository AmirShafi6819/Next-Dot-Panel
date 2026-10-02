package middleware

import (
	"context"
	"net/http"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
)

// Cookie names are part of the HTTP contract; the frontend reads the CSRF
// cookie directly, so the names are exported.
const (
	// SessionCookieName is the opaque session cookie. It is HttpOnly.
	SessionCookieName = "nextpanel_session"
	// CSRFCookieName is the readable double-submit token cookie. Enforcement
	// arrives with the CSRF middleware in a later phase; issuance is here so
	// the cookie is present from the first login.
	CSRFCookieName = "nextpanel_csrf"
)

type actorKey struct{}

// Authenticator resolves an opaque session token into an actor. It is
// satisfied by *auth.Service; the interface keeps this package from depending
// on the concrete service.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (auth.Actor, error)
}

// Session resolves the session cookie, when present, and attaches the actor to
// the request context. It never rejects a request: RequireAuth does that, so
// public endpoints can still see an optional actor.
func Session(a Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a != nil {
				if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
					if actor, err := a.Authenticate(r.Context(), cookie.Value); err == nil {
						r = r.WithContext(WithActor(r.Context(), actor))
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuth rejects unauthenticated requests with the standard envelope.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ActorFrom(r.Context()); !ok {
			dto.WriteError(w, r, http.StatusUnauthorized, "unauthenticated",
				"Authentication is required for this endpoint.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// WithActor returns a context carrying the authenticated actor.
func WithActor(ctx context.Context, actor auth.Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

// ActorFrom extracts the actor attached by Session.
func ActorFrom(ctx context.Context) (auth.Actor, bool) {
	actor, ok := ctx.Value(actorKey{}).(auth.Actor)
	return actor, ok
}
