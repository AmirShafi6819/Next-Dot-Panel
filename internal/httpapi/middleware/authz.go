package middleware

import (
	"context"
	"net/http"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
)

// Authorizer resolves whether an actor holds a permission. It is satisfied by
// *rbac.Service; the interface keeps this package decoupled from the concrete
// authorization implementation.
type Authorizer interface {
	Require(ctx context.Context, actor auth.Actor, perm domain.Permission, serverID *domain.ServerID) error
}

// RequirePermission rejects an actor who lacks perm with a 403 envelope. A
// missing actor is a 401, so the middleware is safe even when it is the first
// guard on a route.
func RequirePermission(authz Authorizer, perm domain.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actor, ok := ActorFrom(r.Context())
			if !ok {
				dto.WriteError(w, r, http.StatusUnauthorized, "unauthenticated",
					"Authentication is required for this endpoint.", nil)
				return
			}
			if err := authz.Require(r.Context(), actor, perm, nil); err != nil {
				dto.WriteError(w, r, http.StatusForbidden, "forbidden",
					"You do not have permission to perform this action.", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
