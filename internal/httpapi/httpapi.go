// Package httpapi wires the HTTP surface: router, middleware, and the
// readiness probes (Design Spec §25.3, §33.4).
package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/handlers"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
)

// Deps are the wiring inputs for the router.
type Deps struct {
	Config *config.Config
	DB     *store.DB
	Log    *logging.Logger
	// Auth is the authentication service. When nil the auth routes are not
	// mounted, so the health surface can be exercised without a database user
	// store.
	Auth *auth.Service
	// Readiness collects the probes behind /ready. When nil a fresh set is
	// created, so a caller that wants to register its own probe passes one in.
	Readiness *handlers.Readiness
}

// New builds the process's HTTP handler.
//
// The middleware order matters: RequestID outermost so everything downstream
// is correlated, then AccessLog, then Recover innermost so a recovered panic
// still produces a correctly logged status.
func New(deps Deps) http.Handler {
	readiness := deps.Readiness
	if readiness == nil {
		readiness = &handlers.Readiness{}
	}
	registerCoreReadiness(readiness, deps.DB)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.AccessLog(deps.Log))
	r.Use(middleware.Recover(deps.Log))

	health := handlers.Health{}
	version := handlers.Version{}
	ready := &handlers.Ready{Readiness: readiness, Log: deps.Log, Timeout: 5 * time.Second}

	r.Get("/health", health.ServeHTTP)
	r.Get("/ready", ready.ServeHTTP)
	r.Get("/version", version.ServeHTTP)

	if deps.Auth != nil {
		registerAuthRoutes(r, deps)
	}

	// Unmatched routes answer with the standard envelope rather than chi's
	// plain text, so clients never see two error shapes.
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		dto.WriteError(w, req, http.StatusNotFound, "not_found", "The requested endpoint does not exist.", nil)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		dto.WriteError(w, req, http.StatusMethodNotAllowed, "method_not_allowed", "That method is not supported for this endpoint.", nil)
	})
	return r
}

// registerAuthRoutes mounts the authentication and session endpoints under
// /api/v1/auth. Session resolution is mounted for the whole subtree so public
// handlers (login) and protected handlers share it; RequireAuth guards the
// endpoints that need an actor.
func registerAuthRoutes(r chi.Router, deps Deps) {
	h := &handlers.Auth{
		Service: deps.Auth,
		Log:     deps.Log,
		Secure:  deps.Config != nil && deps.Config.Env == config.EnvProduction,
	}
	r.Route("/api/v1/auth", func(rt chi.Router) {
		rt.Use(middleware.Session(deps.Auth))
		rt.Post("/login", h.Login)

		rt.Group(func(rt chi.Router) {
			rt.Use(middleware.RequireAuth)
			rt.Post("/logout", h.Logout)
			rt.Post("/password", h.ChangePassword)
			rt.Post("/reauth", h.Reauthenticate)
			rt.Get("/me", h.Me)
			rt.Get("/sessions", h.Sessions)
			rt.Delete("/sessions/{id}", h.RevokeSession)
		})
	})
}

// registerCoreReadiness adds the checks every deployment needs: the database
// answers, and the schema is fully migrated (Design Spec §33.4). The worker
// pool registers its own check when it starts — this package must not depend
// on packages that do not exist yet.
func registerCoreReadiness(r *handlers.Readiness, db *store.DB) {
	r.Register(handlers.Check{
		Name: "database",
		Probe: func(ctx context.Context) error {
			if db == nil {
				return fmt.Errorf("database is not configured")
			}
			return db.Ping(ctx)
		},
	})
	r.Register(handlers.Check{
		Name: "migrations",
		Probe: func(ctx context.Context) error {
			if db == nil {
				return fmt.Errorf("database is not configured")
			}
			status, err := store.MigrationStatus(ctx, db)
			if err != nil {
				return err
			}
			for _, m := range status {
				if !m.Applied {
					return fmt.Errorf("migration %d is not applied", m.Version)
				}
			}
			return nil
		},
	})
}
