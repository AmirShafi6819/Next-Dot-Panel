// Package httpapi wires the HTTP surface: router, middleware, and the
// readiness probes (Design Spec §25.3, §33.4).
package httpapi

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/files"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/handlers"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/metrics"
	"github.com/ashaibery/Next-Dot-Panel/internal/processes"
	"github.com/ashaibery/Next-Dot-Panel/internal/rbac"
	"github.com/ashaibery/Next-Dot-Panel/internal/server"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/terminal"
	"github.com/ashaibery/Next-Dot-Panel/internal/users"
	frontend "github.com/ashaibery/Next-Dot-Panel/web"
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
	// RBAC is the authorization and role-administration service. When nil the
	// RBAC routes are not mounted.
	RBAC *rbac.Service
	// Servers is the managed-server service. When nil the server routes are not
	// mounted.
	Servers *server.Service
	// Terminal is the interactive-terminal manager. When nil the terminal
	// route is not mounted.
	Terminal *terminal.Manager
	// Files is the remote file service. When nil the file routes are not
	// mounted.
	Files *files.Service
	// Users administers accounts. When nil the user routes are not mounted.
	Users *users.Service
	// AuditQuery reads the audit trail. When nil the audit route is absent.
	AuditQuery *audit.Query
	// Metrics serves resource monitoring. When nil the metrics routes are
	// absent.
	Metrics *metrics.Service
	// Processes manages remote processes. When nil those routes are absent.
	Processes *processes.Service
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
	scheme := "http"
	if deps.Config != nil {
		scheme = deps.Config.App.ExternalScheme
	}
	r.Use(middleware.SecurityHeaders(scheme))

	health := handlers.Health{}
	version := handlers.Version{}
	ready := &handlers.Ready{Readiness: readiness, Log: deps.Log, Timeout: 5 * time.Second}

	r.Get("/health", health.ServeHTTP)
	r.Get("/ready", ready.ServeHTTP)
	r.Get("/version", version.ServeHTTP)

	if deps.Auth != nil {
		registerAuthRoutes(r, deps)
	}
	if deps.RBAC != nil {
		registerRBACRoutes(r, deps)
	}
	if deps.Servers != nil {
		registerServerRoutes(r, deps)
	}
	if deps.Terminal != nil {
		registerTerminalRoutes(r, deps)
	}
	if deps.Files != nil {
		registerFilesRoutes(r, deps)
	}
	if deps.Users != nil {
		registerUserRoutes(r, deps)
	}
	if deps.AuditQuery != nil {
		registerAuditRoutes(r, deps)
	}
	if deps.Metrics != nil || deps.Processes != nil {
		registerOpsRoutes(r, deps)
	}

	// Unmatched routes answer with the standard envelope rather than chi's
	// plain text, so clients never see two error shapes.
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		dto.WriteError(w, req, http.StatusNotFound, "not_found", "The requested endpoint does not exist.", nil)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		dto.WriteError(w, req, http.StatusMethodNotAllowed, "method_not_allowed", "That method is not supported for this endpoint.", nil)
	})

	// The embedded single-page application, served for browser navigation.
	// API clients keep the JSON envelope (see serveUI).
	r.Get("/*", serveUI)
	return r
}

// serveUI serves the embedded frontend with an SPA fallback. Requests that
// accept HTML (browsers) receive index.html for unknown paths; API clients
// keep the standard error envelope so automated clients never parse HTML.
func serveUI(w http.ResponseWriter, req *http.Request) {
	p := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(req.URL.Path, "/")), "/")
	if strings.HasPrefix(p, "api/") || p == "health" || p == "ready" || p == "version" {
		dto.WriteError(w, req, http.StatusNotFound, "not_found", "The requested endpoint does not exist.", nil)
		return
	}
	if p == "" {
		p = "index.html"
	}
	if data, err := frontend.Dist.ReadFile("dist/" + p); err == nil {
		if ct := mime.TypeByExtension(path.Ext(p)); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data) // #nosec G705 -- data is the panel's own built frontend, not user input.
		return
	}
	if strings.Contains(req.Header.Get("Accept"), "text/html") {
		if index, err := frontend.Dist.ReadFile("dist/index.html"); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(index)
			return
		}
	}
	dto.WriteError(w, req, http.StatusNotFound, "not_found", "The requested endpoint does not exist.", nil)
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
		rt.Post("/login", rateLimitedLogin(deps, h))

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

// rateLimitedLogin wraps the login handler with a fixed-window limiter so
// brute-force password guessing is throttled per client address. The limit
// comes from configuration; a non-positive value disables it.
func rateLimitedLogin(deps Deps, h *handlers.Auth) http.HandlerFunc {
	login := http.HandlerFunc(h.Login)
	if deps.Config == nil || deps.Config.Security.RateLimitAuth <= 0 {
		return login.ServeHTTP
	}
	limiter := middleware.NewRateLimiter(deps.Config.Security.RateLimitAuth, deps.Config.Security.RateLimitAuthWnd)
	return middleware.Limit(limiter, middleware.ClientIPKey)(login).ServeHTTP
}

// registerRBACRoutes mounts role and permission administration under
// /api/v1. Every route requires a session and the permission named on it, so
// authorization is enforced by the router, not only inside the service.
func registerRBACRoutes(r chi.Router, deps Deps) {
	h := &handlers.RBAC{Service: deps.RBAC, Log: deps.Log}
	r.Route("/api/v1", func(rt chi.Router) {
		rt.Use(middleware.Session(deps.Auth))
		rt.Use(middleware.RequireAuth)

		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersRead)).Get("/permissions", h.ListPermissions)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersRead)).Get("/roles", h.ListRoles)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersRead)).Get("/roles/{id}", h.GetRole)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersManage)).Post("/roles", h.CreateRole)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersManage)).Patch("/roles/{id}", h.UpdateRole)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersManage)).Delete("/roles/{id}", h.DeleteRole)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersManage)).Put("/roles/{id}/permissions", h.SetRolePermissions)

		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersRead)).Get("/users/{id}/roles", h.ListUserRoles)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersManage)).Put("/users/{id}/roles", h.SetUserRoles)
	})
}

// registerServerRoutes mounts the managed-server endpoints. Object-level
// authorization (including 404 for invisible servers) lives in the service, so
// the router only requires an authenticated session.
func registerServerRoutes(r chi.Router, deps Deps) {
	h := &handlers.Servers{Service: deps.Servers, Log: deps.Log}
	r.Group(func(rt chi.Router) {
		rt.Use(middleware.Session(deps.Auth))
		rt.Use(middleware.RequireAuth)
		rt.Get("/api/v1/servers", h.List)
		rt.Post("/api/v1/servers", h.Create)
		rt.Get("/api/v1/servers/{id}", h.Get)
		rt.Patch("/api/v1/servers/{id}", h.Update)
		rt.Delete("/api/v1/servers/{id}", h.Delete)
		rt.Post("/api/v1/servers/{id}/test", h.TestConnection)
		rt.Get("/api/v1/servers/{id}/hostkeys", h.ListHostKeys)
		rt.Post("/api/v1/servers/{id}/hostkeys/trust", h.TrustHostKey)
	})
}

// registerTerminalRoutes mounts the interactive-terminal WebSocket. The
// session middleware resolves the cookie before the upgrade, and the manager
// enforces the terminal.open permission on the target server.
func registerTerminalRoutes(r chi.Router, deps Deps) {
	var origins []string
	if deps.Config != nil {
		origins = deps.Config.Security.AllowedOrigins
	}
	h := &handlers.Terminal{Manager: deps.Terminal, Log: deps.Log, OriginPatterns: origins}
	r.Group(func(rt chi.Router) {
		rt.Use(middleware.Session(deps.Auth))
		rt.Use(middleware.RequireAuth)
		rt.Get("/api/v1/servers/{id}/terminal", h.ServeHTTP)
	})
}

// registerFilesRoutes mounts remote file management. Authorization is
// object-level in the service, so the router only requires a session.
func registerFilesRoutes(r chi.Router, deps Deps) {
	h := &handlers.Files{Service: deps.Files, Log: deps.Log}
	r.Group(func(rt chi.Router) {
		rt.Use(middleware.Session(deps.Auth))
		rt.Use(middleware.RequireAuth)
		rt.Get("/api/v1/servers/{id}/files", h.List)
		rt.Get("/api/v1/servers/{id}/files/stat", h.Stat)
		rt.Get("/api/v1/servers/{id}/files/content", h.Download)
		rt.Put("/api/v1/servers/{id}/files/content", h.Upload)
		rt.Post("/api/v1/servers/{id}/files/mkdir", h.Mkdir)
		rt.Post("/api/v1/servers/{id}/files/rename", h.Rename)
		rt.Post("/api/v1/servers/{id}/files/delete", h.Delete)
		rt.Post("/api/v1/servers/{id}/files/extract", h.Extract)
	})
}

// registerUserRoutes mounts account administration. The RBAC service is
// required to guard these routes; the user service rechecks every call.
func registerUserRoutes(r chi.Router, deps Deps) {
	h := &handlers.Users{Service: deps.Users, Log: deps.Log}
	r.Group(func(rt chi.Router) {
		rt.Use(middleware.Session(deps.Auth))
		rt.Use(middleware.RequireAuth)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersRead)).Get("/api/v1/users", h.List)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersManage)).Post("/api/v1/users", h.Create)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersRead)).Get("/api/v1/users/{id}", h.Get)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersManage)).Patch("/api/v1/users/{id}", h.Update)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersManage)).Delete("/api/v1/users/{id}", h.Delete)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersManage)).Post("/api/v1/users/{id}/reset-password", h.ResetPassword)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersManage)).Post("/api/v1/users/{id}/revoke-sessions", h.RevokeSessions)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermUsersRead)).Get("/api/v1/users/{id}/login-history", h.LoginHistory)
	})
}

// registerAuditRoutes mounts the read-only audit trail.
func registerAuditRoutes(r chi.Router, deps Deps) {
	h := &handlers.Audit{Query: deps.AuditQuery, Log: deps.Log}
	r.Group(func(rt chi.Router) {
		rt.Use(middleware.Session(deps.Auth))
		rt.Use(middleware.RequireAuth)
		rt.With(middleware.RequirePermission(deps.RBAC, domain.PermAuditRead)).Get("/api/v1/audit", h.List)
	})
}

// registerOpsRoutes mounts per-server monitoring and process management.
// Object-level authorization lives in the services.
func registerOpsRoutes(r chi.Router, deps Deps) {
	r.Group(func(rt chi.Router) {
		rt.Use(middleware.Session(deps.Auth))
		rt.Use(middleware.RequireAuth)
		if deps.Metrics != nil {
			mh := &handlers.Metrics{Service: deps.Metrics, Log: deps.Log}
			rt.Get("/api/v1/servers/{id}/metrics/latest", mh.Latest)
			rt.Get("/api/v1/servers/{id}/metrics", mh.Range)
			rt.Post("/api/v1/servers/{id}/metrics/collect", mh.Collect)
		}
		if deps.Processes != nil {
			ph := &handlers.Processes{Service: deps.Processes, Log: deps.Log}
			rt.Get("/api/v1/servers/{id}/processes", ph.List)
			rt.Post("/api/v1/servers/{id}/processes/{pid}/signal", ph.Signal)
		}
		if deps.Metrics != nil && deps.Servers != nil {
			eh := &handlers.Events{Metrics: deps.Metrics, Servers: deps.Servers, Log: deps.Log}
			rt.Get("/api/v1/servers/{id}/events", eh.ServeHTTP)
		}
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
