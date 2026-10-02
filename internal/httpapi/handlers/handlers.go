// Package handlers contains the thin, per-domain HTTP handlers. They decode,
// validate, call a service, and encode — no business logic (Design Spec §5).
package handlers

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/version"
)

// Check is one readiness probe. A non-nil error marks the service not ready;
// the error itself is logged and never returned to the caller (Design Spec
// §33.4: readiness exposes no configuration, paths, or dependencies).
type Check struct {
	Name  string
	Probe func(ctx context.Context) error
}

// Readiness is the set of probes behind /ready. It is safe for concurrent
// use so probes can register their checks as their subsystems start.
type Readiness struct {
	mu     sync.RWMutex
	checks []Check
}

// Register adds a probe. Registering after startup is allowed; the next probe
// call includes it.
func (r *Readiness) Register(c Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks = append(r.checks, c)
}

// Checks returns a copy of the current probes.
func (r *Readiness) Checks() []Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Check, len(r.checks))
	copy(out, r.checks)
	return out
}

// Health is the liveness endpoint: 200 while the process is running, with no
// dependency checks at all (Design Spec §33.4).
type Health struct{}

// ServeHTTP implements GET /health.
func (Health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dto.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Version is the build-metadata endpoint (Design Spec §33.4). It reports the
// build only — never configuration, never the environment.
type Version struct{}

// ServeHTTP implements GET /version.
func (Version) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dto.WriteJSON(w, http.StatusOK, version.Current())
}

// Ready reports readiness: 200 only when every probe passes, 503 otherwise
// (Design Spec §33.4, §26.4).
type Ready struct {
	Readiness *Readiness
	Log       *logging.Logger
	Timeout   time.Duration
}

// ServeHTTP implements GET /ready.
func (h *Ready) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	var failed []string
	for _, c := range h.Readiness.Checks() {
		if err := c.Probe(ctx); err != nil {
			failed = append(failed, c.Name)
			if h.Log != nil {
				// The reason never reaches the client; it reaches the log,
				// correlated by the same request_id.
				h.Log.Error(ctx, "readiness check failed", "check", c.Name, "error", err)
			}
		}
	}
	if len(failed) > 0 {
		dto.WriteError(w, r, http.StatusServiceUnavailable, "not_ready",
			"The service is not ready to accept traffic.",
			map[string]any{"checks": failed})
		return
	}
	dto.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
