package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/handlers"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
)

// newTestRouter builds a router over a migrated SQLite database, which is
// what the process runs against in development.
func newTestRouter(t *testing.T, deps httpapi.Deps) (http.Handler, *store.DB, string) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := &config.Config{
		Env: config.EnvDevelopment,
		App: config.App{
			Env:            config.EnvDevelopment,
			DataDir:        dataDir,
			LogLevel:       "ERROR",
			LogFormat:      "text",
			ExternalScheme: "http",
		},
		Database: config.Database{
			Driver:     config.DriverSQLite,
			SQLitePath: filepath.Join(dataDir, "test.db"),
			MaxConns:   1,
		},
	}
	db, err := store.Open(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(context.Background(), db, nil); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	deps.Config = cfg
	deps.DB = db
	if deps.Log == nil {
		deps.Log = logging.New(&syncBuffer{}, "text", "ERROR")
	}
	return httpapi.New(deps), db, dataDir
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestHealthIsLivenessOnly(t *testing.T) {
	h, _, _ := newTestRouter(t, httpapi.Deps{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID missing")
	}
}

func TestReadyReportsReadyAfterMigrations(t *testing.T) {
	h, _, _ := newTestRouter(t, httpapi.Deps{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"ready"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestReadyReports503WithoutLeakingTheReason(t *testing.T) {
	readiness := &handlers.Readiness{}
	readiness.Register(handlers.Check{
		Name: "storage",
		Probe: func(context.Context) error {
			return &pathError{msg: "open /srv/panel/secret/backup.sql: permission denied"}
		},
	})
	h, _, _ := newTestRouter(t, httpapi.Deps{Readiness: readiness})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
			Details   struct {
				Checks []string `json:"checks"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("body is not the error envelope: %v (%s)", err, body)
	}
	if envelope.Error.Code != "not_ready" {
		t.Fatalf("code = %q, want not_ready", envelope.Error.Code)
	}
	if envelope.Error.RequestID == "" {
		t.Fatal("envelope is missing request_id")
	}
	if len(envelope.Error.Details.Checks) != 1 || envelope.Error.Details.Checks[0] != "storage" {
		t.Fatalf("checks = %v, want [storage]", envelope.Error.Details.Checks)
	}
	if strings.Contains(body, "/srv/panel") || strings.Contains(body, "permission denied") {
		t.Fatalf("503 body leaks the failure reason: %s", body)
	}
}

func TestVersionExposesNoConfiguration(t *testing.T) {
	h, _, dataDir := newTestRouter(t, httpapi.Deps{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{dataDir, "NEXT_PANEL", "://"} {
		if strings.Contains(body, leak) {
			t.Fatalf("/version leaks %q: %s", leak, body)
		}
	}
	var info struct {
		Version   string `json:"version"`
		BuildDate string `json:"build_date"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("/version body is not JSON: %v (%s)", err, body)
	}
	if info.Version == "" {
		t.Fatal("version is empty")
	}
}

func TestUnknownRouteUsesTheErrorEnvelope(t *testing.T) {
	h, _, _ := newTestRouter(t, httpapi.Deps{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"code":"not_found"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "request_id") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestMethodNotAllowedUsesTheErrorEnvelope(t *testing.T) {
	h, _, _ := newTestRouter(t, httpapi.Deps{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/health", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"code":"method_not_allowed"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestAccessLogCarriesTheResponseRequestId(t *testing.T) {
	out := &syncBuffer{}
	dataDir := t.TempDir()
	cfg := &config.Config{
		Env:      config.EnvDevelopment,
		App:      config.App{Env: config.EnvDevelopment, DataDir: dataDir, LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{Driver: config.DriverSQLite, SQLitePath: filepath.Join(dataDir, "test.db"), MaxConns: 1},
	}
	db, err := store.Open(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(context.Background(), db, nil); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := httpapi.New(httpapi.Deps{Config: cfg, DB: db, Log: logging.New(out, "text", "DEBUG")})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	id := rec.Header().Get("X-Request-ID")
	if id == "" {
		t.Fatal("X-Request-ID missing")
	}
	if !strings.Contains(out.String(), "request_id="+id) {
		t.Fatalf("access log does not carry the response's request id %q: %s", id, out.String())
	}
}

// pathError is an error carrying a filesystem path, used to prove readiness
// failures never reach the client.
type pathError struct{ msg string }

func (e *pathError) Error() string { return e.msg }
