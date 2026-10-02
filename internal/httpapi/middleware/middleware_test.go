package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
)

func TestRequestIDIsOursNotTheCallers(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = logging.RequestID(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-ID", "client-supplied-value")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if seen == "" {
		t.Fatal("no request id in the context")
	}
	if seen == "client-supplied-value" {
		t.Fatal("a caller-supplied request id was accepted")
	}
	if got := rec.Header().Get("X-Request-ID"); got != seen {
		t.Fatalf("header = %q, context = %q", got, seen)
	}
	if len(seen) != 32 {
		t.Fatalf("request id = %q, want 32 hex characters", seen)
	}
}

func TestRecoverTurnsPanicIntoEnvelopeWithoutTheStack(t *testing.T) {
	out := &safeBuffer{}
	log := logging.New(out, "text", "DEBUG")
	h := Recover(log)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("kaboom")
	}))
	h = RequestID(h)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"code":"internal_error"`) {
		t.Fatalf("body = %s", body)
	}
	if !strings.Contains(body, "request_id") {
		t.Fatalf("body = %s", body)
	}
	if strings.Contains(body, "goroutine") || strings.Contains(body, "kaboom") {
		t.Fatalf("body leaks panic detail: %s", body)
	}
	if !strings.Contains(out.String(), "panic recovered") {
		t.Fatalf("panic was not logged: %s", out.String())
	}
}

func TestAccessLogDropsTheQueryString(t *testing.T) {
	out := &safeBuffer{}
	log := logging.New(out, "text", "DEBUG")
	// RequestID is outermost in the real stack (httpapi.New), so the access
	// log sees the id it must record.
	h := RequestID(AccessLog(log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers?ticket=super-secret", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	logged := out.String()
	if !strings.Contains(logged, "path=/api/v1/servers") {
		t.Fatalf("path missing from the access log: %s", logged)
	}
	if !strings.Contains(logged, "status=200") {
		t.Fatalf("status missing from the access log: %s", logged)
	}
	if !strings.Contains(logged, "request_id=") {
		t.Fatalf("request_id missing from the access log: %s", logged)
	}
	if strings.Contains(logged, "super-secret") {
		t.Fatalf("query string leaked into the access log: %s", logged)
	}
}

// safeBuffer is a concurrency-safe io.Writer for log capture in tests.
type safeBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
