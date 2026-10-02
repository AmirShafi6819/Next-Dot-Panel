package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func newTestLogger(buf *bytes.Buffer) *Logger {
	return New(buf, "json", "DEBUG")
}

func TestRedactsSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	log := newTestLogger(&buf)

	log.Info(context.Background(), "connect",
		"server", "203.0.113.10",
		"password", "hunter2",
		"api_token", "npx_abcdef",
		"private_key", "-----BEGIN OPENSSH PRIVATE KEY-----",
		"passphrase", "letmein",
		"db_password", "pgsecret",
		"Authorization", "Bearer abc.def",
	)

	out := buf.String()
	for _, leaked := range []string{"hunter2", "npx_abcdef", "BEGIN OPENSSH", "letmein", "pgsecret", "Bearer abc.def"} {
		if strings.Contains(out, leaked) {
			t.Errorf("log output leaked %q:\n%s", leaked, out)
		}
	}
	if strings.Count(out, "[REDACTED]") != 6 {
		t.Errorf("expected 6 redactions, got %d:\n%s", strings.Count(out, "[REDACTED]"), out)
	}
	if !strings.Contains(out, "203.0.113.10") {
		t.Error("non-sensitive values must survive redaction")
	}
}

func TestRedactsAtEveryLevel(t *testing.T) {
	// Debug logging is not a licence to leak (Design Spec §33.3).
	for _, emit := range []struct {
		name string
		fn   func(*Logger, context.Context, string, ...any)
	}{
		{"debug", (*Logger).Debug},
		{"info", (*Logger).Info},
		{"warn", (*Logger).Warn},
		{"error", (*Logger).Error},
	} {
		t.Run(emit.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := newTestLogger(&buf)
			emit.fn(log, context.Background(), "msg", "password", "topsecret")
			if strings.Contains(buf.String(), "topsecret") {
				t.Errorf("%s level leaked a secret:\n%s", emit.name, buf.String())
			}
		})
	}
}

func TestRedactsMessageText(t *testing.T) {
	var buf bytes.Buffer
	log := newTestLogger(&buf)

	log.Info(context.Background(), "connecting to postgres://admin:s3cr3t@db.internal:5432/nextpanel")
	if strings.Contains(buf.String(), "s3cr3t") {
		t.Errorf("message leaked URL userinfo:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "db.internal") {
		t.Error("host should survive redaction")
	}

	buf.Reset()
	log.Info(context.Background(), "dsn password=abc123 user=admin")
	if strings.Contains(buf.String(), "abc123") {
		t.Errorf("message leaked key=value secret:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "user=admin") {
		t.Error("non-sensitive key=value pairs should survive")
	}
}

func TestRedactsNestedGroups(t *testing.T) {
	var buf bytes.Buffer
	log := newTestLogger(&buf)

	log.Info(context.Background(), "cfg",
		"database", map[string]any{
			"host":     "db.internal",
			"password": "nested-secret",
		},
	)

	out := buf.String()
	if strings.Contains(out, "nested-secret") {
		t.Errorf("nested group leaked a secret:\n%s", out)
	}
	if !strings.Contains(out, "db.internal") {
		t.Errorf("nested non-sensitive value missing:\n%s", out)
	}
}

func TestWithAttrsAreRedacted(t *testing.T) {
	var buf bytes.Buffer
	log := newTestLogger(&buf).With("api_key", "static-secret")

	log.Info(context.Background(), "hello")

	if strings.Contains(buf.String(), "static-secret") {
		t.Errorf("static attribute leaked a secret:\n%s", buf.String())
	}
}

func TestContextEnrichment(t *testing.T) {
	var buf bytes.Buffer
	log := newTestLogger(&buf)

	ctx := context.Background()
	ctx = WithRequestID(ctx, "req-123")
	ctx = WithActor(ctx, 7, "admin")
	ctx = WithServer(ctx, 42)
	ctx = WithJob(ctx, 99)
	ctx = WithSession(ctx, "sess-1")

	log.Info(ctx, "doing work")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	for k, want := range map[string]any{
		"request_id": "req-123",
		"actor_id":   float64(7),
		"actor_name": "admin",
		"server_id":  float64(42),
		"job_id":     float64(99),
		"session_id": "sess-1",
	} {
		if got := rec[k]; got != want {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
}

func TestRequestIDHelper(t *testing.T) {
	if got := RequestID(context.Background()); got != "" {
		t.Errorf("RequestID on a bare context = %q, want empty", got)
	}
	ctx := WithRequestID(context.Background(), "abc")
	if got := RequestID(ctx); got != "abc" {
		t.Errorf("RequestID = %q, want abc", got)
	}
}

func TestRedactURLUserinfo(t *testing.T) {
	for _, tc := range []struct{ in, want, notWant string }{
		{"postgres://user:pw@host/db", "user:[REDACTED]@host", "pw"},
		{"redis://:only@host", "[REDACTED]@host", "only"},
		{"http://host/path", "http://host/path", ""},
		{"no url here", "no url here", ""},
	} {
		got := redactURLUserinfo(tc.in)
		if !strings.Contains(got, tc.want) {
			t.Errorf("redactURLUserinfo(%q) = %q, want it to contain %q", tc.in, got, tc.want)
		}
		if tc.notWant != "" && strings.Contains(got, tc.notWant) {
			t.Errorf("redactURLUserinfo(%q) = %q leaked %q", tc.in, got, tc.notWant)
		}
	}
}

func TestRedactKeyValuePairs(t *testing.T) {
	for _, tc := range []struct{ in, notWant string }{
		{"password=secret", "secret"},
		{"password=secret&user=bob", "secret"},
		{"token=abc,other=def", "abc"},
		{"db_password=xyz", "xyz"},
		{"username=bob", ""}, // must NOT be redacted
	} {
		got := redactKeyValuePairs(tc.in)
		if tc.notWant != "" && strings.Contains(got, tc.notWant) {
			t.Errorf("redactKeyValuePairs(%q) = %q leaked %q", tc.in, got, tc.notWant)
		}
	}
	if got := redactKeyValuePairs("username=bob"); !strings.Contains(got, "bob") {
		t.Errorf("non-sensitive key was redacted: %q", got)
	}
}

func TestTextFormat(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "text", "INFO")
	log.Info(context.Background(), "hello", "password", "x")
	if !strings.Contains(buf.String(), "hello") {
		t.Error("text handler did not log the message")
	}
	if strings.Contains(buf.String(), "password=x") {
		t.Errorf("text handler leaked a secret: %s", buf.String())
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "json", "WARN")
	log.Debug(context.Background(), "debug-msg")
	log.Info(context.Background(), "info-msg")
	if buf.Len() != 0 {
		t.Errorf("levels below WARN should be suppressed, got: %s", buf.String())
	}
	log.Warn(context.Background(), "warn-msg")
	if !strings.Contains(buf.String(), "warn-msg") {
		t.Error("WARN should be emitted")
	}
}
