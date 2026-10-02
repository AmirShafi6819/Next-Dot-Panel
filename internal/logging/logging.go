// Package logging configures Next.Panel's structured logger and enforces
// secret redaction on every emitted record.
//
// Design Spec §33.3: redaction happens in the handler, so it applies at every
// level including DEBUG. Debug logging is not a licence to leak.
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"github.com/ashaibery/Next-Dot-Panel/internal/secret"
)

// contextKey is unexported so callers must use the With* helpers.
type contextKey int

const (
	keyRequestID contextKey = iota
	keyActorID
	keyActorName
	keyServerID
	keyJobID
	keySessionID
)

// WithRequestID attaches a correlation id to the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyRequestID, id)
}

// WithActor attaches the acting user to the context.
func WithActor(ctx context.Context, id int64, name string) context.Context {
	ctx = context.WithValue(ctx, keyActorID, id)
	return context.WithValue(ctx, keyActorName, name)
}

// WithServer attaches the target server to the context.
func WithServer(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, keyServerID, id)
}

// WithJob attaches the job to the context.
func WithJob(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, keyJobID, id)
}

// WithSession attaches the session to the context.
func WithSession(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keySessionID, id)
}

// RequestID returns the correlation id carried by the context, if any.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(keyRequestID).(string); ok {
		return v
	}
	return ""
}

// Logger wraps slog.Logger and automatically enriches records with the
// correlation fields present on the context.
type Logger struct {
	inner *slog.Logger
}

// New builds a logger writing to w in the requested format and level.
func New(w io.Writer, format, level string) *Logger {
	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
	}

	var h slog.Handler
	if strings.EqualFold(format, "json") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}

	return &Logger{inner: slog.New(&redactingHandler{inner: h})}
}

// With returns a logger with additional static attributes.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{inner: l.inner.With(args...)}
}

// Debug logs at DEBUG level.
func (l *Logger) Debug(ctx context.Context, msg string, args ...any) {
	l.inner.DebugContext(ctx, msg, l.enrich(ctx, args)...)
}

// Info logs at INFO level.
func (l *Logger) Info(ctx context.Context, msg string, args ...any) {
	l.inner.InfoContext(ctx, msg, l.enrich(ctx, args)...)
}

// Warn logs at WARN level.
func (l *Logger) Warn(ctx context.Context, msg string, args ...any) {
	l.inner.WarnContext(ctx, msg, l.enrich(ctx, args)...)
}

// Error logs at ERROR level.
func (l *Logger) Error(ctx context.Context, msg string, args ...any) {
	l.inner.ErrorContext(ctx, msg, l.enrich(ctx, args)...)
}

// enrich prepends the correlation attributes carried by the context.
func (l *Logger) enrich(ctx context.Context, args []any) []any {
	if ctx == nil {
		return args
	}
	var extra []any
	if v, ok := ctx.Value(keyRequestID).(string); ok && v != "" {
		extra = append(extra, "request_id", v)
	}
	if v, ok := ctx.Value(keyActorID).(int64); ok {
		extra = append(extra, "actor_id", v)
	}
	if v, ok := ctx.Value(keyActorName).(string); ok && v != "" {
		extra = append(extra, "actor_name", v)
	}
	if v, ok := ctx.Value(keyServerID).(int64); ok {
		extra = append(extra, "server_id", v)
	}
	if v, ok := ctx.Value(keyJobID).(int64); ok {
		extra = append(extra, "job_id", v)
	}
	if v, ok := ctx.Value(keySessionID).(string); ok && v != "" {
		extra = append(extra, "session_id", v)
	}
	if len(extra) == 0 {
		return args
	}
	return append(extra, args...)
}

// Handlers returns the underlying slog handler chain, for integration with
// libraries that accept a *slog.Logger.
func (l *Logger) Slog() *slog.Logger { return l.inner }

func parseLevel(level string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// redactingHandler is an slog.Handler that removes credential material from
// attributes and from the message itself before the record is written.
type redactingHandler struct {
	inner slog.Handler
}

func (h *redactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	cleaned := slog.NewRecord(r.Time, r.Level, RedactText(r.Message), r.PC)

	r.Attrs(func(a slog.Attr) bool {
		cleaned.AddAttrs(h.cleanAttr(a))
		return true
	})

	return h.inner.Handle(ctx, cleaned)
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cleaned := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		cleaned = append(cleaned, cleanAttrValue(a))
	}
	return &redactingHandler{inner: h.inner.WithAttrs(cleaned)}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{inner: h.inner.WithGroup(name)}
}

// cleanAttr redacts a single attribute, recurring into groups, maps, and
// slices. Note that a map or slice is reported by slog as KindAny rather than
// KindGroup, so it must be walked explicitly: otherwise a nested
// {"password": ...} would pass straight through to the output.
func (h *redactingHandler) cleanAttr(a slog.Attr) slog.Attr {
	if secret.LooksSensitive(a.Key) {
		return slog.String(a.Key, "[REDACTED]")
	}
	return slog.Attr{Key: a.Key, Value: cleanValue(a.Value)}
}

// cleanValue walks a slog.Value and redacts anything sensitive inside it.
func cleanValue(v slog.Value) slog.Value {
	// Resolve LogValuer implementations first so we inspect the real value
	// rather than the wrapper.
	if lv, ok := v.Any().(slog.LogValuer); ok && v.Kind() == slog.KindLogValuer {
		return cleanValue(lv.LogValue())
	}

	switch v.Kind() {
	case slog.KindGroup:
		group := v.Group()
		cleaned := make([]slog.Attr, 0, len(group))
		for _, g := range group {
			cleaned = append(cleaned, cleanAttrValue(g))
		}
		return slog.GroupValue(cleaned...)

	case slog.KindString:
		return slog.StringValue(RedactText(v.String()))

	case slog.KindAny:
		if cleaned, ok := cleanAny(v.Any()); ok {
			return slog.AnyValue(cleaned)
		}
		return v

	default:
		return v
	}
}

// cleanAttrValue is cleanAttr for use inside groups, where the key check has
// to happen alongside the value walk.
func cleanAttrValue(a slog.Attr) slog.Attr {
	if secret.LooksSensitive(a.Key) {
		return slog.String(a.Key, "[REDACTED]")
	}
	return slog.Attr{Key: a.Key, Value: cleanValue(a.Value)}
}

// cleanAny redacts sensitive entries inside maps and slices. It reports
// whether the value was handled; unsupported types are returned untouched so
// their normal formatting is preserved.
func cleanAny(v any) (any, bool) {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, val := range typed {
			if secret.LooksSensitive(k) {
				out[k] = "[REDACTED]"
				continue
			}
			if s, ok := val.(string); ok {
				out[k] = RedactText(s)
				continue
			}
			if nested, ok := cleanAny(val); ok {
				out[k] = nested
				continue
			}
			out[k] = val
		}
		return out, true

	case map[string]string:
		out := make(map[string]string, len(typed))
		for k, val := range typed {
			if secret.LooksSensitive(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = RedactText(val)
		}
		return out, true

	case []any:
		out := make([]any, len(typed))
		for i, val := range typed {
			if nested, ok := cleanAny(val); ok {
				out[i] = nested
				continue
			}
			out[i] = val
		}
		return out, true

	default:
		return nil, false
	}
}

// RedactText removes credential material from a free-form string. It handles
// the two shapes that realistically leak into log lines: URLs with embedded
// userinfo, and "key=value" pairs whose key looks sensitive.
func RedactText(s string) string {
	s = redactURLUserinfo(s)
	s = redactKeyValuePairs(s)
	return s
}

// redactURLUserinfo rewrites scheme://user:password@host as
// scheme://user:[REDACTED]@host.
func redactURLUserinfo(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		at := strings.IndexByte(s[i:], '@')
		if at < 0 {
			b.WriteString(s[i:])
			break
		}
		at += i
		// Look backwards for a scheme:// within a reasonable distance.
		start := strings.LastIndex(s[:at], "://")
		if start < 0 || at-start > 512 {
			b.WriteString(s[i : at+1])
			i = at + 1
			continue
		}
		authStart := start + 3
		auth := s[authStart:at]
		if colon := strings.IndexByte(auth, ':'); colon >= 0 {
			b.WriteString(s[i:authStart])
			b.WriteString(auth[:colon+1])
			b.WriteString("[REDACTED]")
			b.WriteByte('@')
			i = at + 1
			continue
		}
		b.WriteString(s[i : at+1])
		i = at + 1
	}
	return b.String()
}

// redactKeyValuePairs rewrites "password=secret" as "password=[REDACTED]".
func redactKeyValuePairs(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			b.WriteString(s[i:])
			break
		}
		eq += i
		// Walk back over the key characters.
		keyEnd := eq
		keyStart := keyEnd
		for keyStart > 0 && isKeyByte(s[keyStart-1]) {
			keyStart--
		}
		if keyStart == keyEnd {
			b.WriteString(s[i : eq+1])
			i = eq + 1
			continue
		}
		key := s[keyStart:keyEnd]
		if !secret.LooksSensitive(key) {
			b.WriteString(s[i : eq+1])
			i = eq + 1
			continue
		}
		valStart := eq + 1
		valEnd := valStart
		for valEnd < len(s) && s[valEnd] != ' ' && s[valEnd] != ',' && s[valEnd] != '&' && s[valEnd] != '\n' {
			valEnd++
		}
		b.WriteString(s[i:keyStart])
		b.WriteString(key)
		b.WriteString("=[REDACTED]")
		i = valEnd
	}
	return b.String()
}

func isKeyByte(c byte) bool {
	return c == '_' || c == '-' || c == '.' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
