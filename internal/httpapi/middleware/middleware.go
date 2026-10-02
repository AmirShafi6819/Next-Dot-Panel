// Package middleware contains the HTTP middleware stack: correlation,
// access logging, and panic recovery (Design Spec §26.2, §33.6).
package middleware

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
)

// RequestID attaches a fresh correlation ID to every request and echoes it as
// X-Request-ID. A caller-supplied header is deliberately ignored: the ID is
// the join key between the access log, the application log, and the audit
// record, so it must be ours (Design Spec §33.6).
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(logging.WithRequestID(r.Context(), id)))
	})
}

// AccessLog records one structured line per request: the fields §33.1 lists,
// plus the request_id that ties the line to everything else. Only the path is
// logged — a query string can carry a ticket or a token.
func AccessLog(log *logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			if log != nil {
				log.Info(r.Context(), "http request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", sw.status,
					"duration_ms", time.Since(start).Milliseconds(),
				)
			}
		})
	}
}

// Recover converts a panic into a 500 in the standard error envelope. The
// stack is logged server-side and correlated by request_id; it is never sent
// to the client (Design Spec §26.1).
func Recover(log *logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if log != nil {
					log.Error(r.Context(), "panic recovered",
						"panic", fmt.Sprint(rec),
						"method", r.Method,
						"path", r.URL.Path,
						"stack", string(debug.Stack()),
					)
				}
				dto.WriteError(w, r, http.StatusInternalServerError,
					"internal_error", "An internal error occurred.", nil)
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// statusWriter records the status code for the access log. It forwards the
// optional interfaces the later phases need (streaming and hijacking), so
// adding logging does not silently break SSE or WebSockets.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.wrote = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("response writer does not support hijacking")
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ReadFrom keeps io.Copy fast paths intact when the sink supports them.
func (w *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		if !w.wrote {
			w.wrote = true
		}
		return rf.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}

// newRequestID returns a 128-bit random identifier in lowercase hex.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is fatal for session tokens too, but a request
		// id must never take the process down: fall back to a timestamp.
		return hex.EncodeToString([]byte(fmt.Sprintf("t%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(b[:])
}
