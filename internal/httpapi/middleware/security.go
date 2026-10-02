package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
)

// SecurityHeaders sets baseline response headers. HSTS is only sent when the
// external scheme is https, so plain-HTTP development is not broken.
func SecurityHeaders(externalScheme string) func(http.Handler) http.Handler {
	hsts := externalScheme == "https"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			h.Set("X-Frame-Options", "DENY")
			// The UI and API are same-origin. Scripts, styles and workers load
			// from 'self'; the terminal and metrics use same-origin HTTP and
			// WebSockets. Nothing else is allowed to load or frame the app.
			h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'deny'")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimiter is a fixed-window limiter keyed by an arbitrary string.
type RateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

// NewRateLimiter builds a limiter allowing max events per window per key.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	if max < 1 {
		max = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{max: max, window: window, hits: map[string][]time.Time{}}
}

// Allow reports whether an event for key may proceed.
func (l *RateLimiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// Limit rejects requests whose key exceeds the limiter with a 429 envelope.
func Limit(l *RateLimiter, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l != nil && !l.Allow(keyFunc(r)) {
				dto.WriteError(w, r, http.StatusTooManyRequests, "rate_limited",
					"Too many requests. Please wait and try again.", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClientIPKey returns the peer address for rate limiting. Proxy headers are
// deliberately ignored until trusted proxies are configured.
func ClientIPKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
