package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/metrics"
	"github.com/ashaibery/Next-Dot-Panel/internal/server"
)

// Events streams server status and metrics over Server-Sent Events. It reads
// the persisted latest sample and the server row — never the remote host — so
// subscribers cannot trigger SSH traffic (Design Spec §28, §164).
type Events struct {
	Metrics *metrics.Service
	Servers *server.Service
	Log     *logging.Logger
	// Interval between events. Zero means 10 seconds.
	Interval time.Duration
}

// ServeHTTP implements GET /api/v1/servers/{id}/events.
func (h *Events) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	interval := h.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !h.emit(r.Context(), w, flusher, actor, id) {
				return
			}
		}
	}
}

func (h *Events) emit(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, actor auth.Actor, id domain.ServerID) bool {
	srv, err := h.Servers.Get(ctx, actor, id)
	if err != nil {
		// An invisible server ends the stream instead of leaking 404/403
		// differences over a long-lived connection.
		_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", quoteJSON("gone"))
		flusher.Flush()
		return false
	}
	payload := map[string]any{
		"status": string(srv.Status), "updated_at": srv.UpdatedAt,
	}
	if sample, fs, serr := h.Metrics.Latest(ctx, actor, id); serr == nil {
		payload["metrics"] = map[string]any{
			"timestamp": sample.Timestamp, "cpu_pct": sample.CPUPct,
			"mem_total": sample.MemTotal, "mem_available": sample.MemAvailable,
			"filesystems": len(fs),
		}
	}
	_, _ = fmt.Fprintf(w, "event: state\ndata: %s\n\n", quoteJSON(payload))
	flusher.Flush()
	return true
}

func quoteJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `""`
	}
	return string(b)
}
