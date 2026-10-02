package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/metrics"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
	"github.com/ashaibery/Next-Dot-Panel/internal/server"
)

// Metrics serves current and historical resource metrics.
type Metrics struct {
	Service *metrics.Service
	Log     *logging.Logger
}

// Latest implements GET /api/v1/servers/{id}/metrics/latest.
func (h *Metrics) Latest(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	sample, fs, err := h.Service.Latest(r.Context(), actor, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := dto.MetricsLatestResponse{Sample: ptrMetric(dto.FromMetricSample(sample)), Filesystems: []dto.DiskUsage{}}
	for _, f := range fs {
		out.Filesystems = append(out.Filesystems, dto.FromFilesystem(f))
	}
	dto.WriteJSON(w, http.StatusOK, out)
}

// Range implements GET /api/v1/servers/{id}/metrics.
func (h *Metrics) Range(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	q := r.URL.Query()
	to := time.Now()
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}
	from := to.Add(-time.Hour)
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	samples, err := h.Service.Range(r.Context(), actor, id, from, to, int64(atoiDefault(q.Get("limit"), 500)))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := make([]dto.MetricPoint, 0, len(samples))
	for _, s := range samples {
		out = append(out, dto.FromMetricSample(s))
	}
	dto.WriteJSON(w, http.StatusOK, dto.MetricsRangeResponse{Samples: out})
}

// Collect implements POST /api/v1/servers/{id}/metrics/collect.
func (h *Metrics) Collect(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.CollectAndPersist(r.Context(), actor, id); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Metrics) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, server.ErrNotFound):
		dto.WriteError(w, r, http.StatusNotFound, "not_found", "The requested resource does not exist.", nil)
	default:
		if code := provider.CodeOf(err); code != provider.CodeUnknown {
			dto.WriteError(w, r, http.StatusBadGateway, "provider_error", "The remote server operation failed.", map[string]any{"code": string(code)})
			return
		}
		if h.Log != nil {
			h.Log.Error(r.Context(), "metrics request failed", "error", err)
		}
		dto.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An internal error occurred.", nil)
	}
}

func ptrMetric(m dto.MetricPoint) *dto.MetricPoint { return &m }
