package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Audit serves the audit trail (read-only; records are append-only).
type Audit struct {
	Query *audit.Query
	Log   *logging.Logger
}

// List implements GET /api/v1/audit.
func (h *Audit) List(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	q := r.URL.Query()
	page := domain.Page{Number: atoiDefault(q.Get("page"), 1), PerPage: atoiDefault(q.Get("per_page"), domain.DefaultPerPage)}.Normalize()

	params := repos.AuditQueryParams{PageParams: repos.PageParams{Limit: int64(page.PerPage), Offset: int64(page.Offset())}}
	if v := q.Get("action"); v != "" {
		params.Action = &v
	}
	if v := q.Get("result"); v != "" {
		params.Result = &v
	}
	if v := q.Get("ip"); v != "" {
		params.IP = &v
	}
	if v := q.Get("request_id"); v != "" {
		params.RequestID = &v
	}
	if v := q.Get("search"); v != "" {
		params.Search = &v
	}
	if v := q.Get("actor_id"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			id := domain.UserID(n)
			params.ActorID = &id
		}
	}
	if v := q.Get("server_id"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			id := domain.ServerID(n)
			params.ServerID = &id
		}
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.To = &t
		}
	}

	events, err := h.Query.List(r.Context(), actor, params)
	if err != nil {
		if errors.Is(err, audit.ErrForbidden) {
			dto.WriteError(w, r, http.StatusForbidden, "forbidden", "You do not have permission to perform this action.", nil)
			return
		}
		if h.Log != nil {
			h.Log.Error(r.Context(), "audit request failed", "error", err)
		}
		dto.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An internal error occurred.", nil)
		return
	}
	total, err := h.Query.Count(r.Context(), actor, params)
	if err != nil {
		total = int64(len(events))
	}
	out := make([]dto.AuditEntry, 0, len(events))
	for _, e := range events {
		out = append(out, dto.FromAuditEvent(e))
	}
	dto.WriteJSON(w, http.StatusOK, dto.AuditListResponse{Events: out, Total: total})
}
