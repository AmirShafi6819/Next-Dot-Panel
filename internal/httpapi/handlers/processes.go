package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/processes"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
	"github.com/ashaibery/Next-Dot-Panel/internal/server"
)

// Processes serves remote process management.
type Processes struct {
	Service *processes.Service
	Log     *logging.Logger
}

// List implements GET /api/v1/servers/{id}/processes.
func (h *Processes) List(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	procs, err := h.Service.List(r.Context(), actor, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := make([]dto.Process, 0, len(procs))
	for _, p := range procs {
		out = append(out, dto.FromProcess(p))
	}
	dto.WriteJSON(w, http.StatusOK, dto.ProcessListResponse{Processes: out})
}

// Signal implements POST /api/v1/servers/{id}/processes/{pid}/signal.
func (h *Processes) Signal(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	pid, err := strconv.Atoi(chi.URLParam(r, "pid"))
	if err != nil || pid <= 0 {
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", "The process id is not valid.", nil)
		return
	}
	var req dto.SignalRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if serr := h.Service.Signal(r.Context(), actor, id, pid, req.Force, processes.Meta{
		RequestID: logging.RequestID(r.Context()), IP: clientIP(r), UserAgent: r.UserAgent(),
	}); serr != nil {
		h.writeError(w, r, serr)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Processes) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, server.ErrNotFound):
		dto.WriteError(w, r, http.StatusNotFound, "not_found", "The requested resource does not exist.", nil)
	default:
		if code := provider.CodeOf(err); code != provider.CodeUnknown {
			dto.WriteError(w, r, http.StatusBadGateway, "provider_error", "The remote server operation failed.", map[string]any{"code": string(code)})
			return
		}
		if h.Log != nil {
			h.Log.Error(r.Context(), "processes request failed", "error", err)
		}
		dto.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An internal error occurred.", nil)
	}
}
