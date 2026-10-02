package handlers

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/ashaibery/Next-Dot-Panel/internal/files"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

// Files serves remote file management.
type Files struct {
	Service *files.Service
	Log     *logging.Logger
}

// List implements GET /api/v1/servers/{id}/files.
func (h *Files) List(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	dir := r.URL.Query().Get("path")
	if dir == "" {
		dir = "/"
	}
	entries, err := h.Service.List(r.Context(), actor, id, dir)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := make([]dto.FileInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, dto.FromFileInfo(e))
	}
	dto.WriteJSON(w, http.StatusOK, dto.FileListResponse{Path: dir, Entries: out})
}

// Stat implements GET /api/v1/servers/{id}/files/stat.
func (h *Files) Stat(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	info, err := h.Service.Stat(r.Context(), actor, id, r.URL.Query().Get("path"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusOK, dto.FromFileInfo(*info))
}

// Download implements GET /api/v1/servers/{id}/files/content.
func (h *Files) Download(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	filePath := r.URL.Query().Get("path")
	rc, err := h.Service.OpenDownload(r.Context(), actor, id, filePath, h.meta(r))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	defer func() { _ = rc.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

// Upload implements PUT /api/v1/servers/{id}/files/content.
func (h *Files) Upload(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	filePath := r.URL.Query().Get("path")
	mode := os.FileMode(0o644)
	if m := r.URL.Query().Get("mode"); m != "" {
		if v, err := strconv.ParseUint(m, 8, 32); err == nil {
			mode = os.FileMode(v)
		}
	}
	if err := h.Service.Upload(r.Context(), actor, id, filePath, mode, r.ContentLength, r.Body, h.meta(r)); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Mkdir implements POST /api/v1/servers/{id}/files/mkdir.
func (h *Files) Mkdir(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	var req dto.MkdirRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.Mkdir(r.Context(), actor, id, req.Path, os.FileMode(req.Mode), h.meta(r)); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Rename implements POST /api/v1/servers/{id}/files/rename.
func (h *Files) Rename(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	var req dto.RenameRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.Rename(r.Context(), actor, id, req.From, req.To, h.meta(r)); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Delete implements POST /api/v1/servers/{id}/files/delete.
func (h *Files) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	var req dto.DeleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.Remove(r.Context(), actor, id, req.Paths, req.Recursive, h.meta(r)); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Extract implements POST /api/v1/servers/{id}/files/extract.
func (h *Files) Extract(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	var req dto.ExtractRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.Extract(r.Context(), actor, id, req.Archive, req.Destination, h.meta(r)); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Files) meta(r *http.Request) files.Meta {
	return files.Meta{RequestID: logging.RequestID(r.Context()), IP: clientIP(r), UserAgent: r.UserAgent()}
}

func (h *Files) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		dto.WriteError(w, r, http.StatusNotFound, "not_found", "The file or directory does not exist.", nil)
	case errors.Is(err, files.ErrTooLarge):
		dto.WriteError(w, r, http.StatusRequestEntityTooLarge, "too_large", "The archive exceeds the configured limits.", nil)
	case errors.Is(err, files.ErrUnsafe):
		dto.WriteError(w, r, http.StatusBadRequest, "unsafe_archive", "The archive contains an unsafe entry.", nil)
	case errors.Is(err, files.ErrInvalid):
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", "The path or request is not valid.", nil)
	default:
		if code := provider.CodeOf(err); code != provider.CodeUnknown {
			dto.WriteError(w, r, http.StatusBadGateway, "provider_error", "The remote server operation failed.", map[string]any{"code": string(code)})
			return
		}
		if h.Log != nil {
			h.Log.Error(r.Context(), "file request failed", "error", err)
		}
		dto.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An internal error occurred.", nil)
	}
}
