package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/ashaibery/Next-Dot-Panel/internal/credentials"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/secret"
	"github.com/ashaibery/Next-Dot-Panel/internal/server"
)

// Servers serves the managed-server endpoints (Design Spec §12.3, §12.4).
type Servers struct {
	Service *server.Service
	Log     *logging.Logger
}

// List implements GET /api/v1/servers.
func (h *Servers) List(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	q := r.URL.Query()
	page := domain.Page{
		Number:  atoiDefault(q.Get("page"), 1),
		PerPage: atoiDefault(q.Get("per_page"), domain.DefaultPerPage),
	}
	result, err := h.Service.List(r.Context(), actor, server.Filter{
		Search: q.Get("search"), Status: q.Get("status"), TargetType: q.Get("target_type"), Tag: q.Get("tag"),
	}, page)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := make([]dto.Server, 0, len(result.Items))
	for _, s := range result.Items {
		out = append(out, dto.FromServer(s))
	}
	dto.WriteJSON(w, http.StatusOK, dto.ServerListResponse{
		Servers: out, Total: result.Total, Page: result.Page, PerPage: result.PerPage,
	})
}

// Get implements GET /api/v1/servers/{id}.
func (h *Servers) Get(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	srv, err := h.Service.Get(r.Context(), actor, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusOK, dto.FromServer(srv))
}

// Create implements POST /api/v1/servers.
func (h *Servers) Create(w http.ResponseWriter, r *http.Request) {
	var req dto.ServerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	srv, err := h.Service.Create(r.Context(), actor, server.CreateInput{
		Name: req.Name, TargetType: domain.TargetType(req.TargetType), Host: req.Host, Port: req.Port,
		Username: req.Username, AuthMethod: domain.AuthMethod(req.AuthMethod), HostKeyPolicy: domain.HostKeyPolicy(req.HostKeyPolicy),
		Tags: req.Tags, Notes: req.Notes, IsFavourite: req.IsFavourite, Credential: materialFrom(req),
	}, h.meta(r))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusCreated, dto.FromServer(srv))
}

// Update implements PATCH /api/v1/servers/{id}.
func (h *Servers) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	var req dto.ServerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	srv, err := h.Service.Update(r.Context(), actor, id, server.UpdateInput{
		Name: req.Name, Host: req.Host, Port: req.Port, Username: req.Username,
		AuthMethod: domain.AuthMethod(req.AuthMethod), HostKeyPolicy: domain.HostKeyPolicy(req.HostKeyPolicy),
		Tags: req.Tags, Notes: req.Notes, IsFavourite: req.IsFavourite, Version: req.Version,
		Credential: materialFrom(req),
	}, h.meta(r))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusOK, dto.FromServer(srv))
}

// Delete implements DELETE /api/v1/servers/{id}.
func (h *Servers) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.Delete(r.Context(), actor, id, h.meta(r)); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TestConnection implements POST /api/v1/servers/{id}/test.
func (h *Servers) TestConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	res, err := h.Service.TestConnection(r.Context(), actor, id, h.meta(r))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := dto.ConnectionTestResponse{
		Status: string(res.Status), LatencyMs: res.Latency.Milliseconds(), Detail: res.Detail,
	}
	if res.HostKey != nil {
		out.HostKey = &dto.HostKeyPrompt{
			Algorithm: res.HostKey.Algorithm, Fingerprint: res.HostKey.Fingerprint,
			PublicKey: dto.EncodePublicKey(res.HostKey.PublicKey),
		}
	}
	dto.WriteJSON(w, http.StatusOK, out)
}

// ListHostKeys implements GET /api/v1/servers/{id}/hostkeys.
func (h *Servers) ListHostKeys(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	keys, err := h.Service.ListHostKeys(r.Context(), actor, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := make([]dto.HostKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, dto.FromHostKey(k))
	}
	dto.WriteJSON(w, http.StatusOK, dto.HostKeysResponse{HostKeys: out})
}

// TrustHostKey implements POST /api/v1/servers/{id}/hostkeys/trust.
func (h *Servers) TrustHostKey(w http.ResponseWriter, r *http.Request) {
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}
	var req dto.TrustHostKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) == 0 {
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", "The public key is not valid base64.", nil)
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.TrustHostKey(r.Context(), actor, id, req.Algorithm, req.Fingerprint, pub, h.meta(r)); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Servers) meta(r *http.Request) server.Meta {
	return server.Meta{RequestID: logging.RequestID(r.Context()), IP: clientIP(r), UserAgent: r.UserAgent()}
}

func (h *Servers) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, server.ErrNotFound):
		dto.WriteError(w, r, http.StatusNotFound, "not_found", "The requested resource does not exist.", nil)
	case errors.Is(err, server.ErrForbidden):
		dto.WriteError(w, r, http.StatusForbidden, "forbidden", "You do not have permission to perform this action.", nil)
	case errors.Is(err, server.ErrNoCred):
		dto.WriteError(w, r, http.StatusBadRequest, "credential_required", "A credential is required for this authentication method.", nil)
	case errors.Is(err, server.ErrConflict):
		dto.WriteError(w, r, http.StatusConflict, "conflict", "The server was modified by someone else, or the name is taken.", nil)
	case errors.Is(err, server.ErrInvalid):
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", "The server configuration is not valid.", nil)
	default:
		if h.Log != nil {
			h.Log.Error(r.Context(), "server request failed", "error", err)
		}
		dto.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An internal error occurred.", nil)
	}
}

func materialFrom(req dto.ServerRequest) credentials.Material {
	return credentials.Material{
		Password:   secret.New(req.Password),
		PrivateKey: secret.New(req.PrivateKey),
		Passphrase: secret.New(req.Passphrase),
	}
}

func serverIDParam(w http.ResponseWriter, r *http.Request) (domain.ServerID, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", "The server id is not valid.", nil)
		return 0, false
	}
	return domain.ServerID(id), true
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
