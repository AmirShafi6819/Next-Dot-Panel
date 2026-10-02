package handlers

import (
	"errors"
	"net/http"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/users"
)

// Users serves account administration.
type Users struct {
	Service *users.Service
	Log     *logging.Logger
}

// List implements GET /api/v1/users.
func (h *Users) List(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	q := r.URL.Query()
	page := domain.Page{Number: atoiDefault(q.Get("page"), 1), PerPage: atoiDefault(q.Get("per_page"), domain.DefaultPerPage)}.Normalize()
	var isActive *bool
	if v := q.Get("is_active"); v == "true" || v == "false" {
		b := v == "true"
		isActive = &b
	}
	items, err := h.Service.List(r.Context(), actor, q.Get("search"), isActive, int64(page.PerPage), int64(page.Offset()))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	total, err := h.Service.Count(r.Context(), actor, q.Get("search"), isActive)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := make([]dto.UserDetail, 0, len(items))
	for _, u := range items {
		withRoles, rerr := h.Service.Get(r.Context(), actor, u.ID)
		if rerr != nil {
			h.writeError(w, r, rerr)
			return
		}
		out = append(out, dto.FromUserDetail(withRoles))
	}
	dto.WriteJSON(w, http.StatusOK, dto.UserListResponse{Users: out, Total: total})
}

// Get implements GET /api/v1/users/{id}.
func (h *Users) Get(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	id, ok := userID(w, r)
	if !ok {
		return
	}
	u, err := h.Service.Get(r.Context(), actor, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusOK, dto.FromUserDetail(u))
}

// Create implements POST /api/v1/users.
func (h *Users) Create(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	roleIDs := make([]domain.RoleID, 0, len(req.RoleIDs))
	for _, rid := range req.RoleIDs {
		roleIDs = append(roleIDs, domain.RoleID(rid))
	}
	u, err := h.Service.Create(r.Context(), actor, users.CreateInput{
		Username: req.Username, DisplayName: req.DisplayName, Password: req.Password,
		IsActive: req.IsActive, RoleIDs: roleIDs,
	}, h.meta(r))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusCreated, dto.FromUserDetail(u))
}

// Update implements PATCH /api/v1/users/{id}.
func (h *Users) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := userID(w, r)
	if !ok {
		return
	}
	var req dto.UpdateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	u, err := h.Service.Update(r.Context(), actor, id, users.UpdateInput{
		DisplayName: req.DisplayName, IsActive: req.IsActive, Version: req.Version,
	}, h.meta(r))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusOK, dto.FromUserDetail(u))
}

// Delete implements DELETE /api/v1/users/{id}.
func (h *Users) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := userID(w, r)
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

// ResetPassword implements POST /api/v1/users/{id}/reset-password.
func (h *Users) ResetPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := userID(w, r)
	if !ok {
		return
	}
	var req dto.ResetPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.ResetPassword(r.Context(), actor, id, req.NewPassword, h.meta(r)); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeSessions implements POST /api/v1/users/{id}/revoke-sessions.
func (h *Users) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := userID(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if _, err := h.Service.RevokeSessions(r.Context(), actor, id, h.meta(r)); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// LoginHistory implements GET /api/v1/users/{id}/login-history.
func (h *Users) LoginHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := userID(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	q := r.URL.Query()
	page := domain.Page{Number: atoiDefault(q.Get("page"), 1), PerPage: atoiDefault(q.Get("per_page"), domain.DefaultPerPage)}.Normalize()
	var success *bool
	if v := q.Get("success"); v == "true" || v == "false" {
		b := v == "true"
		success = &b
	}
	attempts, err := h.Service.ListLoginHistory(r.Context(), actor, &id, success, int64(page.PerPage), int64(page.Offset()))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := make([]dto.LoginHistoryEntry, 0, len(attempts))
	for _, a := range attempts {
		out = append(out, dto.FromLoginAttempt(a))
	}
	dto.WriteJSON(w, http.StatusOK, map[string]any{"attempts": out})
}

func (h *Users) meta(r *http.Request) users.Meta {
	return users.Meta{RequestID: logging.RequestID(r.Context()), IP: clientIP(r), UserAgent: r.UserAgent()}
}

func (h *Users) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, users.ErrNotFound):
		dto.WriteError(w, r, http.StatusNotFound, "not_found", "The requested resource does not exist.", nil)
	case errors.Is(err, users.ErrForbidden):
		dto.WriteError(w, r, http.StatusForbidden, "forbidden", "You do not have permission to perform this action.", nil)
	case errors.Is(err, users.ErrLastAdmin):
		dto.WriteError(w, r, http.StatusConflict, "last_admin", "This is the last active administrator.", nil)
	case errors.Is(err, users.ErrSelf):
		dto.WriteError(w, r, http.StatusBadRequest, "own_account", "This action cannot target your own account.", nil)
	case errors.Is(err, users.ErrConflict):
		dto.WriteError(w, r, http.StatusConflict, "conflict", "The username is taken or the record changed.", nil)
	case errors.Is(err, users.ErrInvalid):
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", err.Error(), nil)
	case errors.Is(err, auth.ErrPasswordTooShort):
		dto.WriteError(w, r, http.StatusBadRequest, "password_too_short", "The password is too short.", map[string]any{"min_length": auth.MinPasswordLength})
	case errors.Is(err, auth.ErrPasswordTooCommon):
		dto.WriteError(w, r, http.StatusBadRequest, "password_too_common", "That password is too common.", nil)
	default:
		if h.Log != nil {
			h.Log.Error(r.Context(), "users request failed", "error", err)
		}
		dto.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An internal error occurred.", nil)
	}
}
