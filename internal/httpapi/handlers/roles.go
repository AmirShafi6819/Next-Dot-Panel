package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/dto"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/rbac"
)

// RBAC serves role and permission administration (Design Spec §12).
type RBAC struct {
	Service *rbac.Service
	Log     *logging.Logger
}

// ListPermissions implements GET /api/v1/permissions.
func (h *RBAC) ListPermissions(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	perms, err := h.Service.ListPermissions(r.Context(), actor)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := make([]dto.PermissionInfo, 0, len(perms))
	for _, p := range perms {
		out = append(out, dto.PermissionInfo{Name: string(p), Description: domain.PermissionDescriptions[p]})
	}
	dto.WriteJSON(w, http.StatusOK, dto.PermissionsResponse{Permissions: out})
}

// ListRoles implements GET /api/v1/roles.
func (h *RBAC) ListRoles(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	roles, err := h.Service.ListRoles(r.Context(), actor)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusOK, dto.RolesResponse{Roles: roleDTOs(roles)})
}

// GetRole implements GET /api/v1/roles/{id}.
func (h *RBAC) GetRole(w http.ResponseWriter, r *http.Request) {
	actor, _ := middleware.ActorFrom(r.Context())
	id, ok := roleID(w, r)
	if !ok {
		return
	}
	role, err := h.Service.GetRole(r.Context(), actor, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusOK, dto.FromRole(role))
}

// CreateRole implements POST /api/v1/roles.
func (h *RBAC) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req dto.RoleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	role, err := h.Service.CreateRole(r.Context(), actor, rbac.RoleInput{
		Name: req.Name, Description: req.Description, Permissions: dto.PermissionsFromStrings(req.Permissions),
	}, rbac.Meta{RequestID: logging.RequestID(r.Context()), IP: clientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusCreated, dto.FromRole(role))
}

// UpdateRole implements PATCH /api/v1/roles/{id}.
func (h *RBAC) UpdateRole(w http.ResponseWriter, r *http.Request) {
	id, ok := roleID(w, r)
	if !ok {
		return
	}
	var req dto.RoleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	role, err := h.Service.UpdateRole(r.Context(), actor, id, rbac.RoleInput{
		Name: req.Name, Description: req.Description, Permissions: dto.PermissionsFromStrings(req.Permissions),
	}, rbac.Meta{RequestID: logging.RequestID(r.Context()), IP: clientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusOK, dto.FromRole(role))
}

// DeleteRole implements DELETE /api/v1/roles/{id}.
func (h *RBAC) DeleteRole(w http.ResponseWriter, r *http.Request) {
	id, ok := roleID(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.DeleteRole(r.Context(), actor, id, rbac.Meta{RequestID: logging.RequestID(r.Context()), IP: clientIP(r), UserAgent: r.UserAgent()}); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetRolePermissions implements PUT /api/v1/roles/{id}/permissions.
func (h *RBAC) SetRolePermissions(w http.ResponseWriter, r *http.Request) {
	id, ok := roleID(w, r)
	if !ok {
		return
	}
	var req dto.RolePermissionsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	if err := h.Service.SetRolePermissions(r.Context(), actor, id, dto.PermissionsFromStrings(req.Permissions), rbac.Meta{RequestID: logging.RequestID(r.Context()), IP: clientIP(r), UserAgent: r.UserAgent()}); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListUserRoles implements GET /api/v1/users/{id}/roles.
func (h *RBAC) ListUserRoles(w http.ResponseWriter, r *http.Request) {
	id, ok := userID(w, r)
	if !ok {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	roles, err := h.Service.ListUserRoles(r.Context(), actor, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	dto.WriteJSON(w, http.StatusOK, dto.UserRolesResponse{Roles: roleDTOs(roles)})
}

// SetUserRoles implements PUT /api/v1/users/{id}/roles.
func (h *RBAC) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	id, ok := userID(w, r)
	if !ok {
		return
	}
	var req dto.UserRolesRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	actor, _ := middleware.ActorFrom(r.Context())
	roleIDs := make([]domain.RoleID, 0, len(req.RoleIDs))
	for _, rid := range req.RoleIDs {
		roleIDs = append(roleIDs, domain.RoleID(rid))
	}
	if err := h.Service.SetUserRoles(r.Context(), actor, id, roleIDs, rbac.Meta{RequestID: logging.RequestID(r.Context()), IP: clientIP(r), UserAgent: r.UserAgent()}); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RBAC) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, rbac.ErrNotFound):
		dto.WriteError(w, r, http.StatusNotFound, "not_found", "The requested resource does not exist.", nil)
	case errors.Is(err, rbac.ErrForbidden):
		dto.WriteError(w, r, http.StatusForbidden, "forbidden", "You do not have permission to perform this action.", nil)
	case errors.Is(err, rbac.ErrSystemRole):
		dto.WriteError(w, r, http.StatusConflict, "system_role", "System roles cannot be modified.", nil)
	case errors.Is(err, rbac.ErrInvalid):
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", err.Error(), nil)
	default:
		if h.Log != nil {
			h.Log.Error(r.Context(), "rbac request failed", "error", err)
		}
		dto.WriteError(w, r, http.StatusInternalServerError, "internal_error", "An internal error occurred.", nil)
	}
}

func roleDTOs(roles []domain.Role) []dto.Role {
	out := make([]dto.Role, 0, len(roles))
	for _, role := range roles {
		out = append(out, dto.FromRole(role))
	}
	return out
}

func roleID(w http.ResponseWriter, r *http.Request) (domain.RoleID, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", "The role id is not valid.", nil)
		return 0, false
	}
	return domain.RoleID(id), true
}

func userID(w http.ResponseWriter, r *http.Request) (domain.UserID, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		dto.WriteError(w, r, http.StatusBadRequest, "invalid_request", "The user id is not valid.", nil)
		return 0, false
	}
	return domain.UserID(id), true
}
