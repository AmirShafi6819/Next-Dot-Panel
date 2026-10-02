package dto

import "github.com/ashaibery/Next-Dot-Panel/internal/domain"

// Role is the public projection of a role.
type Role struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IsSystem    bool     `json:"is_system"`
	Permissions []string `json:"permissions"`
}

// FromRole projects a domain role onto the wire format.
func FromRole(r domain.Role) Role {
	perms := make([]string, 0, len(r.Permissions))
	for _, p := range r.Permissions {
		perms = append(perms, string(p))
	}
	return Role{ID: int64(r.ID), Name: r.Name, Description: r.Description, IsSystem: r.IsSystem, Permissions: perms}
}

// RolesResponse is GET /api/v1/roles.
type RolesResponse struct {
	Roles []Role `json:"roles"`
}

// PermissionInfo describes one permission for the UI.
type PermissionInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// PermissionsResponse is GET /api/v1/permissions.
type PermissionsResponse struct {
	Permissions []PermissionInfo `json:"permissions"`
}

// RoleRequest is the create/update payload for a role.
type RoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// PermissionsFromStrings converts wire permission names to domain values.
func PermissionsFromStrings(names []string) []domain.Permission {
	out := make([]domain.Permission, 0, len(names))
	for _, n := range names {
		out = append(out, domain.Permission(n))
	}
	return out
}

// RolePermissionsRequest is PUT /api/v1/roles/{id}/permissions.
type RolePermissionsRequest struct {
	Permissions []string `json:"permissions"`
}

// UserRolesResponse is GET /api/v1/users/{id}/roles.
type UserRolesResponse struct {
	Roles []Role `json:"roles"`
}

// UserRolesRequest is PUT /api/v1/users/{id}/roles.
type UserRolesRequest struct {
	RoleIDs []int64 `json:"role_ids"`
}
