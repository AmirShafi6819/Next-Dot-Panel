-- Users ---------------------------------------------------------------------

-- name: CreateUser :one
INSERT INTO users (username, password_hash, display_name, is_active,
                   is_bootstrap_default, must_change_password)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ?1 AND deleted_at IS NULL;

-- Usernames are compared case-insensitively, matching the partial unique index.
-- name: GetUserByUsername :one
SELECT * FROM users
WHERE lower(username) = lower(?1) AND deleted_at IS NULL;

-- name: ListUsers :many
SELECT * FROM users
WHERE deleted_at IS NULL
  AND (sqlc.narg('search') IS NULL
       OR username LIKE '%' || sqlc.narg('search') || '%'
       OR display_name LIKE '%' || sqlc.narg('search') || '%')
  AND (sqlc.narg('is_active') IS NULL OR is_active = sqlc.narg('is_active'))
ORDER BY username
LIMIT ?1 OFFSET ?2;

-- name: CountUsers :one
SELECT count(*) FROM users
WHERE deleted_at IS NULL
  AND (sqlc.narg('search') IS NULL
       OR username LIKE '%' || sqlc.narg('search') || '%'
       OR display_name LIKE '%' || sqlc.narg('search') || '%')
  AND (sqlc.narg('is_active') IS NULL OR is_active = sqlc.narg('is_active'));

-- name: CountAllUsers :one
SELECT count(*) FROM users WHERE deleted_at IS NULL;

-- name: CountActiveAdmins :one
-- Guards against removing the last administrator.
SELECT count(DISTINCT u.id) FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r ON r.id = ur.role_id
WHERE u.deleted_at IS NULL AND u.is_active = 1 AND r.name = 'admin';

-- name: UpdateUser :one
UPDATE users
SET display_name = ?2,
    is_active    = ?3,
    updated_at   = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    version      = version + 1
WHERE id = ?1 AND deleted_at IS NULL AND version = ?4
RETURNING *;

-- Transparent parameter upgrade on login: rewrites only the hash, so the
-- bootstrap-default flag and the must-change flag are untouched (clearing the
-- bootstrap flag is reserved for an actual password change).
-- name: UpdateUserPasswordHash :exec
UPDATE users SET password_hash = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1;

-- name: SetUserPassword :one
UPDATE users
SET password_hash        = ?2,
    must_change_password = ?3,
    -- Changing the password clears the bootstrap flag: the warning is driven
    -- by this flag, never by comparing against a stored default password.
    is_bootstrap_default = 0,
    updated_at           = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    version              = version + 1
WHERE id = ?1 AND deleted_at IS NULL
RETURNING *;

-- name: SetUserMustChangePassword :exec
UPDATE users SET must_change_password = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1;

-- name: RecordUserLogin :exec
UPDATE users SET last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1;

-- Soft delete preserves audit history and avoids orphaning references.
-- name: SoftDeleteUser :exec
UPDATE users
SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), is_active = 0, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), version = version + 1
WHERE id = ?1 AND deleted_at IS NULL;

-- name: ClearUserBootstrapFlag :exec
UPDATE users SET is_bootstrap_default = 0, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1;

-- name: HasBootstrapDefaultUser :one
SELECT EXISTS (
    SELECT 1 FROM users
    WHERE is_bootstrap_default = 1 AND deleted_at IS NULL AND is_active = 1
) AS present;

-- name: CountUsersWithDefaultCredentials :one
SELECT count(*) FROM users WHERE is_bootstrap_default = 1 AND deleted_at IS NULL;

-- Roles ----------------------------------------------------------------------

-- name: CreateRole :one
INSERT INTO roles (name, description, is_system) VALUES (?1, ?2, ?3) RETURNING *;

-- name: GetRoleByName :one
SELECT * FROM roles WHERE name = ?1;

-- name: GetRoleByID :one
SELECT * FROM roles WHERE id = ?1;

-- name: ListRoles :many
SELECT * FROM roles ORDER BY name;

-- name: UpdateRole :one
UPDATE roles SET name = ?2, description = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE id = ?1 AND is_system = 0
RETURNING *;

-- name: DeleteRole :exec
DELETE FROM roles WHERE id = ?1 AND is_system = 0;

-- name: ListUserRoles :many
SELECT r.* FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = ?1
ORDER BY r.name;

-- name: AddUserRole :exec
INSERT INTO user_roles (user_id, role_id) VALUES (?1, ?2)
ON CONFLICT (user_id, role_id) DO NOTHING;

-- name: RemoveUserRole :exec
DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2;

-- name: ClearUserRoles :exec
DELETE FROM user_roles WHERE user_id = ?1;

-- Permissions ----------------------------------------------------------------

-- name: CreatePermission :one
INSERT INTO permissions (name, description) VALUES (?1, ?2) RETURNING *;

-- name: ListPermissions :many
SELECT * FROM permissions ORDER BY name;

-- name: GetPermissionByName :one
SELECT * FROM permissions WHERE name = ?1;

-- name: ListRolePermissions :many
SELECT p.* FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = ?1
ORDER BY p.name;

-- name: ListUserPermissions :many
-- Effective permissions from every role the user holds.
SELECT DISTINCT p.name FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
JOIN user_roles ur ON ur.role_id = rp.role_id
WHERE ur.user_id = ?1
ORDER BY p.name;

-- name: AddRolePermission :exec
INSERT INTO role_permissions (role_id, permission_id) VALUES (?1, ?2)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- name: RemoveRolePermission :exec
DELETE FROM role_permissions WHERE role_id = ?1 AND permission_id = ?2;

-- name: ClearRolePermissions :exec
DELETE FROM role_permissions WHERE role_id = ?1;
