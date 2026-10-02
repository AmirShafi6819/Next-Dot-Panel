-- Servers -------------------------------------------------------------------

-- name: CreateServer :one
INSERT INTO servers (name, target_type, host, port, username, auth_method,
                     host_key_policy, tags, notes, is_favourite)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetServerByID :one
SELECT * FROM servers WHERE id = $1;

-- name: GetServerByName :one
SELECT * FROM servers WHERE name = $1;

-- name: ListServers :many
SELECT * FROM servers
WHERE (sqlc.narg('search')::text IS NULL
       OR name ILIKE '%' || sqlc.narg('search')::text || '%'
       OR host ILIKE '%' || sqlc.narg('search')::text || '%'
       OR username ILIKE '%' || sqlc.narg('search')::text || '%')
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('target_type')::text IS NULL OR target_type = sqlc.narg('target_type')::text)
  -- Tag filtering uses a substring match on the JSON array text with the
  -- surrounding quotes included, which is precise enough for tag names and
  -- portable across both dialects. PostgreSQL's jsonb @> operator would be
  -- exact but has no SQLite equivalent.
  AND (sqlc.narg('tag')::text IS NULL
       OR tags LIKE '%"' || sqlc.narg('tag')::text || '"%')
ORDER BY is_favourite DESC, name
LIMIT $1 OFFSET $2;

-- name: CountServers :one
SELECT count(*) FROM servers
WHERE (sqlc.narg('search')::text IS NULL
       OR name ILIKE '%' || sqlc.narg('search')::text || '%'
       OR host ILIKE '%' || sqlc.narg('search')::text || '%'
       OR username ILIKE '%' || sqlc.narg('search')::text || '%')
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('target_type')::text IS NULL OR target_type = sqlc.narg('target_type')::text)
  -- Tag filtering uses a substring match on the JSON array text with the
  -- surrounding quotes included, which is precise enough for tag names and
  -- portable across both dialects. PostgreSQL's jsonb @> operator would be
  -- exact but has no SQLite equivalent.
  AND (sqlc.narg('tag')::text IS NULL
       OR tags LIKE '%"' || sqlc.narg('tag')::text || '"%');

-- name: CountServersByStatus :many
SELECT status, count(*) AS count FROM servers GROUP BY status;

-- name: ListAllServers :many
-- Used by background workers that operate across every server.
SELECT * FROM servers ORDER BY id;

-- name: ListServerIDs :many
SELECT id FROM servers ORDER BY id;

-- name: UpdateServer :one
-- Versioned update: a stale version returns no rows, so two administrators
-- editing the same server cannot silently overwrite each other.
UPDATE servers
SET name            = $2,
    host            = $3,
    port            = $4,
    username        = $5,
    auth_method     = $6,
    host_key_policy = $7,
    tags            = $8,
    notes           = $9,
    is_favourite    = $10,
    updated_at      = now(),
    version         = version + 1
WHERE id = $1 AND version = $11
RETURNING *;

-- name: UpdateServerStatus :one
UPDATE servers
SET status        = $2,
    status_detail = $3,
    last_seen_at  = CASE WHEN $2 = 'ONLINE' THEN now() ELSE last_seen_at END,
    last_error_at = CASE WHEN $2 IN ('OFFLINE','ERROR') THEN now() ELSE last_error_at END,
    updated_at    = now()
WHERE id = $1
RETURNING *;

-- name: UpdateServerSystemInfo :exec
UPDATE servers
SET os = $2, kernel = $3, arch = $4, updated_at = now()
WHERE id = $1;

-- Deleting a server removes only the panel's configuration. It never touches
-- the remote host. Credentials and host keys cascade.
-- name: DeleteServer :exec
DELETE FROM servers WHERE id = $1;

-- name: ServerNameExists :one
SELECT EXISTS (SELECT 1 FROM servers WHERE name = $1 AND id <> $2) AS present;

-- Credentials ----------------------------------------------------------------

-- name: CreateServerCredential :one
INSERT INTO server_credentials (server_id, kind, ciphertext, version)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetServerCredential :one
SELECT * FROM server_credentials
WHERE server_id = $1
ORDER BY version DESC
LIMIT 1;

-- name: RotateServerCredential :one
-- Rotation bumps the version, which invalidates pooled connections keyed to
-- the previous version.
INSERT INTO server_credentials (server_id, kind, ciphertext, version)
SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1
FROM server_credentials WHERE server_id = $1
RETURNING *;

-- name: DeleteServerCredentials :exec
DELETE FROM server_credentials WHERE server_id = $1;

-- name: ListCredentialCiphertexts :many
-- Used by the key-rotation sweep.
SELECT id, server_id, ciphertext FROM server_credentials ORDER BY id;

-- name: UpdateCredentialCiphertext :exec
UPDATE server_credentials SET ciphertext = $2, rotated_at = now() WHERE id = $1;

-- Host keys ------------------------------------------------------------------

-- name: GetServerHostKey :one
SELECT * FROM server_host_keys WHERE server_id = $1 ORDER BY first_seen DESC LIMIT 1;

-- name: GetServerHostKeyByFingerprint :one
SELECT * FROM server_host_keys WHERE server_id = $1 AND fingerprint = $2;

-- name: ListServerHostKeys :many
SELECT * FROM server_host_keys WHERE server_id = $1 ORDER BY first_seen DESC;

-- name: CreateServerHostKey :one
INSERT INTO server_host_keys (server_id, algorithm, fingerprint, public_key, state, trusted_at, trusted_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: UpdateHostKeyState :exec
UPDATE server_host_keys SET state = $2, trusted_at = $3, trusted_by = $4 WHERE id = $1;

-- Replacing a changed host key is an explicit, audited action; it never
-- happens as a side effect of connecting.
-- name: DeleteServerHostKeys :exec
DELETE FROM server_host_keys WHERE server_id = $1;

-- Tags -----------------------------------------------------------------------

-- name: UpsertTag :one
INSERT INTO tags (name) VALUES ($1)
ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
RETURNING *;

-- name: ListTags :many
SELECT t.*, count(st.server_id) AS server_count FROM tags t
LEFT JOIN server_tags st ON st.tag_id = t.id
GROUP BY t.id, t.name, t.created_at
ORDER BY t.name;

-- name: AddServerTag :exec
INSERT INTO server_tags (server_id, tag_id) VALUES ($1, $2)
ON CONFLICT (server_id, tag_id) DO NOTHING;

-- name: RemoveServerTag :exec
DELETE FROM server_tags WHERE server_id = $1 AND tag_id = $2;

-- name: ClearServerTags :exec
DELETE FROM server_tags WHERE server_id = $1;

-- name: DeleteOrphanTags :execrows
DELETE FROM tags WHERE id NOT IN (SELECT DISTINCT tag_id FROM server_tags);

-- Per-server permissions ------------------------------------------------------

-- name: ListServerPermissions :many
SELECT p.name FROM server_permissions sp
JOIN permissions p ON p.id = sp.permission_id
WHERE sp.user_id = $1 AND sp.server_id = $2
ORDER BY p.name;

-- name: GrantServerPermission :exec
INSERT INTO server_permissions (user_id, server_id, permission_id, granted_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, server_id, permission_id) DO NOTHING;

-- name: RevokeServerPermission :exec
DELETE FROM server_permissions
WHERE user_id = $1 AND server_id = $2 AND permission_id = $3;

-- name: ClearServerPermissions :exec
DELETE FROM server_permissions WHERE user_id = $1 AND server_id = $2;

-- name: CountServerPermissionsForUser :one
SELECT count(*) FROM server_permissions WHERE user_id = $1 AND server_id = $2;

-- name: ListAccessibleServerIDs :many
-- Servers a user may see. An administrator sees everything; anyone else sees
-- only servers with at least one explicit grant. Returning 404 (not 403) for
-- the others avoids disclosing that they exist.
SELECT DISTINCT sp.server_id FROM server_permissions sp WHERE sp.user_id = $1;

-- name: ListServerPermissionGrants :many
SELECT sp.server_id, p.name FROM server_permissions sp
JOIN permissions p ON p.id = sp.permission_id
WHERE sp.user_id = $1;
