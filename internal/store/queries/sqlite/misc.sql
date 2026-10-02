-- API tokens -----------------------------------------------------------------
--
-- Only the SHA-256 hash is stored. The raw token is returned once, at creation,
-- and is unrecoverable afterwards.

-- name: CreateAPIToken :one
INSERT INTO api_tokens (user_id, name, token_hash, scopes, expires_at)
VALUES (?1, ?2, ?3, ?4, ?5)
RETURNING *;

-- name: GetAPITokenByHash :one
SELECT * FROM api_tokens
WHERE token_hash = ?1 AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now'));

-- name: GetAPIToken :one
SELECT * FROM api_tokens WHERE id = ?1;

-- name: ListAPITokens :many
SELECT * FROM api_tokens WHERE user_id = ?1 ORDER BY created_at DESC;

-- name: ListAllAPITokens :many
SELECT t.*, u.username FROM api_tokens t
JOIN users u ON u.id = t.user_id
ORDER BY t.created_at DESC
LIMIT ?1 OFFSET ?2;

-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1;

-- name: RevokeAPIToken :exec
UPDATE api_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1 AND revoked_at IS NULL;

-- name: RevokeUserAPITokens :execrows
UPDATE api_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id = ?1 AND revoked_at IS NULL;

-- name: DeleteAPIToken :exec
DELETE FROM api_tokens WHERE id = ?1;

-- name: DeleteExpiredAPITokens :execrows
DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND expires_at < ?1;

-- Settings -------------------------------------------------------------------

-- name: UpsertSetting :exec
INSERT INTO settings (key, value, updated_by, updated_at)
VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
ON CONFLICT (key) DO UPDATE SET
    value      = EXCLUDED.value,
    updated_by = EXCLUDED.updated_by,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now');

-- name: GetSetting :one
SELECT * FROM settings WHERE key = ?1;

-- name: ListSettings :many
SELECT * FROM settings ORDER BY key;

-- name: DeleteSetting :exec
DELETE FROM settings WHERE key = ?1;

-- Terminal sessions -----------------------------------------------------------
--
-- Metadata only. Terminal input and output are never persisted: recording
-- keystrokes would capture every secret an operator types (Design Spec 27.5).

-- name: CreateTerminalSession :one
INSERT INTO terminal_sessions (id, user_id, server_id, session_id, cols, rows)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
RETURNING *;

-- name: CloseTerminalSession :exec
UPDATE terminal_sessions SET closed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), close_reason = ?2
WHERE id = ?1 AND closed_at IS NULL;

-- name: GetTerminalSession :one
SELECT * FROM terminal_sessions WHERE id = ?1;

-- name: ListOpenTerminalSessions :many
SELECT * FROM terminal_sessions WHERE closed_at IS NULL ORDER BY opened_at;

-- name: CountOpenTerminalSessionsForUser :one
SELECT count(*) FROM terminal_sessions WHERE user_id = ?1 AND closed_at IS NULL;

-- name: CountOpenTerminalSessionsForServer :one
SELECT count(*) FROM terminal_sessions WHERE server_id = ?1 AND closed_at IS NULL;

-- name: CountOpenTerminalSessions :one
SELECT count(*) FROM terminal_sessions WHERE closed_at IS NULL;

-- name: ListUserTerminalSessions :many
SELECT * FROM terminal_sessions WHERE user_id = ?1 ORDER BY opened_at DESC LIMIT ?2;

-- name: CloseTerminalSessionsForUser :execrows
UPDATE terminal_sessions SET closed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), close_reason = ?2
WHERE user_id = ?1 AND closed_at IS NULL;

-- name: CloseTerminalSessionsForServer :execrows
UPDATE terminal_sessions SET closed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), close_reason = ?2
WHERE server_id = ?1 AND closed_at IS NULL;

-- name: DeleteClosedTerminalSessionsBefore :execrows
DELETE FROM terminal_sessions WHERE closed_at IS NOT NULL AND closed_at < ?1;

-- Notifications ---------------------------------------------------------------

-- name: CreateNotification :one
INSERT INTO notifications (kind, severity, title, body, server_id, dedupe_key)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
ON CONFLICT (dedupe_key) DO UPDATE SET
    title      = EXCLUDED.title,
    body       = EXCLUDED.body,
    severity   = EXCLUDED.severity,
    ts         = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    is_read    = 0
RETURNING *;

-- name: ListNotifications :many
SELECT * FROM notifications
WHERE (sqlc.narg('unread_only') IS NULL OR is_read = 0)
ORDER BY ts DESC
LIMIT ?1 OFFSET ?2;

-- name: CountUnreadNotifications :one
SELECT count(*) FROM notifications WHERE is_read = 0;

-- name: MarkNotificationRead :exec
UPDATE notifications SET is_read = 1 WHERE id = ?1;

-- name: MarkAllNotificationsRead :exec
UPDATE notifications SET is_read = 1 WHERE is_read = 0;

-- name: DeleteNotificationsBefore :execrows
DELETE FROM notifications WHERE ts < ?1;

-- Backups ---------------------------------------------------------------------

-- name: CreateBackup :one
INSERT INTO backups (filename, path, status, created_by)
VALUES (?1, ?2, ?3, ?4)
RETURNING *;

-- name: FinishBackup :exec
UPDATE backups
SET status = ?2, size_bytes = ?3, checksum = ?4, error = ?5, finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE id = ?1;

-- name: GetBackup :one
SELECT * FROM backups WHERE id = ?1;

-- name: ListBackups :many
SELECT * FROM backups ORDER BY started_at DESC LIMIT ?1 OFFSET ?2;

-- name: DeleteBackup :exec
DELETE FROM backups WHERE id = ?1;

-- name: ListBackupsToPrune :many
SELECT * FROM backups
WHERE status = 'succeeded'
ORDER BY started_at DESC
LIMIT -1 OFFSET ?1;

-- Health ----------------------------------------------------------------------

-- name: Ping :one
SELECT 1 AS ok;
