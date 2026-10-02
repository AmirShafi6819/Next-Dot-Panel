-- Sessions ------------------------------------------------------------------

-- name: CreateSession :one
INSERT INTO sessions (id, user_id, token_hash, ip, user_agent, expires_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
RETURNING *;

-- Lookup is by token hash: the raw token is never stored, so a database leak
-- does not yield usable session tokens.
-- name: GetSessionByTokenHash :one
SELECT * FROM sessions
WHERE token_hash = ?1 AND revoked_at IS NULL AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now');

-- name: GetSessionByID :one
SELECT * FROM sessions WHERE id = ?1;

-- name: ListUserSessions :many
SELECT * FROM sessions
WHERE user_id = ?1 AND revoked_at IS NULL AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')
ORDER BY last_seen_at DESC;

-- name: ListAllSessions :many
SELECT s.*, u.username FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.revoked_at IS NULL AND s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')
ORDER BY s.last_seen_at DESC
LIMIT ?1 OFFSET ?2;

-- name: CountActiveSessions :one
SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now');

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1;

-- Records a fresh password confirmation for the re-authentication window
-- (Design Spec section 13.3).
-- name: SetSessionReauthAt :exec
UPDATE sessions SET reauth_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1 AND revoked_at IS NULL;

-- Revoking every other session is part of changing a password.
-- name: RevokeUserSessions :execrows
UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE user_id = ?1 AND revoked_at IS NULL;

-- name: RevokeUserSessionsExcept :execrows
UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE user_id = ?1 AND id <> ?2 AND revoked_at IS NULL;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at <= ?1 OR revoked_at IS NOT NULL;

-- Login history --------------------------------------------------------------

-- name: InsertLoginHistory :one
INSERT INTO login_history (user_id, username, ip, user_agent, success, failure_reason, session_id)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
RETURNING *;

-- name: ListLoginHistory :many
SELECT * FROM login_history
WHERE (sqlc.narg('user_id') IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('ip') IS NULL OR ip = sqlc.narg('ip'))
  AND (sqlc.narg('success') IS NULL OR success = sqlc.narg('success'))
  AND (sqlc.narg('from_ts') IS NULL OR ts >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts') IS NULL OR ts <= sqlc.narg('to_ts'))
ORDER BY ts DESC, id DESC
LIMIT ?1 OFFSET ?2;

-- name: CountLoginHistory :one
SELECT count(*) FROM login_history
WHERE (sqlc.narg('user_id') IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('ip') IS NULL OR ip = sqlc.narg('ip'))
  AND (sqlc.narg('success') IS NULL OR success = sqlc.narg('success'))
  AND (sqlc.narg('from_ts') IS NULL OR ts >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts') IS NULL OR ts <= sqlc.narg('to_ts'));

-- Counts recent failures for one account, used by the progressive-lockout
-- check. Deliberately independent of the IP-based limiter.
-- name: CountRecentLoginFailures :one
SELECT count(*) FROM login_history
WHERE username = ?1 AND success = 0 AND ts > ?2;

-- name: CountRecentLoginFailuresByIP :one
SELECT count(*) FROM login_history
WHERE ip = ?1 AND success = 0 AND ts > ?2;

-- name: DeleteLoginHistoryBefore :execrows
DELETE FROM login_history WHERE ts < ?1;
