-- Audit log -----------------------------------------------------------------
--
-- append-only: these queries only ever INSERT or SELECT. No UPDATE or DELETE
-- query exists, which is what makes the trail tamper-resistant through the
-- application (Design Spec 27.1). Retention pruning runs through
-- DeleteAuditBefore, the single documented exception.

-- name: InsertAuditLog :one
INSERT INTO audit_logs (actor_id, actor_name, action, target, server_id, server_name,
                        result, request_id, ip, user_agent, metadata)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
RETURNING *;

-- name: GetAuditLog :one
SELECT * FROM audit_logs WHERE id = ?1;

-- name: ListAuditLogs :many
SELECT * FROM audit_logs
WHERE (sqlc.narg('actor_id') IS NULL OR actor_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('server_id') IS NULL OR server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('action') IS NULL OR action = sqlc.narg('action'))
  AND (sqlc.narg('result') IS NULL OR result = sqlc.narg('result'))
  AND (sqlc.narg('ip') IS NULL OR ip = sqlc.narg('ip'))
  AND (sqlc.narg('request_id') IS NULL OR request_id = sqlc.narg('request_id'))
  AND (sqlc.narg('from_ts') IS NULL OR ts >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts') IS NULL OR ts <= sqlc.narg('to_ts'))
  AND (sqlc.narg('search') IS NULL
       OR action LIKE '%' || sqlc.narg('search') || '%'
       OR target LIKE '%' || sqlc.narg('search') || '%'
       OR actor_name LIKE '%' || sqlc.narg('search') || '%'
       OR server_name LIKE '%' || sqlc.narg('search') || '%')
ORDER BY ts DESC, id DESC
LIMIT ?1 OFFSET ?2;

-- name: CountAuditLogs :one
SELECT count(*) FROM audit_logs
WHERE (sqlc.narg('actor_id') IS NULL OR actor_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('server_id') IS NULL OR server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('action') IS NULL OR action = sqlc.narg('action'))
  AND (sqlc.narg('result') IS NULL OR result = sqlc.narg('result'))
  AND (sqlc.narg('ip') IS NULL OR ip = sqlc.narg('ip'))
  AND (sqlc.narg('request_id') IS NULL OR request_id = sqlc.narg('request_id'))
  AND (sqlc.narg('from_ts') IS NULL OR ts >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts') IS NULL OR ts <= sqlc.narg('to_ts'))
  AND (sqlc.narg('search') IS NULL
       OR action LIKE '%' || sqlc.narg('search') || '%'
       OR target LIKE '%' || sqlc.narg('search') || '%'
       OR actor_name LIKE '%' || sqlc.narg('search') || '%'
       OR server_name LIKE '%' || sqlc.narg('search') || '%');

-- name: ListRecentAuditForServer :many
SELECT * FROM audit_logs WHERE server_id = ?1 ORDER BY ts DESC, id DESC LIMIT ?2;

-- name: CountAuditByAction :many
SELECT action, count(*) AS count FROM audit_logs
WHERE ts > ?1 GROUP BY action ORDER BY count DESC;

-- name: CountAuditByResult :many
SELECT result, count(*) AS count FROM audit_logs
WHERE ts > ?1 GROUP BY result ORDER BY count DESC;

-- name: CountSecurityEvents :one
SELECT count(*) FROM audit_logs
WHERE ts > ?1 AND action IN ('SECURITY_EVENT', 'ACCESS_DENIED', 'LOGIN_FAILED');

-- The single permitted deletion path. The caller records an AUDIT_PRUNED
-- event so that pruning is itself visible in the trail.
-- name: DeleteAuditBefore :execrows
DELETE FROM audit_logs WHERE ts < ?1;

-- Application logs ------------------------------------------------------------

-- name: InsertApplicationLog :one
INSERT INTO application_logs (level, component, message, request_id, actor_id, server_id, fields)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
RETURNING *;

-- name: ListApplicationLogs :many
SELECT * FROM application_logs
WHERE (sqlc.narg('level') IS NULL OR level = sqlc.narg('level'))
  AND (sqlc.narg('component') IS NULL OR component = sqlc.narg('component'))
  AND (sqlc.narg('server_id') IS NULL OR server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('request_id') IS NULL OR request_id = sqlc.narg('request_id'))
  AND (sqlc.narg('search') IS NULL OR message LIKE '%' || sqlc.narg('search') || '%')
  AND (sqlc.narg('from_ts') IS NULL OR ts >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts') IS NULL OR ts <= sqlc.narg('to_ts'))
ORDER BY ts DESC, id DESC
LIMIT ?1 OFFSET ?2;

-- name: CountApplicationLogs :one
SELECT count(*) FROM application_logs
WHERE (sqlc.narg('level') IS NULL OR level = sqlc.narg('level'))
  AND (sqlc.narg('component') IS NULL OR component = sqlc.narg('component'))
  AND (sqlc.narg('server_id') IS NULL OR server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('request_id') IS NULL OR request_id = sqlc.narg('request_id'))
  AND (sqlc.narg('search') IS NULL OR message LIKE '%' || sqlc.narg('search') || '%')
  AND (sqlc.narg('from_ts') IS NULL OR ts >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts') IS NULL OR ts <= sqlc.narg('to_ts'));

-- name: DeleteApplicationLogsBefore :execrows
DELETE FROM application_logs WHERE ts < ?1;
