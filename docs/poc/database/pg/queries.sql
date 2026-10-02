-- name: CreateUser :one
INSERT INTO users (username, password_hash, display_name) VALUES ($1,$2,$3) RETURNING *;
-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;
-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;
-- name: ListUsers :many
SELECT * FROM users ORDER BY id LIMIT $1 OFFSET $2;
-- name: UpdateUserPassword :exec
UPDATE users SET password_hash=$2, must_change=$3, updated_at=now() WHERE id=$1;
-- name: CreateServer :one
INSERT INTO servers (name,host,port,username,auth_method,tags,notes) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *;
-- name: ListServers :many
SELECT * FROM servers ORDER BY name LIMIT $1 OFFSET $2;
-- name: UpdateServerStatusVersioned :one
UPDATE servers SET status=$2, version=version+1 WHERE id=$1 AND version=$3 RETURNING *;
-- name: UpsertMetric :exec
INSERT INTO metric_samples (server_id,ts,cpu_pct,mem_used) VALUES ($1,$2,$3,$4)
ON CONFLICT (server_id,ts) DO UPDATE SET cpu_pct=EXCLUDED.cpu_pct, mem_used=EXCLUDED.mem_used;
-- name: InsertAudit :one
INSERT INTO audit_logs (actor_id,action,target,server_id,result,request_id,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *;
-- name: ListAudit :many
SELECT * FROM audit_logs
WHERE (sqlc.narg('actor_id')::bigint IS NULL OR actor_id = sqlc.narg('actor_id'))
  AND (sqlc.narg('server_id')::bigint IS NULL OR server_id = sqlc.narg('server_id'))
ORDER BY ts DESC, id DESC LIMIT $1 OFFSET $2;
-- name: ClaimJob :one
UPDATE jobs SET status='running', locked_by=$1, locked_at=now(), attempts=attempts+1
WHERE id=(SELECT id FROM jobs WHERE status='queued' AND run_at<=now() ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING *;
-- name: DeleteMetricBefore :exec
DELETE FROM metric_samples WHERE ts < $1;
