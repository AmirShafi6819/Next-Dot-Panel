-- Jobs ----------------------------------------------------------------------
--
-- ClaimJob is the critical path. It is an UPDATE ... RETURNING, so the claim
-- COMMITS before the row is scanned. If the scan fails, the caller sees an
-- error while the job is already marked running -- a naive retry would strand
-- it forever. Two consequences, both deliberate:
--
--   1. the generated row types must scan cleanly on both dialects (hence the
--      JSON []byte and timestamp overrides in sqlc.yaml);
--   2. a test asserts that a returned error means the job was NOT claimed.
--
-- On PostgreSQL, lets several workers claim jobs
-- concurrently without blocking each other or double-claiming.
-- SQLite has no equivalent, so its variant runs under a single-writer pool and
-- the limitation is documented rather than papered over (Design Spec 22.3).

-- name: EnqueueJob :one
INSERT INTO jobs (kind, priority, max_attempts, run_at, payload, created_by, server_id, dedupe_key)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
RETURNING *;

-- name: GetJob :one
SELECT * FROM jobs WHERE id = ?1;

-- name: ListJobs :many
SELECT * FROM jobs
WHERE (sqlc.narg('status') IS NULL OR status = sqlc.narg('status'))
  AND (sqlc.narg('kind') IS NULL OR kind = sqlc.narg('kind'))
  AND (sqlc.narg('server_id') IS NULL OR server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('created_by') IS NULL OR created_by = sqlc.narg('created_by'))
ORDER BY created_at DESC
LIMIT ?1 OFFSET ?2;

-- name: CountJobs :one
SELECT count(*) FROM jobs
WHERE (sqlc.narg('status') IS NULL OR status = sqlc.narg('status'))
  AND (sqlc.narg('kind') IS NULL OR kind = sqlc.narg('kind'))
  AND (sqlc.narg('server_id') IS NULL OR server_id = sqlc.narg('server_id'))
  AND (sqlc.narg('created_by') IS NULL OR created_by = sqlc.narg('created_by'));

-- name: CountJobsByStatus :many
SELECT status, count(*) AS count FROM jobs GROUP BY status;

-- name: ClaimJob :one
UPDATE jobs
SET status     = 'running',
    locked_by  = ?1,
    locked_at  = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    attempts   = attempts + 1,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE id = (
    SELECT id FROM jobs
    WHERE status = 'queued' AND run_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')
    ORDER BY priority DESC, id
   
    LIMIT 1
)
RETURNING *;

-- name: ClaimJobByKind :one
UPDATE jobs
SET status     = 'running',
    locked_by  = ?1,
    locked_at  = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    attempts   = attempts + 1,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE id = (
    SELECT id FROM jobs
    WHERE jobs.status = 'queued' AND jobs.run_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now') AND jobs.kind = ?2
    ORDER BY priority DESC, id
   
    LIMIT 1
)
RETURNING *;

-- name: CompleteJob :exec
UPDATE jobs
SET status = 'succeeded', progress = 1, finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    locked_by = NULL, locked_at = NULL
WHERE id = ?1;

-- name: UpdateJobProgress :exec
UPDATE jobs SET progress = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1;

-- name: HeartbeatJob :exec
-- Refreshes the lease so the reaper does not reclaim a job that is still
-- running.
UPDATE jobs SET locked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1 AND status = 'running';

-- name: FailJob :exec
-- Transient failure with attempts remaining: schedule a retry.
UPDATE jobs
SET status     = 'retrying',
    run_at     = ?2,
    last_error = ?3,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    locked_by  = NULL,
    locked_at  = NULL
WHERE id = ?1;

-- name: DeadJob :exec
-- Terminal failure: attempts exhausted.
UPDATE jobs
SET status      = 'dead',
    last_error  = ?2,
    finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    updated_at  = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    locked_by   = NULL,
    locked_at   = NULL
WHERE id = ?1;

-- name: CancelJob :exec
UPDATE jobs
SET status = 'cancelled', finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    locked_by = NULL, locked_at = NULL
WHERE id = ?1 AND status IN ('queued', 'retrying', 'running');

-- name: RequeueJob :exec
-- Returns a job to the queue without counting an attempt, used by the reaper
-- when a worker disappears.
UPDATE jobs
SET status = 'queued', run_at = ?2, locked_by = NULL, locked_at = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE id = ?1;

-- name: ListStaleJobs :many
-- Jobs whose worker stopped heartbeating. A crash leaves these behind; without
-- reaping they would sit in 'running' forever.
SELECT * FROM jobs
WHERE status = 'running' AND locked_at IS NOT NULL AND locked_at < ?1
ORDER BY id;

-- name: DeleteFinishedJobsBefore :execrows
DELETE FROM jobs
WHERE status IN ('succeeded', 'dead', 'cancelled') AND finished_at IS NOT NULL AND finished_at < ?1;

-- name: PromoteRetryingJobs :execrows
-- Moves due retries back to queued so the claim query can pick them up.
UPDATE jobs SET status = 'queued', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE status = 'retrying' AND run_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now');

-- name: CountPendingJobs :one
SELECT count(*) FROM jobs WHERE status IN ('queued', 'retrying');

-- name: CountRunningJobs :one
SELECT count(*) FROM jobs WHERE status = 'running';
