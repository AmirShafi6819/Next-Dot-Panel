-- Metric samples ------------------------------------------------------------
--
-- A NULL column means "not collected", which is distinct from 0. Aggregations
-- use AVG/MAX, which ignore NULLs, so an absent metric never drags an average
-- toward zero (Design Spec 18.4).

-- name: UpsertMetricSample :exec
-- Idempotent on (server_id, ts): replaying a sample overwrites rather than
-- duplicating, so a retried job cannot double-count.
INSERT INTO metric_samples (
    server_id, ts, cpu_pct, load1, load5, load15,
    mem_total, mem_used, mem_available, mem_cached, mem_buffers,
    swap_total, swap_used, net_rx_bytes, net_tx_bytes,
    disk_read_bytes, disk_write_bytes, uptime_seconds, process_count
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19
)
ON CONFLICT (server_id, ts) DO UPDATE SET
    cpu_pct          = EXCLUDED.cpu_pct,
    load1            = EXCLUDED.load1,
    load5            = EXCLUDED.load5,
    load15           = EXCLUDED.load15,
    mem_total        = EXCLUDED.mem_total,
    mem_used         = EXCLUDED.mem_used,
    mem_available    = EXCLUDED.mem_available,
    mem_cached       = EXCLUDED.mem_cached,
    mem_buffers      = EXCLUDED.mem_buffers,
    swap_total       = EXCLUDED.swap_total,
    swap_used        = EXCLUDED.swap_used,
    net_rx_bytes     = EXCLUDED.net_rx_bytes,
    net_tx_bytes     = EXCLUDED.net_tx_bytes,
    disk_read_bytes  = EXCLUDED.disk_read_bytes,
    disk_write_bytes = EXCLUDED.disk_write_bytes,
    uptime_seconds   = EXCLUDED.uptime_seconds,
    process_count    = EXCLUDED.process_count;

-- name: GetLatestMetricSample :one
SELECT * FROM metric_samples WHERE server_id = ?1 ORDER BY ts DESC LIMIT 1;

-- name: GetMetricSampleAt :one
SELECT * FROM metric_samples WHERE server_id = ?1 AND ts = ?2;

-- name: ListMetricSamples :many
SELECT * FROM metric_samples
WHERE server_id = ?1 AND ts >= ?2 AND ts <= ?3
ORDER BY ts
LIMIT ?4;

-- name: CountMetricSamples :one
SELECT count(*) FROM metric_samples WHERE server_id = ?1 AND ts >= ?2 AND ts <= ?3;

-- name: ListLatestSamplesForAllServers :many
-- Dashboard summary: one row per server, the most recent sample.
SELECT m.* FROM metric_samples m
JOIN (SELECT server_id AS sid, max(ts) AS mts FROM metric_samples GROUP BY server_id) x
  ON x.sid = m.server_id AND x.mts = m.ts
ORDER BY m.server_id;

-- name: DeleteMetricSamplesBefore :execrows
DELETE FROM metric_samples WHERE ts < ?1;

-- name: DeleteMetricSamplesForServerBefore :execrows
DELETE FROM metric_samples WHERE server_id = ?1 AND ts < ?2;

-- Aggregates -----------------------------------------------------------------

-- name: UpsertMetricAggregate :exec
-- Idempotent on (server_id, resolution, ts), so re-running an aggregation job
-- after a partial failure reproduces the same buckets rather than compounding
-- them.
INSERT INTO metric_aggregates (
    server_id, resolution, ts,
    cpu_pct_avg, cpu_pct_min, cpu_pct_max,
    mem_used_avg, mem_used_max, swap_used_avg, swap_used_max,
    net_rx_rate_avg, net_tx_rate_avg, load1_avg, sample_count
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
ON CONFLICT (server_id, resolution, ts) DO UPDATE SET
    cpu_pct_avg     = EXCLUDED.cpu_pct_avg,
    cpu_pct_min     = EXCLUDED.cpu_pct_min,
    cpu_pct_max     = EXCLUDED.cpu_pct_max,
    mem_used_avg    = EXCLUDED.mem_used_avg,
    mem_used_max    = EXCLUDED.mem_used_max,
    swap_used_avg   = EXCLUDED.swap_used_avg,
    swap_used_max   = EXCLUDED.swap_used_max,
    net_rx_rate_avg = EXCLUDED.net_rx_rate_avg,
    net_tx_rate_avg = EXCLUDED.net_tx_rate_avg,
    load1_avg       = EXCLUDED.load1_avg,
    sample_count    = EXCLUDED.sample_count;

-- Buckets raw samples into fixed windows. floor() works identically on both
-- dialects for integer division of epoch seconds.
-- name: AggregateRawTo5m :many
SELECT
    server_id,
    CAST(?1 AS INTEGER) AS bucket,
    avg(cpu_pct)    AS cpu_avg,
    min(cpu_pct)    AS cpu_min,
    max(cpu_pct)    AS cpu_max,
    avg(mem_used)   AS mem_avg,
    max(mem_used)   AS mem_max,
    avg(swap_used)  AS swap_avg,
    max(swap_used)  AS swap_max,
    avg(load1)      AS load_avg,
    count(*)        AS samples
FROM metric_samples
WHERE ts >= ?2 AND ts < ?3
GROUP BY server_id;

-- name: ListMetricAggregates :many
SELECT * FROM metric_aggregates
WHERE server_id = ?1 AND resolution = ?2 AND ts >= ?3 AND ts <= ?4
ORDER BY ts
LIMIT ?5;

-- name: GetMetricAggregate :one
SELECT * FROM metric_aggregates
WHERE server_id = ?1 AND resolution = ?2 AND ts = ?3;

-- name: DeleteMetricAggregatesBefore :execrows
DELETE FROM metric_aggregates WHERE resolution = ?1 AND ts < ?2;

-- Filesystems ----------------------------------------------------------------

-- name: UpsertMetricFilesystem :exec
INSERT INTO metric_filesystems (
    server_id, ts, mount_point, device, fs_type, total_bytes, used_bytes, avail_bytes, used_pct
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
ON CONFLICT (server_id, ts, mount_point) DO UPDATE SET
    device      = EXCLUDED.device,
    fs_type     = EXCLUDED.fs_type,
    total_bytes = EXCLUDED.total_bytes,
    used_bytes  = EXCLUDED.used_bytes,
    avail_bytes = EXCLUDED.avail_bytes,
    used_pct    = EXCLUDED.used_pct;

-- name: ListLatestFilesystems :many
-- Current usage per mount point, for the dashboard.
SELECT mf.* FROM metric_filesystems mf
JOIN (
    SELECT mount_point AS mp, max(ts) AS mts
    FROM metric_filesystems WHERE metric_filesystems.server_id = ?1
    GROUP BY mount_point
) latest ON latest.mp = mf.mount_point AND latest.mts = mf.ts
WHERE mf.server_id = ?1
ORDER BY mf.mount_point;

-- name: ListMetricFilesystems :many
SELECT * FROM metric_filesystems
WHERE server_id = ?1 AND ts >= ?2 AND ts <= ?3
ORDER BY ts, mount_point
LIMIT ?4;

-- name: DeleteMetricFilesystemsBefore :execrows
DELETE FROM metric_filesystems WHERE ts < ?1;
