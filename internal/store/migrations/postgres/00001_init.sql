-- +goose Up
-- Initial Next.Panel schema (PostgreSQL).
--
-- Portability note: this file and its SQLite sibling must stay structurally
-- identical, differing only in dialect mechanics (types, defaults, sequences).
-- sqlc generates from both; a divergence shows up as a generation failure.

-- ---------------------------------------------------------------------------
-- Identity and access
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id                   BIGSERIAL PRIMARY KEY,
    username             TEXT        NOT NULL,
    password_hash        TEXT        NOT NULL,
    display_name         TEXT        NOT NULL DEFAULT '',
    is_active            BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Set only for the seeded administrator. This flag -- never a plaintext
    -- password comparison -- is what drives the default-credential warning.
    is_bootstrap_default BOOLEAN     NOT NULL DEFAULT FALSE,
    must_change_password BOOLEAN     NOT NULL DEFAULT FALSE,
    last_login_at        TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at           TIMESTAMPTZ,
    -- Optimistic locking for concurrent edits.
    version              BIGINT      NOT NULL DEFAULT 1
);

-- Usernames are compared case-insensitively but stored as entered.
CREATE UNIQUE INDEX users_username_key ON users (lower(username)) WHERE deleted_at IS NULL;

CREATE TABLE roles (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE,
    description TEXT        NOT NULL DEFAULT '',
    is_system   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permissions (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE role_permissions (
    role_id       BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    BIGINT      NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX user_roles_role_idx ON user_roles (role_id);

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

CREATE TABLE sessions (
    id           TEXT        PRIMARY KEY,
    user_id      BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 of the opaque token. The token itself is never stored.
    token_hash   BYTEA       NOT NULL,
    ip           TEXT        NOT NULL DEFAULT '',
    user_agent   TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ
);

CREATE UNIQUE INDEX sessions_token_hash_key ON sessions (token_hash);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- Servers
-- ---------------------------------------------------------------------------

CREATE TABLE servers (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT        NOT NULL UNIQUE,
    -- 'ssh' or 'local'
    target_type   TEXT        NOT NULL DEFAULT 'ssh',
    host          TEXT        NOT NULL DEFAULT '',
    port          INTEGER     NOT NULL DEFAULT 22,
    username      TEXT        NOT NULL DEFAULT '',
    -- 'key' | 'password' | 'agent'
    auth_method   TEXT        NOT NULL DEFAULT 'key',
    -- 'TOFU' | 'STRICT'
    host_key_policy TEXT      NOT NULL DEFAULT 'TOFU',
    tags          JSONB       NOT NULL DEFAULT '[]',
    notes         TEXT        NOT NULL DEFAULT '',
    is_favourite  BOOLEAN     NOT NULL DEFAULT FALSE,
    -- 'UNKNOWN' | 'CONNECTING' | 'ONLINE' | 'OFFLINE' | 'ERROR'
    status        TEXT        NOT NULL DEFAULT 'UNKNOWN',
    -- Bounded, secret-free description of the current status.
    status_detail TEXT        NOT NULL DEFAULT '',
    os            TEXT        NOT NULL DEFAULT '',
    kernel        TEXT        NOT NULL DEFAULT '',
    arch          TEXT        NOT NULL DEFAULT '',
    last_seen_at  TIMESTAMPTZ,
    last_error_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    version       BIGINT      NOT NULL DEFAULT 1
);

CREATE INDEX servers_status_idx ON servers (status);
CREATE INDEX servers_updated_idx ON servers (updated_at DESC);

-- Credentials are stored as ciphertext only. The encryption key never lives in
-- this database (Design Spec §15.2).
CREATE TABLE server_credentials (
    id           BIGSERIAL PRIMARY KEY,
    server_id    BIGINT      NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    kind         TEXT        NOT NULL,
    ciphertext   BYTEA       NOT NULL,
    -- Incremented on rotation; pooled connections keyed to the old version are
    -- invalidated rather than reused.
    version      BIGINT      NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at   TIMESTAMPTZ
);

CREATE INDEX server_credentials_server_idx ON server_credentials (server_id);

-- Pinned host keys. A key whose state is CHANGED hard-stops the connection.
CREATE TABLE server_host_keys (
    id          BIGSERIAL PRIMARY KEY,
    server_id   BIGINT      NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    algorithm   TEXT        NOT NULL,
    -- SHA256:<base64> fingerprint, as displayed to the operator.
    fingerprint TEXT        NOT NULL,
    public_key  BYTEA       NOT NULL,
    -- 'UNKNOWN' | 'TRUSTED' | 'CHANGED' | 'REJECTED'
    state       TEXT        NOT NULL DEFAULT 'UNKNOWN',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    trusted_at  TIMESTAMPTZ,
    trusted_by  BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (server_id, fingerprint)
);

CREATE INDEX server_host_keys_server_idx ON server_host_keys (server_id);

CREATE TABLE tags (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT        NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE server_tags (
    server_id BIGINT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tag_id    BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (server_id, tag_id)
);

CREATE INDEX server_tags_tag_idx ON server_tags (tag_id);

-- Per-user, per-server permission grants (Design Spec §12.4).
CREATE TABLE server_permissions (
    user_id       BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id     BIGINT      NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    permission_id BIGINT      NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by    BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, server_id, permission_id)
);

CREATE INDEX server_permissions_server_idx ON server_permissions (server_id);

-- ---------------------------------------------------------------------------
-- Audit and history
-- ---------------------------------------------------------------------------

-- Append-only by construction: no update or delete path exists in the
-- repository layer. Retention pruning is the sole deletion mechanism.
CREATE TABLE audit_logs (
    id         BIGSERIAL   PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id   BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    -- Denormalised so history stays readable after a user is deleted.
    actor_name TEXT        NOT NULL DEFAULT '',
    action     TEXT        NOT NULL,
    target     TEXT        NOT NULL DEFAULT '',
    server_id  BIGINT      REFERENCES servers(id) ON DELETE SET NULL,
    server_name TEXT       NOT NULL DEFAULT '',
    -- 'SUCCESS' | 'FAILURE' | 'DENIED'
    result     TEXT        NOT NULL,
    request_id TEXT        NOT NULL DEFAULT '',
    ip         TEXT        NOT NULL DEFAULT '',
    user_agent TEXT        NOT NULL DEFAULT '',
    -- Sanitised metadata; never contains credential material.
    metadata   JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_logs_ts_idx ON audit_logs (ts DESC, id DESC);
CREATE INDEX audit_logs_actor_idx ON audit_logs (actor_id, ts DESC);
CREATE INDEX audit_logs_server_idx ON audit_logs (server_id, ts DESC);
CREATE INDEX audit_logs_action_idx ON audit_logs (action, ts DESC);
CREATE INDEX audit_logs_request_idx ON audit_logs (request_id);

CREATE TABLE login_history (
    id            BIGSERIAL   PRIMARY KEY,
    user_id       BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    username      TEXT        NOT NULL DEFAULT '',
    ip            TEXT        NOT NULL DEFAULT '',
    user_agent    TEXT        NOT NULL DEFAULT '',
    success       BOOLEAN     NOT NULL,
    -- Failure category only; never the attempted password.
    failure_reason TEXT       NOT NULL DEFAULT '',
    session_id    TEXT        NOT NULL DEFAULT '',
    ts            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX login_history_user_idx ON login_history (user_id, ts DESC);
CREATE INDEX login_history_ip_idx ON login_history (ip, ts DESC);
CREATE INDEX login_history_ts_idx ON login_history (ts DESC);

CREATE TABLE application_logs (
    id         BIGSERIAL   PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    level      TEXT        NOT NULL,
    component  TEXT        NOT NULL DEFAULT '',
    message    TEXT        NOT NULL,
    request_id TEXT        NOT NULL DEFAULT '',
    actor_id   BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    server_id  BIGINT      REFERENCES servers(id) ON DELETE SET NULL,
    fields     JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX application_logs_ts_idx ON application_logs (ts DESC);
CREATE INDEX application_logs_level_idx ON application_logs (level, ts DESC);

-- ---------------------------------------------------------------------------
-- Metrics
-- ---------------------------------------------------------------------------

CREATE TABLE metric_samples (
    server_id     BIGINT      NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts            TIMESTAMPTZ NOT NULL,
    -- NULL means "not collected", which is distinct from 0. A metric that
    -- could not be read must never be stored as zero (Design Spec §18.4).
    cpu_pct       DOUBLE PRECISION,
    load1         DOUBLE PRECISION,
    load5         DOUBLE PRECISION,
    load15        DOUBLE PRECISION,
    mem_total     BIGINT,
    mem_used      BIGINT,
    mem_available BIGINT,
    mem_cached    BIGINT,
    mem_buffers   BIGINT,
    swap_total    BIGINT,
    swap_used     BIGINT,
    net_rx_bytes  BIGINT,
    net_tx_bytes  BIGINT,
    disk_read_bytes  BIGINT,
    disk_write_bytes BIGINT,
    uptime_seconds   BIGINT,
    process_count    INTEGER,
    PRIMARY KEY (server_id, ts)
);

CREATE INDEX metric_samples_ts_idx ON metric_samples (ts);

CREATE TABLE metric_aggregates (
    server_id  BIGINT      NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    -- '5m' or '1h'
    resolution TEXT        NOT NULL,
    ts         TIMESTAMPTZ NOT NULL,
    cpu_pct_avg    DOUBLE PRECISION,
    cpu_pct_min    DOUBLE PRECISION,
    cpu_pct_max    DOUBLE PRECISION,
    mem_used_avg   BIGINT,
    mem_used_max   BIGINT,
    swap_used_avg  BIGINT,
    swap_used_max  BIGINT,
    net_rx_rate_avg DOUBLE PRECISION,
    net_tx_rate_avg DOUBLE PRECISION,
    load1_avg      DOUBLE PRECISION,
    sample_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (server_id, resolution, ts)
);

CREATE INDEX metric_aggregates_ts_idx ON metric_aggregates (resolution, ts);

-- Filesystem usage is per-mount, so it lives in its own table.
CREATE TABLE metric_filesystems (
    server_id   BIGINT      NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ NOT NULL,
    mount_point TEXT        NOT NULL,
    device      TEXT        NOT NULL DEFAULT '',
    fs_type     TEXT        NOT NULL DEFAULT '',
    total_bytes BIGINT,
    used_bytes  BIGINT,
    avail_bytes BIGINT,
    used_pct    DOUBLE PRECISION,
    PRIMARY KEY (server_id, ts, mount_point)
);

CREATE INDEX metric_filesystems_ts_idx ON metric_filesystems (ts);

-- ---------------------------------------------------------------------------
-- Terminal sessions (metadata only — input is never recorded)
-- ---------------------------------------------------------------------------

CREATE TABLE terminal_sessions (
    id          TEXT        PRIMARY KEY,
    user_id     BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id   BIGINT      NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    session_id  TEXT        NOT NULL DEFAULT '',
    cols        INTEGER     NOT NULL DEFAULT 80,
    rows        INTEGER     NOT NULL DEFAULT 24,
    opened_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at   TIMESTAMPTZ,
    -- 'open' | 'closed' | 'idle_timeout' | 'revoked' | 'error'
    close_reason TEXT       NOT NULL DEFAULT ''
);

CREATE INDEX terminal_sessions_user_idx ON terminal_sessions (user_id, opened_at DESC);
CREATE INDEX terminal_sessions_server_idx ON terminal_sessions (server_id, opened_at DESC);

-- ---------------------------------------------------------------------------
-- Jobs
-- ---------------------------------------------------------------------------

CREATE TABLE jobs (
    id           BIGSERIAL   PRIMARY KEY,
    kind         TEXT        NOT NULL,
    -- 'queued' | 'running' | 'succeeded' | 'failed' | 'retrying' | 'dead' | 'cancelled'
    status       TEXT        NOT NULL DEFAULT 'queued',
    priority     INTEGER     NOT NULL DEFAULT 0,
    attempts     INTEGER     NOT NULL DEFAULT 0,
    max_attempts INTEGER     NOT NULL DEFAULT 3,
    run_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Worker identity and heartbeat, used to recover jobs orphaned by a crash.
    locked_by    TEXT,
    locked_at    TIMESTAMPTZ,
    -- Payload validity is checked by the handler on load; the queue treats it
    -- as opaque bytes.
    payload      JSONB       NOT NULL DEFAULT '{}',
    -- -1 means indeterminate.
    progress     DOUBLE PRECISION NOT NULL DEFAULT -1,
    last_error   TEXT        NOT NULL DEFAULT '',
    created_by   BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    server_id    BIGINT      REFERENCES servers(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ,
    -- Prevents duplicate enqueues after a restart.
    dedupe_key   TEXT
);

CREATE INDEX jobs_claim_idx ON jobs (status, run_at, priority DESC, id);
CREATE INDEX jobs_kind_idx ON jobs (kind, status);
CREATE INDEX jobs_server_idx ON jobs (server_id);
CREATE UNIQUE INDEX jobs_dedupe_key ON jobs (dedupe_key) WHERE dedupe_key IS NOT NULL;

-- ---------------------------------------------------------------------------
-- API tokens
-- ---------------------------------------------------------------------------

CREATE TABLE api_tokens (
    id           BIGSERIAL   PRIMARY KEY,
    user_id      BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT        NOT NULL,
    -- SHA-256 of the token. The token itself is shown once and never stored.
    token_hash   BYTEA       NOT NULL,
    scopes       JSONB       NOT NULL DEFAULT '[]',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

CREATE UNIQUE INDEX api_tokens_hash_key ON api_tokens (token_hash);
CREATE INDEX api_tokens_user_idx ON api_tokens (user_id);

-- ---------------------------------------------------------------------------
-- Settings, notifications, backups
-- ---------------------------------------------------------------------------

CREATE TABLE settings (
    key        TEXT        PRIMARY KEY,
    value      JSONB       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by BIGINT      REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE notification_channels (
    id         BIGSERIAL   PRIMARY KEY,
    name       TEXT        NOT NULL UNIQUE,
    kind       TEXT        NOT NULL,
    -- Channel configuration may embed webhook URLs; treat as sensitive.
    config     JSONB       NOT NULL DEFAULT '{}',
    is_enabled BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notifications (
    id         BIGSERIAL   PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 'server_offline' | 'disk_critical' | 'memory_critical' | 'cpu_sustained'
    -- | 'ssh_failure' | 'auth_failures' | 'host_key_changed' | 'backup_failed'
    -- | 'job_failed'
    kind       TEXT        NOT NULL,
    severity   TEXT        NOT NULL DEFAULT 'info',
    title      TEXT        NOT NULL,
    body       TEXT        NOT NULL DEFAULT '',
    server_id  BIGINT      REFERENCES servers(id) ON DELETE CASCADE,
    -- Prevents duplicate alerts while a condition persists.
    dedupe_key TEXT        NOT NULL DEFAULT '',
    is_read    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX notifications_ts_idx ON notifications (ts DESC);
CREATE INDEX notifications_unread_idx ON notifications (is_read, ts DESC);
CREATE UNIQUE INDEX notifications_dedupe_idx ON notifications (dedupe_key) WHERE dedupe_key <> '';

CREATE TABLE backups (
    id          BIGSERIAL   PRIMARY KEY,
    filename    TEXT        NOT NULL,
    path        TEXT        NOT NULL,
    size_bytes  BIGINT      NOT NULL DEFAULT 0,
    checksum    TEXT        NOT NULL DEFAULT '',
    -- 'running' | 'succeeded' | 'failed'
    status      TEXT        NOT NULL DEFAULT 'running',
    error       TEXT        NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    created_by  BIGINT      REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX backups_started_idx ON backups (started_at DESC);

-- +goose Down
DROP TABLE IF EXISTS backups;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS notification_channels;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS terminal_sessions;
DROP TABLE IF EXISTS metric_filesystems;
DROP TABLE IF EXISTS metric_aggregates;
DROP TABLE IF EXISTS metric_samples;
DROP TABLE IF EXISTS application_logs;
DROP TABLE IF EXISTS login_history;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS server_permissions;
DROP TABLE IF EXISTS server_tags;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS server_host_keys;
DROP TABLE IF EXISTS server_credentials;
DROP TABLE IF EXISTS servers;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;
