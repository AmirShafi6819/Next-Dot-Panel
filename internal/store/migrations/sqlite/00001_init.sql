-- +goose Up
-- Initial Next.Panel schema (SQLite).
--
-- Structurally identical to the PostgreSQL migration, differing only in
-- dialect mechanics:
--   BIGSERIAL PRIMARY KEY -> INTEGER PRIMARY KEY AUTOINCREMENT
--   TIMESTAMPTZ           -> TEXT
--   BYTEA                 -> BLOB
--   JSONB                 -> JSON   (scanned as []byte via sqlc overrides)
--   BOOLEAN               -> INTEGER (0/1, scanned as bool via sqlc overrides)
--   DOUBLE PRECISION      -> REAL
--
-- Timestamp defaults use ISO-8601 with a 'T' separator and a trailing 'Z'.
-- SQLite's built-in CURRENT_TIMESTAMP emits "YYYY-MM-DD HH:MM:SS" with a
-- space, which is NOT lexicographically comparable with the RFC3339 strings
-- Go writes. Mixing the two formats would silently break every range query,
-- so all defaults go through strftime() to stay in one canonical format.

-- ---------------------------------------------------------------------------
-- Identity and access
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT    NOT NULL,
    password_hash        TEXT    NOT NULL,
    display_name         TEXT    NOT NULL DEFAULT '',
    is_active            INTEGER NOT NULL DEFAULT 1,
    -- Set only for the seeded administrator. This flag -- never a plaintext
    -- password comparison -- is what drives the default-credential warning.
    is_bootstrap_default INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at        TEXT,
    created_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    deleted_at           TEXT,
    -- Optimistic locking for concurrent edits.
    version              INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX users_username_key ON users (lower(username)) WHERE deleted_at IS NULL;

CREATE TABLE roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    is_system   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE permissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE role_permissions (
    role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX user_roles_role_idx ON user_roles (role_id);

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

CREATE TABLE sessions (
    id           TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 of the opaque token. The token itself is never stored.
    token_hash   BLOB    NOT NULL,
    ip           TEXT    NOT NULL DEFAULT '',
    user_agent   TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at   TEXT    NOT NULL,
    revoked_at   TEXT
);

CREATE UNIQUE INDEX sessions_token_hash_key ON sessions (token_hash);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- Servers
-- ---------------------------------------------------------------------------

CREATE TABLE servers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    target_type     TEXT    NOT NULL DEFAULT 'ssh',
    host            TEXT    NOT NULL DEFAULT '',
    port            INTEGER NOT NULL DEFAULT 22,
    username        TEXT    NOT NULL DEFAULT '',
    auth_method     TEXT    NOT NULL DEFAULT 'key',
    host_key_policy TEXT    NOT NULL DEFAULT 'TOFU',
    tags            JSON    NOT NULL DEFAULT '[]',
    notes           TEXT    NOT NULL DEFAULT '',
    is_favourite    INTEGER NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'UNKNOWN',
    status_detail   TEXT    NOT NULL DEFAULT '',
    os              TEXT    NOT NULL DEFAULT '',
    kernel          TEXT    NOT NULL DEFAULT '',
    arch            TEXT    NOT NULL DEFAULT '',
    last_seen_at    TEXT,
    last_error_at   TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    version         INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX servers_status_idx ON servers (status);
CREATE INDEX servers_updated_idx ON servers (updated_at DESC);

-- Credentials are stored as ciphertext only. The encryption key never lives in
-- this database (Design Spec 15.2).
CREATE TABLE server_credentials (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL,
    ciphertext BLOB    NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    rotated_at TEXT
);

CREATE INDEX server_credentials_server_idx ON server_credentials (server_id);

-- Pinned host keys. A key whose state is CHANGED hard-stops the connection.
CREATE TABLE server_host_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    algorithm   TEXT    NOT NULL,
    fingerprint TEXT    NOT NULL,
    public_key  BLOB    NOT NULL,
    state       TEXT    NOT NULL DEFAULT 'UNKNOWN',
    first_seen  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    trusted_at  TEXT,
    trusted_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (server_id, fingerprint)
);

CREATE INDEX server_host_keys_server_idx ON server_host_keys (server_id);

CREATE TABLE tags (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE server_tags (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tag_id    INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (server_id, tag_id)
);

CREATE INDEX server_tags_tag_idx ON server_tags (tag_id);

-- Per-user, per-server permission grants (Design Spec 12.4).
CREATE TABLE server_permissions (
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id     INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    granted_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, server_id, permission_id)
);

CREATE INDEX server_permissions_server_idx ON server_permissions (server_id);

-- ---------------------------------------------------------------------------
-- Audit and history
-- ---------------------------------------------------------------------------

-- Append-only by construction: no update or delete path exists in the
-- repository layer. Retention pruning is the sole deletion mechanism.
CREATE TABLE audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    actor_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_name  TEXT    NOT NULL DEFAULT '',
    action      TEXT    NOT NULL,
    target      TEXT    NOT NULL DEFAULT '',
    server_id   INTEGER REFERENCES servers(id) ON DELETE SET NULL,
    server_name TEXT    NOT NULL DEFAULT '',
    result      TEXT    NOT NULL,
    request_id  TEXT    NOT NULL DEFAULT '',
    ip          TEXT    NOT NULL DEFAULT '',
    user_agent  TEXT    NOT NULL DEFAULT '',
    metadata    JSON    NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_logs_ts_idx ON audit_logs (ts DESC, id DESC);
CREATE INDEX audit_logs_actor_idx ON audit_logs (actor_id, ts DESC);
CREATE INDEX audit_logs_server_idx ON audit_logs (server_id, ts DESC);
CREATE INDEX audit_logs_action_idx ON audit_logs (action, ts DESC);
CREATE INDEX audit_logs_request_idx ON audit_logs (request_id);

CREATE TABLE login_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username       TEXT    NOT NULL DEFAULT '',
    ip             TEXT    NOT NULL DEFAULT '',
    user_agent     TEXT    NOT NULL DEFAULT '',
    success        INTEGER NOT NULL,
    failure_reason TEXT    NOT NULL DEFAULT '',
    session_id     TEXT    NOT NULL DEFAULT '',
    ts             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX login_history_user_idx ON login_history (user_id, ts DESC);
CREATE INDEX login_history_ip_idx ON login_history (ip, ts DESC);
CREATE INDEX login_history_ts_idx ON login_history (ts DESC);

CREATE TABLE application_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    level      TEXT    NOT NULL,
    component  TEXT    NOT NULL DEFAULT '',
    message    TEXT    NOT NULL,
    request_id TEXT    NOT NULL DEFAULT '',
    actor_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    server_id  INTEGER REFERENCES servers(id) ON DELETE SET NULL,
    fields     JSON    NOT NULL DEFAULT '{}'
);

CREATE INDEX application_logs_ts_idx ON application_logs (ts DESC);
CREATE INDEX application_logs_level_idx ON application_logs (level, ts DESC);

-- ---------------------------------------------------------------------------
-- Metrics
-- ---------------------------------------------------------------------------

CREATE TABLE metric_samples (
    server_id        INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts               TEXT    NOT NULL,
    -- NULL means "not collected", which is distinct from 0. A metric that
    -- could not be read must never be stored as zero (Design Spec 18.4).
    cpu_pct          REAL,
    load1            REAL,
    load5            REAL,
    load15           REAL,
    mem_total        INTEGER,
    mem_used         INTEGER,
    mem_available    INTEGER,
    mem_cached       INTEGER,
    mem_buffers      INTEGER,
    swap_total       INTEGER,
    swap_used        INTEGER,
    net_rx_bytes     INTEGER,
    net_tx_bytes     INTEGER,
    disk_read_bytes  INTEGER,
    disk_write_bytes INTEGER,
    uptime_seconds   INTEGER,
    process_count    INTEGER,
    PRIMARY KEY (server_id, ts)
);

CREATE INDEX metric_samples_ts_idx ON metric_samples (ts);

CREATE TABLE metric_aggregates (
    server_id       INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    resolution      TEXT    NOT NULL,
    ts              TEXT    NOT NULL,
    cpu_pct_avg     REAL,
    cpu_pct_min     REAL,
    cpu_pct_max     REAL,
    mem_used_avg    INTEGER,
    mem_used_max    INTEGER,
    swap_used_avg   INTEGER,
    swap_used_max   INTEGER,
    net_rx_rate_avg REAL,
    net_tx_rate_avg REAL,
    load1_avg       REAL,
    sample_count    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (server_id, resolution, ts)
);

CREATE INDEX metric_aggregates_ts_idx ON metric_aggregates (resolution, ts);

CREATE TABLE metric_filesystems (
    server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts          TEXT    NOT NULL,
    mount_point TEXT    NOT NULL,
    device      TEXT    NOT NULL DEFAULT '',
    fs_type     TEXT    NOT NULL DEFAULT '',
    total_bytes INTEGER,
    used_bytes  INTEGER,
    avail_bytes INTEGER,
    used_pct    REAL,
    PRIMARY KEY (server_id, ts, mount_point)
);

CREATE INDEX metric_filesystems_ts_idx ON metric_filesystems (ts);

-- ---------------------------------------------------------------------------
-- Terminal sessions (metadata only - input is never recorded)
-- ---------------------------------------------------------------------------

CREATE TABLE terminal_sessions (
    id           TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id    INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    session_id   TEXT    NOT NULL DEFAULT '',
    cols         INTEGER NOT NULL DEFAULT 80,
    rows         INTEGER NOT NULL DEFAULT 24,
    opened_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    closed_at    TEXT,
    close_reason TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX terminal_sessions_user_idx ON terminal_sessions (user_id, opened_at DESC);
CREATE INDEX terminal_sessions_server_idx ON terminal_sessions (server_id, opened_at DESC);

-- ---------------------------------------------------------------------------
-- Jobs
-- ---------------------------------------------------------------------------

CREATE TABLE jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'queued',
    priority     INTEGER NOT NULL DEFAULT 0,
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    run_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    -- Worker identity and heartbeat, used to recover jobs orphaned by a crash.
    locked_by    TEXT,
    locked_at    TEXT,
    payload      JSON    NOT NULL DEFAULT '{}',
    -- -1 means indeterminate.
    progress     REAL    NOT NULL DEFAULT -1,
    last_error   TEXT    NOT NULL DEFAULT '',
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    server_id    INTEGER REFERENCES servers(id) ON DELETE CASCADE,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    finished_at  TEXT,
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
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    -- SHA-256 of the token. The token itself is shown once and never stored.
    token_hash   BLOB    NOT NULL,
    scopes       JSON    NOT NULL DEFAULT '[]',
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at   TEXT,
    last_used_at TEXT,
    revoked_at   TEXT
);

CREATE UNIQUE INDEX api_tokens_hash_key ON api_tokens (token_hash);
CREATE INDEX api_tokens_user_idx ON api_tokens (user_id);

-- ---------------------------------------------------------------------------
-- Settings, notifications, backups
-- ---------------------------------------------------------------------------

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      JSON NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE notification_channels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    kind       TEXT    NOT NULL,
    config     JSON    NOT NULL DEFAULT '{}',
    is_enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    kind       TEXT    NOT NULL,
    severity   TEXT    NOT NULL DEFAULT 'info',
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL DEFAULT '',
    server_id  INTEGER REFERENCES servers(id) ON DELETE CASCADE,
    -- Prevents duplicate alerts while a condition persists.
    dedupe_key TEXT    NOT NULL DEFAULT '',
    is_read    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX notifications_ts_idx ON notifications (ts DESC);
CREATE INDEX notifications_unread_idx ON notifications (is_read, ts DESC);
CREATE UNIQUE INDEX notifications_dedupe_idx ON notifications (dedupe_key) WHERE dedupe_key <> '';

CREATE TABLE backups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename    TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    checksum    TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'running',
    error       TEXT    NOT NULL DEFAULT '',
    started_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    finished_at TEXT,
    created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL
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
