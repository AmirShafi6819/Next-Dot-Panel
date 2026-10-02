CREATE TABLE users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name  TEXT NOT NULL DEFAULT '',
  is_active     INTEGER NOT NULL DEFAULT 1,
  is_bootstrap  INTEGER NOT NULL DEFAULT 0,
  must_change   INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE servers (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL UNIQUE,
  host        TEXT NOT NULL,
  port        INTEGER NOT NULL DEFAULT 22,
  username    TEXT NOT NULL,
  auth_method TEXT NOT NULL,
  tags        JSON NOT NULL DEFAULT '[]',
  notes       TEXT,
  status      TEXT NOT NULL DEFAULT 'unknown',
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  version     BIGINT NOT NULL DEFAULT 1
);
CREATE TABLE audit_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  actor_id   BIGINT REFERENCES users(id) ON DELETE SET NULL,
  action     TEXT NOT NULL,
  target     TEXT,
  server_id  BIGINT REFERENCES servers(id) ON DELETE SET NULL,
  result     TEXT NOT NULL,
  request_id TEXT NOT NULL,
  metadata   JSON NOT NULL DEFAULT '{}'
);
CREATE TABLE metric_samples (
  server_id BIGINT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  ts        TEXT NOT NULL,
  cpu_pct   REAL,
  mem_used  BIGINT,
  PRIMARY KEY (server_id, ts)
);
CREATE TABLE jobs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  kind        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'queued',
  attempts    INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 3,
  run_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  locked_by   TEXT,
  locked_at   TEXT,
  payload     JSON NOT NULL DEFAULT '{}',
  last_error  TEXT,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
