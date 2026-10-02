CREATE TABLE users (
  id            BIGSERIAL PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name  TEXT NOT NULL DEFAULT '',
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  is_bootstrap  BOOLEAN NOT NULL DEFAULT FALSE,
  must_change   BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE servers (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  host        TEXT NOT NULL,
  port        INTEGER NOT NULL DEFAULT 22,
  username    TEXT NOT NULL,
  auth_method TEXT NOT NULL,
  tags        JSONB NOT NULL DEFAULT '[]',
  notes       TEXT,
  status      TEXT NOT NULL DEFAULT 'unknown',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  version     BIGINT NOT NULL DEFAULT 1
);
CREATE TABLE audit_logs (
  id         BIGSERIAL PRIMARY KEY,
  ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_id   BIGINT REFERENCES users(id) ON DELETE SET NULL,
  action     TEXT NOT NULL,
  target     TEXT,
  server_id  BIGINT REFERENCES servers(id) ON DELETE SET NULL,
  result     TEXT NOT NULL,
  request_id TEXT NOT NULL,
  metadata   JSONB NOT NULL DEFAULT '{}'
);
CREATE TABLE metric_samples (
  server_id BIGINT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  ts        TIMESTAMPTZ NOT NULL,
  cpu_pct   DOUBLE PRECISION,
  mem_used  BIGINT,
  PRIMARY KEY (server_id, ts)
);
CREATE TABLE jobs (
  id          BIGSERIAL PRIMARY KEY,
  kind        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'queued',
  attempts    INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 3,
  run_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_by   TEXT,
  locked_at   TIMESTAMPTZ,
  payload     JSONB NOT NULL DEFAULT '{}',
  last_error  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
