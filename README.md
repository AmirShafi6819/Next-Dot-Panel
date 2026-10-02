# Next.Panel

[![CI](https://github.com/AmirShafi6819/Next-Dot-Panel/actions/workflows/ci.yml/badge.svg)](https://github.com/AmirShafi6819/Next-Dot-Panel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Next.Panel** is a self-hostable Linux VPS/server management panel: a single
small process that runs on a server or a dedicated host and manages other
machines over SSH — servers, commands, terminals, files, metrics, services,
containers, jobs and audit history — behind one authenticated web UI.

> **Status: 0.1.0.** Next.Panel is a working panel: sign in, add Linux servers
> over SSH with verified host keys, open terminals, manage files, watch
> metrics and processes, administer users and roles, and review the audit
> trail — from the embedded web UI or the API. See [Features](#features) for
> exactly what is implemented, and [docs/limitations.md](docs/limitations.md)
> for what is not.

## Features

Implemented in 0.1.0 (only these are listed — see
[ROADMAP.md](ROADMAP.md) for what is planned):

- **Authentication** — Argon2id passwords, opaque server-side sessions
  (absolute + idle expiry, revocation), bootstrap `admin` with a
  default-credential warning, login rate limiting.
- **RBAC** — permission catalogue, `admin`/`operator`/`viewer` system roles,
  custom roles, per-server grants; invisible objects return 404, denials are
  audited.
- **Managed servers** — CRUD with optimistic locking, tags/notes/favourites,
  encrypted credentials, TOFU/STRICT host-key pinning with explicit trust,
  connection tests with latency and system discovery.
- **SSH** — fail-closed host keys, modern algorithms, key/password auth,
  command execution with timeouts and output caps, connection reuse pool.
- **Terminal** — real PTY over an authenticated WebSocket (xterm.js UI,
  resize, per-user/server/global limits, idle reaping, audited open/close).
- **File manager** — browse/upload/download/mkdir/rename/delete over SFTP
  with streaming, plus secure tar/tar.gz/zip extraction.
- **Metrics** — `/proc`-based collection, current + historical API, SVG
  history charts, scheduled collection with retention, SSE live state.
- **Processes** — remote `ps` list with search, audited SIGTERM/SIGKILL.
- **Users** — CRUD, disable/delete with last-admin and self guards, password
  reset, session revocation, per-user login history.
- **Audit** — append-only trail with filters, plus the login-history record.
- **Jobs** — persistent DB-backed worker pool with retries and maintenance
  handlers (retention, session cleanup, terminal sweep).
- **UI** — embedded React app (login, servers, terminal, files, metrics,
  processes, users, roles, audit), dark/light aware, responsive.
- **Operations** — Docker + compose, systemd unit, nginx/Caddy examples,
  SQLite and PostgreSQL, versioned migrations, `/health` `/ready` `/version`.

## Architecture

```
cmd/nextpanel/          process entrypoint, CLI, provider/job wiring
internal/auth/          Argon2id, sessions, login, bootstrap admin
internal/rbac/          permissions, roles, seeding, authorization
internal/audit/         audit writer + trail queries
internal/credentials/   encrypted credential store (sole decrypt boundary)
internal/crypto/        AES-256-GCM credential encryption, key IDs
internal/secret/        in-memory secret types that refuse to stringify
internal/server/        managed servers, connection gateway, host-key trust
internal/provider/      execution-provider primitives, pool, error taxonomy
internal/provider/ssh/  SSH provider (fail-closed host keys, exec, SFTP, PTY)
internal/terminal/      PTY session manager (limits, idle sweep, audit)
internal/files/         file operations + secure archive extraction
internal/metrics/       /proc collection, persistence, scheduler
internal/processes/     remote ps + audited signals
internal/users/         account administration with safety guards
internal/jobs/          persistent worker pool + maintenance handlers
internal/store/         database handles, migrations, dialect adapters
internal/store/repos/   generated sqlc repositories + hand-written adapters
internal/httpapi/       chi router, middleware, handlers, error envelopes
internal/domain/        domain types shared by the layers above
internal/version/       build version reporting
web/                    React + TypeScript UI (built to dist/, embedded)
```

Design decisions, endpoint contracts and security requirements live in
[`docs/architecture.md`](docs/architecture.md) and the full specification at
[`docs/superpowers/specs/2026-09-29-next-panel-design.md`](docs/superpowers/specs/2026-09-29-next-panel-design.md).

## Requirements

- **Go 1.26+** to build from source.
- **PostgreSQL 16+** (recommended for production) *or* nothing at all — the
  default SQLite database needs no external service.
- Linux (or macOS/Windows for development; only Linux is a deployment
  target).

## Quick start

```sh
git clone https://github.com/AmirShafi6819/Next-Dot-Panel.git
cd Next-Dot-Panel
go build -o nextpanel ./cmd/nextpanel
```

1. **Create a configuration file.** Copy the annotated template and edit it:

   ```sh
   cp .env.example .env
   ```

2. **Generate the encryption key.** The panel will not start without it:

   ```sh
   ./nextpanel crypto generate-key
   # paste the output as NEXT_PANEL_ENCRYPTION_KEY in .env
   ```

   Back this key up separately from the database. A database backup without
   the key cannot decrypt stored credentials.

3. **Export the environment and run:**

   ```sh
   set -a; . ./.env; set +a
   ./nextpanel
   ```

4. **Verify it is alive:**

   ```sh
   curl -s localhost:8080/health    # {"status":"ok"}
   curl -s localhost:8080/ready     # {"status":"ready"}
   curl -s localhost:8080/version   # version JSON
   ```

Migrations run automatically at startup (a `--migrate-only` style mode and a
systemd unit are planned). Docker images and a compose file arrive with
Phase 25 — **no container image is published yet, and none should be trusted
if you find one.**

### First login

On the first start, when the users table is empty, a bootstrap administrator is
created from `NEXT_PANEL_BOOTSTRAP_USERNAME`/`NEXT_PANEL_BOOTSTRAP_PASSWORD`
(defaults `admin` / `123456`, matching the master spec). That account is flagged
`is_bootstrap_default` and the server logs a warning on every start until the
password is changed; `/api/v1/auth/me` also reports
`default_credentials_warning`. Change the password immediately (it must be at
least 12 characters). Set `NEXT_PANEL_BOOTSTRAP_ADMIN=false` to skip seeding and
create the first administrator another way.

## Configuration

Every setting is an environment variable prefixed `NEXT_PANEL_`. The
authoritative, annotated list is [`.env.example`](.env.example). Highlights:

| Variable | Default | Notes |
|---|---|---|
| `NEXT_PANEL_ENV` | `development` | `production` requires `NEXT_PANEL_EXTERNAL_SCHEME=https` |
| `NEXT_PANEL_LISTEN` | `:8080` | HTTP bind address |
| `NEXT_PANEL_DATA_DIR` | `./data` | SQLite database, backups, runtime state; must be writable |
| `NEXT_PANEL_DB_DRIVER` | `sqlite` | `sqlite` or `postgres` |
| `NEXT_PANEL_DB_DSN` | — | Required for `postgres` |
| `NEXT_PANEL_ENCRYPTION_KEY` | — | **Required.** `nextpanel crypto generate-key` |
| `NEXT_PANEL_LOG_LEVEL` | `INFO` | `DEBUG` … `ERROR` |
| `NEXT_PANEL_LOG_FORMAT` | `text` | `json` for production |

Secrets are environment-only: they never appear in the database, in logs, or
in error messages, and startup failures name the variable but never echo its
value.

## Development

```sh
go build ./...                    # compile everything
go test ./...                     # unit + SQLite integration tests
golangci-lint run ./...           # lint (config in .golangci.yml)
gofmt -l .                        # formatting must print nothing
go vet ./...
sqlc generate                     # regenerate repositories (committed output)
bash scripts/security-greps.sh    # Design Spec §28.6 forbidden patterns
```

### Testing against PostgreSQL

Integration tests skip themselves when no database is offered, so a plain
`go test ./...` is always safe:

```sh
export TEST_DATABASE_URL='postgres://user:pass@127.0.0.1:5432/nextpanel_test?sslmode=disable'
go test ./internal/store/... -count=1
```

Each package that touches PostgreSQL runs in its own schema, so tests are
safe to run in parallel and never touch application data.

### Repository conventions

- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `test:`, `chore:`) with
  the change scope when useful.
- Failures are fixed, never muted: a failing or skipped-to-green test is
  replaced by a correct one, committed separately.
- `.gitattributes` enforces LF for Go and SQL — sqlc output is sensitive to
  line endings.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

| Gate | What it checks |
|---|---|
| Format | `gofmt -l .` must print nothing |
| Vet | `go vet ./...` |
| Modules | `go mod verify` |
| Lint | `golangci-lint` (v2 config, standard linters + `gosec`) |
| Security greps | Forbidden patterns from Design Spec §28.6 |
| Tests (SQLite) | `go test ./... -race` on Go 1.26.x **and** 1.27.x |
| Tests (PostgreSQL) | Same suite against a PostgreSQL 16 service container |
| sqlc drift | `sqlc generate` must leave a clean tree |

Later phases add the dependency vulnerability scan, frontend
lint/typecheck/build, Playwright E2E, Docker build and smoke test.

## Security

- Report vulnerabilities privately (GitHub private vulnerability reporting,
  or a private message to the maintainers). **Do not open a public issue for
  an unpatched vulnerability.**
- Design guarantees that the code must uphold: no credentials in logs,
  responses, or error messages; strict SSH host-key verification with no
  auto-accept path; every endpoint authorised; no backdoors, magic tokens or
  debug authentication. See Design Spec §28.
- `scripts/security-greps.sh` enforces a first subset of these mechanically
  in CI.

## Roadmap

Phases follow Design Spec §38. Each phase lands with tests, lint, docs,
CHANGELOG entry and a commit.

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Repository bootstrap, CI, tooling | ✅ |
| 1 | Config, logging, startup checks, `/health` `/ready` `/version` | ✅ |
| 2 | Store layer: migrations, sqlc dual-dialect, adapters, repositories | ✅ |
| 3 | Auth: Argon2id, sessions, login/logout, bootstrap admin | ✅ |
| 4 | RBAC: permissions, roles, object-level authorisation | ✅ |
| 5 | Servers: CRUD, tags, status, connection test | ✅ |
| 6 | SSH provider: connection, host-key policy, pooling | ✅ |
| 7–13 | Exec gateway, terminal, files, metrics, processes, audit, users | ✅ |
| 14–21 | Jobs, SSE, rate limiting, security headers, UI, Docker/systemd | ✅ |
| 22–25 | Documentation, CI (Go + web), security review, 0.1.0 release | ✅ |
| 26–29 | 2FA, containers/systemd control, notifications, agent, plugins (future) | ⏳ |

## Screenshots

The web UI is Phase 24; screenshots will be added when there is one. Until
then, the endpoint probes above are the only thing to look at.

## Contributing

Contributions are welcome. Keep them small and reviewable: one change per
commit, Conventional Commit messages, tests for behaviour changes, and a
green `golangci-lint run ./...` plus `go test ./...` before you push. Read
the design spec before adding a feature — most hard decisions have already
been made and documented there.

## License

MIT — see [`LICENSE`](LICENSE) and the rationale, including the full
dependency licence inventory, in [`docs/licensing.md`](docs/licensing.md).
