# Changelog

All notable changes to Next.Panel are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries are grouped under `Added`, `Changed`, `Fixed`, `Deprecated`,
`Removed`, `Security`. Nothing is listed before it exists, and no historical
entries are invented.

## [Unreleased]

### Added

- **Phase 0 — bootstrap.** Module and tooling configuration (`go.mod`,
  `sqlc.yaml`, `.env.example`, `.gitattributes`, `.gitignore`, `.golangci.yml`),
  CI pipeline (`.github/workflows/ci.yml`) covering format check, `go vet`,
  `go mod verify`, golangci-lint, the Design Spec §28.6 security greps, unit
  tests on Go 1.26.x/1.27.x, PostgreSQL 16 integration tests, and an sqlc
  drift gate; `scripts/security-greps.sh` implements the §28.6 greps with
  verified exit codes; MIT `LICENSE` with the rationale and dependency licence
  inventory in `docs/licensing.md`.
- **Phase 1 — process and operations.** `cmd/nextpanel` entrypoint with
  `run`/`serve`, `crypto generate-key`, and `version` subcommands; startup
  checks for configuration, data directory writability, database, and
  migrations; graceful shutdown on `SIGINT`/`SIGTERM`; `internal/httpapi`
  chi router serving `GET /health`, `GET /ready`, `GET /version` with request
  IDs, access logs, panic recovery, and the design-spec error envelope.
- **Phase 2 — store layer.** `internal/store` with dual-dialect (PostgreSQL,
  SQLite) handles, goose migrations guarded for concurrent use, and sqlc
  generated queries committed to the tree; repository adapters and domain
  mapping in `internal/store/repos`; integration tests that run against
  SQLite by default and against PostgreSQL when `TEST_DATABASE_URL` is set,
  each package in its own schema so suites cannot collide.
- **Supporting packages.** `internal/config` (typed, validated, env-only
  configuration with secret-free aggregated errors), `internal/logging`
  (structured logger with redaction), `internal/crypto` (AES-256-GCM
  credential encryption with key identifiers), `internal/secret` (secrets
  that never stringify), `internal/domain`, `internal/version`.
- **Phase 3 — authentication.** `internal/auth`: Argon2id password hashing and
  verification (OWASP-aligned parameters, transparent rehash-on-login), a
  length-first password policy with a bundled common-password blocklist,
  opaque server-side sessions (256-bit token, only its SHA-256 stored) with
  absolute and idle expiry and throttled `last_seen_at` touches, constant-time
  credential checks with a dummy verification for unknown users, login/logout,
  re-authentication with a per-session window, self-service password change
  that revokes every other session, IDOR-safe session listing/revocation, and
  bootstrap seeding of an `admin` account flagged for an immediate password
  change. HTTP surface under `/api/v1/auth` (`login`, `logout`, `password`,
  `reauth`, `me`, `sessions`) with `HttpOnly` session and readable double-submit
  CSRF cookies; a `sessions.reauth_at` migration on both dialects.
- **Phase 4 — RBAC.** `internal/rbac`: the permission catalogue and default
  `admin`/`operator`/`viewer` system roles are seeded idempotently at startup
  (system roles are reconciled, custom roles are left alone); role CRUD,
  permission-set management and user-role assignment; and the authorization
  checks every service routes through — global permissions plus per-server
  grants, with denials audited as `DENIED`. `internal/audit` centralises audit
  writes. HTTP: `/api/v1/roles`, `/api/v1/permissions` and
  `/api/v1/users/{id}/roles` behind a `RequirePermission` middleware. The
  bootstrap administrator is granted the admin role on first start.
- **Phase 5 — managed servers.** `internal/credentials` is the only boundary
  that decrypts stored material (AES-256-GCM via `internal/crypto`); it seals a
  password/private-key/passphrase payload and unwraps it late, closing it after
  use. `internal/provider` defines the primitive execution-provider interface,
  a reuse pool keyed by server id, and the safe error taxonomy.
  `internal/server` implements server CRUD with optimistic locking, tag
  handling, credential storage/rotation (which invalidates pooled connections),
  connection testing with system-info discovery, and explicit, audited
  host-key trust. Object-level authorization is enforced in the service:
  a server the actor cannot see is reported as 404, not 403. HTTP:
  `/api/v1/servers` and its `{id}` sub-resources (`test`, `hostkeys`,
  `hostkeys/trust`).
- **Phase 6 — SSH.** `internal/provider/ssh` implements the SSH execution
  provider on `golang.org/x/crypto/ssh`: host-key verification that fails
  closed (unknown keys are refused with a SHA256 fingerprint for an explicit
  trust step; changed keys are a hard stop with no auto-accept), modern
  algorithm allow-lists, key and password auth, command execution with a
  timeout and bounded stdout/stderr captured in independent buffers, exit
  status as a result rather than an error, and context cancellation. Commands
  are sent with POSIX single-quote escaping, never interpolated raw. The
  provider is registered with the execution registry at startup, and connection
  testing now connects over SSH for real.

### Security

- Authentication failures are indistinguishable: unknown user, wrong password,
  and disabled account all return the same `invalid_credentials` error and the
  same timing, and only a category (never a password) reaches login history.
- The bootstrap administrator is flagged `is_bootstrap_default`; the panel
  warns on every start and on `/me` while the default password stands, and the
  warning clears only after a real password change.
- Password changes and re-authentication are audited, and changing a password
  revokes all of the account's other sessions.

- Startup fails when `NEXT_PANEL_ENCRYPTION_KEY` is missing or malformed;
  the error names the variable and never echoes the value.
- Access logs carry a request ID and log the path only, never the query
  string; panic recovery returns a 500 envelope without leaking a stack
  trace.
- `scripts/security-greps.sh` fails CI on the §28.6 forbidden patterns
  (disabled host-key verification, hardcoded credential literals, PEM
  private keys in the tree, raw HTML injection, shell invocation with a
  non-constant command, and SQL built by string concatenation).
