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

### Security

- Startup fails when `NEXT_PANEL_ENCRYPTION_KEY` is missing or malformed;
  the error names the variable and never echoes the value.
- Access logs carry a request ID and log the path only, never the query
  string; panic recovery returns a 500 envelope without leaking a stack
  trace.
- `scripts/security-greps.sh` fails CI on the §28.6 forbidden patterns
  (disabled host-key verification, hardcoded credential literals, PEM
  private keys in the tree, raw HTML injection, shell invocation with a
  non-constant command, and SQL built by string concatenation).
