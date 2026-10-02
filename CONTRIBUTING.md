# Contributing to Next.Panel

## Development setup

Prerequisites: Go 1.26+, Node 20+, SQLite (via the wasm driver — no CGO),
optionally PostgreSQL 16 and Docker.

```sh
# backend
go build ./...
go test ./...

# frontend
cd web && npm install && npm run build

# run (development)
NEXT_PANEL_ENCRYPTION_KEY=$(go run ./cmd/nextpanel crypto generate-key) \
NEXT_PANEL_DATA_DIR=./data \
go run ./cmd/nextpanel
```

Copy `.env.example` to `.env` for local settings (never commit `.env`).

## Branch strategy

- `main` is always releasable. Short-lived feature branches, pull requests,
  squash or rebase merges.
- Conventional Commits: `feat(auth): …`, `fix(files): …`, `docs(deployment): …`.

## Before a pull request

- `gofmt -l .` is empty, `go vet ./...` passes, `golangci-lint run ./...`
  reports no issues.
- `go test ./...` passes; with `TEST_DATABASE_URL` set, the PostgreSQL
  dialect suite runs too.
- `cd web && npm run build` passes (typecheck + production build).
- New behavior has tests, including negative/authorization tests where
  applicable.
- Docs and CHANGELOG.md are updated.

## Security-sensitive changes

Changes touching authentication, sessions, RBAC, SSH, host keys, credentials,
file paths, archives, terminals or WebSockets must:

- explain the threat model in the PR description,
- add regression tests for the abuse case (IDOR, traversal, Zip Slip,
  host-key mismatch, session reuse),
- never log or return credential material.

## Architecture changes

Internal packages own their domain (`internal/auth`, `internal/server`,
`internal/provider/ssh`, …). Cross-package rules:

- HTTP handlers decode, authorize via services, and encode — no business logic.
- Services take an `actor` and authorize first; repositories never see actors.
- Generated sqlc code is never edited by hand; change the `.sql`, keep it
  ASCII-only and LF, and regenerate.
