# Contributing to Next.Panel

## Finding something to work on

- Issues labelled `good first issue` are small, well-scoped entry points;
  `help wanted` marks work maintainers would like assistance with;
  `documentation`, `frontend`, `backend` and `security` describe the area.
- If no labelled issue fits, small improvements with tests (typo fixes,
  missing test coverage, docs gaps) are welcome without prior discussion.
- For anything larger — new endpoints, new UI areas, behaviour changes —
  open an issue first so the design can be agreed before code is written.

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
- Docs and CHANGELOG.md are updated for user-visible changes.

## Pull request size and review

- Keep PRs small and reviewable: one change per PR, ideally under ~400 lines
  of diff excluding generated code. Split refactors from behaviour changes.
- Use Conventional Commit titles (`feat(auth): …`, `fix(files): …`); the PR
  template lists the verification checklist — fill it in.
- Maintainers review for correctness, security, test coverage and docs; expect
  at least one round of feedback on non-trivial changes. `main` merges are
  squash or rebase, keeping history linear.

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
