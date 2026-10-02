# Development & Testing

## Layout

`cmd/nextpanel` (binary + CLI), `internal/*` (all backend code),
`web/` (React UI, built to `web/dist` and embedded), `deploy/` (docker,
systemd, proxy), `docs/`, `scripts/`.

## Backend

```sh
gofmt -l .            # must be empty
go vet ./...
golangci-lint run ./...   # %USERPROFILE%\go\bin on Windows
go test ./...         # SQLite suites
TEST_DATABASE_URL=postgres://… go test ./...   # + PostgreSQL suites
sqlc generate         # after editing *.sql (ASCII-only, LF)
```

sqlc types are generated per dialect and never imported outside
`internal/store/repos`; services use `domain` types. New queries go in
`internal/store/queries/{sqlite,postgres}/`, migrations in
`internal/store/migrations/{sqlite,postgres}/` (goose, `-- +goose Up/Down`).

`go test -race` runs in CI (it needs CGO, unavailable on stock Windows).

## Frontend

```sh
cd web
npm install
npm run build   # typecheck + production build into dist/
npm run dev     # dev server on :5173, proxies /api to :8080
```

The API client (`src/api.ts`) mirrors `docs/api.md`; keep them in sync.

## Configuration

Everything is `NEXT_PANEL_*` environment variables; see the annotated
`.env.example`. Invalid critical config fails fast at startup (missing
encryption key, bad database URL, production without https).

## Smoke test

```sh
go build -o /tmp/nextpanel ./cmd/nextpanel
export NEXT_PANEL_ENCRYPTION_KEY=$(/tmp/nextpanel crypto generate-key)
export NEXT_PANEL_DATA_DIR=/tmp/npdata
/tmp/nextpanel &  # then: /health, login as admin/123456, add a server, test
```

## Troubleshooting

- `sqlc` reports a syntax error at an unrelated line → a non-ASCII character
  (e.g. `§`) is in a `.sql` file; keep them ASCII-only.
- Login rate-limited in tests → the limiter is per-router; defaults are
  10 attempts / 15 min per IP.
- `run_at` comparisons use UTC; always store `run_at` and cutoff timestamps
  with `time.Now().UTC()`.
