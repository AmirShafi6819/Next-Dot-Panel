# Next.Panel

[![CI](https://github.com/AmirShafi6819/Next-Dot-Panel/actions/workflows/ci.yml/badge.svg)](https://github.com/AmirShafi6819/Next-Dot-Panel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Status: beta](https://img.shields.io/badge/status-beta-yellow.svg)

> A self-hosted server management panel for remote Linux machines over SSH —
> with an integrated web terminal, file management, metrics, process
> management, RBAC, and auditing.

Next.Panel is a single small process you run on a server or a dedicated host.
It manages other machines over SSH — servers, terminals, files, metrics,
processes, users, roles and audit history — behind one authenticated web UI.
SQLite works out of the box with no external services; PostgreSQL is
supported for larger deployments.

**[Quick start](#quick-start) · [Documentation](docs/) · [Security](SECURITY.md) ·
[Support](SUPPORT.md) · [Contributing](CONTRIBUTING.md) · [Roadmap](ROADMAP.md) ·
[Changelog](CHANGELOG.md)**

> **Beta.** This is the first public Beta baseline (`v0.1.0`): the panel is
> functional and tested, but it is still evolving. APIs and the UI may change,
> and some planned features are not implemented yet — see
> [Beta status](#beta-status) and [ROADMAP.md](ROADMAP.md). Evaluate carefully
> before trusting it with production infrastructure.

## Why Next.Panel?

Managing a few Linux servers usually means a terminal multiplexer, scattered
SSH keys, ad-hoc scripts, and no shared view of who did what. Next.Panel
puts the everyday operations — shell access, files, resource graphs,
processes, and user permissions — behind one login, while keeping the
footprint small: a single Go binary, an embedded web UI, and SQLite by
default. No agent to install on managed machines — if a server speaks SSH,
Next.Panel can manage it.

## Who is it for?

- **VPS owners and self-hosters** running one or a handful of Linux boxes
- **Homelab users** who want a browser UI over their machines without a
  heavyweight platform
- **Developers** who need to give collaborators scoped server access with an
  audit trail instead of sharing SSH keys
- **Small infrastructure teams** that need roles, per-server permissions,
  and a record of administrative actions

## What Next.Panel is not

- Not a cloud control plane: there is no hosted service, and the panel runs
  on infrastructure you control.
- Not an agent-based fleet manager: managed servers need only SSH, but that
  also means no offline queuing or push-based orchestration.
- Not a monitoring suite: metrics cover CPU, memory, disk and processes for
  operational awareness, not alerting pipelines (see [ROADMAP.md](ROADMAP.md)).
- Not finished: this is a Beta — check [Beta status](#beta-status) before
  committing to it.

## Where Next.Panel fits

Next.Panel belongs to the self-hosted server-panel category: a web UI for
day-to-day administration of your own Linux machines. Within that category it
leans toward the lightweight end — one process, SSH-native access, RBAC and
auditing built in from the start rather than bolted on. If you need
container orchestration, configuration management, or a managed SaaS
dashboard, use a tool built for that; Next.Panel deliberately does not try to
be one.

## Screenshots

> Screenshots of the Beta UI will be added here. Placeholders below mark the
> views that will be captured — no mockups, only real UI once available.

### Servers

*Screenshot: server list with connection status — coming soon.*

### Web Terminal

*Screenshot: browser terminal session — coming soon.*

### File Manager

*Screenshot: remote file browser — coming soon.*

### Monitoring

*Screenshot: metrics history charts — coming soon.*

## Demo

> A public demo is not currently available.

The fastest way to evaluate Next.Panel is to run it locally — see
[Quickest local evaluation](#quickest-local-evaluation). A future demo GIF or
video walkthrough will be linked from this section when one exists.

## Features

Everything below is implemented. Backend behavior is covered by automated
unit and integration tests on SQLite and PostgreSQL; the frontend is
verified by TypeScript typecheck and production build (no browser E2E
suite yet). Planned but unimplemented work is listed separately in
[ROADMAP.md](ROADMAP.md), never here.

### Server management

- Server inventory with CRUD, optimistic locking, tags, notes and favourites
- Connection test with latency measurement and remote system discovery
- SSH connection pooling with per-server and per-user limits
- Remote command execution with timeouts and output caps

### Web terminal

- Real PTY sessions in the browser (xterm.js) over an authenticated
  WebSocket, with resize
- Per-user, per-server and global session limits, idle reaping, audited
  open/close

### File management

- Browse, upload, download, mkdir, rename and delete over SFTP with
  streaming and strict path validation
- Secure tar / tar.gz / zip extraction (rejects traversal, absolute paths,
  links and oversized payloads)

### Monitoring

- CPU, memory and disk collection from `/proc`, current + historical API,
  history charts, scheduled collection with retention
- Remote process list with search and audited SIGTERM / SIGKILL
- Live server state over server-sent events

### Authentication & RBAC

- Argon2id password hashing with a breached/common-password blocklist and a
  minimum-length policy
- Opaque server-side sessions (absolute + idle expiry, revocation, login
  history per user)
- Bootstrap administrator with a default-credential warning until the
  password is changed
- Permission catalogue, `admin` / `operator` / `viewer` system roles, custom
  roles, per-server grants; invisible objects return 404, denials are
  audited

### Security

- SSH host keys fail closed: unknown keys are refused with a fingerprint for
  explicit trust; changed keys hard-stop the connection — no auto-accept path
- Stored server credentials are AES-256-GCM ciphertext; the key comes from
  the environment, never the database
- Login rate limiting with progressive lockout, security headers, same-site
  cookies; privileged subsystems (local execution, containers, services) are
  all disabled by default

### Audit & administration

- User CRUD with disable/delete guards (last admin and self are protected),
  password reset, session revocation
- Append-only audit trail with filters, plus per-user login history
- Persistent DB-backed job queue with retries (retention sweeps, session
  cleanup)

## Architecture

```mermaid
flowchart TD
    Browser --> UI["Web UI (React, embedded)"]
    Browser --> API["HTTP API (chi)"]
    API --> Auth["Auth (sessions)"]
    API --> RBAC["RBAC (permissions)"]
    API --> Srv["Servers"]
    API --> Term["Terminal manager"]
    API --> Files["File service"]
    API --> Met["Metrics / processes"]
    Srv --> Pool["SSH pool"]
    Term --> Pool
    Files --> Pool
    Met --> Pool
    Pool --> SSH["SSH provider"]
    SSH --> Managed["Managed Linux server"]
    API --> DB[("SQLite / PostgreSQL")]
    Auth --> DB
```

- **Backend** (Go, `cmd/` + `internal/`): one binary. HTTP handlers decode and
  encode; services authorize `user → permission → object → operation` first;
  repositories are storage only. Query code is generated with `sqlc` from
  reviewed `.sql` files, one dialect each for SQLite and PostgreSQL.
- **Frontend** (`web/`, React + TypeScript): built with Vite and embedded
  into the binary — the server serves the UI itself, no separate web server
  needed. Without a frontend build the binary serves the API only.
- **Database**: versioned `goose` migrations run automatically at startup.
  SQLite needs no service; PostgreSQL 16+ is supported via `DATABASE` DSN.
- **SSH layer** (`internal/provider/ssh`): fail-closed host-key policy
  (TOFU/STRICT with explicit trust), modern algorithm allow-lists, key and
  password auth, exec + SFTP + PTY over a pooled connection registry.
- **Deployment model**: one process + one database file (or Postgres) +
  one encryption key. Stateless apart from those three.

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Go | 1.26+ | to build the backend from source |
| Node.js | 20+ | to build the web UI (`npm run build`) |
| PostgreSQL | 16+ | optional; SQLite is the default and needs nothing |
| OS | Linux (deploy), Linux/macOS/Windows (develop) | only Linux is a deployment target |

No CGO, no external daemons, no message queue.

## Quick start

### Quickest local evaluation

The fastest way is the launcher script for your OS — it checks dependencies,
builds the frontend (if Node is available) and backend, sets up a local
`.env`, and starts the panel:

- Windows: `run.bat` (or `run.ps1`)
- Linux / macOS: `./run.sh`

Then open the URL it prints (default <http://localhost:8080>) and sign in.
To evaluate manually instead, follow the steps below.

### Manual setup

```sh
git clone https://github.com/AmirShafi6819/Next-Dot-Panel.git
cd Next-Dot-Panel

# 1. Build the web UI (needs Node 20+)
cd web && npm install && npm run build && cd ..

# 2. Build the backend (needs Go 1.26+)
go build -o nextpanel ./cmd/nextpanel

# 3. Create configuration from the annotated template
cp .env.example .env

# 4. Generate the encryption key (the panel refuses to start without it)
./nextpanel crypto generate-key
# paste the output as NEXT_PANEL_ENCRYPTION_KEY in .env,
# then back the key up separately from the database

# 5. Run (the shell exports .env into the environment first)
set -a; . ./.env; set +a
./nextpanel
```

Open <http://localhost:8080>. On first start an administrator is created
from `NEXT_PANEL_BOOTSTRAP_USERNAME` / `NEXT_PANEL_BOOTSTRAP_PASSWORD`
(defaults `admin` / `123456`, flagged until changed — change it immediately,
minimum 12 characters).

Verify it is alive:

```sh
curl -s localhost:8080/health    # {"status":"ok"}
curl -s localhost:8080/ready     # {"status":"ready"}
curl -s localhost:8080/version   # build metadata
```

### Production deployment

For anything beyond local evaluation — systemd, reverse proxy with TLS,
PostgreSQL, backups — follow [Production deployment](#production-deployment)
and the full guide in [`docs/deployment.md`](docs/deployment.md).

## Configuration

Every setting is an environment variable prefixed `NEXT_PANEL_`. The
authoritative annotated list is [`.env.example`](.env.example) — copy it to
`.env` and edit. The panel never reads secrets from files you commit; a
populated `.env` is git-ignored.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `NEXT_PANEL_ENCRYPTION_KEY` | **yes** | — | `nextpanel crypto generate-key`. Encrypts stored SSH credentials. Back up separately from the DB |
| `NEXT_PANEL_DATA_DIR` | no | `./data` | SQLite database, backups, runtime state; must be writable |
| `NEXT_PANEL_DB_DRIVER` | no | `sqlite` | `sqlite` or `postgres` |
| `NEXT_PANEL_DB_DSN` | for postgres | — | Full DSN, e.g. `postgres://user:pass@127.0.0.1:5432/nextpanel?sslmode=require` |
| `NEXT_PANEL_ENV` | no | `development` | `production` requires `NEXT_PANEL_EXTERNAL_SCHEME=https` |
| `NEXT_PANEL_LISTEN` | no | `:8080` | HTTP bind address |
| `NEXT_PANEL_BASE_URL` | no | `http://localhost:8080` | Public base URL for origins and links |
| `NEXT_PANEL_EXTERNAL_SCHEME` | no | `http` | `https` when behind a TLS proxy |
| `NEXT_PANEL_BOOTSTRAP_ADMIN` | no | `true` | `false` skips default-credential seeding |
| `NEXT_PANEL_BOOTSTRAP_USERNAME` / `NEXT_PANEL_BOOTSTRAP_PASSWORD` | no | `admin` / `123456` | First-start admin; flagged until the password changes |

Security-relevant defaults: privileged subsystems (local execution,
containers, systemd control) are all **disabled** by default; session
lifetime/idle timeouts, re-auth window and auth rate limits are configured in
`.env.example`. Startup failures name the variable but never echo its value.

## Running on Windows

Windows is a development platform, not a deployment target — run it to try
the panel and manage remote Linux servers from the browser terminal.

1. Install [Go 1.26+](https://go.dev/dl/) and, for the web UI,
   [Node.js 20+](https://nodejs.org/).
2. Clone the repository and open a terminal in it.
3. Run `run.bat` (or `run.ps1` in PowerShell). The script checks for Go and
   Node, builds the UI if Node is present (otherwise the API runs without
   the UI, and it tells you so), creates `.env` from the template on first
   run, generates an encryption key into it, and starts the server.
4. Open the URL it prints (default <http://localhost:8080>), sign in with
   the bootstrap admin, and change the password.

Data lives in `.\data\` next to the script; delete that directory for a
fresh start. Never commit `.env`.

## Running on Linux

```sh
git clone https://github.com/AmirShafi6819/Next-Dot-Panel.git
cd Next-Dot-Panel
./run.sh
```

`run.sh` is not destructive: it never overwrites an existing `.env` or
touches `./data`. Open the printed URL when it is up.

For a permanent installation, use the systemd unit and reverse-proxy
examples instead — see [Production deployment](#production-deployment).

## Production deployment

Supported and tested: binary + systemd + reverse proxy + TLS. See
[`docs/deployment.md`](docs/deployment.md) for the full guide and
[`deploy/`](deploy/) for the assets.

1. **Build**: `cd web && npm ci && npm run build`, then
   `CGO_ENABLED=0 go build -trimpath -o nextpanel ./cmd/nextpanel`.
   (Or `docker build -f deploy/docker/Dockerfile -t nextpanel:beta .` —
   no image is published yet; build your own.)
2. **Configure**: copy `deploy/systemd/nextpanel.env.example` to
   `/etc/nextpanel/nextpanel.env` (`chmod 600`), set
   `NEXT_PANEL_ENV=production`, `NEXT_PANEL_EXTERNAL_SCHEME=https`, paste a
   generated encryption key, point `NEXT_PANEL_DB_DSN` at PostgreSQL for
   anything beyond a handful of servers.
3. **Service**: install `deploy/systemd/nextpanel.service`, `daemon-reload`,
   `enable --now`. It runs as an unprivileged user with hardening flags.
4. **Reverse proxy**: terminate TLS at nginx or Caddy
   (`deploy/proxy/nginx.conf.example`, `deploy/proxy/Caddyfile.example`) and
   forward to `127.0.0.1:8080`. Set `NEXT_PANEL_TRUSTED_PROXIES` to the proxy.
5. **Storage & backups**: back up `NEXT_PANEL_DATA_DIR` (or the Postgres
   database) **and** the encryption key separately — a database backup
   without the key cannot decrypt stored credentials, and storing them
   together removes the protection.
6. **Users**: sign in, change the bootstrap password (or disable bootstrap
   seeding and create the admin another way), create per-operator accounts
   with least-privilege roles.

## Docker

Docker support exists as buildable assets; no image is published.

```sh
docker build -f deploy/docker/Dockerfile -t nextpanel:beta .
docker run --rm nextpanel:beta crypto generate-key   # fresh encryption key
export NEXT_PANEL_ENCRYPTION_KEY='<paste the key>'
docker compose -f deploy/docker/compose.yaml up -d
```

`compose.yaml` runs the app with a persistent SQLite volume by default; a
commented-out PostgreSQL service is included for production use (uncomment
it and set `NEXT_PANEL_DB_DRIVER=postgres` plus `NEXT_PANEL_DB_DSN`). The
compose file requires `NEXT_PANEL_ENCRYPTION_KEY` in the environment before
first start and seeds the default bootstrap admin (`admin` / `123456`,
flagged until changed) unless you add `NEXT_PANEL_BOOTSTRAP_USERNAME` /
`NEXT_PANEL_BOOTSTRAP_PASSWORD` overrides — see
[`docs/deployment.md`](docs/deployment.md).

## Development

```sh
go build ./...                    # compile everything
go test ./...                     # unit + SQLite integration tests
go test ./... -race               # with the race detector (CI runs this)
golangci-lint run ./...           # lint (config in .golangci.yml)
gofmt -l .                        # must print nothing
go vet ./...
sqlc generate                     # regenerate repos; must leave a clean tree
bash scripts/security-greps.sh    # forbidden-pattern greps (also in CI)
cd web && npm run build           # typecheck + production frontend build
```

PostgreSQL dialect tests skip without `TEST_DATABASE_URL`:

```sh
export TEST_DATABASE_URL='postgres://user:pass@127.0.0.1:5432/nextpanel_test?sslmode=disable'
go test ./... -count=1
```

Conventions: Conventional Commits (`feat(auth): …`), tests for behaviour
changes, docs + CHANGELOG updates with user-visible changes. Full guide:
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Testing

| Command | What it runs |
|---|---|
| `go test ./...` | unit + SQLite integration tests (always safe, no services needed) |
| `TEST_DATABASE_URL=… go test ./...` | same suite against PostgreSQL 16 (per-package schemas) |
| `cd web && npm run build` | TypeScript typecheck + Vite production build |
| `golangci-lint run ./...` | configured linters incl. `gosec` |
| `bash scripts/security-greps.sh` | Design-spec §28.6 forbidden patterns |

CI (`.github/workflows/ci.yml`) runs all of these on Go 1.26.x and 1.27.x
plus sqlc drift and the frontend build.

## Beta status

`v0.1.0` is the first public Beta baseline. It is usable, but:

- APIs and UI text may change between Beta releases without a migration path
  for API clients.
- Planned work is tracked in [ROADMAP.md](ROADMAP.md) — 2FA, container and
  systemd control, notifications, API tokens, and more are **not** in this
  release.
- Known limits are listed in [`docs/limitations.md`](docs/limitations.md)
  (e.g. no aggregate metric rollup job yet, numeric file owners, archive
  creation is not exposed in the UI).
- Keep regular database **and** encryption-key backups, and evaluate
  carefully before managing production infrastructure with a Beta.

## Security

- Report vulnerabilities **privately** via a GitHub Security Advisory — never
  a public issue. See [SECURITY.md](SECURITY.md).
- Secrets are environment-only: never in the database, logs, or errors.
- Every endpoint is authorized; denials and sensitive operations are
  audited. There are no debug backdoors or magic tokens.
- SSH host keys fail closed; stored credentials are AES-256-GCM ciphertext.
- Terminals and file access are intentionally powerful — protect them with
  least-privilege roles, OS permissions and the audit trail, not with
  command blacklists (there are none, by design).
- Compromising the panel host can expose managed servers: harden the host,
  the key and backups. Threat model:
  [`docs/threat-model.md`](docs/threat-model.md).

## Troubleshooting

- **`NEXT_PANEL_ENCRYPTION_KEY is required`** — generate one with
  `nextpanel crypto generate-key` and set it. It must be 32 bytes of
  base64; anything else is rejected at startup.
- **Login shows a default-credentials warning** — expected on first start;
  change the bootstrap password (minimum 12 characters) or set
  `NEXT_PANEL_BOOTSTRAP_ADMIN=false`.
- **`address already in use`** — something occupies the port; set
  `NEXT_PANEL_LISTEN=127.0.0.1:9090` (and `NEXT_PANEL_BASE_URL` to match).
- **SSH connection test fails** — check host/port/credentials, then the
  host key: unknown keys are refused with a fingerprint — verify it
  out-of-band and trust it explicitly. Changed keys hard-stop; investigate
  before trusting.
- **`sql: no rows` / permission 404s** — invisible objects return 404 by
  design; grant the role a permission or a per-server grant.
- **UI shows only the API / blank page** — the frontend was not built; run
  `cd web && npm install && npm run build`, then rebuild the binary.
- **`npm run build` fails** — use Node 20+; delete `web/node_modules` and
  retry with `npm ci`.
- **PostgreSQL tests are skipped** — set `TEST_DATABASE_URL` (see
  [Development](#development)); otherwise only the SQLite dialect runs.
- **`sqlc generate` shows a diff** — generated code is committed; change the
  `.sql` (ASCII-only, LF endings) and regenerate.

## Project structure

```text
cmd/nextpanel/      process entrypoint, CLI, provider/job wiring
internal/           backend packages (auth, rbac, server, ssh, terminal,
                    files, metrics, processes, users, jobs, store, httpapi…)
internal/store/     migrations (goose), sqlc queries, dual-dialect repos
web/                React + TypeScript UI (src/; dist/ is built, embedded)
deploy/             Dockerfile, compose, systemd unit, proxy examples
docs/               architecture, API, deployment, decisions (ADRs), specs
scripts/            CI security greps and helpers
.github/workflows/  CI: format, vet, lint, tests (SQLite + Postgres),
                    sqlc drift, frontend build
.env.example        annotated configuration template (safe to commit)
run.sh / run.bat / run.ps1
                    one-command local launchers
```

## Contributing

Small, reviewable pull requests with tests and green lint. Read the design
spec before adding features — most hard decisions are already documented.
Details: [`CONTRIBUTING.md`](CONTRIBUTING.md). Be kind:
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

MIT — see [`LICENSE`](LICENSE). Dependency licence inventory and rationale:
[`docs/licensing.md`](docs/licensing.md).
