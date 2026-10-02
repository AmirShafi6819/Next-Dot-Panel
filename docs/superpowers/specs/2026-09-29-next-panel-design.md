# Next.Panel — Design Specification

- **Version:** 1.0 (design)
- **Date:** 2026-09-29
- **Status:** Approved for implementation planning
- **Companion decisions:** [ADR-0001 Technology Stack](../../decisions/ADR-0001-technology-stack.md)
- **Evidence:** [docs/poc/](../../poc/), [docs/research.md](../../research.md)

> **Reading note.** This spec is written to be implementable by a developer or
> coding agent with no access to the design conversation. Where a decision is
> backed by executed evidence it is marked **[verified]**. Where something is
> genuinely undecided it appears in §36 Open Questions or §37 Risks with an
> explicit validation method — not as a silent gap. Claims that were **not**
> verified are stated as unverified.

---

## 1. Project Goals

Next.Panel is a self-hostable Linux VPS/server management panel with a modern
web UI. The written brand name is exactly **Next.Panel** (Next Dot Panel).

### 1.0 Branding and internal identifiers

The public brand name is always written **Next.Panel**. Internal technical
identifiers cannot contain a dot without breaking tooling, so the following
lowercase forms are used deliberately and are **not** branding violations:

| Context | Identifier | Reason |
|---|---|---|
| Binary / CLI command | `nextpanel` | Executable names cannot contain `.` |
| Go module path | `github.com/ashaibery/Next-Dot-Panel` | Repository name |
| systemd unit, user, group | `nextpanel.service`, `nextpanel` | systemd unit naming |
| Config directory | `/etc/nextpanel/` | Filesystem convention |
| Data directory | `/var/lib/nextpanel/` | Filesystem convention |
| Environment variable prefix | `NEXT_PANEL_*` | Shell identifiers cannot contain `.` |
| Repository name | `Next-Dot-Panel` | GitHub repository |

All user-facing text, documentation prose, UI strings, and package
descriptions use **Next.Panel**. A CI check enforces that the rendered UI never
displays `nextpanel` as a product name.

### 1.1 Primary goals

1. **Multi-server management.** Manage an unbounded number of Linux servers,
   bounded only by configuration, never by architecture.
2. **Real remote control.** Interactive terminals, file management, process
   inspection, and service control that genuinely operate the remote host —
   never simulated.
3. **Real monitoring.** Live and historical CPU, memory, swap, disk, network,
   load, and process data collected from the real system.
4. **Security as a first-class property.** Credential encryption, fail-closed
   host-key verification, server-side object-level authorization, and an
   append-only audit trail.
5. **Operational simplicity.** One static binary with the UI embedded; SQLite
   for small installs, PostgreSQL for production.
6. **Maintainability by a small team.** A modular monolith with enforced
   boundaries and a bounded dependency set.
7. **Extensibility without rework.** Stable interfaces so an agent transport, a
   different job queue, or a different SQLite driver can be added later.

### 1.2 Success criteria

The project is successful when a user can, on a clean install, log in, change
the bootstrap password, add a Linux VPS, verify its host key, open a real
terminal, upload and download files, view live and historical metrics, inspect
processes and services, and read the resulting audit trail — with every one of
those actions authorized and recorded.

### 1.3 Non-goals for v0.1

Deferred by explicit decision, recorded in ROADMAP.md rather than implemented
half-way:

- Application marketplace / one-click app installs
- Automated provisioning of servers or control-panel-style stack installs
- Cloud provider APIs (Hetzner, DigitalOcean, AWS, …)
- Multi-tenant SaaS operation, billing, or organisation hierarchies
- Clustering of multiple Next.Panel instances
- Agent-based transport (interface defined, not implemented)
- Plugin framework (interfaces defined, not implemented)
- 2FA / WebAuthn / OIDC (schema and interfaces are prepared)
- Mobile-native applications

### 1.4 Scope of v0.1.0 (final)

Confirmed scope. Items marked *(privileged)* ship **disabled by default**.

| Group | Included |
|---|---|
| Auth & identity | Local accounts, Argon2id, sessions, RBAC, login history, bootstrap warning |
| Servers | CRUD, tags, notes, favourite, connection test, status, host-key trust |
| Execution | `SSHExecutionProvider`; `LocalExecutionProvider` *(privileged)* |
| Terminal | WebSocket + PTY, multi-tab, resize, reconnect |
| Files | Browse, upload, download, rename, delete, mkdir, archive create/extract, preview, streaming |
| Monitoring | CPU, memory, swap, disk, network, load, uptime, system info, live + historical |
| Processes | List, search, sort; signal with permission *(privileged)* |
| Services | systemd list/status/start/stop/restart/enable/disable/logs *(privileged)* |
| Containers | Docker/Podman list, start/stop/restart, logs *(privileged)* |
| Audit | Structured append-only audit, searchable, exportable |
| Jobs | DB-backed worker pool for long operations and retention |
| Backups | Panel database backup/restore + scheduled local backup |
| Users | CRUD, roles, per-server permission scoping |
| API tokens | Scoped, expiring, revocable, hashed at rest |
| Settings | Global configuration, themes, retention windows |

---

## 2. Non-Goals and Explicit Boundaries

Stated because each is a place where scope creep is likely and where a wrong
choice has security consequences.

1. **No WebSocket or HTTP endpoint may accept an arbitrary command string from
   the browser.** Every operation is an enumerated, typed request.
2. **No command blacklisting.** Filtering "dangerous" shell commands is not
   claimed to provide security. A terminal is *supposed* to run powerful
   commands; security comes from authentication, authorization, credential
   custody, and audit.
3. **No decrypted credentials in any API response, log, audit event, error
   message, metric, or WebSocket frame.**
4. **No whole-file buffering** for uploads, downloads, archive operations, or
   hashing.
5. **No fabricated metric values.** Absent data is `unavailable`, not `0`.
6. **No silent host-key acceptance,** ever, under any configuration.
7. **No automatic package installation** on managed servers.
8. **No trusting unconfigured proxy headers.**

---

## 3. Architecture Overview

### 3.1 Shape

A **modular monolith**: one Go binary containing the API, the realtime hubs, the
background workers, and the embedded frontend. Internally it is strictly
layered, and the layers are enforced by package boundaries and import rules.

```
┌──────────────────────────────────────────────────────────────────┐
│ Browser (React 19 + TypeScript)                                  │
│   REST (fetch)   │   SSE (EventSource)   │   WebSocket (xterm.js) │
└────────┬──────────────────┬───────────────────────┬──────────────┘
         │                  │                       │
┌────────▼──────────────────▼───────────────────────▼──────────────┐
│ HTTP / WS / SSE edge                                              │
│   router · middleware: requestid · authn · authz · csrf ·        │
│   ratelimit · recover · secureheaders · logging                    │
└────────┬──────────────────────────────────────────────────────────┘
         │  typed request → typed response   (no business logic here)
┌────────▼──────────────────────────────────────────────────────────┐
│ Application services                                              │
│   auth · users · servers · terminal · files · metrics ·           │
│   processes · services · containers · audit · jobs · backups      │
└───┬──────────────┬───────────────┬──────────────┬─────────────────┘
    │              │               │              │
    │              │               │              └──────────────┐
    │              │               │                             │
┌───▼──────┐  ┌────▼─────┐  ┌──────▼───────┐  ┌─────────────────▼──┐
│Reposito- │  │ Provider │  │ Credential   │  │ Job queue +        │
│ry ifaces │  │ registry │  │ store +      │  │ worker pool        │
│          │  │          │  │ encryptor    │  │                    │
└───┬──────┘  └────┬─────┘  └──────┬───────┘  └────────────────────┘
    │              │               │
    │        ┌─────┴──────┐        │
    │        ▼            ▼        │
    │   ┌─────────┐  ┌─────────┐   │
    │   │  SSH    │  │ Local   │   │
    │   │provider │  │provider │   │
    │   └────┬────┘  └────┬────┘   │
    │        │            │        │
    │   x/crypto/ssh   os/exec     │
    │   + sftp         + creack/pty│
    │                             │
┌───▼─────────────────────────────▼─────────────────────────────────┐
│ Store layer: sqlc-generated code + hand-written adapters           │
│   PostgreSQL  |  SQLite                                            │
└────────────────────────────────────────────────────────────────────┘
```

### 3.2 Layer rules (enforced, not advisory)

| Rule | Rationale |
|---|---|
| Handlers contain **no** business logic — decode, validate shape, call one service, encode | Keeps authorization and invariants in one place |
| Services never import generated sqlc packages | Generated types differ per dialect (finding F1); services must be dialect-agnostic |
| Services never construct an SSH client, an `exec.Cmd`, or a `docker` call directly | All remote/local execution goes through the provider registry |
| Providers expose **primitives only** (§8.2) | Prevents SSH and local providers drifting into different business logic |
| Every service method that touches an object takes the caller's identity | Object-level authorization cannot be forgotten if it is a required argument |
| Response models are separate types from store models | Prevents leaking columns (e.g. `password_hash`) by accident |
| No package outside `internal/crypto` performs encryption | One implementation, one place to audit |

These rules are checked in CI (§31.5) by an import-boundary test, not by review
alone.

### 3.3 Request lifecycle (representative)

```
POST /api/v1/servers/{id}/files/extract
  → requestid middleware assigns/propagates X-Request-ID
  → authn middleware resolves session → Actor{UserID, Permissions, SessionID}
  → csrf middleware verifies double-submit token
  → ratelimit middleware checks the bucket for (actor, route class)
  → handler decodes + validates shape, calls files.Service.Extract(ctx, actor, req)
  → service: authorize(actor, Perms.FilesArchive, serverID)
             resolve target → credential store → decrypt (only if needed)
             provider.ListDir/OpenRead/... → archive.Extract (hardened)
  → service emits audit event(s) inside the same transaction where required
  → handler maps result/error → typed response
  → logging middleware records {request_id, actor, route, status, duration_ms}
```

### 3.4 Data flow summary

| Flow | Path |
|---|---|
| Browser → Backend | HTTPS, cookie session, CSRF token on mutations |
| Backend → Database | Repository interfaces → adapters → sqlc → `database/sql` |
| Backend → VPS | Provider registry → `SSHExecutionProvider` → `x/crypto/ssh` |
| Backend → Host (privileged) | Provider registry → `LocalExecutionProvider` → `os/exec` |
| Metrics → Browser | shared per-server collector → store → SSE hub → `EventSource` |
| Terminal | xterm.js ↔ WebSocket ↔ PTY session ↔ provider ↔ remote PTY |
| Audit | service → audit writer → append-only table (in-transaction where required) |

### 3.5 Security boundaries

```
[ Browser ]  ── untrusted ──  [ Next.Panel backend ]  ── privileged ──  [ VPS ]
     │                                  │
     │                                  ├── [ Database ]      (ciphertext only)
     │                                  ├── [ Local host ]    (privileged, off by default)
     │                                  └── [ Docker socket ] (host-equivalent, off by default)
```

**Trust model, stated plainly:** the panel administrator controls Next.Panel
and its host. SSH credentials in the panel grant *real* access to the managed
servers. **Compromise of the Next.Panel host can lead to compromise of every
connected server.** This is documented in SECURITY.md and must not be softened
in any public description of the product.

---

## 4. Technology Stack

Full justification and rejected alternatives: [ADR-0001](../../decisions/ADR-0001-technology-stack.md).

| Layer | Choice | Verified in env |
|---|---|---|
| Backend | Go (developed on 1.27.1) | yes |
| HTTP router | `go-chi/chi/v5` | yes |
| Database | PostgreSQL 16 (production) / SQLite (dev, small) | yes |
| SQLite driver | `ncruces/go-sqlite3` (pure Go, no CGO) | yes |
| SQL layer | `sqlc` 1.30.0 + handwritten adapters | yes |
| Migrations | `pressly/goose/v3` | yes |
| SSH | `golang.org/x/crypto/ssh` | yes |
| SFTP | `pkg/sftp` | yes |
| Local PTY | `creack/pty`, `golang.org/x/term` | yes |
| WebSocket | `github.com/coder/websocket` | yes |
| Realtime (metrics/logs) | Server-Sent Events (stdlib) | yes |
| Jobs | DB-backed table + in-process worker pool | yes (POC) |
| Crypto | `golang.org/x/crypto/argon2`, stdlib AES-GCM | yes |
| Frontend | React 19 + TypeScript + Vite | **not built** |
| Terminal UI | `@xterm/xterm` | **not built** |
| Charts | uPlot | **not built** |
| E2E | Playwright | **not built** |

**Go version policy.** The *development* environment runs 1.27.1. The
`go.mod` floor will be set to the oldest version the project actually tests
against (target: the two most recent Go releases at release time), and CI will
build on both the floor and the newest. The project does not require a specific
patch release.

---

## 5. Repository Structure

```
next.panel/
├── cmd/
│   └── nextpanel/            # main + CLI subcommands
├── internal/                 # ALL v0.1 code lives here (no pkg/)
│   ├── config/               # env loading, validation, fail-fast startup
│   ├── logging/              # structured slog setup + redaction
│   ├── version/              # build metadata
│   ├── httpapi/
│   │   ├── middleware/       # requestid, authn, authz, csrf, ratelimit, recover
│   │   ├── handlers/         # thin, per-domain
│   │   └── dto/              # request/response models (never store models)
│   ├── realtime/
│   │   ├── sse/              # hub + per-topic fan-out
│   │   └── terminal/         # WebSocket terminal hub + protocol
│   ├── auth/                 # password hashing, session mgmt, login flow
│   ├── rbac/                 # permissions, roles, authorization checks
│   ├── audit/                # event writer + query service
│   ├── crypto/               # CredentialEncryptor (AES-256-GCM)
│   ├── credentials/          # CredentialStore (encrypt/decrypt boundary)
│   ├── provider/
│   │   ├── registry.go       # resolves a Server → ServerExecutionProvider
│   │   ├── ssh/              # SSHExecutionProvider, host keys, pool, keepalive
│   │   └── local/            # LocalExecutionProvider (privileged, off by default)
│   ├── terminal/             # PTY session lifecycle, limits, audit
│   ├── files/                # service-level file ops built on provider primitives
│   ├── archive/              # hardened extract/create (own test suite)
│   ├── metrics/
│   │   ├── collectors/       # cpu, memory, load, network, disk, filesystem, system
│   │   ├── collector.go      # shared per-server scheduler
│   │   └── retention.go      # aggregation + pruning jobs
│   ├── processes/            # ps parsing, signal service
│   ├── services/             # systemd (structured ops only)
│   ├── containers/           # Docker/Podman via API, never the socket to browser
│   ├── jobs/                 # queue interface, DB impl, worker pool
│   ├── backups/              # panel DB backup/restore
│   └── store/
│       ├── migrations/       # goose, per dialect
│       ├── postgres/         # sqlc-generated + adapters
│       ├── sqlite/           # sqlc-generated + adapters
│       └── repos/            # repository interfaces + implementations
├── web/                      # React app (built → embedded)
├── deploy/
│   ├── docker/               # Dockerfile, compose
│   ├── systemd/              # unit file
│   └── proxy/                # nginx, caddy, traefik examples
├── docs/
│   ├── decisions/            # ADRs
│   ├── superpowers/specs/    # this spec
│   ├── poc/                  # preserved POC evidence
│   ├── research.md
│   ├── architecture.md       # (planned, derived from this spec)
│   └── …                     # security, deployment, etc. (planned)
├── scripts/                  # dev + release helpers
└── tests/
    ├── integration/          # needs TEST_DATABASE_URL (skips gracefully)
    └── e2e/                  # Playwright
```

**No `pkg/`.** Nothing is published as a public Go API until an actual external
consumer exists. Generated code lives only under `store/{postgres,sqlite}/` and
is never imported outside `store/repos/`.

---

## 6. Domain Model

Types below are the *application* types. They are deliberately distinct from
generated store types (§7.5).

```go
// Identity
type User struct {
    ID                UserID
    Username          string
    PasswordHash      string   // never leaves the auth package
    DisplayName       string
    IsActive          bool
    IsBootstrapDefault bool    // set only for the seeded admin
    MustChangePassword bool
    Roles             []Role
    CreatedAt, UpdatedAt time.Time
}

type Role struct {
    ID          RoleID
    Name        string          // "admin", "operator", "viewer", custom
    Permissions []Permission
}

type Permission string   // see §12.2

// Server targeting — credentials are REFERENCED, never embedded
type Target struct {
    ID            ServerID
    Type          TargetType     // TargetSSH | TargetLocal
    Host          string
    Port          int
    Username      string
    AuthMethod    AuthMethod     // AuthKey | AuthPassword | AuthAgent
    CredentialRef CredentialID   // opaque handle into the credential store
    HostKeyPolicy HostKeyPolicy  // TOFU | STRICT
    Metadata      map[string]string
}

// Credential material lives ONLY inside the credentials package
type Credential struct {
    ID         CredentialID
    ServerID   ServerID
    Kind       AuthMethod
    Secret     Secret          // write-only; no String(), no JSON marshal
    Passphrase Secret          // optional, for encrypted keys
    CreatedAt  time.Time
    RotatedAt  *time.Time
}

type Server struct {
    ID           ServerID
    Name         string
    Target       Target
    Tags         []string
    Notes        string
    IsFavourite  bool
    Status       ServerStatus   // UNKNOWN|CONNECTING|ONLINE|OFFLINE|ERROR
    StatusDetail string         // bounded, secret-free reason
    OS           string         // discovered
    Kernel       string
    Arch         string
    LastSeenAt   *time.Time
    LastErrorAt  *time.Time
    Version      int64          // optimistic locking
    CreatedAt, UpdatedAt time.Time
}

type Session struct {
    ID         SessionID
    UserID     UserID
    TokenHash  []byte          // SHA-256 of the opaque token
    IP         string
    UserAgent  string
    CreatedAt  time.Time
    LastSeenAt time.Time
    ExpiresAt  time.Time
    RevokedAt  *time.Time
}

type AuditEvent struct {
    ID        int64
    Timestamp time.Time
    ActorID   *UserID
    ActorName string          // denormalised so history survives user deletion
    Action    string          // §27.3
    Target    string
    ServerID  *ServerID
    Result    AuditResult     // SUCCESS|FAILURE|DENIED
    RequestID string
    IP        string
    UserAgent string
    Metadata  map[string]any  // sanitised; never contains secrets
}

type Job struct {
    ID          JobID
    Kind        string
    Status      JobStatus     // §22.2
    Priority    int
    Attempts    int
    MaxAttempts int
    RunAt       time.Time
    LockedBy    *string
    LockedAt    *time.Time
    Payload     []byte        // kind-specific, validated on load
    Progress    float64       // 0..1, or -1 when indeterminate
    LastError   string
    CreatedAt, UpdatedAt time.Time
}
```

### 6.1 Secret handling

`Secret` is a distinct type, not `string`:

- no `String()`, `Format()` (beyond a redacted form), or JSON marshalling;
- zeroed in memory after use where practical;
- never placed in a struct that gets logged wholesale;
- only the `credentials` package may unwrap it.

This makes accidental leakage a compile-time or test-time failure rather than a
review failure.

---

## 7. Database Model

### 7.1 Storage layering

```
Application services
      ↓  (application types only)
Repository interfaces        ← internal/store/repos
      ↓
Adapters                     ← internal/store/repos/{pg,sqlite}
      ↓  (converts generated ↔ application types)
sqlc-generated code          ← internal/store/{postgres,sqlite}
      ↓
database/sql → pgx | ncruces
```

**The adapter layer is mandatory, not optional.** Measured reason (finding F1):
`sqlc.narg()` generates `*int64` on PostgreSQL but `interface{}` on SQLite;
`LIMIT`/`OFFSET` generate `int32` vs `int64`; `COUNT` differs similarly. And
(finding F2) SQLite JSON columns require explicit overrides or the row scan
fails — in the `ClaimJob` case, *after* the UPDATE had already committed
(finding F2a).

### 7.2 Repositories

Scoped to application concepts; not one per table, and not one giant interface.

```go
type UserRepository interface {
    Create(ctx, NewUser) (*User, error)
    ByID(ctx, UserID) (*User, error)
    ByUsername(ctx, string) (*User, error)
    List(ctx, UserFilter, Page) ([]*User, error)
    Update(ctx, UserID, UserUpdate) (*User, error)   // optimistic locking
    SetPassword(ctx, UserID, hash string, mustChange bool) error
    SoftDelete(ctx, UserID) error
}

type SessionRepository interface {
    Create(ctx, NewSession) (*Session, error)
    ByTokenHash(ctx, []byte) (*Session, error)
    Touch(ctx, SessionID, time.Time) error
    Revoke(ctx, SessionID) error
    RevokeAllForUser(ctx, UserID) (int, error)
    DeleteExpired(ctx, before time.Time) (int, error)
}

type ServerRepository interface { /* CRUD + List with filters + status updates (versioned) */ }
type CredentialRepository interface { /* create/rotate/delete; never returns plaintext */ }
type AuditRepository interface {
    Insert(ctx, AuditEvent) error
    InsertTx(ctx, Tx, AuditEvent) error      // in-transaction, when required
    Query(ctx, AuditFilter, Page) ([]*AuditEvent, error)
    Export(ctx, AuditFilter, io.Writer, Format) error
}
type MetricRepository interface {
    InsertBatch(ctx, []MetricSample) error
    QueryRange(ctx, ServerID, from, to time.Time, Resolution) ([]MetricSeries, error)
    Aggregate(ctx, Resolution, from, to time.Time) (int, error)
    PruneBefore(ctx, Resolution, time.Time) (int, error)
}
type JobRepository interface { /* Enqueue, Claim, Complete, Fail, Retry, ReapStale, List, Cancel */ }
```

### 7.3 Tables

Core (all dialects):

| Table | Notes |
|---|---|
| `users` | `username` UNIQUE; `is_bootstrap_default`, `must_change_password` flags |
| `roles`, `permissions`, `role_permissions`, `user_roles` | RBAC |
| `sessions` | `token_hash` UNIQUE, indexed on `user_id`, `expires_at` |
| `server_permissions` | per-user, per-server permission grants (§12.4) |
| `servers` | `name` UNIQUE; `version` for optimistic locking; `status` indexed |
| `server_credentials` | `ciphertext`, `nonce`, `key_version` — never plaintext |
| `server_host_keys` | pinned key per server; states UNKNOWN/TRUSTED/CHANGED/REJECTED |
| `tags`, `server_tags` | |
| `audit_logs` | append-only; indexed per §7.3.1 |
| `application_logs` | structured app logs, separate retention |
| `login_history` | auth outcomes, distinct retention from audit |
| `metric_samples` | raw tier; PK `(server_id, ts)` for idempotent upsert |
| `metric_aggregates` | PK `(server_id, resolution, ts)` |
| `terminal_sessions` | session metadata; **no terminal input recorded** |
| `jobs` | queue state, `locked_by`/`locked_at`, `run_at` |
| `api_tokens` | `token_hash`, scopes, `expires_at`, `last_used_at` |
| `notification_channels`, `notifications` | provider interface (requirements spec §40) |
| `settings` | key/value, typed accessors |
| `backups` | panel DB backup records |

#### 7.3.1 Indexes (initial; adjusted against real query plans)

```
users(username)              UNIQUE
sessions(token_hash)         UNIQUE
sessions(user_id, expires_at)
servers(name)                UNIQUE
servers(status)
servers(updated_at)
audit_logs(ts DESC, id DESC)          -- primary access path
audit_logs(actor_id, ts DESC)
audit_logs(server_id, ts DESC)
audit_logs(action, ts DESC)
audit_logs(request_id)                -- correlation lookups
login_history(user_id, ts DESC)
login_history(ip, ts DESC)
metric_samples(server_id, ts)         PRIMARY KEY
metric_aggregates(server_id, resolution, ts)  PRIMARY KEY
jobs(status, run_at)                  -- claim path
jobs(kind, status)
api_tokens(token_hash)       UNIQUE
```

Indexes are justified by the queries in this spec. No speculative indexes.

### 7.4 SQLite specifics — documented behaviour and limits

Explicit, because "SQLite works too" without qualification would be misleading.

| Aspect | Behaviour | Reason |
|---|---|---|
| WAL mode | Enabled at open | **[verified]** `journal_mode` returns `wal` |
| Busy timeout | 5000 ms | **[verified]** avoids immediate `SQLITE_BUSY` |
| Foreign keys | Enforced per connection | **[verified]** `foreign_keys` returns `1` |
| `synchronous` | `NORMAL` (WAL) | Durability/throughput balance, documented |
| Connection pool | **`SetMaxOpenConns(1)`** | SQLite permits one writer; a larger pool produces `SQLITE_BUSY` under load |
| Concurrent writes | Serializable through one writer | **[verified]** 20 concurrent inserts, 0 errors via a single-writer pool |
| Job claiming | **No `FOR UPDATE SKIP LOCKED`** | **[verified]** SQLite does not support it; single-writer serialisation is *not* equivalent to row locking |
| JSON columns | Mapped to `[]byte` via sqlc overrides | **[verified]** default mapping produces unscannable `jsontext.Value` |
| Backup | `VACUUM INTO` snapshot | Safe while running; see §23 |
| Migration | goose, SQLite dialect | Same versioning as PostgreSQL |

**Positioning (must be stated in user-facing docs):** SQLite is for
single-instance and small deployments. It is **not** recommended for
high-concurrency multi-user operation, and PostgreSQL is the documented
production default. This limitation is a consequence of measurement, not
caution.

*Validation task (§36):* characterise SQLite write throughput and contention
under a realistic panel workload to publish concrete supported limits rather
than an adjective.

### 7.5 sqlc configuration requirements

Non-negotiable, from measured findings:

1. **Explicit per-column overrides** on SQLite for every JSON column → `[]byte`
   and every timestamp column → `time.Time`. Without these the generated code
   does not work (§7.1).
2. **Portable query subset.** One logical query set, two files, differing only
   in: placeholder syntax (`$n` / `?n`), `now()` / `CURRENT_TIMESTAMP`, and
   omission of `FOR UPDATE SKIP LOCKED` on SQLite.
3. **`sqlc.narg()` for optional filters** — portable, but expect different
   generated types per dialect; the adapter absorbs this.
4. **`ClaimJob` is critical-path.** Its `UPDATE … RETURNING` committed before a
   scan failure in the POC. It requires dedicated tests asserting that a
   returned error means the job was *not* claimed.
5. CI runs `sqlc generate` and fails if the working tree becomes dirty.

Reference configuration: [`docs/poc/database/sqlc.yaml`](../../poc/database/sqlc.yaml).

### 7.6 Transactions

Multi-step operations are transactional. Specifically:

- user creation + role assignment + audit record;
- server creation + credential write + audit record;
- **audit writes for security-sensitive actions** — if the audit insert fails,
  the action fails (§27.6);
- job claim (single statement, `RETURNING`);
- metric batch insert (single statement / batched upsert).

Isolation: default (`READ COMMITTED` on PostgreSQL). Optimistic locking via
`version` columns where concurrent edits are realistic (servers, users).

### 7.7 Timestamps

- Stored in **UTC**.
- PostgreSQL: `timestamptz`. SQLite: RFC3339 text via `time.Time` overrides.
- Remote host clock skew is real: metric timestamps are stamped by **the
  panel**, with the remote uptime used only as a sanity check. Documented in
  §18.6.
- Audit ordering uses `(ts, id)`, not `ts` alone — two events can share a
  timestamp with sub-millisecond resolution.

---

## 8. Provider Architecture

### 8.1 The registry

```go
type ProviderRegistry interface {
    For(ctx context.Context, t Target) (ServerExecutionProvider, error)
    Release(ctx context.Context, t Target) error   // returns pooled conn, may be a no-op
}
```

Resolution is by `Target.Type`. **No service knows whether it is talking to SSH
or to the local host.**

### 8.2 Provider interface — primitives only

```go
type ServerExecutionProvider interface {
    ID() string
    Connect(ctx context.Context, t Target, creds CredentialSource) error
    Disconnect(ctx context.Context) error
    Status() ConnectionStatus
    Ping(ctx context.Context) (time.Duration, error)

    Exec(ctx context.Context, cmd Command) (*ExecResult, error)
    ExecStream(ctx context.Context, cmd Command) (io.ReadCloser, error)

    OpenPTY(ctx context.Context, o PTYOptions) (PTY, error)

    Stat(ctx context.Context, path string) (*FileInfo, error)
    ListDir(ctx context.Context, path string) ([]FileInfo, error)
    OpenRead(ctx context.Context, path string, offset int64) (io.ReadCloser, error)
    OpenWrite(ctx context.Context, path string, mode os.FileMode, size int64) (io.WriteCloser, error)
    Remove(ctx context.Context, paths []string, recursive bool) error
    Rename(ctx context.Context, from, to string) error
    Mkdir(ctx context.Context, path string, mode os.FileMode) error
}

type PTY interface {
    Read(p []byte) (int, error)
    Write(p []byte) (int, error)
    Resize(ctx context.Context, cols, rows uint16) error
    Wait() (exitCode int, err error)
    Close() error
}

type Command struct {
    Path string      // absolute path or resolved name, e.g. "/usr/bin/stat"
    Args []string    // passed as a slice — NEVER concatenated into a shell string
    Env  []string    // explicit, minimal
    Stdin io.Reader  // optional
    Timeout time.Duration
    MaxOutputBytes int64  // truncate with an explicit marker rather than OOM
}
```

**Explicitly NOT provider methods**, because they are policy and belong above
the abstraction:

`Upload`, `Download`, `Extract`, `Compress`, `GetMetrics`, `GetProcesses`,
`ManageSystemd`, `ManageContainers`, `Reboot`, `TerminateProcess`.

Rationale: if these were provider methods, the SSH and local implementations
would inevitably diverge into two copies of the same business logic, and every
new feature would need implementing twice with two chances to get authorization
wrong.

### 8.3 Composition at the service layer

```
files.Service.Upload   = OpenWrite (provider)  + io.Copy (streaming) + audit
files.Service.Extract  = OpenRead  (provider)  + archive.Extract (hardened) + OpenWrite batch
metrics.Service.Collect= Exec (one batched /proc read) + collectors.*(parse) + store
```

One implementation of each, exercised identically against both providers.

### 8.4 Provider lifecycle

```
        Connect()
           │
           ▼
    ┌─────────────┐   keepalive ok    ┌──────────────┐
    │  CONNECTED  │◄─────────────────►│   (steady)   │
    └──────┬──────┘                   └──────┬───────┘
           │ failure                         │ idle > idleTimeout
           ▼                                 ▼
    ┌─────────────┐                   ┌──────────────┐
    │ RECONNECTING│  backoff          │   DRAINED    │
    │ (capped)    │  (1s→2s→…→30s)    │  (closed)    │
    └──────┬──────┘                   └──────────────┘
           │ exhausted attempts
           ▼
    ┌─────────────┐
    │   FAILED    │
    └─────────────┘
```

Rules:

- **Reuse.** A server's connection is reused across operations; a new TCP+SSH
  handshake per small request is forbidden.
- **Isolation.** A pooled connection is keyed by `(server, credential_version)`.
  Credentials are never shared across servers or across users with different
  authorization. **A connection is never reused for a caller who could not have
  created it.**
- **Idle timeout.** Default 5 min idle → drained and closed.
- **Keepalive.** `keepalive@openssh.com` every 30 s; failure transitions state.
- **Backoff.** Reconnect attempts back off 1s, 2s, 4s, 8s, 16s, 30s (cap),
  jittered ±20%; after `maxReconnectAttempts` (default 5) the server is marked
  `ERROR` and left until the next explicit attempt or the scheduled health
  check. **No unbounded reconnect loop.**
- **Cancellation.** Every provider call takes a `context.Context`; cancellation
  closes the in-flight channel and does not poison the connection.
- **Per-server and per-user connection caps** (defaults: 4 per server, 8 per
  user) to bound resource use.
- **Graceful shutdown.** On `SIGTERM`: stop accepting new work, close SSE/WS,
  drain or cancel in-flight jobs, close PTYs, close providers, flush logs,
  close the DB pool.

### 8.5 Error taxonomy

Providers map transport errors to a stable, safe-to-display taxonomy
(§26.3), so the UI can show a useful category without exposing internals:

`DNS_ERROR`, `NETWORK_UNREACHABLE`, `TIMEOUT`, `AUTHENTICATION_FAILED`,
`HOST_KEY_MISMATCH`, `HOST_KEY_UNKNOWN`, `PERMISSION_DENIED`, `SERVER_OFFLINE`,
`INVALID_CONFIGURATION`, `PROTOCOL_ERROR`, `RESOURCE_EXHAUSTED`,
`UNSUPPORTED`, `UNKNOWN_ERROR`.

---

## 9. SSH Architecture

### 9.1 Host key verification — fail closed

**Verified end-to-end in POC 2** ([`docs/poc/ssh/`](../../poc/ssh/)): unknown
rejected, trusted accepted, changed hard-stopped, ANSI passthrough intact.

```go
type HostKeyPolicy string

const (
    HostKeyTOFU   HostKeyPolicy = "TOFU"    // trust on first use, with explicit prompt
    HostKeyStrict HostKeyPolicy = "STRICT"  // must already be pinned
)

type HostKeyState string

const (
    HostKeyUnknown HostKeyState = "UNKNOWN"  // never seen → prompt user
    HostKeyTrusted HostKeyState = "TRUSTED"  // matches pin → connect
    HostKeyChanged HostKeyState = "CHANGED"  // differs from pin → HARD STOP
    HostKeyRejected HostKeyState = "REJECTED"// explicitly refused by the user
)
```

Callback behaviour:

| State | Action |
|---|---|
| `UNKNOWN` (TOFU) | Refuse the connection. Return the SHA256 fingerprint to the UI. User must explicitly trust; only then is the key persisted and the connection retried. |
| `UNKNOWN` (STRICT) | Refuse. No prompt path; operator must pin out of band. |
| `TRUSTED` | Proceed. |
| `CHANGED` | **Refuse and raise a security event.** The connection is not re-established, the pin is not updated, and no "accept automatically" path exists. A deliberate review-and-replace workflow updates the pin and records an audit event. |
| `REJECTED` | Refuse. |

`ssh.InsecureIgnoreHostKey` is **forbidden in the codebase**, enforced by a CI
grep. Fingerprints are displayed as `SHA256:<base64>` (verified format).

### 9.2 Connection pooling

- Keyed `(serverID, credentialVersion)`.
- Per-server cap default 4; per-user cap default 8.
- Idle timeout default 5 min.
- Keepalive 30 s.
- Health check on demand via `Ping` (measures round-trip latency).
- A pooled connection whose server row was updated (credentials rotated, host
  changed) is invalidated by `credentialVersion` mismatch, not by inspection.

### 9.3 Command execution

- `Command.Args` is a slice. **No shell interpolation of untrusted values
  anywhere.** For remote execution the provider sends argv to the remote
  `exec` channel, which does not invoke a shell.
- Where a shell is genuinely unavoidable, arguments are quoted with a
  well-tested library (e.g. POSIX single-quote escaping) — never hand-rolled.
- Every command has a timeout (default 30 s; per-call overrides) and an output
  cap (default 1 MiB) that truncates with an explicit marker rather than
  exhausting memory.
- Exit status, stdout, stderr, and duration are captured. Non-zero exit is a
  *result*, not automatically an error — callers decide.

### 9.4 Implementation trap — recorded because it cost real debugging time

**`x/crypto/ssh` copies stdout and stderr in separate goroutines.** Assigning
both `session.Stdout` and `session.Stderr` to the same `bytes.Buffer` is a data
race; in POC 2 it produced a completely empty result while the server logged
`wrote 29 bytes err=<nil>`. The failure is silent and looks like a protocol
problem.

**Rule:** stdout and stderr must go to independent, concurrency-safe writers.
`bytes.Buffer` is *not* concurrency-safe. Use separate buffers, or a mutexed
writer, or a channel-fed sink.

### 9.5 Algorithms

- Host keys: `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`, `ecdsa-sha2-nistp256`.
  SHA-1 variants (`ssh-rsa`, `ssh-dss`) are **not** offered.
- Key exchange: curve25519-sha256 and modern ECDH only.
- Ciphers: chacha20-poly1305, aes256-gcm, aes128-gcm.
- MACs: umac-128-etm, hmac-sha2-256-etm.
- Password auth is supported but **must be deliberately enabled** per server;
  key auth is the default.
- Private keys are accepted in OpenSSH and PEM form, validated on upload, and
  stored encrypted (§14). Keys are never returned by any endpoint.

---

## 10. Local Execution Architecture (**privileged**)

`LocalExecutionProvider` lets Next.Panel manage the host it runs on, using the
same interface as SSH: `os/exec` for commands, `creack/pty` for PTYs,
`os`/`filepath` for filesystem operations.

**Security posture — stated plainly, not softened:**

- **Disabled by default.** Requires `NEXT_PANEL_LOCAL_EXECUTION_ENABLED=true`.
- Protected by a dedicated permission; not implied by being an administrator.
- Requires confirmation for state-changing operations.
- Every operation is audited with the actor, the operation, and the result.
- **It is effectively host-root equivalent** when the panel process has those
  privileges. Running the panel as a dedicated unprivileged user reduces but
  does not eliminate this.

**Recommended posture (documented in deployment guide):** run Next.Panel as an
unprivileged user, manage *remote* servers over SSH, and enable local execution
only where genuinely needed.

**Operational safeguard:** local file operations are restricted to a
configurable allow-list of roots (default: none). Paths are resolved and
verified against the allow-list after full normalisation, with symlink
resolution, so a symlink cannot escape the root (§17.3).

---

## 11. Authentication

### 11.1 Password storage

**Argon2id** via `golang.org/x/crypto/argon2`.

| Parameter | Default | Notes |
|---|---|---|
| memory | 64 MiB | OWASP-aligned baseline; configurable |
| iterations | 3 | |
| parallelism | 2 | |
| salt | 16 bytes | `crypto/rand` |
| key length | 32 bytes | |
| encoded form | PHC string | `$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>` |

The PHC encoding carries its own parameters, so they can be raised later
without invalidating existing hashes; on successful login a hash whose
parameters are below current policy is transparently re-hashed.

- Passwords are never logged, never returned, never included in audit metadata,
  never placed in an error string.
- Comparison uses `subtle.ConstantTimeCompare`.
- Password policy: minimum 12 characters, reject a bundled list of the most
  common passwords, allow password managers, allow paste, **no** arbitrary
  symbol-class rules. Length beats composition.

### 11.2 Bootstrap administrator

Hard product requirement: first install seeds `admin` / `123456`.

- Created **only** when the users table is empty.
- The row carries `is_bootstrap_default = true` and `must_change_password = true`.
- **Default-credential detection is the flag, never a plaintext comparison.**
  The original password is not retained for comparison (requirements spec §369). Once the
  password is changed, `is_bootstrap_default` is cleared and the warning
  disappears permanently.
- While the flag is set: the login page shows a prominent warning, and a
  persistent banner is shown after login indicating the requirement to change
  the password.
- **Configurable:** `NEXT_PANEL_BOOTSTRAP_ADMIN_ENABLED=false` skips seeding
  entirely for packaging that must not ship default credentials; the setup
  wizard then creates the first administrator interactively.
- On startup, if a bootstrap-default account is detected, a `SECURITY_EVENT`
  audit entry is written and a warning is logged. **No secret is logged.**

### 11.3 Login flow

```
POST /api/v1/auth/login  {username, password}
  → rate limit (IP + username buckets, §16)
  → constant-time-ish path: always perform a hash verification (a dummy hash
    when the user does not exist) to avoid a username-existence timing oracle
  → on failure: audit LOGIN_FAILED (category only, never the password),
    increment the failure counter, return a generic error
  → on success:
       check is_active; if disabled → generic failure + audit
       verify password; if parameters below policy → re-hash
       create session (opaque 256-bit token; store SHA-256 hash)
       set cookie (HttpOnly, SameSite=Lax, Secure in production, Path=/)
       return the CSRF token + the default-credentials warning flag
       audit LOGIN_SUCCESS
```

Error responses never distinguish "no such user" from "wrong password".

### 11.4 Session management

| Property | Value |
|---|---|
| Token | 256 bits from `crypto/rand`, base64url |
| Storage | **SHA-256 hash only**; the raw token is never persisted |
| Cookie | `HttpOnly`, `SameSite=Lax`, `Secure` in production, `Path=/` |
| Lifetime | 12 h absolute (configurable) |
| Idle timeout | 2 h (configurable); sliding on activity |
| Rotation | New token issued on login and on privilege change |
| Revocation | Immediate — the session row is deleted, so the next request fails |
| Logout | Deletes the session row; audit `LOGOUT` |
| Password change | **All other sessions for that user are revoked** |
| Listing | Users see their own sessions with IP, user agent, and times |

**Not JWT.** Opaque server-side tokens were chosen specifically so revocation
is immediate; a stateless token cannot be revoked before expiry without
maintaining a denylist, which reintroduces the state JWT was meant to avoid.

### 11.5 Authentication by channel

Explicitly distinguished, because each has different attack surface:

| Channel | Mechanism | Authorization |
|---|---|---|
| Browser session | `HttpOnly` cookie | Session row + permissions |
| REST API (automation) | `Authorization: Bearer npx_…` | Token hash + scopes |
| WebSocket (terminal) | Cookie **plus** origin check **plus** a short-lived one-time ticket | Re-checked per connection |
| SSE (metrics/logs) | Cookie, `EventSource` (cannot set headers) | Re-checked on every connect |

**WebSocket and SSE do not rely on the cookie alone:**

- **Origin validation** on every upgrade/handshake, against a configured
  allow-list. A missing or mismatched `Origin` is rejected.
- The WebSocket terminal requires a **one-time ticket** obtained from
  `POST /api/v1/servers/{id}/terminal/tickets`, valid 30 s, single use, bound
  to `(user, server, session)`. This defeats cross-site WebSocket hijacking and
  prevents replay.
- Authorization is re-evaluated **at connect time**, so a session revoked after
  page load cannot open a new stream. Existing streams are closed on
  revocation (§24.5).

### 11.6 API tokens

- Format `npx_<32 bytes base64url>`; only the **SHA-256 hash** is stored.
- Shown **once**, at creation. Never retrievable afterwards.
- Explicit scopes (§12.5), optional expiry, revocable.
- `last_used_at` updated; creation, revocation, and use on sensitive endpoints
  are audited.
- Tokens carry permissions, never a role; a token can never exceed its owner's
  current permissions.

---

## 12. RBAC

### 12.1 Model

`User → Roles → Permissions`, plus optional per-server grants. Roles are
convenience bundles; **authorization checks are always against permissions**,
never against a role name.

Default roles:

| Role | Intent |
|---|---|
| `admin` | All permissions, including user and settings management |
| `operator` | Full server operations; cannot manage users or global settings |
| `viewer` | Read-only: servers, metrics, processes; no terminal, no writes |

Roles are editable and new roles can be created; a role is just a named
permission set.

### 12.2 Permission catalogue

```
servers.read      servers.create   servers.update   servers.delete
servers.connect   servers.hostkey.manage

terminal.open

files.read        files.write      files.upload     files.download
files.delete      files.archive

metrics.read

processes.read    processes.signal

services.read     services.control

containers.read   containers.control   containers.exec

backups.read      backups.create       backups.restore

users.read        users.manage
audit.read        settings.manage
```

Privileged capabilities additionally require their subsystem to be enabled by
configuration (§13.4) — **permission and enablement are independent gates; both
must pass.**

### 12.3 Enforcement

Authorization is a required function argument, not a decorator that can be
forgotten:

```go
func (s *Service) Delete(ctx context.Context, actor Actor, serverID ServerID) error {
    if err := s.authz.Require(ctx, actor, Perms.ServersDelete, serverID); err != nil {
        s.audit.Denied(ctx, actor, "SERVER_DELETED", serverID)  // denials are audited too
        return err
    }
    …
}
```

Rules:

1. Every service method that touches an object takes `actor Actor`.
2. **Object-level** checks: `user → permission → object → operation`. Being
   logged in is never sufficient (requirements spec §226).
3. **IDOR defence:** every object is fetched *through* an authorization check;
   changing an ID in a URL cannot reach another user's object. Tested
   explicitly (§30.4).
4. The frontend may hide controls for usability. **Hiding is never
   authorization.**
5. Denials are audited as `result = DENIED`.

### 12.4 Per-server scoping

`server_permissions` grants a user a permission set on a specific server.
Effective permission = role permissions ∪ direct grants, evaluated per server.

Example:

| User | Server 1 | Server 2 | Server 3 |
|---|---|---|---|
| A | terminal + files | metrics only | no access |

Server listing is filtered by effective permission, and a request for a server
the actor cannot see returns **404, not 403**, so the existence of other
servers is not disclosed.

### 12.5 Token scopes

Mirror permissions with a colon form: `servers:read`, `servers:write`,
`terminal:access`, `files:read`, `files:write`, `metrics:read`, `audit:read`,
`users:read`, `users:write`. A token's effective permission is
`token.scopes ∩ owner.permissions`, so revoking a user's role immediately
narrows every token they hold.

---

## 13. Sessions, Realms, and Privileged Subsystems

### 13.1 Session lifecycle (server-side)

`created → active → (idle-expired | absolute-expired | revoked | logged-out)`

Every transition except expiry-by-time is an audited event. Cleanup removes
expired rows on a schedule (§22.5) and never removes unexpired ones.

### 13.2 Realm separation

The four authentication channels in §11.5 are *separate realms*: a browser
session cannot be upgraded into an API token, and a token cannot open a
terminal WebSocket. A ticket obtained for one server is not valid for another.

### 13.3 Re-authentication for sensitive operations

Operations that change the security posture require a fresh password
confirmation even with a valid session (default window: 5 minutes):

- changing your own password,
- creating/revoking API tokens,
- managing host keys,
- enabling `LocalExecutionProvider`, Docker, or systemd control,
- deleting a user or a server.

### 13.4 Privileged subsystem gates

| Subsystem | Config gate | Permission | Confirmation | Audit |
|---|---|---|---|---|
| Local execution | `NEXT_PANEL_LOCAL_EXECUTION_ENABLED` (default **false**) | `servers.connect` on a local target | destructive ops | yes |
| Docker/Podman | `NEXT_PANEL_CONTAINERS_ENABLED` (default **false**) | `containers.*` | destructive ops | yes |
| systemd | `NEXT_PANEL_SERVICES_ENABLED` (default **false**) | `services.*` | destructive ops | yes |
| Local file roots | `NEXT_PANEL_LOCAL_FILE_ROOTS` (default **empty**) | `files.*` | deletes | yes |

Each of these is documented in the threat model (§29) as
host-privilege-equivalent.

---

## 14. Credentials

### 14.1 The indirection

```
Server ──CredentialID──► CredentialStore ──► CredentialEncryptor ──► ciphertext (DB)
                                                      │
                                          key from NEXT_PANEL_ENCRYPTION_KEY (env)
```

`Target` holds only `CredentialRef`. **Raw credential material never enters a
`Target`, a `Server`, a DTO, a log line, an audit event, or a WebSocket frame.**

### 14.2 CredentialStore

```go
type CredentialStore interface {
    Put(ctx context.Context, serverID ServerID, c Credential) (CredentialID, error)
    Rotate(ctx context.Context, id CredentialID, c Credential) (CredentialID, error)
    Delete(ctx context.Context, id CredentialID) error
    // Unwrap is the ONLY path to plaintext. Callers must scope it narrowly.
    Unwrap(ctx context.Context, id CredentialID) (*Unwrapped, error)
}

type Unwrapped struct {
    Password   Secret
    PrivateKey Secret
    Passphrase Secret
    Close      func()   // mandatory zeroing hook
}
```

- `Unwrap` is called as late as possible and the result closed/zeroed
  immediately after use.
- Credential version is incremented on rotation; pooled connections keyed to
  the old version are invalidated (§8.4).
- Deletion is immediate; no soft-deleted plaintext lingers.

### 14.3 Leak prevention

| Vector | Control |
|---|---|
| Logs | `Secret` has no `String()`; the log handler redacts known key names |
| Audit | Sanitising constructor rejects secret-shaped values |
| API responses | DTOs never contain credential fields; store models never serialised directly |
| Errors | Provider errors are mapped to the taxonomy; raw errors never reach clients |
| WebSocket | Terminal frames carry bytes, never credential material |
| Metrics | Collectors never read credential material |
| UI | Credentials are write-only; the field renders empty and is never pre-filled |

A CI check greps for the forbidden patterns listed in §28.6.

---

## 15. Encryption

Single abstraction: `internal/crypto.CredentialEncryptor`.

### 15.1 Algorithm and format

**AES-256-GCM** (AEAD) from the standard library.

```
ciphertext blob layout (versioned):
  ┌────────┬──────────┬──────────────┬─────────────────────┐
  │ ver(1) │ nonce(12)│ key_id(1)    │ ciphertext+tag      │
  └────────┴──────────┴──────────────┴─────────────────────┘
```

- `ver` — format version, starts at `1`; enables migration between formats.
- `nonce` — 12 bytes from `crypto/rand`, **freshly generated per encryption**.
  Nonce reuse is catastrophic for GCM, so nonces are never derived from data or
  counters, and a nonce is never reused under the same key.
- `key_id` — identifies which configured key encrypted this blob, enabling
  rotation without re-encrypting everything at once.
- `ciphertext+tag` — GCM output including its authentication tag.

Additional authenticated data: the format version and `key_id`, so a blob
cannot be reinterpreted under a different key id.

### 15.2 Key management

| Aspect | Decision |
|---|---|
| Source | `NEXT_PANEL_ENCRYPTION_KEY`, base64-encoded 32 bytes, **environment only** |
| Never in DB | The database holds ciphertext only; the key is never stored in it |
| Validation | Length and decodability checked at startup; failure is fatal (§30 startup checks) |
| Multiple keys | `NEXT_PANEL_ENCRYPTION_KEY_ID` (default `1`) plus optional previous keys for rotation |
| Rotation | Re-encrypt on read/write under the active key; a CLI command sweeps the rest (`nextpanel crypto rotate`) |
| Rotation of `key_id` | New blobs carry the new id; old blobs decrypt via the retained old key until swept |

### 15.3 Failure behaviour

- **Decryption failure is never silently ignored.** It returns a typed error,
  surfaces as `INVALID_CONFIGURATION` to the user with a safe message, is
  logged without ciphertext or key material, and is audited as a
  `SECURITY_EVENT`.
- A wrong or missing key does **not** fall back to plaintext under any
  circumstance.
- Startup refuses to run if any existing credential fails to decrypt, unless
  `--allow-decrypt-failures` is passed explicitly for recovery.

### 15.4 Not invented

No custom cipher constructions, no custom KDF beyond Argon2id, no custom
padding scheme. Only established primitives via established libraries.

---

## 16. Rate Limiting

Bounded buckets, keyed by a combination of actor and source.

| Class | Endpoints | Default limit | Key |
|---|---|---|---|
| Authentication | login, password change | 10 / 15 min | IP **and** username (independent buckets) |
| Sensitive reads | audit, login history | 60 / min | actor |
| Connection tests | server test | 10 / min | actor |
| Server connect | any connect | 30 / min | actor |
| File operations | upload/download/delete | 120 / min | actor |
| Payload writes | upload bytes | configurable total per user | actor |
| Terminal creation | ticket + upgrade | 20 / min | actor |
| WebSocket upgrades | all | 30 / min | IP |
| API tokens | create/revoke | 10 / min | actor |
| Public endpoints | health/version | generous | IP |

Rules:

- **IP and account buckets are independent** for authentication, so rotating
  source IPs does not bypass the account bucket and vice versa.
- Progressive delay on repeated authentication failure; **accounts are not
  permanently locked based on IP heuristics alone** (a shared NAT must not lock
  out an office).
- Rate-limit responses include `Retry-After`; `429` carries a stable error code.
- Limits are configuration, with documented defaults; **no limit is so tight
  that normal use is disrupted.** Values above are starting points to be
  re-tuned after load testing (§34).

---

## 17. File Manager

### 17.1 Operations

Browse, breadcrumbs, sort, search (bounded), refresh, upload, download, rename,
delete (single/bulk), mkdir, create empty file, stat/permissions, archive
extract, archive create, preview.

### 17.2 Streaming — no whole-file buffering

```
Download:  Remote file → provider.OpenRead → io.Copy → HTTP response (chunked)
Upload:    HTTP request body → io.Copy → provider.OpenWrite → remote file
```

- Neither path ever holds a whole file in memory. `io.Copy` with a fixed-size
  buffer is the implementation.
- Upload bounds: max size (default 2 GiB, configurable), max concurrent uploads
  per user (default 3).
- Downloads stream with `Content-Length` when known; `Range` is supported where
  the provider can seek.
- **Cancellation** is context-driven: client disconnect cancels the copy and
  closes the remote handle; partial uploads are removed unless resumable.
- **Backpressure** is inherent in `io.Copy` — the slower side dictates pace, so
  a slow client cannot make the server buffer unboundedly.
- Progress is reported to the UI from a counted reader/writer wrapper, not by
  polling the filesystem.

### 17.3 Path safety

All paths are validated by one dedicated function before any operation:

1. Reject NUL bytes and control characters.
2. Reject absolute paths where a relative path is expected.
3. Normalise (resolve `.`, collapse `..`) **lexically first**, then verify the
   result is within the allowed root.
4. Resolve symlinks on the remote side and re-verify containment, so a symlink
   cannot be used to escape the root.
5. Reject Windows-style separators and mixed separators where the target is
   POSIX.
6. Enforce a maximum path length.
7. `LocalExecutionProvider` additionally checks against
   `NEXT_PANEL_LOCAL_FILE_ROOTS`.

**Never** build a shell command from a path. Providers receive a path argument
and use direct APIs (`sftp`, `os`); where a command is unavoidable the path is
passed as a distinct argv element.

### 17.4 Archive security — dedicated module

`internal/archive` is separately implemented and separately tested, because
this is a classic remote-code-execution vector.

**Extraction defences:**

| Threat | Control |
|---|---|
| Absolute paths (`/etc/passwd`) | Rejected |
| `..` traversal (Zip Slip) | Each entry path normalised and verified inside the destination |
| Symlink / hardlink escape | Symlinks are **not** created by default; if enabled, the link target is resolved and verified inside the destination. Hardlinks to outside targets are rejected |
| Device nodes / FIFOs / sockets | Rejected (not extractable) |
| Excessive file count | Cap (default 100 000 entries) |
| Excessive total size | Cap (default 4 GiB) |
| Excessive single file size | Cap (default 1 GiB) |
| Compression bomb | Ratio cap (default 100:1 aggregate) |
| Unsafe permissions | Setuid/setgid/sticky bits stripped; mode masked to `0755`/`0644` |
| Nested archives | Not auto-extracted |

**Formats:** `zip`, `tar`, `tar.gz`, `tar.bz2`, `tar.xz`. Format is determined
by content sniffing plus extension, and the two must agree.

**Creation** uses the same module, walking a bounded file list and refusing to
follow symlinks out of the source root.

**Resource limits** (CPU, memory, disk) are enforced through the size and entry
caps above, applied *during* extraction rather than after — a bomb must be
stopped mid-stream, not measured once it has filled the disk.

### 17.5 Preview

Safe previews for text, JSON, YAML, XML, Markdown, source, logs, and images.

- Content is fetched with a size cap (default 1 MiB) and streamed.
- **Rendered as text, never as HTML.** Markdown is sanitised with an
  allow-list; raw HTML in Markdown is escaped, not rendered.
- Images are served with an explicit `Content-Type` and
  `Content-Disposition: inline`, plus `X-Content-Type-Options: nosniff`.
- No preview is ever executed.

### 17.6 Filenames are hostile

Rendered as text, never interpreted. Handled correctly: RTL/Unicode
bidirectional text, emoji, control characters, zero-width characters, very long
names. The UI escapes them for display and shows a visual indicator for
bidirectional overrides. Sorting and search operate on the raw bytes, not the
rendered form.

### 17.7 File conflicts

Uploading onto an existing path never silently overwrites. The client is asked
to overwrite, rename, or cancel; the decision is passed explicitly to the
server, which is the party that enforces it (a client-side-only check is not a
control).

### 17.8 Race conditions

A file can vanish between listing and acting. Every operation handles
"not found mid-operation" gracefully: the UI refreshes and reports the change
rather than showing a generic failure.

---

## 18. Metrics

### 18.1 Sources — `/proc` first

| Metric | Source | Why |
|---|---|---|
| CPU | `/proc/stat` | Counters; deltas give usage. Locale-independent |
| Memory | `/proc/meminfo` | Includes `Cached`, `Buffers`, `SReclaimable` |
| Swap | `/proc/meminfo` | `SwapTotal`, `SwapFree` |
| Load | `/proc/loadavg` | 1/5/15-min plus runnable count |
| Network | `/proc/net/dev` | Per-interface rx/tx counters |
| Disk I/O | `/proc/diskstats` | Per-device counters |
| Uptime | `/proc/uptime` | Also used for clock sanity checks |
| Boot time | `/proc/stat` (`btime`) | Absolute boot time |
| Filesystems | `df -Pk` | See below |

**Why not `top`, `free`, `ifconfig`:** all three produce human-oriented,
locale-dependent, version-dependent output. Parsing them is fragile across
distributions. `/proc` files are stable kernel interfaces.

**Why `df -Pk` for filesystems:** `statfs(2)` is per-path, so enumerating
filesystems would require reading `/proc/self/mountinfo` (parsing mount escape
sequences such as `\040`) and calling `statfs` per mount — more code and more
parsing than `df -Pk`, whose `-P` (POSIX) output is columnar and locale-stable
by definition. `-k` pins the block size to 1024 so the arithmetic is
unambiguous. **Both approaches are viable; `df -Pk` was selected for
simplicity and its POSIX guarantee.** `statfs` remains the documented fallback
if `df` is absent.

### 18.2 Collectors

Independently testable, each parsing one input into a typed result:

```go
type Collector[T any] interface {
    Name() string
    Parse(raw []byte) (T, error)   // pure function — no I/O, trivially testable
}
```

`CPUCollector`, `MemoryCollector`, `LoadCollector`, `NetworkCollector`,
`DiskCollector`, `FilesystemCollector`, `SystemCollector`.

Pure `Parse` functions mean fixture-based unit tests with no SSH and no
container: real `/proc` samples from multiple distributions are checked in as
test data (§30.2).

### 18.3 Collection strategy — one shared collector per server

```
                Server
                   │
          MetricsCollector (one per server, panel-wide)
                   │
        ┌──────────┼──────────┐
        ▼          ▼          ▼
     Client A   Client B   Client C
```

**One collection per interval per server**, fanned out to every subscribed
client. 20 servers and 100 viewers is **20 collectors, not 2000**.

Each tick executes a **single batched command** reading all `/proc` inputs plus
one `df -Pk`:

```
cat /proc/stat /proc/meminfo /proc/loadavg /proc/net/dev \
    /proc/diskstats /proc/uptime; echo '---DF---'; df -Pk
```

One SSH round trip per tick, not one per metric. Default interval 5 s
(configurable; **floor 1 s**, because over SSH a sub-second interval would
saturate the connection for no benefit).

CPU percentage is computed from counter deltas between consecutive samples —
the first sample after connect reports `unavailable` for CPU rather than a
fabricated value, because a delta needs two points.

### 18.4 Value states — no fabricated zeros

```go
type MetricValue[T any] struct {
    Value  T
    State  MetricState
    At     time.Time
}

type MetricState string
const (
    StateOK          MetricState = "ok"           // freshly collected
    StateStale       MetricState = "stale"        // last value is older than 3× interval
    StateUnavailable MetricState = "unavailable"  // supported but not collected
    StateUnsupported MetricState = "unsupported"  // not applicable to this host
    StateOffline     MetricState = "offline"      // server unreachable
)
```

Rules:

- A missing field yields `unavailable`. **Never `0`.**
- A `0%` CPU reading and "we could not read CPU" are different values and
  render differently.
- The UI shows "Unavailable", "Stale", or "Offline" explicitly.
- Charts render a **gap** for any non-`ok` period. History is never redrawn as
  a continuous line across an outage.

### 18.5 Defensive parsing

Remote output is untrusted input.

| Hazard | Handling |
|---|---|
| Missing field | `unavailable` for that metric; others still parse |
| Non-numeric value | Reject the value; log at debug without the raw contents |
| Different field counts | Parse by key where keys exist; by position with bounds checks where they do not |
| Locale decimal separators | Avoided by using `/proc` (always `.`); `df -Pk` numbers are integers |
| Very large counters | `uint64`; overflow detection on delta |
| Counter reset (reboot, interface flap) | If current < previous, treat as a reset: emit `unavailable` for that interval and re-baseline — **never a negative rate** |
| Filesystem disappears mid-run | Drop that mount from the result; no error for the whole collection |
| Permission denied | `unavailable` for that metric, `unsupported` where structurally impossible |
| Command failure | Whole tick is `offline`/`stale`; previous history is preserved |
| Command hangs | Context timeout (default: 2× interval); killed, tick marked failed |

A malformed response never panics a collector and never zeroes prior history.

### 18.6 Clock and timestamp authority

- **The panel stamps metric timestamps.** Remote clocks may be wrong; a managed
  VPS is exactly the kind of machine likely to have a skewed clock.
- Remote uptime is compared against expected elapsed panel time as a
  diagnostic; large divergence is surfaced as a warning, not used to alter
  stored timestamps.
- Stored in UTC; rendered in the user's selected timezone (§25.6).

### 18.7 Units

| Metric | Unit | Note |
|---|---|---|
| CPU, memory %, disk % | % | one decimal place |
| Memory, swap | MiB / GiB | binary, labelled as such |
| Disk capacity | GiB / TiB | binary |
| Network rate | KiB/s → MiB/s → GiB/s | binary, clearly labelled; also offer Mbit/s |
| Network totals | KiB → GiB | cumulative |
| Uptime | `Nd Nh Nm` | |
| Load | plain | 1/5/15-min |

Decimal (kB, MB) and binary (KiB, MiB) units are **never mixed silently**;
labels always state which is in use.

### 18.8 Retention

```
raw samples ──(aggregate every 5 min)──► 5-minute aggregates
                                               │
                                    (aggregate hourly)
                                               ▼
                                       1-hour aggregates

raw          : default  24 h  (configurable)
5-minute     : default  30 d
1-hour       : default 365 d
```

Implemented as **controlled background jobs**, never unbounded goroutines:

| Job | Default cadence | Action |
|---|---|---|
| `metrics.aggregate.5m` | every 5 min | Roll raw → 5-minute buckets |
| `metrics.aggregate.1h` | hourly | Roll 5-minute → 1-hour buckets |
| `metrics.prune.raw` | hourly | Delete raw older than the raw window |
| `metrics.prune.5m` | daily | Delete 5-minute older than its window |
| `metrics.prune.1h` | daily | Delete 1-hour older than its window |

Aggregates store count, min, max, avg, and last per bucket, so charts can show
a true envelope rather than only an average. Aggregation is **idempotent**
(`ON CONFLICT … DO UPDATE`, verified in POC 1), so a retried job cannot
double-count.

### 18.9 History queries

Ranges: 5 m, 15 m, 1 h, 6 h, 12 h, 24 h, 7 d, 30 d. The service selects the
finest resolution that satisfies the range within a point budget (default
~1500 points per series), so a 30-day request reads 1-hour aggregates rather
than millions of raw rows.

---

## 19. Processes

Parsed from `/proc/[pid]/{stat,status,cmdline}` — not from `ps`, avoiding
locale and version differences.

| Column | Source |
|---|---|
| PID | directory name |
| Name | `stat` comm |
| CPU % | delta of utime+stime between samples ÷ elapsed |
| Memory (RSS) | `statm` resident pages × page size |
| User | `status` Uid → resolved name |
| State | `stat` state char |
| Start time | `stat` starttime + `btime` |
| Command | `cmdline` (NUL-separated; joined for display, truncated) |

Handled: permission denied (fields become `unavailable`, the row still lists),
process exits mid-scan (skipped), PID reuse (start time is part of identity),
very long command lines (truncated with an indicator).

CPU percentage requires two samples, so the first view marks CPU as
`unavailable` rather than showing a misleading instant.

**Signalling** (`processes.signal`, privileged):

1. Permission required; the target server must be authorized.
2. Confirmation shows PID, name, user, CPU, memory, and full command, and warns
   that killing system processes can take down services.
3. **`SIGTERM` is the default and only one-click option.**
4. `SIGKILL` is a separate, explicitly advanced action with its own warning.
5. Audited as `PROCESS_TERMINATED` with signal, PID, name, and actor.
6. Refuses to signal PID 1, the panel's own PID, and its own process group.

---

## 20. systemd (**privileged**)

Structured operations only. **The browser can never send an arbitrary
`systemctl` command.**

```go
type ServiceManager interface {
    List(ctx, filter) ([]Service, error)
    Status(ctx, unit string) (*ServiceStatus, error)
    Start(ctx, unit string) error
    Stop(ctx, unit string) error
    Restart(ctx, unit string) error
    Enable(ctx, unit string) error
    Disable(ctx, unit string) error
    Logs(ctx, unit string, opts LogOptions) (io.ReadCloser, error)
}
```

- Unit names are validated against a strict pattern (`^[a-zA-Z0-9@._-]+\.(service|socket|timer|target|mount|path)$`)
  and passed as a distinct argv element. **No shell.**
- Prefers `systemctl` with `--no-pager --plain` and `LC_ALL=C` for stable
  parsing; D-Bus is the documented upgrade path for a future version.
- Data is parsed from `systemctl show <unit>` (`Key=Value`), which is far more
  stable than the human-readable output.
- Requires `services.read` to list/inspect and `services.control` to change
  state. Start/stop/restart/enable/disable require confirmation and are
  audited. **Stopping a critical unit triggers an additional warning.**
- Disabled by default (§13.4).

---

## 21. Containers (**privileged**)

Docker/Podman accessed through the **Engine API over the Unix socket from the
backend only**. The socket is never exposed to the browser, and no raw Docker
API proxying exists.

```go
type ContainerManager interface {
    List(ctx) ([]Container, error)
    Inspect(ctx, id string) (*ContainerDetail, error)
    Start(ctx, id string) error
    Stop(ctx, id string, timeout time.Duration) error
    Restart(ctx, id string, timeout time.Duration) error
    Remove(ctx, id string, force bool) error
    Logs(ctx, id string, opts LogOptions) (io.ReadCloser, error)
}
```

- **Host-equivalence is documented explicitly:** membership of the `docker`
  group, or access to the Docker socket, is effectively root on the host. This
  goes in the threat model, SECURITY.md, and the feature's own UI copy.
- Permissions: `containers.read` / `containers.control` / `containers.exec`.
  **`containers.exec` is separate and off by default** — exec into a container
  is a shell and belongs in the same risk class as the terminal.
- Container IDs are validated against the Docker ID pattern before use.
- Remove with force requires confirmation and is audited; `Stop` sends the
  normal SIGTERM-then-SIGKILL path with a timeout rather than an abrupt kill.
- Disabled by default (§13.4).
- Runtime detection: if `/var/run/docker.sock` is absent, Docker features
  report `unsupported` rather than erroring.

---

## 22. Jobs

### 22.1 Interface

```go
type JobQueue interface {
    Enqueue(ctx context.Context, j NewJob) (JobID, error)
    Claim(ctx context.Context, workerID string) (*Job, error)
    Complete(ctx context.Context, id JobID) error
    Fail(ctx context.Context, id JobID, err error, retry bool) error
    Progress(ctx context.Context, id JobID, p float64) error
    Cancel(ctx context.Context, id JobID) error
    ReapStale(ctx context.Context, olderThan time.Duration) (int, error)
    List(ctx context.Context, f JobFilter, p Page) ([]*Job, error)
}
```

Kept abstract so a different implementation can replace the DB-backed one
without touching callers.

### 22.2 States

```
queued ──claim──► running ──success──► succeeded
                    │
                    ├──failure (attempts < max)──► retrying ──► running
                    │
                    ├──failure (attempts = max)──► dead
                    │
                    └──cancel / timeout──────────► cancelled
stale (running, heartbeat expired, worker gone) ──► requeued or dead
```

| State | Meaning |
|---|---|
| `queued` | Waiting; `run_at` may be in the future |
| `running` | Claimed by a worker; heartbeat expected |
| `succeeded` | Terminal, success |
| `failed` | Transient failure; may be retried |
| `retrying` | Awaiting its backoff window |
| `dead` | Terminal failure; attempts exhausted |
| `cancelled` | Terminal; user or shutdown cancelled it |

### 22.3 Claiming

**PostgreSQL** — atomic claim, verified in POC 1:

```sql
UPDATE jobs SET status='running', locked_by=$1, locked_at=now(), attempts=attempts+1
WHERE id = (SELECT id FROM jobs
            WHERE status='queued' AND run_at <= now()
            ORDER BY priority DESC, id
            FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING *;
```

**Measured: 20 jobs claimed by 8 concurrent workers, 0 double-claims.**

**SQLite** — no `SKIP LOCKED` (**verified unsupported**). The job claim runs
inside a `BEGIN IMMEDIATE` transaction with a single-writer pool, which is
correct but serialised. **Documented as a concurrency limitation, not parity.**
Measured: 20 jobs claimed with 0 double-claims under a single writer.

**Critical-path note (finding F2a):** in the POC, the `UPDATE … RETURNING`
**committed** and then the row scan failed on a JSON column, so the function
returned an error while the job was already marked running. Required
behaviour: **a returned error must mean the job was not claimed.** This is
asserted by a dedicated test (§30.3), and the scan cannot fail once the stored
schema uses `[]byte` overrides.

### 22.4 Semantics

| Property | Behaviour |
|---|---|
| Retry | Transient failures only |
| Backoff | Exponential: 5 s, 10 s, 30 s, 2 m, 10 m; jittered ±20% |
| Max attempts | Default 3, per-kind override |
| Timeout | Per-kind; a job exceeding it is failed and its context cancelled |
| Cancellation | Cooperatively via context; the queue records the request |
| Idempotency | **Required of every handler.** A retry after a partial failure must not double-apply |
| Concurrency limits | Global worker count plus per-kind limits |
| Progress | `0..1`, or `-1` when genuinely indeterminate |
| Crash recovery | Workers heartbeat; `ReapStale` requeues or dead-letters jobs whose worker vanished |
| Stale detection | Heartbeat older than 3× the interval ⇒ requeue (bounded by attempts) |
| Shutdown | Stop claiming, cancel or drain in-flight per the job's `Cancellable` flag, mark outcomes |

**Never retried:** invalid credentials, permission denied, host-key mismatch,
and destructive operations. Retrying these is either useless or dangerous.

**Idempotency in practice:** aggregation jobs upsert on the bucket key
(verified `ON CONFLICT` idempotency in POC 1), notification jobs carry a
dedupe key, and file jobs write to a temporary path and rename into place.

### 22.5 Scheduled jobs

| Job | Default cadence | Purpose |
|---|---|---|
| `metrics.aggregate.5m` | 5 min | Rollup |
| `metrics.aggregate.1h` | 1 h | Rollup |
| `metrics.prune.*` | 1 h / daily | Retention |
| `sessions.cleanup` | 15 min | Delete expired sessions |
| `jobs.reap_stale` | 1 min | Recover orphaned jobs |
| `audit.prune` | daily | Apply audit retention (**see §27.7**) |
| `logs.prune` | daily | Application log retention |
| `login_history.prune` | daily | Login history retention |
| `servers.health_check` | 1 min | Status, latency, reachability |
| `backups.scheduled` | configured | Database backups |

Scheduling uses `run_at` and a dedupe key, so a restart cannot enqueue
duplicates.

---

## 23. Backups

### 23.1 What is and is not backed up

**Critical distinction, stated plainly in user-facing documentation:**

| Domain | Backed up by Next.Panel? | Note |
|---|---|---|
| Panel database | **Yes** | Users, servers, credentials (encrypted), audit, metrics, settings |
| Panel configuration / secrets | **Guidance only** | `.env` contains the encryption key; back it up **separately** |
| Managed VPS data | **No** | Next.Panel does not back up remote servers' files |
| Managed VPS config | **No** | |

**Claiming otherwise would be a lie.** The UI and docs say this explicitly.

### 23.2 Database backup

- **PostgreSQL:** `pg_dump` in custom format, streamed to the destination,
  verified by reading the archive's table of contents.
- **SQLite:** `VACUUM INTO '<path>'` — consistent while the database is in use.
- Destination: a configured local path (default) or S3-compatible storage
  (interface defined; S3 is Roadmap).
- Schedule: configured cadence via a job; retention applies to backup files.
- Every backup records size, duration, checksum, and outcome; failures raise a
  notification (requirements spec §40) rather than failing silently.

### 23.3 Restore

`nextpanel backup restore <file>` — an explicit CLI operation, not a UI button,
because a wrong restore is destructive.

**A backup is not considered valid until a restore has been tested.** The
project's own test suite performs this (§30.6): back up, restore into a clean
database, and assert row counts and content for key tables.

### 23.4 Encryption key coupling

Credentials in a backup are useless without `NEXT_PANEL_ENCRYPTION_KEY`. This
is documented prominently: **a database backup is not a complete backup unless
the key is also preserved — and the key must not be stored alongside the
backup**, or the encryption provides nothing against a compromise of the backup
destination.

---

## 24. Realtime Architecture

### 24.1 Transport selection

| Data | Transport | Why |
|---|---|---|
| Terminal I/O | WebSocket | Bidirectional, latency-sensitive, binary |
| Metrics stream | SSE | Unidirectional; `EventSource` reconnects natively |
| Live logs | SSE | Unidirectional |
| Server status | SSE | Unidirectional |
| Job progress | SSE | Unidirectional |

### 24.2 SSE hub

```
Topic: server:{id}:metrics | server:{id}:logs | jobs:{userID} | servers:status
```

- Each SSE connection is **authorized at connect**, and re-verified on
  reconnect. A cookie alone is insufficient: the hub checks the session, the
  permission for the topic's server, and that the session is still valid.
- Payloads are compact JSON events: `{type, server_id, ts, data}`.
- Client-side bounded buffering: the browser keeps at most N points and drops
  the oldest, so a long-lived tab cannot exhaust memory.
- Server-side: each subscriber has a **bounded output channel** (default 64
  messages). A subscriber that cannot keep up is disconnected with a
  `slow_consumer` event rather than blocking the collector or growing a queue
  without limit.
- Heartbeat comment lines every 15 s keep intermediaries from closing idle
  streams.
- **Shared collection** (§18.3): subscribers attach to the per-server stream;
  they never trigger their own collection.

### 24.3 Terminal WebSocket

```
Browser (xterm.js)
   │  wss://…/api/v1/ws/terminal?ticket=<one-time>
   ▼
Terminal hub  ── authorize(actor, server, session) ──► ticket validated & burned
   │
   ▼
terminal.Session ── provider.OpenPTY ──► remote PTY
```

Protocol (all messages validated; unknown types rejected):

```jsonc
// client → server
{"type":"input",  "data":"<base64>"}
{"type":"resize", "cols":120, "rows":40}
{"type":"ping"}

// server → client
{"type":"ready",  "session_id":"…", "server_id":1}
{"type":"output", "data":"<base64>"}
{"type":"exit",   "code":0}
{"type":"error",  "code":"TERMINAL_LIMIT_REACHED", "message":"…"}
{"type":"pong"}
```

Rules:

- **Ticket required.** Cookie-only upgrades are rejected, defeating
  cross-site WebSocket hijacking (§11.5).
- Base64 preserves arbitrary bytes (invalid UTF-8, control sequences) without
  corruption. Terminal output is **never** interpreted as HTML.
- Rate limiting on input; output is byte-capped per interval to bound a
  runaway process.
- Idle timeout (default 30 min of no input and no output) closes the session.
- Limits: default 5 concurrent terminals per user, 10 per server, 200 globally
  — all configurable.
- Every open/close is audited. **Terminal input is not recorded** (§27.5).

### 24.4 Lifecycle

| Event | Behaviour |
|---|---|
| Connect | Validate ticket → authorize → per-user/server limit check → open PTY → audit |
| Disconnect (browser) | Detach; per policy the PTY is closed (default) after a short grace period |
| Reconnect | A new ticket is required; the old session is not silently resumed |
| Idle timeout | Close PTY, audit `TERMINAL_CLOSED` with reason `idle` |
| Session revoked | All of that session's terminals close immediately (§24.5) |
| Logout | All terminals for the session close |
| Server deleted | Its terminals close; audit |
| Shutdown | All terminals close; PTYs are killed |
| Backpressure | Bounded write buffer; if the remote produces faster than the client consumes, the buffer is capped and the session is closed with an explicit error rather than growing without limit |

### 24.5 Revocation propagation

When a session is revoked (logout, password change, admin action) the server
publishes a revocation event; the SSE hub and terminal hub close every stream
belonging to that session **immediately**. In-flight HTTP requests holding that
session are rejected on their next authorization check. This is tested (§30.4)
because "the session is gone but the terminal still works" is exactly the kind
of gap that looks fine in a demo.

---

## 25. API Architecture

### 25.1 Layering

```
HTTP handler → request validation → application service → repository/provider
             → response mapping
```

Handlers decode and validate *shape*; services enforce *invariants and
authorization*. Handlers contain no business logic and never touch a
repository directly.

### 25.2 Conventions

- Base path `/api/v1/`.
- JSON in and out; `snake_case` field names.
- IDs are opaque strings in URLs, integers internally.
- Pagination: `?page=1&per_page=50` (`per_page` capped at 200), responses
  include `{ "items": [...], "page": 1, "per_page": 50, "total": 1234 }`.
- Sorting: `?sort=name&order=asc` with a **server-side allow-list** of sortable
  fields. Unlisted fields are rejected, not silently ignored.
- Filtering: explicit typed query parameters per endpoint; no generic filter
  DSL.
- `X-Request-ID` accepted from a trusted proxy or generated; echoed in the
  response and recorded in logs and audit events.

### 25.3 Endpoint groups

```
POST   /api/v1/auth/login | logout | password | reauth
GET    /api/v1/auth/me | sessions
DELETE /api/v1/auth/sessions/{id}

GET    /api/v1/users            POST   /api/v1/users
GET    /api/v1/users/{id}       PATCH  /api/v1/users/{id}
DELETE /api/v1/users/{id}       POST   /api/v1/users/{id}/password
POST   /api/v1/users/{id}/sessions/revoke

GET    /api/v1/servers          POST   /api/v1/servers
GET    /api/v1/servers/{id}     PATCH  /api/v1/servers/{id}
DELETE /api/v1/servers/{id}
POST   /api/v1/servers/{id}/test            # connection test, categorized errors
POST   /api/v1/servers/{id}/hostkey/trust   # explicit TOFU accept
POST   /api/v1/servers/{id}/hostkey/replace # reviewed key replacement

GET    /api/v1/servers/{id}/metrics/live
GET    /api/v1/servers/{id}/metrics/history?from&to&resolution
GET    /api/v1/servers/{id}/system
GET    /api/v1/servers/{id}/processes
POST   /api/v1/servers/{id}/processes/{pid}/signal

GET    /api/v1/servers/{id}/files?path=
POST   /api/v1/servers/{id}/files/upload
GET    /api/v1/servers/{id}/files/download?path=
POST   /api/v1/servers/{id}/files/rename | delete | mkdir | touch
POST   /api/v1/servers/{id}/files/extract | compress
GET    /api/v1/servers/{id}/files/preview?path=

POST   /api/v1/servers/{id}/terminal/tickets
GET    /api/v1/ws/terminal?ticket=      # upgrade
GET    /api/v1/events                   # SSE

GET    /api/v1/servers/{id}/services
POST   /api/v1/servers/{id}/services/{unit}/start | stop | restart | enable | disable
GET    /api/v1/servers/{id}/services/{unit}/logs

GET    /api/v1/servers/{id}/containers
POST   /api/v1/servers/{id}/containers/{cid}/start | stop | restart | remove
GET    /api/v1/servers/{id}/containers/{cid}/logs

GET    /api/v1/jobs             DELETE /api/v1/jobs/{id}
GET    /api/v1/audit            GET    /api/v1/audit/export
GET    /api/v1/login-history
GET    /api/v1/tokens           POST   /api/v1/tokens      DELETE /api/v1/tokens/{id}
GET    /api/v1/settings         PATCH  /api/v1/settings
GET    /api/v1/backups          POST   /api/v1/backups

GET    /health  /ready  /version        # unauthenticated, minimal
```

### 25.4 Error format

Every error, without exception:

```json
{
  "error": {
    "code": "SERVER_CONNECTION_TIMEOUT",
    "message": "Unable to connect to 203.0.113.10 on port 22. The connection timed out after 10 seconds.",
    "request_id": "01J8Z4K2M9Q7X3",
    "details": { "category": "TIMEOUT", "server_id": "3" }
  }
}
```

- `code` is stable and machine-readable.
- `message` is human-readable, safe, and **specific** — it names the actual
  host and timeout rather than saying "something went wrong".
- `request_id` allows correlation with logs and audit.
- `details` is optional and never contains secrets or internals.
- **No stack traces, no SQL, no filesystem paths, no credentials — ever, in any
  environment.** In development a stack trace is logged server-side and
  correlated by `request_id`.

### 25.5 Validation

All external input is validated on the server. The frontend validates for
usability only.

| Input | Rule |
|---|---|
| username | 3–32 chars, `[a-zA-Z0-9._-]`, unique, case-insensitive compare |
| password | policy in §11.1 |
| server name | 1–64 chars, unique |
| host | hostname (RFC 1123) or IP (v4/v6); validated, never resolved for SSRF purposes |
| port | 1–65535 |
| path | §17.3 |
| filename | length cap, NUL/control rejected |
| pagination | `page ≥ 1`, `1 ≤ per_page ≤ 200` |
| sort | allow-listed per endpoint |
| id | must exist and be **authorized** — authorization is the check that matters |
| archive entry | §17.4 |
| unit name | §20 |
| container id | Docker ID pattern |

Validation failures return `400` with `validation_error` and the offending
field. **They are never silently coerced.**

### 25.6 Time and locale

Timestamps are ISO-8601 UTC in all API payloads. The UI converts to the user's
selected timezone and displays the timezone where ambiguity is possible.
User-facing strings come from the i18n layer (requirements spec §43); the API never returns
translated text.

---

## 26. Error Handling

### 26.1 Principles

- Errors are values with a stable code, a safe message, and a category.
- Internal detail is logged; the client receives the safe projection.
- **No panics in request paths.** A recover middleware converts a panic into a
  500 with a `request_id`, logs the stack server-side, and audits a
  `SECURITY_EVENT` if it occurred in a security-relevant path.
- A failure in one server never fails an unrelated request. There is no global
  request that blocks on an unhealthy server; every outbound call has a
  timeout.

### 26.2 Layered rules

| Layer | Rule |
|---|---|
| Provider | Maps transport errors to the taxonomy; includes no credentials |
| Service | Adds context, decides retryability, emits audit on security-relevant failures |
| Handler | Maps to HTTP status + error code; never passes a raw error through |
| Middleware | Catches panics; adds `request_id`; records access logs |

### 26.3 Error taxonomy

| Category | HTTP | Example code |
|---|---|---|
| Validation | 400 | `validation_error` |
| Unauthenticated | 401 | `unauthenticated` |
| Forbidden | 403 | `permission_denied` |
| Not found / not authorized to see | 404 | `not_found` |
| Conflict | 409 | `server_name_taken` |
| Rate limited | 429 | `rate_limited` |
| Upstream failure | 502 | `SERVER_CONNECTION_FAILED` |
| Timeout | 504 | `SERVER_CONNECTION_TIMEOUT` |
| Internal | 500 | `internal_error` |

Connection-test errors always include the category from §8.5 so the wizard can
show a precise failure reason (requirements spec §126) without exposing internals.

### 26.4 Degraded operation

- **Database unavailable:** `/ready` returns `503` with a clear body; in-flight
  requests fail cleanly with `503`; the process stays up and retries, rather
  than crash-looping.
- **One server offline:** that server's cards show `OFFLINE` with the last
  successful connection and last error; other servers are unaffected.
- **Encryption key invalid:** startup fails fast (§30) rather than running in a
  state where credentials cannot be decrypted.

### 26.5 Offline servers

Per spec 59: the dashboard must not break because one VPS is unreachable.
Status, last success, last error, and a retry action are shown; collection is
skipped with backoff; historical data is retained; no request waits
indefinitely.

### 26.6 Timeouts

| Operation | Default | Configurable |
|---|---|---|
| SSH connect | 10 s | yes |
| SSH auth | 15 s | yes |
| Command | 30 s | per call |
| File transfer | 30 min idle | yes |
| Metrics tick | 2× interval | yes |
| WebSocket idle | 30 min | yes |
| SSE heartbeat | 15 s | no |
| HTTP request (server-side) | 60 s | yes |
| Database query | 15 s | yes |

**No network operation is unbounded.** Every one has a context deadline.

---

## 27. Audit Logging

### 27.1 Properties

- **Append-only.** No update path exists in the repository layer; no UI has an
  edit or delete control for audit records. The only deletion is retention
  pruning, which is itself audited (§27.7).
- **Structured.** Every event has the same shape.
- **Transactional where required** (§27.6).
- **Sanitised.** Metadata passes through a constructor that rejects
  secret-shaped values.

### 27.2 Event shape

```json
{
  "id": 91234,
  "ts": "2026-09-29T17:04:22.184Z",
  "actor_id": 1,
  "actor_name": "admin",
  "action": "FILE_DELETED",
  "target": "/var/log/old.log",
  "server_id": 3,
  "server_name": "web-1",
  "result": "success",
  "request_id": "01J8Z4K2M9Q7X3",
  "ip": "203.0.113.10",
  "user_agent": "Mozilla/5.0 …",
  "metadata": { "size_bytes": 1024, "recursive": false }
}
```

`actor_name` and `server_name` are denormalised so history remains readable
after a user or server is deleted.

### 27.3 Action vocabulary

```
AUTH:      LOGIN_SUCCESS LOGIN_FAILED LOGOUT PASSWORD_CHANGED PASSWORD_RESET
           REAUTH_SUCCESS REAUTH_FAILED SESSION_REVOKED API_TOKEN_CREATED
           API_TOKEN_REVOKED API_TOKEN_USED

USER:      USER_CREATED USER_UPDATED USER_DISABLED USER_ENABLED USER_DELETED
           ROLE_CHANGED PERMISSION_CHANGED

SERVER:    SERVER_CREATED SERVER_UPDATED SERVER_DELETED
           SERVER_CONNECTION_SUCCESS SERVER_CONNECTION_FAILED
           SERVER_HOSTKEY_TRUSTED SERVER_HOSTKEY_CHANGED SERVER_HOSTKEY_REJECTED
           SERVER_CREDENTIAL_ROTATED

TERMINAL:  TERMINAL_OPENED TERMINAL_CLOSED

FILES:     FILE_UPLOADED FILE_DOWNLOADED FILE_DELETED FILE_RENAMED
           FILE_MOVED DIRECTORY_CREATED ARCHIVE_EXTRACTED ARCHIVE_CREATED
           PERMISSION_CHANGED

PROCESS:   PROCESS_TERMINATED
SERVICE:   SERVICE_STARTED SERVICE_STOPPED SERVICE_RESTARTED
           SERVICE_ENABLED SERVICE_DISABLED
CONTAINER: CONTAINER_STARTED CONTAINER_STOPPED CONTAINER_RESTARTED
           CONTAINER_REMOVED CONTAINER_EXEC

SYSTEM:    SETTINGS_CHANGED BACKUP_CREATED BACKUP_RESTORED
           METRICS_RETENTION_APPLIED AUDIT_PRUNED
SECURITY:  SECURITY_EVENT ACCESS_DENIED
```

### 27.4 Query and export

Filterable by actor, action, server, result, IP, resource, and date range.
Server-side filtering with pagination (§25.2). Export to JSON, NDJSON, or CSV,
**respecting the active filters and requiring `audit.read`**; exports are
themselves audited. No secret material is ever present to leak.

### 27.5 What is never recorded

- Passwords, in any form, including in metadata
- Private keys, passphrases
- Session tokens, API tokens, CSRF tokens
- Decrypted credentials
- Full file contents
- **Terminal input.** Sessions record metadata only: who, which server, when
  opened, when closed, and why it ended. Command contents are not captured
  (requirements spec §393). This is documented as a deliberate privacy decision, including
  its limitation: an operator cannot reconstruct what was typed.

### 27.6 Failure semantics

**For security-sensitive actions, if the audit write fails, the action
fails.** Creating a user, changing a password, rotating a credential, deleting
a server, trusting a host key, and terminating a process all write their audit
record **in the same transaction** as the change. This is the honest reading of
"audit must not silently lose security events".

For high-volume, low-risk events (file downloads, metric retention runs), the
write is asynchronous with a bounded buffer; if the buffer overflows, the loss
is logged loudly and counted as a metric. **The two classes are explicitly
distinguished and documented**, rather than pretending every event is
transactional.

### 27.7 Retention and immutability

- Retention is configurable per category (`AUDIT_RETENTION`, default 365 days).
- Pruning is performed by a scheduled job that writes an `AUDIT_PRUNED` event
  recording how many rows were removed and over what window — **audit data is
  never deleted silently.**
- Tamper resistance is by construction: no update or delete API, append-only
  repository, and no UI affordance. This is **not** cryptographic
  immutability; an operator with direct database access can modify rows. That
  limitation is stated rather than overstated. Cryptographic chaining or an
  external sink is Roadmap.

---

## 28. Security Model

### 28.1 Controls summary

| Area | Control |
|---|---|
| Passwords | Argon2id, per-hash parameters, constant-time compare |
| Sessions | Opaque 256-bit token, SHA-256 at rest, immediate revocation |
| Cookies | `HttpOnly`, `SameSite=Lax`, `Secure` in production |
| CSRF | Double-submit token on all mutations (cookie auth) |
| Realtime auth | Origin check + one-time ticket for WS; per-connect auth for SSE |
| Credentials | AES-256-GCM, key from env, versioned ciphertext, single abstraction |
| Host keys | TOFU with explicit prompt; changed key hard-stops |
| Authorization | Server-side, object-level, permission-based, denials audited |
| Input validation | Server-side for every field; no silent coercion |
| Paths | Normalised, root-contained, symlink-resolved |
| Archives | Dedicated hardened module with size/count/ratio caps |
| Rate limiting | Independent IP and account buckets |
| Audit | Append-only, sanitised, transactional for security-sensitive actions |
| Headers | CSP, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, frame options, HSTS |
| Secrets | Env-only, never in the DB, `Secret` type prevents accidental logging |
| SQL | Parameterised exclusively; no string concatenation |
| XSS | Escaped by default; markdown sanitised; terminal output never DOM-interpreted |

### 28.2 CSRF reasoning

Cookie-based session auth is used, so CSRF is a real risk and is mitigated
with a double-submit token: a random token in a readable cookie, echoed in the
`X-CSRF-Token` header and compared server-side. `SameSite=Lax` provides
defence in depth but is **not** relied on alone, because `Lax` still permits
top-level `GET` navigations and older browsers behave inconsistently.

Token-authenticated API requests are not CSRF-susceptible, since a browser does
not attach the `Authorization` header automatically — but the realtime
channels still require origin checks, because WebSocket upgrades *do* carry
cookies (§11.5).

### 28.3 SSRF

The panel connects to operator-supplied addresses by design, so blanket private
IP blocking would break the primary use case. The control is **architecture,
not a blocklist**:

1. **No generic URL-fetch functionality exists anywhere.** There is no
   endpoint that fetches an arbitrary URL.
2. Server targets are **operator-configured records**, not per-request inputs.
   A user cannot make the panel connect somewhere the operator did not add.
3. Connections use SSH/SFTP to a configured host/port — not HTTP to a
   user-supplied URL.
4. **DNS is resolved and the resolved IP is what is connected to**, closing the
   TOCTOU gap; the hostname is re-resolved only on reconnect.
5. **Cloud metadata endpoints** (`169.254.169.254`, `fd00:ec2::254`, GCP/Azure
   equivalents) and link-local ranges are **denied by default**, with an
   explicit operator override, because a panel has no legitimate reason to SSH
   to a metadata service.
6. Unix sockets are not reachable through the SSH provider.
7. Creating a server requires `servers.create`; a low-privilege user cannot
   turn the panel into a scanner.

The distinction that matters: **user-configured server connections are not
arbitrary URL fetching**, and the design keeps them separate.

### 28.4 XSS

- Escaped output by default in the React templates.
- No `dangerouslySetInnerHTML` for untrusted data — reviewed and prohibited.
- Markdown is sanitised with an allow-list; raw HTML is escaped, not rendered.
- Terminal output is written to xterm.js, which renders to a canvas/screen
  buffer — **it is never parsed into DOM HTML**.
- File names, server names, user names, log lines, and audit metadata are all
  treated as untrusted text (§17.6).
- A strict CSP (§28.5) limits the impact of any XSS that does slip through.

### 28.5 Security headers

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=(), payment=()` |
| `X-Frame-Options` | `DENY` (with CSP `frame-ancestors`) |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` — **only when the scheme is HTTPS** |

**`'unsafe-inline'` for styles is a real concession**, required by some
component libraries and xterm.js. It is not extended to scripts. The CSP is
**tested against the running UI** before release; an untested CSP that breaks
the app is worse than none, and one that silently allows everything is worse
still. If the tested CSP requires `'unsafe-eval'` for any dependency, that
dependency is replaced rather than the CSP weakened.

### 28.6 Prohibited patterns (CI-enforced)

Grepped for and failed on in CI:

```
ssh.InsecureIgnoreHostKey
Password = "…"  / password: "…"     (hardcoded literals)
BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY
dangerouslySetInnerHTML
exec.Command("sh", "-c", …) with a non-constant argument
fmt.Sprintf("… %s …", userInput) passed to a shell
SELECT … " + userInput
```

### 28.7 No backdoors

No hardcoded master password, no hidden account, no undocumented endpoint, no
authentication bypass, no debug auth path, no magic token. The only credential
seeding is the documented bootstrap administrator (§11.2), which is
configurable off and whose default state is loudly surfaced. Recovery is via
`nextpanel admin reset-password` at a shell — **documented, audited, and
requiring filesystem access**, not a hidden convenience in the web tier.

---

## 29. Threat Model

Also planned as `docs/threat-model.md`. This section is the source for it.

### 29.1 Assets

SSH credentials · session tokens · API tokens · the encryption key · the audit
trail · server metadata · file contents in transit · terminal sessions ·
database contents · the panel host itself.

### 29.2 Trust boundaries

```
Browser (untrusted) ──► Panel backend (trusted) ──► VPS (semi-trusted)
                              │
                              ├──► Database (trusted for confidentiality of ciphertext)
                              ├──► Local host        ← host-privilege equivalent
                              └──► Docker socket     ← host-privilege equivalent
```

### 29.3 Threats and status

| Threat | Mitigation | Residual risk |
|---|---|---|
| Unauthorised panel login | Argon2id, rate limiting, lockout heuristics | Weak/leaked password |
| Brute force | Independent IP+account buckets, progressive delay | Distributed attack against one account |
| Stolen session | `HttpOnly`, `Secure`, short lifetime, idle timeout, immediate revocation | XSS or a compromised browser |
| Compromised browser | CSP, no credential exposure to the client, re-auth for sensitive ops | **Real risk; not fully solvable** |
| Session fixation | New token on login and privilege change | — |
| CSRF | Double-submit token + `SameSite=Lax` | — |
| XSS | Escaping, sanitised markdown, strict CSP, no DOM-interpreted terminal output | A dependency with an XSS hole |
| SQL injection | Parameterised queries only | — |
| Path traversal | Normalisation + root containment + symlink resolution | **Root containment is not a sandbox** if the SSH user is privileged |
| Archive traversal | Dedicated module, tested (§17.4) | — |
| SSRF | Architectural separation; metadata endpoints denied | Operator-configured target may be internal (by design) |
| MITM | Host-key pinning, fail-closed on change, modern KEX/ciphers | First connection is TOFU — **trusted on first use is a real window** |
| Malicious SSH server | Output capped and parsed defensively; no shell interpretation; no auto-execution of output | Malicious output that is valid but misleading |
| DNS manipulation | Resolve-then-connect; host key catches substitution | — |
| Host key change | Hard stop + security event + reviewed replacement | — |
| Malicious uploaded file | Never executed in the backend; not interpreted as HTML | Stored on the remote host exactly as uploaded |
| Malicious archive | Dedicated module with caps | Memory/CPU cost up to the caps |
| Resource exhaustion | Per-user/per-server limits, caps, rate limits, bounded buffers | Sustained attack up to configured limits |
| Credential leakage | `Secret` type, redaction, DTO separation, CI greps | A future coding mistake; mitigated, not eliminated |
| Insider administrator | Audit trail, append-only, transactional for sensitive ops | **An admin with database access can alter audit rows — stated, not hidden** |
| Compromised panel host | Least privilege, encryption at rest, short sessions, audit | **If the host and key are both compromised, all credentials are recoverable** |
| Compromised VPS | Out of scope for the panel's own security; noted | A managed server's compromise is the operator's incident |
| Backup exfiltration | Encryption key stored **separately** from backups | Backup + key co-located removes the benefit |
| Local exec / Docker / systemd abuse | Off by default, dedicated permissions, confirmation, audit | **Host-privilege equivalent when enabled** |

### 29.4 Explicitly not protected against

Stated so nobody assumes otherwise:

- A compromised Next.Panel host **with** access to the encryption key
- An administrator who is malicious **and** has direct database access
- A compromised browser or a user's stolen device
- Compromise of a managed server through means unrelated to the panel
- Resource exhaustion sustained within configured limits
- Malicious output that is syntactically valid and merely misleading

### 29.5 Privilege statement

Next.Panel is a **credential custodian**. Compromise of the panel is, in
practice, compromise of every server it manages. The product must not be
described as "safe" or "secure by default"; it can be described as
**hardened, with documented controls and documented residual risk**.

---

## 30. Testing Strategy

### 30.1 Levels

| Level | Scope | Runs |
|---|---|---|
| Unit | Pure logic: hashing, parsing, path validation, archive safety, RBAC, DTO mapping, adapters | Always |
| Integration | Repositories, services, HTTP handlers, WS/SSE auth — needs `TEST_DATABASE_URL` | Skips gracefully if unset |
| E2E | Full flows through a real browser (Playwright) | CI with a live stack |
| Security | The specific cases in §30.4 | Always + CI |
| Load | Throughput and concurrency characterisation | CI, nightly |

Integration tests run against **PostgreSQL** in CI, with a dedicated
**SQLite** job so dialect-specific breakage is caught in the pipeline rather
than in production.

### 30.2 Collector tests

Collectors have pure `Parse` functions, so fixtures are checked in as test
data: real `/proc/stat`, `/proc/meminfo`, `/proc/net/dev`, `/proc/diskstats`,
and `df -Pk` output captured from Ubuntu 24.04. Fields exercised: normal input,
truncated input, missing fields, non-numeric values, counter resets, a
disappeared filesystem, and permission-denied responses. **Each asserts the
value state, including that a missing metric yields `unavailable` and never
`0`.**

### 30.3 Critical-path tests

- `ClaimJob` returns an error ⇒ **the job was not claimed** (the F2a
  regression test).
- Aggregation is idempotent: running it twice produces identical buckets.
- Provider connection reuse: N operations on one server use one connection.
- Pooled connections are not shared across differing authorization.
- `Secret` values never appear in log output (verified by capturing logs).

### 30.4 Security test cases (explicit)

| Case | Assertion |
|---|---|
| SQL injection | Payloads in every string field are stored/queries safely |
| XSS | Payloads in names, filenames, notes, and audit metadata render escaped |
| CSRF | A mutation without a valid token is rejected |
| Path traversal | `../`, encoded, double-encoded, absolute, NUL, mixed-separator all rejected |
| Zip Slip | An archive with `../` entries is rejected, nothing written outside the destination |
| Archive bombs | Count/size/ratio caps trigger and abort mid-extraction |
| SSRF | Metadata endpoints denied by default |
| Auth bypass | Unauthenticated requests to every endpoint return 401 |
| Authz bypass | A low-privilege user cannot perform privileged operations |
| WebSocket authz | A WS upgrade without a valid ticket is rejected |
| WS cross-origin | A mismatched `Origin` is rejected |
| IDOR | Changing an object ID in a URL cannot reach another user's object |
| Session fixation | Token changes on login |
| Session reuse after logout | A logged-out token is rejected on the next request |
| Revocation propagation | A revoked session's WS and SSE streams close |
| Brute force | Threshold triggers rate limiting and progressive delay |
| Host key mismatch | Connection hard-stops; no auto-accept path exists |
| Credential leakage | Credentials absent from logs, audit, API responses, and errors |
| Log leakage | Secrets absent from all log levels including DEBUG |
| Privileged gates | Local exec / Docker / systemd refuse when disabled, regardless of permission |

### 30.5 Test environment

- **Ubuntu 24.04.5 in WSL2** — verified present, with real PostgreSQL 16.15
  and a real filesystem for archive and file tests.
- An in-process SSH server (**validated in POC 2**) provides deterministic SSH
  behaviour: host-key states, auth failure, PTY, disconnects, malformed output.
- A real remote host test is **required before claiming distribution support**
  (§37 risk 5).

### 30.6 Backup/restore test

Backup → restore into a clean database → assert row counts and content for
`users`, `servers`, `audit_logs`. **A backup that has never been restored is
not considered tested.**

### 30.7 Cross-distribution testing

To be performed on Ubuntu, Debian, and one RHEL-family distribution. Until it
is, **the project claims only Ubuntu 24.04 as verified**, and says so.

### 30.8 CI gates (all must pass)

Format check · `go vet` / `staticcheck` · `golangci-lint` · unit tests ·
integration tests (PostgreSQL) · integration tests (SQLite) · `sqlc generate`
leaves a clean tree · import-boundary test · security greps (§28.6) ·
frontend lint + typecheck + build · Playwright E2E · dependency vulnerability
scan · Docker build **and** smoke test.

**Failures are fixed, never muted.** Disabling or skipping a test to get a
green pipeline is prohibited; an invalid test is replaced with a correct one
and the replacement is committed separately.

---

## 31. Deployment Strategy

### 31.1 Artefacts

- Static binary with the frontend embedded (`embed.FS`), for `linux/amd64` and
  `linux/arm64`.
- Container image (distroless or a minimal base, non-root user).
- systemd unit for non-container installs.

### 31.2 Non-container install

Install the runtime → create a dedicated `nextpanel` user → place the binary →
configure `.env` (including the encryption key) → run migrations → start under
systemd → place behind a reverse proxy.

**The panel does not require root.** Root is only needed if an operator
deliberately enables local execution against privileged paths.

### 31.3 systemd hardening

```
[Service]
User=nextpanel
Group=nextpanel
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
ReadWritePaths=/var/lib/nextpanel
Restart=on-failure
RestartSec=5
EnvironmentFile=/etc/nextpanel/env
```

**Caveat, documented honestly:** `ProtectSystem=strict` and the other
directives constrain the panel process itself. If an operator enables local
execution or Docker access, these directives **do not protect the rest of the
host** — they only limit the panel's own footprint. That interaction must be
spelled out, because it is easy to assume hardening covers a feature it does
not.

### 31.4 Reverse proxy

Examples provided for **Nginx, Caddy, and Traefik**, each covering:

- TLS termination and HSTS,
- WebSocket upgrade (`Upgrade`/`Connection` headers, long read timeouts),
- **SSE-specific settings** (`proxy_buffering off`, `X-Accel-Buffering: no` —
  without these, metrics arrive in bursts or not at all),
- large uploads (`client_max_body_size` or equivalent),
- generous timeouts for file transfer and terminals,
- trusted-proxy configuration so `X-Forwarded-For` is honoured **only** when
  the peer is a configured trusted proxy.

### 31.5 Trusted proxies

Real client IPs come from `X-Forwarded-For`/`Forwarded` **only** when the
immediate peer is in `NEXT_PANEL_TRUSTED_PROXIES`. Otherwise the socket address
is used. Headers from untrusted peers are ignored entirely. The rightmost
non-trusted hop is taken as the client, preventing client-supplied spoofing.

### 31.6 Docker

`Dockerfile` and `compose.yaml` with the panel plus PostgreSQL, health checks,
named volumes for data and configuration, migration on start, and documented
backup guidance.

**Honest status: Docker was not built or run in the development environment**
(no Docker on the host). Container support **must not be presented as verified
until a build and smoke test actually pass** (§37 risk 4).

### 31.7 HTTPS

Next.Panel expects TLS termination in front of it. It does not manage
certificates. `Secure` cookies and HSTS are enabled based on a configured
"external scheme" setting rather than inferred from the request, so a
misconfigured proxy cannot silently downgrade cookie flags.

---

## 32. Migration Strategy

### 32.1 Tooling and rules

goose, per dialect, embedded via `embed.FS`.

- **Every schema change has a migration.** Manual production schema edits are
  prohibited.
- **Forward-only in production.** `down` migrations exist for development, but
  production rollback is by restoring a backup, because a destructive `down`
  is more likely to lose data than to help.
- Migrations are **deterministic** and **idempotent where practical**
  (`IF NOT EXISTS`).
- Migrations run automatically at startup **inside a lock**, so two instances
  starting together cannot race. A `--migrate-only` mode exists for
  orchestrated deployments.
- **`sqlc generate` runs in CI** and the pipeline fails if the working tree is
  dirty, so generated code cannot drift from the schema.

### 32.2 Adding a column

Add nullable → backfill in a job → enforce constraints in a later migration.
No `NOT NULL` column is added to a populated table in one step.

### 32.3 Dual-dialect migrations

Migration files are maintained per dialect where syntax differs (`SERIAL` vs
`AUTOINCREMENT`, types, defaults). Where SQL is identical, it is shared. The
version numbers stay aligned across dialects.

### 32.4 Compatibility

- The database schema is a contract; columns are not casually dropped.
- **Breaking changes are documented in CHANGELOG** with explicit
  upgrade steps.
- API changes follow semantic versioning (requirements spec §141).
- Public interfaces (`ServerExecutionProvider`, `JobQueue`,
  `CredentialEncryptor`) are contracts; changing one requires a new ADR and a
  migration path.

---

## 33. Observability and Logging

### 33.1 Structured logging

`log/slog` with a JSON handler in production and a human-readable handler in
development. Levels: `DEBUG`, `INFO`, `WARN`, `ERROR`. Production default
`INFO`.

Every record carries, where applicable: `request_id`, `actor_id`, `server_id`,
`job_id`, `session_id`, `component`, `duration_ms`.

### 33.2 Categories

`AUTH SERVER SSH TERMINAL FILES METRICS USER SECURITY SYSTEM API DATABASE JOB
ERROR AUDIT` — mapped onto the `component` field so logs can be filtered by
subsystem.

### 33.3 Redaction

A redaction layer runs before the handler emits anything. Key-name matching
(`password`, `token`, `secret`, `key`, `authorization`, `cookie`) plus
`Secret`-type awareness. **Secrets are redacted at DEBUG too** — debug logging
is not a licence to leak.

### 33.4 Endpoints

| Endpoint | Auth | Content |
|---|---|---|
| `/health` | none | Liveness; `200` while the process is running |
| `/ready` | none | `200` only if the DB is reachable **and** migrations are applied **and** workers are running; `503` otherwise |
| `/version` | none | Version, commit, build date — **no configuration, no environment** |

None of these expose configuration, file paths, or dependencies.

### 33.5 Startup checks

Failure is fatal, with a clear message and **no secret in the output**:

1. Configuration parses and validates.
2. The encryption key decodes to exactly 32 bytes.
3. The database is reachable and migrations apply cleanly.
4. Existing credentials decrypt (unless `--allow-decrypt-failures`).
5. The configured port is bindable.
6. The data directory is writable.
7. If bootstrap seeding applies, it is performed and audited.

### 33.6 Correlation

`X-Request-ID` propagates through HTTP → service → job → audit, so a single
identifier ties together the API call, the log lines, the audit event, and any
job it spawned.

---

## 34. Performance Considerations

### 34.1 Design-level

- One shared collector per server, not per viewer (§18.3).
- One batched `/proc` read per tick, not one command per metric.
- Connection reuse; no handshake per request.
- Streaming everywhere; no whole-file buffering.
- Server-side pagination and filtering; no "fetch everything then filter in the
  browser".
- Bounded buffers on every stream, so a fast producer cannot exhaust memory.
- Indexes chosen from actual query patterns (§7.3.1).

### 34.2 Measured so far (not projected)

| Measurement | Result |
|---|---|
| Concurrent inserts, PostgreSQL | 20 goroutines, 0 errors **[verified]** |
| Concurrent inserts, SQLite single writer | 20 goroutines, 0 errors **[verified]** |
| Job claiming, PostgreSQL `SKIP LOCKED` | 20 jobs by 8 workers, 0 double-claims **[verified]** |
| Job claiming, SQLite single writer | 20 jobs, 0 double-claims **[verified]** |
| Upsert idempotency | 3 writes to one key → 1 row, both dialects **[verified]** |

### 34.3 Not yet measured — no claims made

API latency · dashboard load time · WebSocket throughput · terminal round-trip
latency · file transfer throughput · metrics collection overhead · memory and
CPU footprint · concurrent-user capacity.

**No performance number is published until it is measured.** Benchmarks will be
recorded in `docs/performance.md` with hardware and workload described, and
load-test results (§30.1) will report observed limits rather than a promised
figure.

### 34.4 Frontend performance

Code splitting per route · virtualised long lists (files, processes, audit) ·
memoisation where it measurably helps · a single SSE connection per topic
rather than per component · bounded client-side metric buffers · uPlot for
dense series.

---

## 35. Future Extension Points

Interfaces defined now so these can be added without redesign. **None is
implemented in v0.1**, and none should be presented as available.

| Extension | Seam | Notes |
|---|---|---|
| Agent transport | `ServerExecutionProvider` | A second implementation; no service changes |
| Alternative job queue | `JobQueue` | e.g. River if PostgreSQL-only becomes acceptable |
| Alternative SQLite driver | `database/sql` boundary | Swap without touching repositories |
| Key rotation | `CredentialEncryptor` `key_id` | Already versioned |
| Notification channels | `NotificationProvider` | Email/webhook/Discord/Telegram/Slack behind one interface |
| Additional auth providers | Auth service interface | TOTP, WebAuthn, OIDC |
| Cloud providers | `ServerExecutionProvider` | Provider APIs as another implementation |
| Plugin framework | Deferred deliberately | Stable interfaces first; a framework before the core is stable ossifies the wrong abstractions |

---

## 36. Open Questions

Genuinely undecided, each with an explicit closure method. **None blocks
starting implementation.**

| # | Question | Closure method |
|---|---|---|
| 1 | Exact `go.mod` floor version | Set after CI confirms which versions build and test cleanly |
| 2 | Final frontend dependency versions (React, Vite, xterm.js, uPlot) | Fetch, build, and pin at first frontend commit; no versions are asserted before that |
| 3 | Whether `modernc.org/sqlite` should replace `ncruces` as the default | Re-test when reachable; the driver is already swappable |
| 4 | Concrete SQLite concurrency limits to publish | Characterise with a realistic workload (§34.3) |
| 5 | CSP compliant with all dependencies without `unsafe-eval` | Test against the running UI; replace any dependency that requires it |
| 6 | Whether `systemctl` parsing or D-Bus is the v0.1 implementation | Try D-Bus first; fall back to `systemctl show` (already the stated default) |
| 7 | Whether terminal sessions survive brief network blips or are closed | Prototype both; decide by UX evidence, default to closing with a clear message |
| 8 | Metric point budget per series (currently ~1500) | Measure chart rendering with uPlot; adjust |
| 9 | Whether audit events need cryptographic chaining in v0.1 | Security review; currently documented as a known limitation |
| 10 | Which notification channels ship first | After the provider interface is exercised by at least one implementation |

---

## 37. Risks and Mitigations

| # | Risk | Impact | Mitigation | Status |
|---|---|---|---|---|
| 1 | SQLite concurrency limits are real, not theoretical | Data contention under multi-user load | Documented as single-instance/small; PostgreSQL recommended for production; single-writer claim path verified | Open (documented) |
| 2 | `ncruces/go-sqlite3` chosen partly due to an environment block | Dependency risk | Driver isolated behind `database/sql`; swap is a small change | Open |
| 3 | Frontend stack entirely unverified | Could invalidate a UI assumption | Verify and pin before building features on it | Open |
| 4 | Docker support documented but untested | Published claims could be wrong | Build and smoke-test in WSL2/CI before any public container claim | Open |
| 5 | No real remote host tested | Distribution quirks (`/proc` differences, `df` behaviour, sudo posture) unknown | Test Ubuntu + Debian + RHEL-family; claim only what is verified | Open |
| 6 | `x/crypto/ssh` stdout/stderr race (F6) can silently produce empty output | Wrong results with no error | Independent concurrency-safe writers; regression test | **Mitigated** |
| 7 | `UPDATE … RETURNING` committing before a scan failure (F2a) | Stranded jobs, silent data loss | `[]byte` overrides; mandatory adapters; critical-path test | **Mitigated** |
| 8 | Dual-dialect SQL drift as the schema grows | Maintenance burden | Portable query subset; adapters; CI checks generation is clean; bun fallback documented | Open (monitored) |
| 9 | CSP breaks the UI or is weakened to accommodate a dependency | Security or functionality loss | Test the real UI; replace offending dependencies rather than relaxing the CSP | Open |
| 10 | Privileged subsystems (local/Docker/systemd) widen the blast radius | Host compromise | Off by default; separate permissions; confirmation; audit; documented honestly | Open (accepted) |
| 11 | Audit trail is not cryptographically immutable | An operator with DB access can alter it | Documented limitation; append-only by construction; chaining is Roadmap | Open (accepted, documented) |
| 12 | Panel compromise is server compromise | Severe | Encryption at rest, least privilege, short sessions, audit, explicit trust-model documentation | Open (inherent; documented) |
| 13 | No load testing performed yet | Published capacity would be guesswork | No capacity claim until measured | Open |
| 14 | Environment network restrictions could affect a future dependency | Build breakage | Dependencies verified at adoption; no dependency assumed available | Open |

---

## 38. Implementation Phases

Each phase ends with: run tests → lint → typecheck → manual sanity check →
update docs → update CHANGELOG → a precise conventional commit → push.
**A phase does not start while the previous phase is functionally broken.**

| Phase | Deliverable | Exit criteria |
|---|---|---|
| 0 | Repo bootstrap, `go.mod`, CI skeleton, tooling config | CI runs and fails on a deliberate lint error |
| 1 | Config, logging, startup checks, `/health` `/ready` `/version` | Process starts, refuses to start on bad config |
| 2 | Store layer: schema, migrations, sqlc dual-dialect, adapters, repositories | Repository integration tests pass on **both** dialects |
| 3 | Auth: Argon2id, sessions, login/logout, bootstrap admin + warning, re-auth | Auth integration tests + session revocation tests pass |
| 4 | RBAC: permissions, roles, object-level authorization, per-server scoping | Authorization tests incl. IDOR and denial auditing pass |
| 5 | Servers: CRUD, tags, notes, favourite, status, connection test | Server CRUD + categorized connection errors pass |
| 6 | SSH provider: connection, host-key policy, pooling, keepalive, backoff | POC-2 behaviours reproduced as tests |
| 7 | Command execution service + Exec/ExecStream + output caps | Provider conformance tests pass for SSH and local |
| 8 | Server dashboard + system info | Dashboard renders real data; offline handled |
| 9 | Terminal: WebSocket hub, tickets, PTY lifecycle, limits, audit | Terminal E2E: input, output, resize, exit, revocation |
| 10 | Files: browse/stat/rename/delete/mkdir + path safety | Path traversal tests pass on both providers |
| 11 | Transfer: streaming upload/download, progress, cancellation | Large-file test without memory growth |
| 12 | Archive: hardened extract/create | Zip Slip and bomb tests pass |
| 13 | Metrics: collectors, batched collection, shared stream, SSE | Collector fixture tests + SSE integration pass |
| 14 | Historical metrics: aggregates, retention jobs, charts | Idempotency + retention tests pass; charts gap on outage |
| 15 | Processes + signalling | Parse fixtures + signal authorization/audit tests |
| 16 | systemd (privileged, off by default) | Structured ops + permission gates + audit |
| 17 | Containers (privileged, off by default) | Lifecycle ops + gates + audit; `unsupported` when absent |
| 18 | Jobs: queue, worker pool, retries, reaping, progress | Claim-correctness + stale-recovery + idempotency tests |
| 19 | Audit: writer, query, export, retention, login history | Query/permission/export tests; transactional-write test |
| 20 | API tokens + user management + sessions UI | Scope intersection + revocation tests |
| 21 | Backups: dump, restore, scheduling, retention | Backup→restore round-trip test passes |
| 22 | Security hardening: headers, CSP, CSRF, rate limits, SSRF guards | Full security test suite (§30.4) green |
| 23 | UI refinement: design system, dark/light, responsive, a11y, empty/loading/error states | Accessibility and responsive checks pass |
| 24 | Frontend build + `embed.FS` + production mode | Single binary serves the UI with production headers |
| 25 | Docker, systemd, reverse-proxy examples | **Container build + smoke test actually executed** |
| 26 | Documentation: README, SECURITY, CONTRIBUTING, deployment, api, threat model, limitations | Fresh-clone test passes using docs alone |
| 27 | CI complete: all gates in §30.8 | Pipeline green on a clean checkout |
| 28 | Security review + `docs/security-review.md` | Findings recorded with severity and status; no hidden high-risk findings |
| 29 | Release prep: CHANGELOG, ROADMAP, versioning, fresh-clone test, final audit | Release checklist complete; no secrets in the tree |

### 38.1 Definition of Done

A feature is done only when it is **implemented, integrated, authorised,
tested, documented, error-handled, reviewed, and committed.**

It is **not** done because it compiles, because an endpoint exists, or because
the UI renders. A placeholder is not an implementation. A flag hiding unfinished
work is not completion.

### 38.2 Mandatory pre-release verification

Before v0.1.0 is tagged, each of these must actually pass, not be asserted:

- [ ] Clean clone → documented install → login works
- [ ] Bootstrap warning shows, and clears only after the password is changed
- [ ] Add a server, verify host key, connect
- [ ] A changed host key hard-stops
- [ ] Terminal: real commands, resize, exit, revocation closes it
- [ ] Files: browse, upload, download, rename, delete, extract
- [ ] Large file transfer without memory growth
- [ ] Live metrics update; historical charts render
- [ ] An outage produces a chart **gap**, not a fake continuous line
- [ ] Processes list and signal (with permission)
- [ ] Audit records every action above and is searchable
- [ ] Login history accurate
- [ ] Permissions enforced; a viewer cannot open a terminal
- [ ] Persistence: restart the app, all data survives
- [ ] Session revocation kills live streams
- [ ] Backup → restore round-trip verified
- [ ] No secrets in the repository or its history
- [ ] Tests, lint, typecheck, build all green
- [ ] Docker image builds and passes smoke test **(or is explicitly marked unverified)**
- [ ] Documentation matches actual behaviour

**Any item that cannot be verified is reported as unverified in the final
report. It is not omitted and it is not claimed.**

---

## 39. Cross-Cutting Consistency Review

Recorded because the instruction was to verify that every requirement has an
architectural home before implementation. Checked against this spec:

| Requirement | Where satisfied | ✓ |
|---|---|---|
| No service bypasses authorization | §3.2 rule, §12.3 signature | ✓ |
| No service bypasses the provider abstraction | §3.2 rule, §8.1 | ✓ |
| No browser can execute arbitrary commands | §2 (2, 3), §20, §21, §25.5 | ✓ |
| No credentials leak into logs/audit/responses/errors | §14.3, §27.5, §33.3, §28.6 | ✓ |
| No whole-file memory buffering | §17.2, §23.2 | ✓ |
| Metrics shared per server | §18.3 | ✓ |
| Jobs survive restart appropriately | §22.4 (heartbeat, reaping, idempotency) | ✓ |
| SQLite behaviour understood + documented | §7.4 (measured) | ✓ |
| PostgreSQL behaviour understood | §7.5, §22.3 (measured) | ✓ |
| SSH lifecycle defined | §8.4, §9 | ✓ |
| WebSocket lifecycle defined | §24.3, §24.4 | ✓ |
| SSE lifecycle defined | §24.2 | ✓ |
| Shutdown behaviour defined | §8.4, §22.4 | ✓ |
| Migrations defined | §32 | ✓ |
| Backups defined (and honestly scoped) | §23 | ✓ |
| Encryption versioning defined | §15.1 | ✓ |
| Audit logging defined | §27 | ✓ |
| RBAC enforced server-side | §12 | ✓ |
| Three privileged subsystems gated | §10, §13.4, §20, §21 | ✓ |
| Archive security isolated + tested | §17.4, §30.4 | ✓ |
| Unavailable ≠ zero | §18.4 | ✓ |
| Modular monolith, no over-engineering | §3, [ADR-0001 §3.7](../../decisions/ADR-0001-technology-stack.md) | ✓ |

**Known deliberate gaps, all documented rather than hidden:** cryptographic
audit immutability, SQLite concurrency parity, verified Docker support,
verified non-Ubuntu distributions, and measured performance figures. Each
appears in §36 or §37 with a closure method.

---

## 40. Document Status

| Item | State |
|---|---|
| Architecture decisions | Settled |
| Database layer | Settled, POC-verified on both dialects |
| SSH provider and host-key policy | Settled, POC-verified |
| Local provider | Settled, privileged and off by default |
| Terminal, files, metrics, audit, jobs | Settled |
| Privileged subsystems | Settled, off by default |
| Backups | Settled |
| Frontend stack | Chosen, **unverified** |
| Deployment (Docker) | Documented, **unverified** |
| Performance figures | **Not measured** — none claimed |
| Distribution support | **Ubuntu 24.04 only**, until tested |

This spec is implementation-ready. Every item that could not be settled without
execution is marked as a validation task with a stated closure method, not left
as a silent TODO.

