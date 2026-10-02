# ADR-0001: Technology Stack and Core Architecture

- **Status:** Accepted
- **Date:** 2026-09-29
- **Decision drivers:** security, maintainability by a small team, real-world
  performance, deployment simplicity, long-term stability
- **Validation evidence:** [`docs/poc/`](../poc/) and [`docs/research.md`](../research.md) §1.4

---

## 1. Context

Next.Panel is a self-hostable Linux VPS/server management panel with a web UI.
It manages many remote servers over SSH and, optionally, the host it runs on.
The feature set spans long-lived interactive terminals, large bidirectional file
transfers, real-time and historical metrics, process and service control,
container control, and a security-sensitive audit trail.

The project must be maintainable by a small team, deployable by a
non-specialist operator (single binary or container), and secure enough that
compromise of the panel is not trivially equivalent to compromise of every
managed server.

Two constraints shaped this decision and are recorded because they are
environmental rather than architectural:

1. **The development host is Windows 11 with no C compiler and no Docker.**
   Any dependency requiring CGO fails the default developer build.
2. **Outbound network access is restricted.** `proxy.golang.org` and
   `gitlab.com` returned `403` for `modernc.org/*` during evaluation, and
   neither web search nor repository fetching was available.

Both constraints are documented in `docs/research.md` §0 and §1. They are
*not* assumed to hold for other contributors or for production, and the
architecture is designed not to depend on them (see §5, SQLite driver).

### Requirements that most influenced the choice

| # | Requirement | Architectural consequence |
|---|---|---|
| R1 | Full control of SSH host-key policy; must fail closed | Needs a low-level SSH library, not a wrapper |
| R2 | Real PTY streaming with resize and cancellation | Needs genuine concurrency, not a request/response model |
| R3 | Large file transfer without whole-file buffering | Needs streaming primitives end-to-end |
| R4 | Argon2id (CPU- and memory-hard) + archive compression | CPU-bound work must not stall unrelated requests |
| R5 | Many servers, each with a shared metric collector | Cheap, isolated concurrency |
| R6 | SQLite for small installs, PostgreSQL for production | Portable SQL layer with a real abstraction boundary |
| R7 | Single-artefact self-hosted deployment | No runtime/framework zoo on the operator's host |
| R8 | Panel compromise must not silently equal server compromise | Credential encryption, least privilege, separate trust boundaries |

---

## 2. Decision

**A modular monolith in Go** — a single deployable binary — with a React +
TypeScript frontend embedded into it.

| Layer | Selected | Verified |
|---|---|---|
| Backend language | Go (developed on 1.27.1; go.mod floor to be set lower) | yes |
| HTTP | `go-chi/chi/v5` | yes |
| Database | PostgreSQL (production) and SQLite (dev/small) | yes — PG 16.15 |
| SQLite driver | `ncruces/go-sqlite3` (pure Go, no CGO) | yes |
| SQL layer | `sqlc` 1.30.0 + hand-written adapter | yes |
| Migrations | `pressly/goose/v3` | yes |
| SSH | `golang.org/x/crypto/ssh` | yes |
| PTY (local) | `creack/pty` (+ `x/term`) | yes |
| SFTP | `pkg/sftp` | yes |
| Realtime | WebSocket (`coder/websocket`) for terminal; SSE for metrics/logs/status | yes |
| Jobs | DB-backed table + in-process worker pool | yes (POC) |
| Frontend | React 19 + TypeScript + Vite | not built |
| Terminal UI | `@xterm/xterm` | not built |
| Charts | uPlot | not built |

**"Verified" means the dependency was fetched and/or exercised on this
machine, not that the feature is implemented.** Frontend rows are unbuilt and
their versions require live confirmation before pinning.

---

## 3. Considered Alternatives and Rejection Reasons

Factual reasons only; no scoring or ranking is used.

### 3.1 Backend language

**Go — selected.** `golang.org/x/crypto/ssh` exposes host-key callbacks, raw
channel requests, and PTY handling directly, which R1 and R2 require; the POC
confirmed the exact `UNKNOWN`/`TRUSTED`/`CHANGED` policy could be implemented
and that failure is closed. Goroutines make per-server collectors, per-session
PTY pumps, and per-connection keepalives ordinary code rather than special
infrastructure (R2, R5). Argon2id and archive work are CPU-bound and simply run
on another core (R4) — the POC exercised a 20-goroutine concurrent write path
against both databases with zero errors. Compilation produces a static binary
with `embed.FS` support (R7).

**Node.js / TypeScript — rejected.** The strongest alternative, and the natural
choice for a frontend-heavy team; rejected on specific grounds, not on dislike.
Argon2id is deliberately CPU- and memory-hard and archive work is CPU-bound;
both block the event loop unless offloaded to worker threads, which adds a
concurrency model that must then be maintained (R4). The Node SSH ecosystem is
centred on `ssh2`, which has a smaller contributor base than `x/crypto/ssh` and
offers less direct control over advanced channel and PTY behaviour (R1, R2).
The compensating benefit — one language for the whole stack — was judged not to
outweigh these.

**Python — rejected.** Paramiko provides less precise control over SSH channels
and PTY behaviour than `x/crypto/ssh` (R1, R2); the GIL complicates CPU-heavy
hashing and archive work (R4); and venv/dependency-management friction makes a
self-hosted install meaningfully harder for the target operator (R7).

**Rust — rejected on ecosystem maturity, not on merit.** Safety and performance
are attractive, but `russh` is materially less battle-tested than
`x/crypto/ssh` for the SSH behaviours this product depends on, and async
runtime complexity plus a smaller contributor pool raises the maintenance bar
for a small team — the opposite of the R-maintainability driver.

**C/C++ — rejected.** Manual memory management in a network-facing daemon that
parses untrusted remote output introduces a risk class the project does not
need to accept.

No blocking issue was found in Go. The decision stands.

### 3.2 SQL layer

**sqlc — selected, with two mandatory conditions.** Validated by POC 1
(`docs/poc/database/`, 38/38 assertions). The decisive measured result: one
logical query set, maintained as two files differing only in three mechanical
substitutions (placeholder syntax, `now()`, `FOR UPDATE SKIP LOCKED`),
generated working code for both dialects. sqlc's failure mode is a loud,
early generation error rather than a production-time error, which suits a
security-sensitive codebase.

Two conditions are now architectural requirements, both derived from measured
findings rather than theory:

- **Mandatory per-column `overrides`** for JSON and timestamp columns on
  SQLite. Without them, SQLite JSON columns generate `jsontext.Value`, whose
  `Scan` rejects the `string` the driver returns (finding F2).
- **Mandatory adapter layer** between generated structs and repository
  interfaces. `sqlc.narg()` generated `*int64` on PostgreSQL but `interface{}`
  on SQLite; `LIMIT`/`OFFSET` generated `int32` vs `int64`;
  `COUNT` differs similarly (finding F1). Generated code types are therefore
  *not* the application's types.

Finding F2a is the strongest justification for both conditions: the `ClaimJob`
`UPDATE … RETURNING` **committed** the claim and then failed its scan, so the
function returned an error while the job was already marked running. A blind
retry would have silently stranded every job. The adapter layer plus
critical-path tests are the mitigation.

**Correction to a common claim:** sqlc does **not** provide "automatic SQL
injection protection" as a product property. The security property comes from
using **parameterized queries** and constructing queries correctly. sqlc helps
by making parameterization the path of least resistance and by failing at
generation time, but the guarantee is the parameterization, not the tool.

**`uptrace/bun` — rejected, with a documented fallback.** Bun offers a better
dialect abstraction and would have avoided both conditions above. It was
rejected because it trades compile-time query verification for runtime query
building: sqlc fails at generation, bun fails at runtime. Since the POC showed
the dual-dialect cost is bounded and mechanical, earlier feedback was preferred.
**Fallback:** if divergence proves unmanageable during implementation, migrate
to bun. Repository interfaces do not change — that is precisely why they exist.

*Requires live verification:* sqlc's release cadence and ongoing SQLite support
quality (`docs/research.md` §5).

### 3.3 SQLite driver — env-constrained, deliberately swappable

`mattn/go-sqlite3` requires CGO and the development host has no C compiler
(verified), so it fails the default developer build. `modernc.org/sqlite` — the
usual pure-Go choice — is unreachable here (`403` from both the module proxy
and GitLab), and `zombiezen.com/go/sqlite` depends on it transitively and fails
identically. `ncruces/go-sqlite3` (pure-Go WASM SQLite) fetched and passed the
entire POC.

**Decision: `ncruces/go-sqlite3`, with the driver isolated behind
`database/sql` so it can be swapped without touching repositories or services.**
This is a concession to one environment, not a claim that it is universally the
best pick; switching the default to `modernc.org/sqlite` once reachable is an
open, contained item (`docs/research.md` §5).

### 3.4 Realtime transport

**WebSocket for the terminal, SSE for everything else.** The terminal is
intrinsically bidirectional and keystroke-latency-sensitive. Metrics, logs, and
status are strictly server→client; SSE gives a browser-native `EventSource`
with automatic reconnect, no bespoke heartbeat, and better pass-through behind
common proxies. It also removes a second WebSocket
authentication/heartbeat/reconnect implementation from the security-critical
surface — less code that must be got right.

**Socket.IO — rejected.** Its reconnection/rooms abstractions are valuable in
Node, but it adds a protocol layer and a second client runtime for behaviour
the browser already provides, and it does not reduce the authorization work,
which is the part that actually matters.

### 3.5 Frontend

React 19 + TypeScript + Vite, with `@xterm/xterm` and uPlot. Selected because
the two components this product most depends on have their deepest integration
coverage there, and because TypeScript types can be generated from the Go API
surface, keeping the client honest.

**Rejected:** Svelte (leaner, but thinner examples for the terminal and
charting integrations that matter here); Vue (capable, no advantage sufficient
to justify deviating from the ecosystem the chosen components are best covered
in); ECharts (roughly an order of magnitude larger than uPlot for a dashboard
that renders dense time series); Chart.js/Recharts (degrade at the point counts
real-time metrics produce).

### 3.6 Jobs

**DB-backed job table + in-process worker pool.** Works identically on SQLite
and PostgreSQL, so one implementation serves both. **`river` rejected** because
it is PostgreSQL-only, which contradicts the SQLite requirement. The internal
`JobQueue` interface is kept abstract so a different implementation can replace
it if PostgreSQL-only operation ever becomes acceptable.

### 3.7 Rejected wholesale

Microservices, Kubernetes, Redis, Kafka/RabbitMQ/NATS, a second backend
language, and distributed tracing infrastructure. No concrete requirement
justifies any of them for a single-binary panel that manages servers over SSH.
Adding them would increase operational surface without improving the product.

---

## 4. Consequences

### 4.1 Security implications

- **Credential encryption:** AES-256-GCM with the key supplied by
  `NEXT_PANEL_ENCRYPTION_KEY`, never from the database. Encryption is confined
  to a single `CredentialEncryptor` abstraction with a versioned ciphertext
  format so key rotation is possible later. Plaintext credentials are never
  logged, returned in API responses, or placed in audit metadata.
- **Host-key policy fails closed** (POC 2): `UNKNOWN` surfaces a fingerprint
  prompt, `TRUSTED` connects, `CHANGED` hard-stops. `InsecureIgnoreHostKey` is
  forbidden anywhere in the codebase.
- **Three subsystems are host-equivalent to root** and are therefore
  **disabled by default**, individually enabled by operator configuration,
  protected by dedicated permissions, and audited: `LocalExecutionProvider`,
  Docker/Podman socket access, and systemd control. They are documented as
  privileged rather than described as safe.
- **Authorization is server-side and object-level** on every operation. Reducer
  note: frontend visibility is never treated as authorization.
- **A committed write with a failed read is a correctness *and* security
  problem** — it can strand jobs and, by extension, leak or duplicate work
  (finding F2a). Mitigated by the adapter layer and critical-path tests.
- **Threat model required** covering malicious SSH servers, DNS manipulation,
  MITM, SSRF-via-server-target, path traversal, archive traversal, resource
  exhaustion, and the insider-administrator case. Documented in
  `docs/threat-model.md` (planned).
- **Honest limitation:** if the panel host is fully compromised *and* the
  encryption key is available, encrypted credentials are recoverable. This is
  stated in SECURITY.md rather than papered over.

### 4.2 Performance implications

- Goroutine-per-connection concurrency means a slow or unresponsive server
  occupies only its own goroutine; it cannot stall other servers or other
  users. This is the main reason a blocking-on-the-event-loop failure mode does
  not exist here.
- Argon2id and archive work are CPU-bound and parallelise across cores.
- **One shared collector per server**, not one per connected browser: 20 servers
  and 100 viewers is 20 collectors, not 2000.
- Metrics are collected in one batched read from `/proc` plus a single
  `df -Pk`, not one SSH command per metric.
- **Measured, not projected:** the SQL POC performed 20 concurrent inserts with
  0 errors and claimed 20 jobs from 8 workers with 0 double-claims on
  PostgreSQL. **No performance claim about the panel as a whole is made** —
  end-to-end benchmarks must be taken after implementation, and none are
  invented here.

### 4.3 Development implications

- Two languages (Go, TypeScript) — a deliberate cost, justified by the frontend
  ecosystem. Shared types are maintained by generating or hand-syncing from the
  Go API surface.
- `sqlc` adds a generation step to the build, and `overrides` must be kept
  current when the schema changes. This is enforced by CI running
  `sqlc generate` and failing on a dirty working tree.
- The environment's lack of a C compiler is now a soft guarantee: the stack has
  **no CGO dependency**, so it builds anywhere Go builds.
- A contributor on Linux/macOS/Windows can run the full test suite; PostgreSQL
  integration tests skip gracefully when `TEST_DATABASE_URL` is unset.

### 4.4 Deployment implications

- One static binary with the frontend embedded — no Node runtime, no asset
  directory, no CORS configuration on the operator's host.
- SQLite by default for single-instance and small installs; PostgreSQL for
  concurrency and larger installs. The choice is configuration, not a code
  branch.
- **Docker is documented but was not built or run in this environment** (Docker
  is absent from the dev host). Container claims must not be presented as
  verified until a container build and smoke test actually pass.
- systemd unit provided for non-container installs, running as a dedicated
  unprivileged user.
- Cross-compilation makes multi-architecture release artefacts
  (`linux/amd64`, `linux/arm64`) straightforward.

### 4.5 Maintainability implications

- Bounded, well-known dependency set; no message broker, cache server, or
  service mesh to operate.
- Modular monolith with enforced boundaries: handlers → services →
  repositories/providers. Services never see generated sqlc types; services
  never bypass the provider abstraction.
- One implementation of upload, extraction, metrics, and process parsing shared
  by SSH and local providers, because those are composed from provider
  primitives rather than implemented per provider.
- Clear extension seams: `ServerExecutionProvider` (agent transport later),
  `JobQueue` (different queue later), `CredentialEncryptor` (key rotation),
  `CredentialStore`, and a driver-swappable store layer.
- All code lives under `internal/` in v0.1. No `pkg/` is created until an
  actual external consumer exists — a premature public API is a contract that
  cannot be changed.

### 4.6 Future scaling implications

If a single component ever needs independent scaling, the boundaries already
exist: the provider registry (extract an agent-facing service), the job worker
pool (extract a worker process), the SSE hub (extract a metrics service), and
the store layer (move to a dedicated database tier). Extraction is *possible*
because the seams exist — it is not planned, and no work will be done in
anticipation of it. Scaling SQLite→PostgreSQL is a configuration change; scaling
PostgreSQL further is the documented next step, and neither requires touching
application services.

---

## 5. Open Items and Risk Register

Honest statement of what is unresolved at the time of this decision.

| # | Item | Severity | Mitigation / plan |
|---|---|---|---|
| 1 | SQLite job claiming has no row-level locking; measured single-writer behaviour is **not** equivalent to PostgreSQL's `SKIP LOCKED` | Medium | Documented limitation; SQLite is positioned for single-instance/small installs, not high concurrency; PostgreSQL is documented for production |
| 2 | `ncruces/go-sqlite3` selected partly because `modernc.org` was unreachable here | Medium | Driver isolated behind `database/sql`; switchable without touching repositories. Re-verify before release |
| 3 | Frontend dependencies (xterm.js, uPlot, React 19 compatibility) never fetched or built in this environment | Medium | Must be verified and pinned at first frontend commit; no version is asserted in this ADR |
| 4 | Docker deployment documented but **untested** — Docker absent from dev host | Medium | Must be built and smoke-tested in WSL2 or CI before any container claim is made public |
| 5 | No real remote VPS tested; SSH validated against an in-process server only | Medium | Validates protocol/host-key/PTY behaviour but not real-world distribution quirks. Real-host testing required before claiming distribution support |
| 6 | Competitor research is from prior knowledge, not live sources | Low | Re-verify before repeating in public material (`docs/research.md` §5) |
| 7 | `modernc.org/*` proxy restriction could affect a future dependency | Low | Dependency additions must be fetched and verified before being adopted; no dependency is assumed available |
| 8 | Two languages mean duplicated type definitions | Low | Generate/sync types from the Go API surface; CI checks drift |

---

## 6. Decision Outcome

The decision is **committed**. Per project policy, it will not be revisited
because another framework appears preferable. A change to this architecture
requires a new ADR documenting the technical justification, and any change to
the public interfaces defined here requires a versioned migration path.

**Architecture validation tasks** carried forward (each states exactly how it
will be closed):

1. **Frontend stack pinning** — fetch and build React 19 + Vite + xterm.js +
   uPlot; record exact versions. Closes risk #3.
2. **Docker build and smoke test** — build the image in WSL2/CI, run it against
   PostgreSQL, exercise login and one server connection. Closes risk #4.
3. **Real-host SSH validation** — connect to Ubuntu, Debian, and one RHEL-family
   host; verify `/proc` parsing, `df -Pk` output, and PTY behaviour. Closes
   risk #5 and determines which distributions may be claimed as supported.
4. **SQLite concurrency characterisation** — measure write throughput and
   contention under a realistic panel workload to set the documented limits for
   SQLite deployments. Closes risk #1.
5. **Dependency re-verification** — confirm versions, licences, and maintenance
   status of all direct dependencies when a research-capable environment is
   available. Closes risks #2 and #7.
