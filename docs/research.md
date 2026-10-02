# Research Log — Next.Panel

This document records prior art, architectural lessons, and the technology
evaluation that informed Next.Panel's design.

**Status of this document:** it is split into three sections by *evidence
quality*, because remote web research was **not available** in the development
environment at the time of writing (see "Research Limitations" below). Claims
are labelled accordingly. Nothing in the "Known from Existing Knowledge"
section should be treated as verified fact until it is confirmed against live
sources.

---

## 0. Research Limitations

An honest statement of what was and was not possible:

| Capability | Status | Consequence |
|---|---|---|
| Outbound HTTPS to arbitrary sites | **Unavailable** (blocked by network policy; `403` on `proxy.golang.org`, `raw.githubusercontent.com` and web search) | Competitor architecture claims are from prior knowledge, not freshly verified |
| Go module proxy (`proxy.golang.org`) | **Partially available** — most modules fetched, but `modernc.org/*` returns `403` | One dependency swap was forced; see §3 |
| Direct VCS fetch (`GOPROXY=direct`) | **Unavailable** — `gitlab.com` returns `403` | Cannot bypass the proxy block for `modernc.org` |
| Local Go toolchain | **Available** — Go 1.27.1, Windows amd64 | POCs executed for real |
| Local Linux (WSL2 Ubuntu 24.04.5) | **Available**, systemd running, passwordless `root` via `wsl -u root` | Real PostgreSQL 16.15 and real SSH tested |
| Docker | **Unavailable** on the Windows host | Container deployment is *documented but untested* in this environment |

**Policy going forward:** any dependency version, maintenance status, or
licence claim marked "Requires Live Verification" must be confirmed before it
is relied upon in a release. Where a claim is version- or
maintenance-sensitive it is marked inline.

---

## 1. Verified in Current Environment

These facts were established by executing commands on the development machine
on 2026-09-29, not from documentation.

### 1.1 Toolchain

| Item | Verified value |
|---|---|
| Go | `go1.27.1 windows/amd64` |
| Node.js | `v26.8.2` |
| npm | `11.19.1` |
| Python | `3.13.15` |
| OpenSSH client (Windows) | `OpenSSH_10.5p1, OpenSSL 3.5.7` |
| Docker | **not installed** |
| `psql` on Windows host | **not installed** (PostgreSQL runs inside WSL2) |
| C compiler on Windows | **none** (`gcc` absent from PATH) |

The absence of a C compiler is architecturally significant: it rules out any
CGO-requiring dependency for the default Windows developer build. See §3.2.

### 1.2 WSL2 test environment

| Item | Verified value |
|---|---|
| Distribution | Ubuntu 24.04.5 LTS (noble) |
| Kernel | `6.18.33.2-microsoft-standard-WSL2` |
| systemd | running (`systemctl is-system-running` → `running`) |
| `wsl -u root` | works (uid 0, no password prompt) |
| PostgreSQL | 16.15 installed from Ubuntu archive, accepting connections |
| Reachability from Windows | `postgres://…@localhost:5432` works via WSL2 localhost forwarding |

**Note:** WSL's `dpkg` database was found in an interrupted state
(`dpkg was interrupted, you must manually run 'dpkg --configure -a'`). Running
`dpkg --configure -a` repaired it and allowed the PostgreSQL install to
proceed. This repair step is documented in the setup guide because a fresh
developer hitting it will otherwise be blocked.

### 1.3 Module availability (actual fetch results)

| Module | Result |
|---|---|
| `github.com/google/uuid` | OK |
| `golang.org/x/crypto` | OK |
| `golang.org/x/term` | OK |
| `github.com/go-chi/chi/v5` | OK |
| `github.com/jackc/pgx/v5` | OK (resolved to v5.11.0) |
| `github.com/creack/pty` | OK |
| `github.com/pkg/sftp` | OK |
| `github.com/coder/websocket` | OK |
| `github.com/pressly/goose/v3` | OK |
| `github.com/mattn/go-sqlite3` | OK (but requires CGO — rejected, §3.2) |
| **`modernc.org/sqlite`** | **FAIL — `403 Forbidden` from proxy *and* GitLab** |
| **`zombiezen.com/go/sqlite`** | **FAIL — transitively depends on `modernc.org/sqlite`** |
| `github.com/ncruces/go-sqlite3` | OK (v0.35.6 — selected, §3.2) |

### 1.4 Proof-of-concept results

Two POCs were executed against real infrastructure. Full sources are preserved
under [`docs/poc/`](poc/) so the results can be reproduced.

#### POC 1 — Dual-dialect SQL layer (`docs/poc/database/`)

**Question:** can one repository architecture realistically serve both
PostgreSQL and SQLite without an unmaintainable volume of dialect-specific SQL?

**Method:** a schema of five tables (`users`, `servers`, `audit_logs`,
`metric_samples`, `jobs`) written twice — once per dialect — plus **one**
logical query set maintained as two files that differ only in three mechanical
substitutions (placeholder syntax, `now()`, `FOR UPDATE SKIP LOCKED`). sqlc
1.30.0 generated Go for both; a single test program exercised both.

**Result: PASS — 38/38 assertions across both dialects.**

PostgreSQL 16.15: schema+FK+unique enforcement, `RETURNING *`,
`ErrNoRows`, pagination, nullable actor + JSONB, filtered list with NULL
parameters, FK violation rejection, `ON CONFLICT` upsert idempotency,
optimistic locking via version column, `FOR UPDATE SKIP LOCKED` (20 jobs
claimed by 8 workers, **0 double-claimed**), 20 concurrent inserts with 0
errors, transaction rollback, timestamp-range deletion, graceful pool
shutdown.

SQLite (ncruces, pure-Go, no CGO): WAL confirmed active, `foreign_keys`
confirmed enforced, `busy_timeout` confirmed 5000 ms, plus the equivalent of
every test above except `SKIP LOCKED` (unsupported — see finding F3).

**Findings that changed the design:**

- **F1 — `sqlc.narg()` emits *different Go types per dialect.*** For
  `sqlc.narg('actor_id')::bigint` PostgreSQL produced `ActorID *int64` while
  SQLite produced `ActorID interface{}`. Likewise `LIMIT`/`OFFSET` generated
  `int32` on PostgreSQL and `int64` on SQLite, and `COUNT` columns differ
  similarly. **Consequence:** a hand-written adapter layer between generated
  code and the repository interface is *mandatory*, not a stylistic choice.
  This is now a hard architectural requirement (Design Spec §7).
- **F2 — SQLite JSON columns fail to scan by default.** sqlc generated
  `jsontext.Value` for SQLite JSON columns. The ncruces driver returns JSON
  columns as Go `string` (`[]byte` destination also works). `jsontext.Value.Scan`
  does not accept `string`, producing
  `unsupported Scan, storing driver value type string`.
- **F2a — the F2 failure was *actively dangerous*.** The `ClaimJob` statement is
  an `UPDATE … RETURNING`. The UPDATE **committed successfully** (`status='running'`,
  `attempts=1`) and *then* the row scan failed. The function returned an error
  while the job had already been marked running — so a naive retry loop would
  silently strand every job. This is precisely the class of bug that makes
  "compiles fine" worthless as a completion criterion, and it is why
  `ClaimJob` must be treated as a critical-path operation with dedicated tests.
  Fixed by explicit per-column sqlc `overrides` mapping JSON columns to
  `[]byte` and timestamp columns to `time.Time`.
- **F3 — SQLite has no `FOR UPDATE SKIP LOCKED`.** The PostgreSQL job-claim
  strategy cannot be expressed on SQLite. Measured behaviour instead: a
  single-writer pool (`SetMaxOpenConns(1)`) claimed all 20 jobs with 0
  double-claims, but this serialises *all* database access, so it is **not
  equivalent** to row-level locking under real concurrency. SQLite therefore
  gets a documented, explicit concurrency limitation rather than a pretence of
  parity (Design Spec §7.4).
- **F4 — optional-filter SQL is portable with `sqlc.narg()`.** The
  `(narg IS NULL OR col = narg)` idiom works on both dialects, though the
  generated parameter type differs (F1).
- **F5 — remaining type asymmetries are absorbable but real.** PostgreSQL's
  nullable timestamp is `pgtype.Timestamptz` while SQLite's is `*string`;
  `attempts` is `int32` vs `int64`. Each is a one-line adapter conversion.

**Verdict: sqlc retained**, with mandatory overrides and a mandatory adapter
layer. The dialect-specific SQL is confined to three mechanical substitutions;
that is a maintainable ratio.

#### POC 2 — SSH host-key policy and PTY streaming (`docs/poc/ssh/`)

**Question:** does `golang.org/x/crypto/ssh` give the control needed to enforce
the required host-key policy, and does PTY allocation with ANSI passthrough
work end-to-end?

**Method:** an in-process SSH server with a real Ed25519 host key and
public-key auth, paired with a client implementing the intended
`UNKNOWN → TRUSTED → CHANGED` callback policy.

**Result: PASS — 8/8 assertions.**

- Unknown host key **rejected**, surfacing the SHA256 fingerprint in the error
  so the UI can present a trust prompt.
- Pinned/trusted host key **accepted**.
- Rotated host key **hard-stopped** — no silent acceptance. The callback had to
  be written to *fail closed*; `ssh.InsecureIgnoreHostKey` was never used.
- SHA256 fingerprint available in the standard `SHA256:<base64>` form for display.
- PTY negotiated at `xterm-256color` 120×40 and the remote side observed a real
  PTY.
- ANSI SGR sequences (`\x1b[32m…\x1b[0m`) passed through **unmodified**.
- Window-change (resize) accepted.

**Findings that changed the design:**

- **F6 — `x/crypto/ssh` copies stdout and stderr in separate goroutines.**
  Assigning both `session.Stdout` and `session.Stderr` to the *same*
  `bytes.Buffer` is a data race; in testing it silently produced a **completely
  empty** result while the server confirmed `wrote 29 bytes err=<nil>`. This
  cost real debugging time and is a trap for any implementer. **Consequence:**
  the terminal and command-execution services must capture stdout and stderr
  into independent, concurrency-safe writers. Recorded as an explicit
  implementation note in the Design Spec (§9.4).
- **F7 — `modernc.org` unreachability can appear mid-build.** The host-key POC
  itself depends only on `golang.org/x/crypto`, which fetched fine; the block
  affected `modernc.org/sqlite` only. This confirms the proxy restriction is
  path-specific rather than a blanket outage, and that a dependency could
  become unavailable later — motivating the dependency-risk note in ADR-0001.

### 1.5 What was *not* verified

Explicitly, so no claim is inflated:

- No connection to a real remote Linux VPS over SSH.
- No real remote host's `/proc` output parsed.
- No terminal round-trip through a browser (no WebSocket→xterm.js path tested).
- No Docker image built or run.
- No frontend built or rendered.
- No multi-user concurrency beyond the 20-goroutine database case.
- Nothing tested on Debian, RHEL-family, or Arch — only Ubuntu 24.04.

---

## 2. Comparable Projects — Architectural Study

> **Evidence note:** written from prior knowledge. Remote repositories were not
> reachable at the time of writing. Feature lists, licence terms, and current
> maintenance status all require live verification before being repeated in
> user-facing material (README, website, release notes). Where a claim is
> version-sensitive it is flagged.

### 2.1 Cockpit

- **Category:** host-local web console, Red Hat–originated.
- **Architecture lesson:** the most important idea is that Cockpit manages the
  *local* host and uses the SSH transport mainly to reach *other* machines. Its
  privileged operations go through a separate, narrowly-scoped helper process
  rather than running the whole web tier as root. That separation of the web
  surface from a privileged broker is directly relevant to Next.Panel.
- **Adopted:** Next.Panel's `LocalExecutionProvider` mirrors this model, but is
  **disabled by default** and gated behind dedicated permissions, because
  unlike Cockpit, Next.Panel primarily manages *remote* hosts and treating local
  execution as ordinary is the wrong default.
- **Rejected:** Cockpit's bidirectional D-Bus/Cockpit-bridge protocol. It is
  elegant but requires client-side cooperation and a non-trivial protocol
  implementation; a plain REST + SSE/WebSocket surface is easier to secure and
  document.
- *Requires live verification:* current language mix (C/JS/Python) and whether
  the privileged-helper split is still as described.

### 2.2 Webmin

- **Category:** the oldest widely-deployed web admin panel.
- **Architecture lesson:** its long life came at the cost of a very large,
  loosely-structured module set where modules frequently manipulate
  configuration files directly by string substitution. This is the cautionary
  tale that motivates Next.Panel's "structured operations only" rule for
  systemd, Docker, and services.
- **Adopted:** explicit, enumerated, permission-checked operations instead of
  an open command surface.
- **Rejected:** the file-editing-as-API model. It is unauditable and
  transport-unaware.

### 2.3 1Panel and aaPanel

- **Category:** modern VPS panels with strong UI emphasis.
- **Architecture lesson:** a single modern binary bundling the API and the
  pre-built frontend is a genuinely good deployment experience, and their
  opinionated "install the panel, then install apps" flow lowers the barrier for
  new users.
- **Adopted:** `embed.FS` for the built frontend — one artefact to ship, no
  separate web root to configure, no CORS surface.
- **Rejected:** bundling an application marketplace and package-management
  layer into v0.1. That breadth is a large attack surface and the source of a
  long tail of support burden; Next.Panel keeps package management out of the
  initial scope (Roadmap).

### 2.4 CloudPanel

- **Category:** opinionated single-language stack panel.
- **Architecture lesson:** opinionation is a feature for its audience, but it
  makes the tool unusable outside its supported stack.
- **Adopted:** Next.Panel is deliberately *un*opinionated about what runs on the
  managed server — it manages the host, not an imposed stack.
- **Rejected:** hard-coding a single web-server/database topology.

### 2.5 Pterodactyl

- **Category:** game-server management, split Panel/ Wings daemon.
- **Architecture lesson:** the daemon split (control plane vs data plane, with
  the daemon holding the actual host-level privileges) is the cleanest security
  boundary among the projects studied. It is also the strongest argument for a
  future Next.Panel Agent.
- **Adopted:** Next.Panel defines `ServerExecutionProvider` now precisely so an
  agent-backed provider can be added later without touching application
  services (Design Spec §8).
- **Rejected:** requiring an agent in v0.1. It raises install friction
  substantially and the SSH path is sufficient for the initial feature set.

### 2.6 Netdata and Grafana

- **Category:** monitoring and visualisation.
- **Architecture lesson:** both converge on the same economics — high-resolution
  retention is expensive, so raw data is rolled up into coarser tiers, and the
  UI renders *gaps* where data is genuinely absent rather than interpolating.
  Netdata's per-second freshness badge is a good pattern; Grafana's explicit
  "No data" state is the correct way to render absence.
- **Adopted:** two-tier retention (raw → 5-minute → 1-hour), explicit
  `unavailable`/`stale`/`offline` states, and chart gaps instead of
  interpolation. Directly reflected in Design Spec §18.
- **Rejected:** Netdata's per-second granularity as a default. Over SSH that is
  an untenable collection rate; Next.Panel uses a configurable interval
  (default 5 s, floor 1 s) and shares one collector per server.

### 2.7 Portainer

- **Category:** Docker/container management UI.
- **Architecture lesson:** it makes container management genuinely approachable,
  but direct Docker API access is *effectively host-root* — a fact frequently
  under-appreciated by its users.
- **Adopted:** Next.Panel's Docker/Podman support goes through an
  authorization-controlled backend service and never exposes the socket to the
  browser; the host-equivalence is documented explicitly rather than glossed.
- **Rejected:** the "just proxy the Docker socket" convenience pattern.

### 2.8 CasaOS

- **Category:** home-server UI.
- **Architecture lesson:** excellent first-run experience and visual polish.
- **Rejected:** its consumer-appliance framing. Next.Panel targets operators of
  real infrastructure and should not hide the actual system state behind a
  simplified abstraction.

### 2.9 FileBrowser

- **Category:** web file manager.
- **Architecture lesson:** a strong reminder that path handling is the whole
  security story for a file manager, and that naïvely joining user input onto a
  root path is the standard way these tools get path-traversal bugs.
- **Adopted:** dedicated, independently-tested archive and path-safety module,
  normalisation against an explicit root, and refusal of absolute/`..`/symlinked
  escapes (Design Spec §17.3).
- **Rejected:** using a shell (`tar`, `unzip`) with interpolated filenames —
  filenames are hostile input and must never reach a shell.

### 2.10 ttyd and Wetty

- **Category:** terminal-over-web.
- **Architecture lesson:** both prove WebSocket↔PTY streaming is a solved
  problem, but both are thin shims that delegate *all* authorization to
  whatever fronts them. They have no concept of a per-user, per-server
  authorization model because they do not need one — Next.Panel does.
- **Adopted:** xterm.js on the browser side (a built terminal emulator, never
  hand-rolled ANSI parsing) with an independently authorized WebSocket.
- **Rejected:** treating the terminal as a standalone utility. In Next.Panel the
  terminal is a first-class, permission-gated, audited resource.

### 2.11 Ajenti

- **Category:** modular Python panel.
- **Architecture lesson:** its plugin model is genuinely extensible, but the
  plugin API was never a frozen contract, so third-party plugins track a moving
  target.
- **Adopted:** Next.Panel defines small, stable interfaces *first* and adds no
  plugin framework in v0.1. Premature plugin frameworks ossify the wrong
  abstractions.

### 2.12 Consolidated feature comparison

"Next.Panel approach" states what was actually decided, not an aspiration.

| Feature | Seen in | Idea worth taking | Next.Panel approach |
|---|---|---|---|
| Privilege separation | Cockpit, Pterodactyl | Keep the web tier unprivileged; isolate host-level power | Local exec, Docker, systemd each behind dedicated permissions, off by default |
| Single-binary deploy | 1Panel, Cockpit | One artefact, embedded UI | `embed.FS` frontend in one Go binary |
| Tiered metric retention | Netdata, Grafana | Roll up, and render gaps honestly | raw → 5 min → 1 hour; explicit `unavailable` / `stale` / `offline` |
| Real terminal emulator | ttyd, Wetty | Never parse ANSI by hand | xterm.js over an authorized WebSocket |
| Daemon/agent split | Pterodactyl | Separate privileged data plane | Provider interface now, agent transport later |
| Host-key verification | (weak in most) | Fail closed on change | `UNKNOWN`→prompt, `TRUSTED`→connect, `CHANGED`→hard stop |
| Container management | Portainer | Approachable container UX | Backend-mediated, audited, socket never exposed |
| Path-traversal defence | FileBrowser | Treat filenames as hostile | Dedicated tested module, no shell interpolation |
| Structured systemd ops | Webmin (counter-example) | Enumerated operations, not file edits | Explicit service verbs, permission-checked |
| Avoid marketplace scope | 1Panel, aaPanel | — | Package management deferred to Roadmap |

---

## 3. Technology Evaluation

### 3.1 Backend language

Evaluated against Next.Panel's real workload: long-lived multiplexed SSH
connections, PTY byte streaming, large file streaming, and CPU/memory-hard
Argon2id hashing plus archive compression/decompression.

| Candidate | Assessment |
|---|---|
| **Go** | `golang.org/x/crypto/ssh` is the most capable non-OpenSSH SSH implementation, giving full control of host-key policy, PTY requests, and channels. Concurrency is cheap, so per-server collectors and per-session PTY pumps are natural rather than special. Argon2id and tar/gzip are CPU-bound and simply occupy another core. Static single binary; cross-compiles trivially; `embed.FS` ships the UI inside the artefact. **Selected.** |
| Node.js / TypeScript | The strongest competitor, and the natural choice if the team were frontend-first. Rejected because Argon2id and archive work block the single event loop unless offloaded to worker threads, and the Node SSH ecosystem (`ssh2`) has a materially smaller contributor base and narrower control over advanced channel/PTY behaviour than `x/crypto/ssh`. |
| Python | Rejected. Paramiko is slower and offers less precise control over SSH channels; the GIL complicates CPU-heavy crypto and archive work; and venv/packaging friction makes self-hosted deployment meaningfully harder for the target audience. |
| Rust | Genuinely attractive on safety and performance, but `russh` is far less battle-tested than `x/crypto/ssh`, and async/tokio complexity plus a smaller contributor pool raises the bar for "a small team can maintain this". Rejected on ecosystem maturity, not on merit. |
| C / C++ | Rejected. Manual memory management in a network-facing daemon handling untrusted remote output is an unnecessary risk class. |

No blocking issue was found that would overturn Go. **Decision: Go retained.**

### 3.2 SQLite driver — forced by the environment

This is the one place where the environment overrode a preference, and it is
worth documenting precisely.

1. `github.com/mattn/go-sqlite3` fetched fine, but requires CGO. The Windows
   dev host has **no C compiler** (verified, §1.1), so it would break the
   default developer build.
2. `modernc.org/sqlite` (pure Go, the usual answer) is **unreachable**: `403`
   from `proxy.golang.org` *and* `404/403` from `gitlab.com` via
   `GOPROXY=direct`.
3. `zombiezen.com/go/sqlite` transitively depends on `modernc.org/sqlite`, so
   it fails identically.
4. `github.com/ncruces/go-sqlite3` — a pure-Go WASM build of SQLite — fetched
   successfully and passed the full POC, including WAL, foreign keys, upserts,
   and concurrent access.

**Selected: `github.com/ncruces/go-sqlite3`.** It satisfies the no-CGO
constraint, which `mattn/go-sqlite3` does not, and is reachable where
`modernc.org` is not.

**Dependency risk (must be re-checked):** the `modernc.org` block is a
*network* restriction in this environment and may not exist elsewhere, where
`modernc.org/sqlite` would be the more conventional choice. The store layer is
therefore designed so the driver is replaceable behind `database/sql` without
touching repositories or services. *Requires live verification:* ncruces'
project maturity, release cadence, and whether it should remain the default for
published releases or be switched to `modernc.org/sqlite` once reachable.

### 3.3 SQL layer: sqlc

Retained on **measured** evidence rather than preference (POC 1, §1.4). It
generates typed Go from real SQL with no runtime reflection, and the
dual-dialect cost was measured as three mechanical substitutions plus a small
adapter layer. Two conditions are now architectural requirements:

- explicit per-column `overrides` for JSON and timestamp columns on SQLite;
- a hand-written adapter between generated structs and repository interfaces,
  because `sqlc.narg()` and `LIMIT`/`OFFSET` types differ per dialect (F1).

Note F2a — the committed-UPDATE-with-failed-scan bug — is the strongest
argument for the adapter layer and for treating `ClaimJob` as critical-path.

*Requires live verification:* sqlc release cadence and its ongoing SQLite
support quality.

**Rejected alternative:** `uptrace/bun`. It is a fine library and its
dialect abstraction is genuinely better, but it trades compile-time query
verification for runtime query building. sqlc's failure mode is loud and early
(a generation error); bun's is a runtime error in production. Given that the
POC showed the dual-dialect cost is bounded, sqlc's earlier feedback wins.
**Documented fallback:** if divergence proves unmanageable during
implementation, switch to bun — the repository interfaces do not change, which
is exactly why they exist.

### 3.4 Realtime transport

- **Terminal → WebSocket.** Bidirectional, keystroke-latency-sensitive, needs a
  binary-safe channel. No alternative is suitable.
- **Metrics, logs, status → SSE.** These are strictly server→client. SSE gives
  a browser-native `EventSource` with automatic reconnect and no custom
  heartbeat, and passes through more proxies unmodified than WebSocket. It also
  removes a second WebSocket authorization/heartbeat/reconnect implementation
  from the security-critical surface, which is a real reduction in code that
  must be got right.

Verified available: `github.com/coder/websocket` (fetched OK, §1.3).

### 3.5 Frontend

**React 19 + TypeScript + Vite.** Selected because the two components that
actually matter for this product — `@xterm/xterm` for the terminal and
time-series charting for metrics — have their deepest integration coverage in
the React ecosystem, and because TypeScript types can be generated from the
Go API surface to keep the client honest.

**Charts: uPlot.** ~45 KB and designed for dense time series; it stays smooth
at point counts where Chart.js and Recharts degrade, and ECharts is roughly an
order of magnitude larger. Real-time metrics is precisely its use case.

*Requires live verification:* current major versions and React 19 compatibility
of xterm.js and uPlot before pinning.

### 3.6 Routing, migrations, jobs

- **chi** — plain `http.Handler`-compatible, so standard middleware and stdlib
  tooling keep working. Gin/Echo add non-idiomatic APIs for little benefit;
  Fiber's fasthttp base breaks stdlib compatibility.
- **goose** — embedded `embed.FS` migrations with up/down and multi-dialect
  support.
- **DB-backed job table + in-process worker pool** — works on both SQLite and
  PostgreSQL. `river` is excellent but PostgreSQL-only, which contradicts the
  SQLite requirement. The internal `JobQueue` interface is kept abstract so a
  different implementation can replace it.

### 3.7 Explicitly rejected

Microservices, Kubernetes, Redis, Kafka/RabbitMQ/NATS, a second backend
language, and distributed tracing infrastructure. None is justified by a
single-binary panel managing servers over SSH. The architecture is a modular
monolith with enforced internal boundaries, so a component can be extracted
later *if a concrete need appears* — not in anticipation of one.

---

## 4. Security Lessons Carried Forward

Drawn from the studied projects, the POCs, and the specification. Each maps to
a concrete control in the Design Spec.

| Lesson | Source | Control |
|---|---|---|
| Host-key verification must fail closed | POC 2 | `CHANGED` state hard-stops; no `InsecureIgnoreHostKey` anywhere |
| Filenames are hostile input | FileBrowser, spec §91 | Dedicated path/archive module, never shell interpolation |
| Container socket access is host-root | Portainer | Backend-mediated, dedicated permission, documented explicitly |
| Metrics must distinguish absent from zero | Netdata, Grafana | `unavailable` / `stale` / `offline`; chart gaps, never fabricated `0` |
| A committed write with a failed read is a silent data-loss bug | POC 1, F2a | `ClaimJob` critical-path tests; adapter layer; no blind retry |
| Concurrent writes to one buffer lose data | POC 2, F6 | Independent concurrency-safe writers for stdout/stderr |
| Removing unaudited capability beats filtering it | Webmin, ttyd | Enumerated operations + audit; no command blacklists |
| Deferred privilege must be default-off | Cockpit, Pterodactyl | Local exec, Docker, systemd off by default, permission-gated |

---

## 5. Open Research Items

To be closed when a research-capable environment is available. Each is a
*verification* task, not a design decision:

1. Confirm current versions and maintenance status of: `ncruces/go-sqlite3`,
   `sqlc`, `goose`, `coder/websocket`, xterm.js, uPlot.
2. Decide whether `modernc.org/sqlite` should replace ncruces as the default
   once reachable, given the driver-swap design.
3. Re-verify competitor architecture claims in §2 against live repositories
   before any is repeated in public-facing material.
4. Confirm licences of every direct and transitive dependency for
   `docs/licensing.md` (planned, not yet written).
5. Verify current SSH host-key-algorithm deprecations to set a sane default
   `HostKeyAlgorithms` list rather than accepting library defaults.
