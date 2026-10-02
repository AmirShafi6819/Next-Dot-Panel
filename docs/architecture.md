# Architecture

Next.Panel is a Go backend serving a JSON API and an embedded React UI. It
manages remote Linux hosts over SSH. There is no required agent.

```
Browser ──HTTPS──► Next.Panel ──SSH──► Linux servers
                      │
                      ▼
                 SQLite / PostgreSQL
```

## Layers (enforced, not advisory)

```
HTTP handlers (internal/httpapi) — decode, call a service, encode. No logic.
Application services (internal/*) — authorize first (actor → permission →
  object → operation), then act. Every method takes an actor.
Repositories (internal/store/repos) — dialect-neutral Queries over sqlc output.
Providers (internal/provider) — primitives only: connect, exec, files, PTY.
```

Services never touch SQL; repositories never see actors; providers never see
credentials (only a narrow `CredentialSource`); credentials decrypt only inside
`internal/credentials`.

## Request lifecycle (representative)

```
POST /api/v1/servers/3/files/delete
  → RequestID → AccessLog → Recover → SecurityHeaders
  → Session (cookie → actor) → RequireAuth
  → handler → files.Service.Remove(actor, …)
      → server.Service.Connect (RBAC files.delete on server 3, unwrap creds)
      → provider.Remove → audit FILE_DELETED
```

## Authentication flow

Argon2id password → opaque 256-bit session (SHA-256 stored) → `HttpOnly`
cookie + readable CSRF cookie. Absolute + idle expiry, throttled touches,
revocation on logout/password change. Failures are indistinguishable and
audited by category.

## SSH flow

`server.Service.TestConnection` → registry pool → `ssh.Connect` with the
pinned key from `server_host_keys` → fail-closed callback (unknown → fingerprint
for explicit trust; changed → hard stop) → ping + `uname` discovery → status
recorded. Credentials rotate by version; the pool entry is invalidated.

## Terminal flow

WebSocket upgrade (session middleware already attached the actor) →
`terminal.Manager.Open` (terminal.open on the server, limits) → SSH PTY shell.
Binary frames both ways; JSON control frames for input/resize/close. Idle
sweep and shutdown close sessions; open/close audited, keystrokes never logged.

## File transfer flow

Uploads stream request body → SFTP write (no buffering, no temp files).
Downloads stream SFTP → response. Extraction validates every archive entry
before writing (no traversal, no links, entry/size caps; zip spools to a
0600 temp file because `archive/zip` needs random access).

## Metrics flow

Scheduler → one collector per server per interval → reads `/proc` over SFTP
(no shell) + `df` → defensive parsers (nil, not zero, for missing data) →
`metric_samples`/`metric_filesystems` → UI polls `latest` and `range`, or
subscribes to SSE `events` (persisted state only, never SSH).

## Audit flow

Services call `audit.Writer.Record` with actor, action, target, server and
sanitised metadata. Denials use `DENIED`. The trail is append-only; only
retention pruning deletes.

## Security boundaries

Browser ⇄ backend (cookies, CSRF cookie, CSP, origin-checked WebSockets) ⇄
database (no secrets in plaintext; encrypted credential blobs) ⇄ remote host
(SSH with pinned keys). A compromised panel host with the encryption key
exposes stored credentials — protect host, key and backups (see SECURITY.md).

## Future agent

`provider.ServerExecutionProvider` is transport-agnostic. A future agent
transport implements the same primitives; services, authorization and audit
do not change.
