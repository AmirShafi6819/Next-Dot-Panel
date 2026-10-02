# Roadmap

0.1.0 is the first functional release: multi-server SSH management, terminal,
file manager, metrics, processes, users/RBAC, audit and a React UI.

Only items below marked as shipped exist. Everything else is planned, not promised.

## Shipped in 0.1.0

- Local auth (Argon2id), sessions, bootstrap admin with default-credential warning
- RBAC with per-server grants, role administration UI + API
- Managed servers, encrypted credentials, TOFU/STRICT host keys, connection tests
- Interactive terminal (WebSocket + PTY, resize, limits, audit)
- File manager (browse/upload/download/mkdir/rename/delete, secure archive extract)
- Metrics (realtime latest, historical ranges, scheduled collection, retention)
- Processes (list, audited SIGTERM/SIGKILL)
- Audit trail + login history (filterable API + UI)
- User administration (CRUD, disable, delete, reset, revoke, last-admin guards)
- Background job queue with maintenance handlers
- SQLite + PostgreSQL, migrations, backups guidance
- Docker, compose, systemd, reverse-proxy examples

## Planned (not scheduled)

- 2FA (TOTP), WebAuthn/passkeys, OIDC/SSO
- API tokens with scopes (schema exists; issuance UI pending)
- systemd unit management, container management (Docker/Podman)
- Cron management, package management
- File archive *creation* from the UI (extraction shipped)
- Notifications (webhook/email) and alerting thresholds
- Persian (fa) localization (the UI is structured for i18n)
- Optional lightweight remote agent transport alongside SSH
- Backup/restore of the panel database from the UI
- Global search, notification center, dark/light/system theme toggle polish
