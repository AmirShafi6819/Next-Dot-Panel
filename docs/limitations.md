# Known Limitations (0.1.0)

- **Metrics need a second reading for CPU%**: the first collection after a
  (re)start leaves `cpu_pct` empty; deltas are in-memory, not persisted.
- **Historical aggregates**: raw samples are retained per `MetricRetentionRaw`;
  downsampled 5m/1h aggregates exist in schema but no rollup job runs yet —
  long ranges read raw samples (capped at 5000 rows per request).
- **File owner/group are numeric ids** from SFTP; names are not resolved via
  `/etc/passwd`.
- **Archive creation** from the UI is not implemented; extraction (tar,
  tar.gz, zip) is.
- **API tokens**: the `api_tokens` schema exists but issuance/revocation
  endpoints are not wired yet; use sessions.
- **Local execution provider** (`local` target type) is defined but disabled
  and unimplemented; only SSH targets connect.
- **Password auth over SSH** works but key auth remains the default and
  recommended path.
- **Mobile terminal** works but is cramped; desktop is the primary target.
- **SQLite** suits single-instance/small installs; use PostgreSQL for
  multi-user or larger deployments (higher concurrency).
- **No 2FA/WebAuthn/OIDC yet**; see ROADMAP.md.
- `go test -race` requires CGO and runs in CI, not on stock Windows.
