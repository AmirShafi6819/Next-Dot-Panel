# Privacy

Next.Panel is self-hosted and phones home to nothing by default: there is no
telemetry, no analytics and no update check in 0.1.0.

## What the panel stores, and why

| Data | Where | Why | Deletion |
|---|---|---|---|
| User accounts (usernames, display names, password hashes) | Panel database (`users`) | Authentication and audit attribution | Delete the user (soft delete; audit rows keep the name for accountability) |
| Sessions (hashed tokens, IP, user agent) | Panel database (`sessions`) | Login state, revocation, history | Logout / revoke / expiry; expired rows are pruned by retention |
| Login attempts (username, IP, user agent, outcome category) | Panel database (`login_history`) | Brute-force visibility | Retention pruning (`LoginHistoryRetention`) |
| Servers (names, addresses, usernames, tags, notes) | Panel database (`servers`) | Managing your infrastructure | Delete the server (panel config only; the remote host is untouched) |
| Server credentials (encrypted) | Panel database (`server_credentials`) | Connecting to your servers | Delete the server or rotate the credential |
| SSH host keys (fingerprints, public keys) | Panel database (`server_host_keys`) | Verification of remote hosts | Replace via the trust workflow |
| Metrics (CPU, memory, disk, network samples) | Panel database (`metric_samples`, `metric_aggregates`, `metric_filesystems`) | Dashboards and history | Retention pruning (`MetricRetention*`) |
| Audit events | Panel database (`audit_logs`) | Accountability | Retention pruning (`AuditRetention`); never edited through the UI |
| Application logs | Panel logs | Operations and debugging | Retention pruning (`AppLogRetention`) |
| Terminal I/O | Nowhere by default | Privacy: only open/close are audited, never keystrokes or output | N/A |

## What never leaves your infrastructure

Credentials are decrypted only in panel memory at connection time. Passwords,
keys and tokens are never logged, never returned by the API, and never placed
in audit metadata. File contents are streamed, not logged.

## Backups

Backing up the panel database backs up the data above (including encrypted
credentials, which additionally require the encryption key to be useful).
Backing up the panel does **not** back up your remote servers' data.
