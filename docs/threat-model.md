# Threat Model (0.1.0)

## Assets

Panel database (accounts, sessions, server inventory, encrypted credentials),
encryption key, operator browsers, remote Linux hosts reachable via SSH.

## Actors

Legitimate admins/operators/viewers; malicious authenticated low-privilege
users; network attackers (MITM, DNS); malicious or compromised SSH servers;
stolen browsers/sessions.

## What is protected, and how

| Threat | Control |
|---|---|
| Password guessing | Argon2id, indistinguishable failures + dummy verification, login rate limit (10/15m/IP), failure categories audited |
| Stolen session cookie | HttpOnly + SameSite=Lax (+Secure behind https), absolute/idle expiry, revocation on logout/password change |
| CSRF | Session cookie is Lax; state-changing browser flows additionally carry a double-submit CSRF cookie (enforcement lands with the Phase-22 hardening; cookie issuance is already live) |
| IDOR / privilege escalation | `user → permission → object → operation` in every service; invisible → 404; denials audited DENIED; tested |
| SSH MITM | Pinned host keys; unknown refused with fingerprint; changed hard-stops; no auto-accept; modern algorithm allow-lists |
| Credential theft from DB | AES-256-GCM blobs; key from env, never DB; plaintext only in memory at connect time |
| Path traversal / Zip Slip | Path normalisation; extraction validates every entry (no abs/traversal/links/devices; entry + size caps) |
| Command injection via filenames | argv arrays + POSIX quoting at the single choke point; SFTP for file ops, not shell |
| XSS via filenames/logs/audit | React escapes by default; terminal renders in xterm, never as HTML; CSP same-origin |
| SSRF via server addresses | No generic fetch feature; SSH targets are explicit operator configuration, documented as trusted |
| Audit tampering | Append-only; no edit/delete endpoints; retention pruning is the only deletion |
| Resource exhaustion | Output caps, upload streaming, archive caps, terminal/session/connection limits, job retries with backoff |

## What is NOT protected

- A fully compromised panel host **with the encryption key** exposes stored
  credentials. Harden the host, restrict the key, back both up separately.
- A terminal is intentionally root-equivalent on the target for its SSH user.
  There are no command blacklists (they provide no real security).
- Terminal keystrokes/output are not recorded; session auditing covers
  open/close only, by design.
- No 2FA yet: a stolen password is sufficient until second factors land.
- DNS rebinding against operator-configured SSH targets is accepted risk:
  targets are explicit trust, not browser-driven URLs.
