# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1.0 | No (pre-release development) |

## Reporting a vulnerability

**Do not open a public GitHub issue for a suspected vulnerability.**

Use a private GitHub Security Advisory on this repository (Security →
Advisories → New draft advisory). Include:

- Next.Panel version and deployment method (binary, Docker, systemd)
- Linux distribution of the panel host and of any affected remote server
- Steps to reproduce (without real credentials, keys or hostnames)
- What you expected vs. what happened
- Logs with secrets redacted

You will receive an acknowledgement, and fixes are released with credit
unless you prefer to stay anonymous.

## What is protected

- Local authentication uses Argon2id; sessions are opaque, server-side,
  revocable and expire (absolute + idle).
- Every service method authorizes `user → permission → object → operation`;
  invisible objects return 404 so ids cannot be probed.
- SSH host keys fail closed: unknown keys are refused with a fingerprint for
  explicit trust; changed keys hard-stop the connection. There is no
  auto-accept path.
- Stored server credentials are AES-256-GCM ciphertext; the key comes from
  the environment, never the database.
- File operations validate paths; archive extraction rejects traversal,
  absolute paths, links and oversized payloads.
- Terminal and file access require per-server permissions and are audited.

## Trust model (read this before deploying)

- The panel administrator controls Next.Panel; compromising the panel can
  compromise every connected server, because SSH credentials grant real
  server access.
- A terminal is intentionally powerful. Security comes from authentication,
  authorization, OS permissions and audit — not from command blacklists
  (there are none, by design).
- If the panel host itself is fully compromised and the encryption key is
  available to the attacker, stored credentials must be considered exposed.
  Protect the host, the key and backups accordingly.

## Known limitations

See [docs/limitations.md](docs/limitations.md) and
[docs/threat-model.md](docs/threat-model.md). No software is "100% secure";
this document lists concrete controls instead of making that claim.
