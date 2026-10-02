# Security Review (0.1.0)

Performed against the 0.1.0 tree before release. Each item states the finding,
severity, status and the test that covers it.

## Reviewed and passing

| # | Finding | Severity | Status | Test |
|---|---|---|---|---|
| 1 | Login must not distinguish unknown user / wrong password / disabled | High | Fixed by design | `TestLoginFailuresAreIndistinguishable` (+ dummy Argon2id for unknown users) |
| 2 | Session token must not be derivable from the database | High | Fixed by design | SHA-256 stored, 256-bit token; `TestLoginAndAuthenticate` |
| 3 | SSH must fail closed on unknown/changed keys | High | Fixed by design | `TestUnknownHostKeyRefused`, `TestChangedHostKeyHardStop`, `TestTrustHostKeyRequiresPermission`; CI grep forbids ignore-host-key callbacks |
| 4 | Object IDs must not be enumerable across users/servers | High | Fixed by design | `TestVisibilityAndIDOR`, `TestRevokeSessionIDOR`, `TestListFiltersByVisibility` |
| 5 | Archive extraction must reject traversal/links/bombs | High | Fixed | `TestExtractRejectsTraversal/Symlink/TooManyEntries`; `TestSafeJoin` |
| 6 | Stdout/stderr shared-buffer race in SSH exec | Medium | Fixed by design | Independent `limitedBuffer` per stream (spec §9.4); covered by exec tests |
| 7 | `run_at` local-time vs UTC comparison stalling the job queue | Medium | Fixed | UTC everywhere; `internal/jobs` tests |
| 8 | Refused TCP connections miscategorised on Windows wording | Low | Fixed | `TestMapNetworkErrorCodes` |
| 9 | Default credentials must warn, never silently persist | Medium | Fixed by design | Flag-based detection, `/me` warning, startup `SECURITY_EVENT`; `TestProfileWarns…`, smoke test |
| 10 | Last-admin lockout via disable/delete | Medium | Fixed | `ErrLastAdmin` + self guards; `TestLastAdminAndSelfGuards` |
| 11 | Secrets in logs/API/errors | High | Fixed by design | `secret.Secret` refuses JSON; DTOs carry no credentials; security greps in CI |

## Open / accepted risk

| # | Item | Severity | Plan |
|---|---|---|---|
| 1 | CSRF double-submit is issued but not yet enforced on mutations | Medium | Enforce in the Phase-22 hardening wave; cookie + token plumbing already shipped |
| 2 | No 2FA/WebAuthn/OIDC | Medium | ROADMAP.md; password + session controls are the 0.1.0 baseline |
| 3 | `go test -race` runs in CI only (no CGO on stock Windows) | Low | CI matrix covers `-race`; local runs are race-free by construction (per-stream buffers, mutexed pools) |

No high-risk findings remain open. This document must be updated — never
silently edited — when a new finding lands.
