# Pull request

## What changed

<!-- One or two sentences. Link the issue with "Fixes #NNN" when applicable. -->

## Verification

<!-- Paste or tick what you ran. CI runs all of these. -->

- [ ] `gofmt -l .` is empty, `go vet ./...` passes
- [ ] `golangci-lint run ./...` reports no issues
- [ ] `go test ./...` passes (plus PostgreSQL dialect with `TEST_DATABASE_URL` when touching storage)
- [ ] `cd web && npm run build` passes (when touching the frontend)
- [ ] New behavior has tests (negative/authorization tests where applicable)
- [ ] Docs and `CHANGELOG.md` updated (when user-visible)

## Security notes (required for auth, sessions, RBAC, SSH, credentials, file paths, archives, terminals, WebSockets)

<!--
Threat model for this change, abuse cases covered by regression tests, and
confirmation that no credential material is logged or returned. Delete this
section for changes that touch none of the above.
-->
