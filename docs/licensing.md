# Licensing

This document records the license decision required by Design Spec §97 and the
license inventory used to confirm that the choice is compatible with every
dependency that ships in the binary.

## Decision

Next.Panel is licensed under the **MIT License** (see [`LICENSE`](../LICENSE)).

## Why MIT

The choice was made deliberately rather than by habit:

| Criterion | MIT | Apache-2.0 | GPL-3.0 / AGPL-3.0 |
|---|---|---|---|
| Intent of this project | Self-hosted tool that others may fork, embed, rebrand, or ship inside commercial hosting products | Same | Same, but the copyleft obligations would follow derivative works — including a hosting provider's deployment under AGPL |
| Obligations on users | Keep the copyright notice | Keep notice + state changes + explicit patent clause text | Publish derivative source (GPL) or serve source to users (AGPL) |
| Dependency compatibility | Compatible with every license in the inventory below | Compatible, but adds a patent clause that our dependencies do not uniformly carry | Compatible *from* permissive *to* copyleft, but would constrain future dependency choice |
| Contribution surface | Lowest friction for outside contributors and for downstream packaging (Debian, AUR, Homebrew) | Slightly higher friction (DCO-style paperwork expectations) | Highest friction |
| Patent protection | Implicit patent termination via copyright grant only | Explicit patent grant and retaliation clause | Covered, at the cost of copyleft |

**Why not copyleft (GPL/AGPL):** Next.Panel is a server control panel. Under
AGPL, an operator exposing it over a network must publish their modifications;
that is a legitimate model, but it conflicts with the stated goal of letting
hosts — including commercial VPS providers — run and integrate the panel
freely. The security posture of this project also benefits from broad peer
review, which a permissive license maximises.

**Why not Apache-2.0:** Apache-2.0's explicit patent grant is genuinely
valuable, and it was the second candidate. MIT was chosen because every
dependency is already MIT/BSD/ISC/Apache-2.0, so no relicensing pressure
exists either way, and MIT keeps the compliance story to a single paragraph
that downstream packagers rarely rewrite. The project may be dual-licensed or
moved to Apache-2.0 later if a patent grant becomes important; that is a
governance decision, not something a dependency forces today.

**Why MIT-0 for our own code is not used:** MIT's attribution condition is
desirable — redistributors must retain the notice — so plain MIT it is.

## Dependency license inventory

Generated from the modules actually linked into the binary
(`go list -deps -f '{{.Module}}' ./...`), not from the wider module graph.

| Module | License |
|---|---|
| `github.com/go-chi/chi/v5` | MIT |
| `github.com/jackc/pgx/v5` | MIT |
| `github.com/jackc/pgpassfile` | MIT |
| `github.com/jackc/pgservicefile` | MIT |
| `github.com/jackc/puddle/v2` | MIT |
| `github.com/mfridman/interpolate` | MIT |
| `github.com/ncruces/go-sqlite3` | MIT |
| `github.com/ncruces/go-sqlite3-wasm/v6` | MIT-0 |
| `github.com/ncruces/julianday` | MIT |
| `github.com/pressly/goose/v3` | MIT |
| `github.com/sethvargo/go-retry` | Apache-2.0 |
| `go.uber.org/multierr` | MIT |
| `golang.org/x/sync` | BSD-3-Clause |
| `golang.org/x/sys` | BSD-3-Clause |
| `golang.org/x/text` | BSD-3-Clause |

Every licence in the inventory is permissive (MIT, MIT-0, BSD-3-Clause or
Apache-2.0); all are compatible with distributing this project under MIT. No
copyleft, share-alike, or network-use licence is present in the linked set.
The wider module graph also contains only permissive licences (Go's own BSD-3
toolchain, plus MIT/BSD/Apache dependencies of `goose`).

## Build-time and development-only tools

These tools are never linked into or distributed with the binary, so their
licences create no obligation for this project's consumers:

| Tool | Licence | Use |
|---|---|---|
| `sqlc` | MIT | Code generation (`sqlc.yaml`), output committed to this repository |
| `golangci-lint` | GPL-3.0 (with the Go `runtime exception`) | CI/static analysis only; invoked as a separate executable, never imported |
| Go toolchain | BSD-3-Clause | Build and test |

If a future dependency carries a licence that is incompatible with MIT (for
example GPL without the runtime exception in a linked library), it must not be
added; §98 requires the licence question to be answered before adoption.

## Adding a dependency

1. Confirm it is maintained, minimal, and justified (Design Spec §98).
2. Read its `LICENSE` in the module cache: `go mod download <module>` then
   open `$(go env GOMODCACHE)/<module>@<version>/LICENSE`.
3. Add it to the table above when it lands in the linked set.
4. Only permissive licences (MIT, ISC, BSD, Apache-2.0, MPL-2.0 as file-level
   copyleft) may be linked; anything else needs an explicit, written decision
   recorded in this file.
