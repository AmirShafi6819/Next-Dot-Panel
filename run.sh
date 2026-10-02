#!/bin/sh
# Next.Panel local launcher (Linux/macOS).
#
# Checks dependencies, builds the frontend (if Node is available) and the
# backend, prepares a local .env on first run, and starts the panel.
# Safe: never overwrites an existing .env, never touches ./data.

set -eu

cd "$(dirname "$0")"

die() { echo "error: $1" >&2; exit 1; }
info() { echo "--> $1"; }

# 1. Go is required.
command -v go >/dev/null 2>&1 || die "Go 1.26+ is required but 'go' was not found.
Install it from https://go.dev/dl/ and re-run ./run.sh"

# 2. Frontend: build only when dist is missing and npm exists.
if [ ! -f web/dist/index.html ]; then
  if command -v npm >/dev/null 2>&1; then
    info "building the web UI (npm install && npm run build)…"
    (cd web && npm install --no-audit --no-fund && npm run build) \
      || die "frontend build failed; see the npm output above"
  else
    info "WARNING: Node/npm not found and web/dist is missing — starting API-only."
    info "Install Node 20+ from https://nodejs.org/ and re-run to get the web UI."
  fi
else
  info "web UI already built."
fi

# 3. Backend.
info "building the backend…"
go build -o nextpanel ./cmd/nextpanel || die "go build failed"

# 4. Configuration: create .env from the template on first run only.
if [ ! -f .env ]; then
  info "creating .env from .env.example (first run only)…"
  cp .env.example .env
fi

# 5. Encryption key: generate one only when neither the environment nor .env has it.
if [ -z "${NEXT_PANEL_ENCRYPTION_KEY:-}" ] && ! grep -q '^NEXT_PANEL_ENCRYPTION_KEY=.' .env; then
  info "generating NEXT_PANEL_ENCRYPTION_KEY…"
  KEY="$(./nextpanel crypto generate-key)" || die "key generation failed"
  if grep -q '^NEXT_PANEL_ENCRYPTION_KEY=$' .env; then
    # Replace the empty template line (portable sed, no backup file).
    TMPENV="$(mktemp)"; trap 'rm -f "$TMPENV"' EXIT INT TERM
    sed "s|^NEXT_PANEL_ENCRYPTION_KEY=$|NEXT_PANEL_ENCRYPTION_KEY=${KEY}|" .env > "$TMPENV"
    cat "$TMPENV" > .env
    rm -f "$TMPENV"; trap - EXIT INT TERM
  else
    printf '\nNEXT_PANEL_ENCRYPTION_KEY=%s\n' "$KEY" >> .env
  fi
  info "wrote a fresh encryption key to .env — back it up separately from ./data."
fi

# 6. Export .env into the environment (the file is the configuration source).
set -a
# shellcheck disable=SC1091
. ./.env
set +a

PORT="${NEXT_PANEL_LISTEN##*:}"
case "$PORT" in ''|*[!0-9]*) PORT="8080" ;; esac

info "starting Next.Panel — open http://localhost:${PORT}"
exec ./nextpanel
