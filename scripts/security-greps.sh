#!/usr/bin/env bash
# CI security greps (Design Spec §28.6).
#
# Every pattern listed in §28.6 is grepped across first-party source; any hit
# fails the build. Failures are fixed, never muted: the pattern list is only
# ever extended, and a false positive is resolved by restructuring the code,
# not by deleting the check.

set -uo pipefail

cd "$(dirname "$0")/.."

targets=()
for d in cmd internal web frontend src scripts; do
  [ -d "$d" ] && targets+=("$d")
done

if [ "${#targets[@]}" -eq 0 ]; then
  echo "security-greps: no source directories to scan"
  exit 0
fi

fail=0

check() {
  local label="$1" pattern="$2"
  local hits
  hits=$(grep -rInE --exclude=security-greps.sh --exclude-dir=node_modules --exclude-dir=dist -i -e "$pattern" "${targets[@]}" || true)
  if [ -n "$hits" ]; then
    echo "::error::security grep failed: ${label}"
    printf '%s\n' "$hits"
    fail=1
  fi
}

# ssh: no opt-out host key verification.
check "host key verification disabled" 'ssh\.InsecureIgnoreHostKey'

# hardcoded credential literals: an exact password-ish identifier assigned a
# non-empty string literal (PasswordHash: "…" and ActionPasswordChanged = "…"
# are not credentials and do not match; neither is an empty initializer such
# as password: '', which carries no secret).
check "hardcoded credential literal" '\<(password|passwd|pwd)\>[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']'

# private keys committed to the tree: a PEM header on its own line (a quoted
# marker inside a log-redaction fixture is not key material).
check "private key material" '^[[:space:]]*-----BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY-----[[:space:]]*$'

# raw HTML injection (frontend).
check "dangerouslySetInnerHTML" 'dangerouslySetInnerHTML'

# shell invocation with a non-constant command string.
check "shell invocation with non-constant command" 'exec\.Command\("(sh|bash|zsh)",[[:space:]]*"-c",[[:space:]]*[^"]'

# shell invocation of a constructed command string.
check "shell invocation of constructed command" 'exec\.Command\([^)]*fmt\.Sprintf'

# SQL built by string concatenation.
check "SQL built by string concatenation" '(select|insert|update|delete)[^"]*"[[:space:]]*\+|\+[[:space:]]*"[^"]*(select|insert|update|delete)'

if [ "$fail" -ne 0 ]; then
  echo "security-greps: forbidden patterns found (Design Spec §28.6)"
  exit 1
fi

echo "security-greps: clean"
