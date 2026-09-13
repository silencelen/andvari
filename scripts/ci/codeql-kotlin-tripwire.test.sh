#!/usr/bin/env bash
# Self-test for scripts/ci/codeql-kotlin-tripwire.sh (H40, docs/design/2026-09-13-full-surface-audit.md).
#
# The G18 tripwire's first version was verified only against the one shape it had been written
# for; four other ways of re-introducing an empty Kotlin CodeQL leg passed it green, and nothing
# would have said so. This test makes the tripwire's coverage a checked claim: every
# fixtures/codeql-tripwire/fail-* directory MUST trip it (exit 1), every pass-* directory and the
# live .github/workflows/ MUST pass (exit 0). scripts/verify.sh runs this, so a change to the
# tripwire that narrows what it recognises fails the gate rather than the next audit.
#
# Usage: scripts/ci/codeql-kotlin-tripwire.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$HERE/../.." && pwd)"
TRIPWIRE="$HERE/codeql-kotlin-tripwire.sh"
FIXTURES="$HERE/fixtures/codeql-tripwire"

fails=0 ran=0
expect() {  # expect <want-exit> <label> <path…>
  local want="$1" label="$2"; shift 2
  local out rc
  out=$(bash "$TRIPWIRE" "$@" 2>&1); rc=$?
  ran=$((ran + 1))
  if [ "$rc" = "$want" ]; then
    echo "  ok   $label (exit $rc)"
  else
    echo "  FAIL $label: wanted exit $want, got $rc" >&2
    printf '%s\n' "$out" | sed 's/^/       /' >&2
    fails=$((fails + 1))
  fi
}

echo "==> codeql tripwire self-test"
shopt -s nullglob
for d in "$FIXTURES"/fail-*/; do expect 1 "trips on ${d#"$FIXTURES"/}" "$d"; done
for d in "$FIXTURES"/pass-*/; do expect 0 "passes ${d#"$FIXTURES"/}" "$d"; done
# Pointing the tripwire at nothing must not pass vacuously — that is the node --test lesson
# (scripts/verify.sh) applied here.
empty=$(mktemp -d); expect 1 "refuses an empty directory" "$empty"; rmdir "$empty"
expect 1 "refuses a missing path" "$FIXTURES/does-not-exist"
# And the live workflows, the whole point: a fixture pass means nothing if the real dir fails.
expect 0 "live .github/workflows/ is clean" "$REPO_DIR/.github/workflows"

# Floor on the fixture count so a deleted fixture directory cannot silently shrink the claim.
nfail=$(find "$FIXTURES" -maxdepth 1 -type d -name 'fail-*' | wc -l)
if [ "$nfail" -lt 7 ]; then echo "  FAIL: only $nfail fail-* fixtures, expected 7+ — did a fixture go missing?" >&2; fails=$((fails + 1)); fi

if [ "$fails" != 0 ]; then echo "codeql tripwire self-test: $fails of $ran checks FAILED" >&2; exit 1; fi
echo "codeql tripwire self-test: $ran checks passed"
