#!/usr/bin/env bash
# Self-test for scripts/ci/doc-leak-scan.sh (H109, docs/design/2026-09-13-full-surface-audit.md).
#
# The §5.5 prose gate was widened from three hand-picked literals to address CLASSES and the
# operator's machine names, and its scope grew to include the normative spec/. A widened pattern
# that nobody proves still fires is exactly the shape of the defect being fixed — the previous
# version was described in a release note as covering "the whole public tree" while it read six
# paths for three strings. So: every fixtures/doc-leak/fail-* root MUST trip the scanner (exit 1),
# every pass-* root MUST come back clean (exit 0), and the live tree MUST be clean.
#
# Usage: scripts/ci/doc-leak-scan.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$HERE/../.." && pwd)"
SCAN="$HERE/doc-leak-scan.sh"
FIXTURES="$HERE/fixtures/doc-leak"

fails=0 ran=0
expect() {  # expect <want-exit> <label> <root>
  local want="$1" label="$2" root="$3" out rc
  out=$(bash "$SCAN" "$root" 2>&1); rc=$?
  ran=$((ran + 1))
  if [ "$rc" = "$want" ]; then
    echo "  ok   $label (exit $rc)"
  else
    echo "  FAIL $label: wanted exit $want, got $rc" >&2
    printf '%s\n' "$out" | sed 's/^/       /' >&2
    fails=$((fails + 1))
  fi
}

echo "==> doc-leak scan self-test"
shopt -s nullglob
for d in "$FIXTURES"/fail-*/; do expect 1 "trips on ${d#"$FIXTURES"/}" "${d%/}"; done
for d in "$FIXTURES"/pass-*/; do expect 0 "passes ${d#"$FIXTURES"/}" "${d%/}"; done
# Scanning nothing must not pass: an empty scope exiting 0 is the collected-nothing trap that
# scripts/verify.sh calls out for `node --test`, and a gate is the last place to repeat it.
empty=$(mktemp -d); expect 1 "refuses a root with none of the scoped paths" "$empty"; rmdir "$empty"
expect 1 "refuses a missing root" "$FIXTURES/does-not-exist"
# The fixtures are only worth their bytes if the real tree is held to the same scanner.
expect 0 "live tree is clean" "$REPO_DIR"

# Floors, so a deleted fixture cannot silently shrink the claim this test makes.
n_fail=$(find "$FIXTURES" -maxdepth 1 -type d -name 'fail-*' | wc -l)
n_pass=$(find "$FIXTURES" -maxdepth 1 -type d -name 'pass-*' | wc -l)
if [ "$n_fail" -lt 5 ] || [ "$n_pass" -lt 2 ]; then
  echo "  FAIL fixture floor: $n_fail fail-* / $n_pass pass-* dirs, expected at least 5/2 — did a fixture get deleted?" >&2
  fails=$((fails + 1)); ran=$((ran + 1))
fi

if [ "$fails" -ne 0 ]; then
  echo "==> doc-leak scan self-test: $fails of $ran checks FAILED" >&2
  exit 1
fi
echo "==> doc-leak scan self-test: $ran checks pass"
