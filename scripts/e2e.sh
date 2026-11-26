#!/usr/bin/env bash
# The end-to-end run: every web journey (web/src/journeys/) against the real server, driven by the
# web client's own flow modules over real HTTP. Each journey starts its own server in test mode on
# 127.0.0.1 (`andvari setup --test`, with its mail sink and test clock), and the engine's
# command-line module and recovery-cli where a journey needs them, all built here from this working
# copy. Nothing leaves this machine.
#
# A journey that cannot find what it runs skips itself (journeysUnavailable() and
# recoveryCliUnavailable() in web/src/journeys/harness.ts), and vitest does not count a skip as a
# failure. Here a skip IS a failure: the run passes only when every test file under web/src/journeys/
# passed and vitest reports no test skipped. scripts/verify.sh runs the same journeys inside its web
# leg; this runs them alone.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK=/tmp/andvari-gradle.lock

echo "==> building the server, andvari-cli and recovery-cli (installDist)"
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :server:installDist :tools:andvari-cli:installDist \
  :tools:recovery-cli:installDist --console=plain -q)

# Each output where harness.ts looks for it, and harness.ts still looking there (the same check
# scripts/verify.sh makes before its TypeScript leg): a moved output fails here, not as a skip.
for p in server/build/install/server/bin/server tools/andvari-cli/build/install/andvari-cli/lib \
         tools/recovery-cli/build/install/recovery-cli/bin/recovery-cli; do
  if ! grep -qF "\"$p\"" "$REPO_DIR/web/src/journeys/harness.ts"; then
    echo "    E2E: web/src/journeys/harness.ts no longer reads $p — point this check at what it reads now." >&2
    exit 1
  fi
  if [ ! -e "$REPO_DIR/$p" ]; then
    echo "    E2E: $p is missing after the build (its installDist task builds it); the journeys would skip." >&2
    exit 1
  fi
done

FILES=$(find "$REPO_DIR/web/src/journeys" -maxdepth 1 -name '*.test.ts' | wc -l)
JOURNEYS=$(find "$REPO_DIR/web/src/journeys" -maxdepth 1 -name '*.journey.test.ts' | wc -l)
if [ "$JOURNEYS" -lt 1 ]; then
  echo "    E2E: no *.journey.test.ts under web/src/journeys — nothing to run." >&2
  exit 1
fi

echo "==> running $FILES test files under web/src/journeys ($JOURNEYS journeys); the output is printed when the run ends"
rc=0
OUT=$(cd "$REPO_DIR/web" && NO_COLOR=1 npx vitest run src/journeys --testTimeout 300000 2>&1) || rc=$?
printf '%s\n' "$OUT"
if [ "$rc" -ne 0 ]; then
  echo "==> E2E FAILED (vitest exit $rc)" >&2
  exit 1
fi

# Nothing skipped. vitest's summary reads "Test Files  N passed (N)" and "Tests  M passed (M)" only
# when every file and every test passed; a skip adds "| K skipped" to the line. A journey that skips
# itself also prints why (the console.warn of harness.ts), so that text is refused as well.
files_line=$(printf '%s\n' "$OUT" | grep -m1 -E '^[[:space:]]*Test Files[[:space:]]') || true
tests_line=$(printf '%s\n' "$OUT" | grep -m1 -E '^[[:space:]]*Tests[[:space:]]') || true
re_files='^[[:space:]]*Test Files[[:space:]]+([0-9]+) passed \(([0-9]+)\)[[:space:]]*$'
re_tests='^[[:space:]]*Tests[[:space:]]+([0-9]+) passed \(([0-9]+)\)[[:space:]]*$'
skipped=""
if [[ "$files_line" =~ $re_files ]] && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] \
   && [ "${BASH_REMATCH[1]}" -eq "$FILES" ]; then
  :
else
  skipped="the files line is \"${files_line:-<none>}\", not \"Test Files  $FILES passed ($FILES)\""
fi
if [ -z "$skipped" ]; then
  if [[ "$tests_line" =~ $re_tests ]] && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] \
     && [ "${BASH_REMATCH[1]}" -ge 1 ]; then
    TESTS="${BASH_REMATCH[1]}"
  else
    skipped="the tests line is \"${tests_line:-<none>}\", not every test passed"
  fi
fi
if [ -z "$skipped" ] && printf '%s\n' "$OUT" | grep -qE 'journeys skipped:|build the offline tool first'; then
  skipped="a journey printed that it skips itself"
fi
if [ -n "$skipped" ]; then
  echo "==> E2E INCOMPLETE: $skipped. A journey that did not run is not a journey that passed." >&2
  exit 1
fi

echo "==> E2E PASSED: $FILES test files ($JOURNEYS journeys), $TESTS tests, none skipped"
