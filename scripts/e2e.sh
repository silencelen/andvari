#!/usr/bin/env bash
# Local end-to-end: real server (shadowJar) + real web client code + real WebSocket,
# across a SIGKILL to prove crash-durable idempotency (P1 verification gate).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d /tmp/andvari-e2e.XXXXXX)"
DB="$WORK/andvari.db"
STATE="$WORK/state.json"
PORT=8099
BASE="http://127.0.0.1:$PORT"
BOOTSTRAP="e2e-bootstrap-$$"
LOCK=/tmp/andvari-gradle.lock

cleanup() { [ -n "${SRV_PID:-}" ] && kill -9 "$SRV_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

echo "==> building server + recovery-cli shadowJars"
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :server:shadowJar :tools:recovery-cli:shadowJar -q)
SERVER_JAR="$(ls "$REPO_DIR"/server/build/libs/andvari-server*.jar | head -1)"
RECOVERY_JAR="$(ls "$REPO_DIR"/tools/recovery-cli/build/libs/andvari-recovery-cli*.jar | head -1)"

echo "==> escrow ceremony (recovery-cli keygen)"
KEYGEN="$(java -jar "$RECOVERY_JAR" keygen 2>/dev/null)"
PUBKEY="$(echo "$KEYGEN" | grep 'ANDVARI_RECOVERY_PUBKEY=' | head -1 | cut -d= -f2)"
FINGERPRINT="$(echo "$KEYGEN" | grep 'ANDVARI_RECOVERY_FINGERPRINT=' | head -1 | cut -d= -f2)"
echo "    recovery pubkey pinned, fingerprint ${FINGERPRINT:0:16}…"

start_server() {
  ANDVARI_HOST=127.0.0.1 ANDVARI_PORT=$PORT ANDVARI_DB="$DB" \
    ANDVARI_BLOB_DIR="$WORK/blobs" \
    ANDVARI_RECOVERY_PUBKEY="$PUBKEY" ANDVARI_RECOVERY_FINGERPRINT="$FINGERPRINT" \
    ANDVARI_ENUM_SECRET="$(head -c32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')" \
    ANDVARI_BOOTSTRAP_TOKEN="$BOOTSTRAP" \
    java -jar "$SERVER_JAR" >"$WORK/server.log" 2>&1 &
  SRV_PID=$!
}

wait_health() {
  for _ in $(seq 1 50); do
    curl -sf "$BASE/healthz" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "server did not become healthy; log:"; cat "$WORK/server.log"; exit 1
}

# ---- phase runner ------------------------------------------------------------
# Each phase used to be `(... npx vitest ...) | tail -15`, and the banner at the bottom printed
# unconditionally. That lied in two ways at once (audit H96):
#
#   1. The phases were selected by an early `return` INSIDE the test body, so vitest counted the
#      two phases that were not selected as PASSES: every phase printed "Tests  3 passed (3)"
#      while running exactly one of them. The test file now uses `it.runIf(PHASE === …)`, so a
#      phase reports `1 passed | 2 skipped` — which is a number worth asserting.
#   2. Nothing asserted that any phase actually executed. `describe.skipIf(!BASE)` skipping the
#      whole file, an unknown ANDVARI_E2E_PHASE, or a rename that makes the glob match nothing
#      would all leave "E2E PASSED" on the screen having proved nothing — the exact
#      collected-nothing-exits-0 trap scripts/verify.sh guards the extension leg against.
#
# So: run each phase into its own log, require the runner to report at least one PASSING test,
# count the phases that cleared that floor, and refuse the final banner unless all three did.
# The log also replaces `tail -15`: on failure the whole thing is printed, because a truncated
# assertion message is the one line you needed.
PHASES_RUN=0
run_phase() {
  local phase="$1" title="$2"
  local log="$WORK/phase-$phase.log" rc=0 passed=""
  echo "==> PHASE $(printf '%s' "$phase" | tr '[:lower:]' '[:upper:]'): $title"
  if (cd "$REPO_DIR/web" && ANDVARI_E2E="$BASE" ANDVARI_E2E_PHASE="$phase" ANDVARI_E2E_STATE="$STATE" \
        ANDVARI_E2E_BOOTSTRAP="$BOOTSTRAP" npx vitest run src/e2e/live.e2e.test.ts) >"$log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    echo "    PHASE $phase FAILED (vitest exit $rc) — full output follows:" >&2
    cat "$log" >&2
    exit 1
  fi
  # vitest summary line: "Tests  1 passed | 2 skipped (3)". No "N passed" at all means the whole
  # file was skipped (no BASE) or nothing was collected — a green exit code that proves nothing.
  passed=$(grep -oE 'Tests[[:space:]]+[0-9]+ passed' "$log" | head -1 | grep -oE '[0-9]+' | head -1) || true
  if [ "${passed:-0}" -lt 1 ]; then
    cat "$log" >&2
    echo "    PHASE $phase COLLECTED NOTHING: vitest reported ${passed:-0} passing tests." >&2
    echo "    A phase that runs no test is not a phase that passed — refusing to continue." >&2
    exit 1
  fi
  tail -15 "$log"
  PHASES_RUN=$((PHASES_RUN + 1))
}

echo "==> starting server (pid capture)"
start_server
wait_health
echo "    healthy at $BASE"

run_phase a "enroll + push + WebSocket propagation"

echo "==> SIGKILL the server mid-life, then restart on the SAME db (crash simulation)"
kill -9 "$SRV_PID"; wait "$SRV_PID" 2>/dev/null || true
start_server
wait_health
echo "    server restarted, db survived"

run_phase b "replay same mutationId (idempotent) + continue"

run_phase c "offline durable-cache drills (fake-indexeddb + the SAME surviving server/db)"

# The banner is a claim about three phases, so assert three phases. (Each already proved it ran at
# least one test; this catches a phase deleted from the script or short-circuited past run_phase.)
if [ "$PHASES_RUN" -ne 3 ]; then
  echo "    E2E INCOMPLETE: $PHASES_RUN of 3 phases executed — not printing a pass banner." >&2
  exit 1
fi
echo "==> E2E PASSED: WebSocket propagation + crash-durable idempotency + offline-cache drills ($PHASES_RUN/3 phases, each with a passing test)"
