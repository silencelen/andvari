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

echo "==> starting server (pid capture)"
start_server
wait_health
echo "    healthy at $BASE"

echo "==> PHASE A: enroll + push + WebSocket propagation"
(cd "$REPO_DIR/web" && ANDVARI_E2E="$BASE" ANDVARI_E2E_PHASE=a ANDVARI_E2E_STATE="$STATE" \
  ANDVARI_E2E_BOOTSTRAP="$BOOTSTRAP" npx vitest run src/e2e/live.e2e.test.ts 2>&1) | tail -15

echo "==> SIGKILL the server mid-life, then restart on the SAME db (crash simulation)"
kill -9 "$SRV_PID"; wait "$SRV_PID" 2>/dev/null || true
start_server
wait_health
echo "    server restarted, db survived"

echo "==> PHASE B: replay same mutationId (idempotent) + continue"
(cd "$REPO_DIR/web" && ANDVARI_E2E="$BASE" ANDVARI_E2E_PHASE=b ANDVARI_E2E_STATE="$STATE" \
  ANDVARI_E2E_BOOTSTRAP="$BOOTSTRAP" npx vitest run src/e2e/live.e2e.test.ts 2>&1) | tail -15

echo "==> E2E PASSED: WebSocket propagation + crash-durable idempotency"
