#!/usr/bin/env bash
# Automated account-recovery drill (spec 04 §4, ROADMAP step 6):
# stands up a scratch server with a recovery keypair generated for THIS run (the seed stands in
# for the printed sheet — we can't drive the live org key without the owner's physical sheet),
# then drives the full spec 04 §4 forgot-master-password path end to end with the REAL
# recovery-cli jar + real web client code. Proves the machinery between the sheet and a working
# account is sound (incl. the PRC-1 bundle-accepted-as-is fix). Nothing here touches prod.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d /tmp/andvari-drill.XXXXXX)"
DB="$WORK/andvari.db"
PORT=8098
BASE="http://127.0.0.1:$PORT"
BOOTSTRAP="drill-bootstrap-$$"
LOCK="${ANDVARI_GRADLE_LOCK:-/tmp/andvari-gradle.lock}"

cleanup() { [ -n "${SRV_PID:-}" ] && kill -9 "$SRV_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

echo "==> building server + recovery-cli shadowJars"
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :server:shadowJar :tools:recovery-cli:shadowJar -q)
SERVER_JAR="$(ls "$REPO_DIR"/server/build/libs/andvari-server*.jar | head -1)"
RECOVERY_JAR="$(ls "$REPO_DIR"/tools/recovery-cli/build/libs/andvari-recovery-cli*.jar | head -1)"

echo "==> recovery-cli keygen (the SEED stands in for the printed sheet)"
KEYGEN="$(java -jar "$RECOVERY_JAR" keygen 2>/dev/null)"
SEED="$(echo "$KEYGEN" | grep -A1 'Recovery seed (base64url)' | tail -1 | tr -d ' ')"
PUBKEY="$(echo "$KEYGEN" | grep 'ANDVARI_RECOVERY_PUBKEY=' | head -1 | cut -d= -f2)"
FINGERPRINT="$(echo "$KEYGEN" | grep 'ANDVARI_RECOVERY_FINGERPRINT=' | head -1 | cut -d= -f2)"
[ -n "$SEED" ] && [ -n "$PUBKEY" ] && [ -n "$FINGERPRINT" ] || { echo "keygen parse failed"; exit 1; }
echo "    recovery fingerprint ${FINGERPRINT:0:16}…"

echo "==> starting scratch server"
ANDVARI_HOST=127.0.0.1 ANDVARI_PORT=$PORT ANDVARI_DB="$DB" ANDVARI_BLOB_DIR="$WORK/blobs" \
  ANDVARI_RECOVERY_PUBKEY="$PUBKEY" ANDVARI_RECOVERY_FINGERPRINT="$FINGERPRINT" \
  ANDVARI_ENUM_SECRET="$(head -c32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')" \
  ANDVARI_BOOTSTRAP_TOKEN="$BOOTSTRAP" \
  java -jar "$SERVER_JAR" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 50); do curl -sf "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
curl -sf "$BASE/healthz" >/dev/null 2>&1 || { echo "server did not become healthy; log:"; cat "$WORK/server.log"; exit 1; }
echo "    healthy at $BASE"

echo "==> running the account-recovery drill (real recovery-cli jar + real web client)"
# The banner below is a claim that an escrow → recover → apply test RAN and passed, so it is gated
# on vitest's own count, not on its exit code: a drill whose test body was skipped (a skipIf on a
# missing env value, an it.skip, a rename) exits 0 having proved nothing. Same floor as e2e.sh's
# run_phase (audit H96); the whole log is printed on failure, not the last 30 lines.
DRILL_LOG="$WORK/drill.log"
rc=0
(cd "$REPO_DIR/web" && ANDVARI_DRILL="$BASE" ANDVARI_DRILL_BOOTSTRAP="$BOOTSTRAP" \
  ANDVARI_DRILL_SEED="$SEED" ANDVARI_DRILL_RECOVERY_JAR="$RECOVERY_JAR" ANDVARI_DRILL_WORK="$WORK" \
  npx vitest run src/e2e/recovery-drill.e2e.test.ts) >"$DRILL_LOG" 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
  cat "$DRILL_LOG" >&2
  echo "==> RECOVERY DRILL FAILED (vitest exit $rc) — full output above" >&2
  exit 1
fi
passed=$(grep -oE 'Tests[[:space:]]+[0-9]+ passed' "$DRILL_LOG" | head -1 | grep -oE '[0-9]+' | head -1) || true
if [ "${passed:-0}" -lt 1 ]; then
  cat "$DRILL_LOG" >&2
  echo "==> RECOVERY DRILL COLLECTED NOTHING: vitest reported ${passed:-0} passing tests." >&2
  echo "    A drill that runs no test is not a drill that passed — refusing the banner." >&2
  exit 1
fi
tail -30 "$DRILL_LOG"

echo "==> RECOVERY DRILL PASSED ($passed test(s)): escrow → recover → apply → temp login → forced change → data intact"
