#!/usr/bin/env bash
# Automated account-recovery drill (docs/drills/account-recovery-drill.md, ROADMAP step 6):
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
LOCK=/tmp/andvari-gradle.lock

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
(cd "$REPO_DIR/web" && ANDVARI_DRILL="$BASE" ANDVARI_DRILL_BOOTSTRAP="$BOOTSTRAP" \
  ANDVARI_DRILL_SEED="$SEED" ANDVARI_DRILL_RECOVERY_JAR="$RECOVERY_JAR" ANDVARI_DRILL_WORK="$WORK" \
  npx vitest run src/e2e/recovery-drill.e2e.test.ts 2>&1) | tail -30

echo "==> RECOVERY DRILL PASSED: escrow → recover → apply → temp login → forced change → data intact"
