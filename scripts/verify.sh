#!/usr/bin/env bash
# andvari verify — the local CI gate. Runs BOTH implementations' test suites off
# the same spec/test-vectors files. Every ship path must pass this first.
# Gradle invocations are flock-serialized per house norm (8-12 GB build hosts).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK=/tmp/andvari-gradle.lock

echo "==> Release-version consistency (one source of truth: ANDVARI_CLIENT_VERSION)"
# 0.4.0 shipped with SERVER_VERSION and DESKTOP_VERSION still hardcoded to 0.3.0. Those
# Kotlin constants now alias the core const; the Gradle-side literals (android versionName,
# desktop packageVersion) can't import it, so assert they match here — one skew fails the gate.
CORE_VER=$(grep -oE 'ANDVARI_CLIENT_VERSION = "[^"]+"' "$REPO_DIR/core/src/commonMain/kotlin/io/silencelen/andvari/core/client/AndvariApi.kt" | grep -oE '"[^"]+"' | tr -d '"')
AND_VER=$(grep -oE 'versionName = "[^"]+"' "$REPO_DIR/app-android/build.gradle.kts" | grep -oE '"[^"]+"' | tr -d '"')
DESK_VER=$(grep -oE 'packageVersion = "[^"]+"' "$REPO_DIR/app-desktop/build.gradle.kts" | grep -oE '"[^"]+"' | tr -d '"')
WEB_VER=$(grep -oE 'CLIENT_VERSION = "[^"]+"' "$REPO_DIR/web/src/api/client.ts" | grep -oE '"[^"]+"' | tr -d '"')
if [ "$CORE_VER" != "$AND_VER" ] || [ "$CORE_VER" != "$DESK_VER" ] || [ "$CORE_VER" != "$WEB_VER" ]; then
  echo "    VERSION SKEW: core=$CORE_VER android=$AND_VER desktop=$DESK_VER web=$WEB_VER — bump all to match." >&2
  exit 1
fi
echo "    all clients report $CORE_VER"

echo "==> Kotlin: :core + :server + recovery-cli tests (RFC pins, vectors, full server integration)"
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :core:jvmTest :server:test :tools:recovery-cli:test --console=plain -q)

echo "==> Android: :app-android:assembleDebug (the only compile gate for the app/autofill glue)"
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :app-android:assembleDebug --console=plain -q)

echo "==> TypeScript: web vitest (RFC pins + vector consumption) + typecheck"
(cd "$REPO_DIR/web" && npx vitest run --silent && npx tsc --noEmit)

echo "==> verify: Kotlin + TypeScript green off the same spec/test-vectors; server + crypto suites pass"
echo "    (run scripts/e2e.sh for the live server + WebSocket + crash-idempotency E2E)"
