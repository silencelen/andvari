#!/usr/bin/env bash
# andvari verify — the local CI gate. Runs BOTH implementations' test suites off
# the same spec/test-vectors files. Every ship path must pass this first.
# Gradle invocations are flock-serialized per house norm (8-12 GB build hosts).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK=/tmp/andvari-gradle.lock

echo "==> Kotlin: :core + :server + recovery-cli tests (RFC pins, vectors, full server integration)"
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :core:jvmTest :server:test :tools:recovery-cli:test --console=plain -q)

echo "==> Android: :app-android:assembleDebug (the only compile gate for the app/autofill glue)"
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :app-android:assembleDebug --console=plain -q)

echo "==> TypeScript: web vitest (RFC pins + vector consumption) + typecheck"
(cd "$REPO_DIR/web" && npx vitest run --silent && npx tsc --noEmit)

echo "==> verify: Kotlin + TypeScript green off the same spec/test-vectors; server + crypto suites pass"
echo "    (run scripts/e2e.sh for the live server + WebSocket + crash-idempotency E2E)"
