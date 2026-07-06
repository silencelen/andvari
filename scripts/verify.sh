#!/usr/bin/env bash
# andvari verify — the local CI gate. Runs BOTH implementations' test suites off
# the same spec/test-vectors files. Every ship path must pass this first.
# Gradle invocations are flock-serialized per house norm (8-12 GB build hosts).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK=/tmp/andvari-gradle.lock

echo "==> Kotlin: :core JVM tests (RFC pins + vector consumption)"
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :core:jvmTest --console=plain -q)

echo "==> TypeScript: web vitest (RFC pins + vector consumption) + typecheck"
(cd "$REPO_DIR/web" && npx vitest run --silent && npx tsc --noEmit)

echo "==> verify: BOTH implementations green off spec/test-vectors"
