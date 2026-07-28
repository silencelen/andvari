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
#
# lit <label> <file> <extended-regex> — pull one "quoted" literal out of a source file. A pattern
# that no longer matches (a Kotlin/TS reformat, a moved const) used to kill the script under
# `set -e` with no output at all; now it says WHICH literal went missing. Patterns tolerate
# arbitrary whitespace around the `=` / `:` so a formatter can't silently blind the gate.
lit() {
  local label="$1" file="$2" re="$3" out=""
  [ -f "$file" ] || { echo "    VERSION GATE: missing ${file#"$REPO_DIR"/}" >&2; exit 1; }
  out=$(grep -oE "$re" "$file" | head -1 | grep -oE '"[^"]+"' | tail -1 | tr -d '"') || true
  [ -n "$out" ] || { echo "    VERSION GATE: no $label literal in ${file#"$REPO_DIR"/} (pattern moved?)" >&2; exit 1; }
  printf '%s' "$out"
}

CORE_VER=$(lit ANDVARI_CLIENT_VERSION "$REPO_DIR/core/src/commonMain/kotlin/io/silencelen/andvari/core/client/AndvariApi.kt" 'ANDVARI_CLIENT_VERSION[[:space:]]*=[[:space:]]*"[^"]+"')
AND_VER=$(lit versionName "$REPO_DIR/app-android/build.gradle.kts" 'versionName[[:space:]]*=[[:space:]]*"[^"]+"')
DESK_VER=$(lit packageVersion "$REPO_DIR/app-desktop/build.gradle.kts" 'packageVersion[[:space:]]*=[[:space:]]*"[^"]+"')
WEB_VER=$(lit CLIENT_VERSION "$REPO_DIR/web/src/api/client.ts" 'CLIENT_VERSION[[:space:]]*=[[:space:]]*"[^"]+"')
if [ "$CORE_VER" != "$AND_VER" ] || [ "$CORE_VER" != "$DESK_VER" ] || [ "$CORE_VER" != "$WEB_VER" ]; then
  echo "    VERSION SKEW: core=$CORE_VER android=$AND_VER desktop=$DESK_VER web=$WEB_VER — bump all to match." >&2
  exit 1
fi

# The CHANGELOG heading is release paperwork, and paperwork is what gets skipped: assert the top
# `## <ver>` matches the fleet the tree actually builds, so a bump without an entry (or an entry
# without a bump) fails here instead of at publish time.
CHANGELOG_VER=$(grep -m1 -oE '^## [0-9]+\.[0-9]+\.[0-9]+' "$REPO_DIR/CHANGELOG.md" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+') || true
if [ "$CHANGELOG_VER" != "$CORE_VER" ]; then
  echo "    CHANGELOG SKEW: top heading is '${CHANGELOG_VER:-<none>}' but the fleet is $CORE_VER — add/retitle the entry." >&2
  exit 1
fi
echo "    all clients report $CORE_VER (CHANGELOG heading agrees)"

# The extension rides its OWN version track (separate store review cadence), so it is reported,
# not equated. Its three hand-edited literals are held in lockstep by extension/src/version.test.ts,
# which the extension leg below runs — no need to re-assert that here; the gap this closes is the
# gate never naming the extension version at all.
# (web/package.json's "0.0.1" is deliberately inert: the package is `private: true` and never
# published, so it carries no release meaning and is not gated.)
EXT_VER=$(lit '"version"' "$REPO_DIR/extension/manifest.json" '"version"[[:space:]]*:[[:space:]]*"[^"]+"')
echo "    extension track at $EXT_VER (lockstep of its 3 literals asserted by extension/src/version.test.ts)"

echo "==> Kotlin: :core + :server + :app-desktop + recovery-cli tests (RFC pins, vectors, full server integration)"
# :app-desktop:test was missing until 0.20.x — the desktop suites (endpoint-switch token isolation,
# originKey byte-parity, trust gate) had gone 2.5 days stale behind HEAD and, worse, the module was
# never even COMPILED by the gate: a desktop-only regression once got through and was caught by a
# hand-run :app-desktop:classes. `test` compiles it transitively, so that hole closes with it.
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :core:jvmTest :server:test :app-desktop:test :tools:recovery-cli:test --console=plain -q)

echo "==> Android: :app-android:testDebugUnitTest (originKey byte-parity pins) + assembleDebug (app/autofill compile gate)"
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :app-android:testDebugUnitTest :app-android:assembleDebug --console=plain -q)

echo "==> TypeScript: web vitest (RFC pins + vector consumption) + typecheck"
(cd "$REPO_DIR/web" && npx vitest run --silent && npx tsc --noEmit)

echo "==> Extension: typecheck + node --test (the LIVE browser fill path runs the same shared vectors)"
(cd "$REPO_DIR/extension" && npm run typecheck && npm test)

# Tag state — ADVISORY (never fails the gate; it is offline and says nothing about the code).
# Releases were being tagged from somewhere other than the build host and never fetched back, so
# this clone — the one that runs every release script — could not answer "what is released" from
# its own git state. Surface the drift where the operator is already looking.
if git -C "$REPO_DIR" rev-parse -q --verify "refs/tags/v$CORE_VER" >/dev/null 2>&1; then
  echo "==> tag state: v$CORE_VER present locally"
else
  echo "==> tag state: NO local tag v$CORE_VER"
  echo "    if it was cut elsewhere:  git fetch --tags origin"
  echo "    if it is not cut at all:  git tag -a v$CORE_VER -m 'andvari $CORE_VER' && git push origin v$CORE_VER"
fi

echo "==> verify: Kotlin + TypeScript green off the same spec/test-vectors; server + crypto suites pass"
echo "    (run scripts/e2e.sh for the live server + WebSocket + crash-idempotency E2E)"
