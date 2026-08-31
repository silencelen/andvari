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
# web/package.json sat at a never-maintained 0.0.1 until 0.21.0 (audit hygiene-docs--14). Nothing
# reads it — but a version literal nobody checks is exactly how the other four drifted, so now
# that it carries a real number it joins the gate rather than becoming the next stale one.
PKG_VER=$(lit 'package.json version' "$REPO_DIR/web/package.json" '"version"[[:space:]]*:[[:space:]]*"[^"]+"')
if [ "$CORE_VER" != "$AND_VER" ] || [ "$CORE_VER" != "$DESK_VER" ] || [ "$CORE_VER" != "$WEB_VER" ] || [ "$CORE_VER" != "$PKG_VER" ]; then
  echo "    VERSION SKEW: core=$CORE_VER android=$AND_VER desktop=$DESK_VER web=$WEB_VER pkg=$PKG_VER — bump all to match." >&2
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

# The extension rides its OWN version track (separate store review cadence), so it is never equated
# with the fleet. Its three hand-edited literals are held in lockstep by extension/src/version.test.ts,
# which the extension leg below runs — no need to re-assert that here.
EXT_VER=$(lit '"version"' "$REPO_DIR/extension/manifest.json" '"version"[[:space:]]*:[[:space:]]*"[^"]+"')

# ...but merely PRINTING it is what let the paperwork rot (audit F41): the 0.21.0 heading still read
# "extension 0.20.0" after the extension had shipped 0.20.1 and 0.21.0 into that very section, because
# only the fleet number was ever asserted. So the top heading must NAME the shipped extension version
# too. Read from the first `## ` line whatever its shape — a fleet cut ("· fleet 0.21.0, extension
# 0.21.0") and an extension-only cut ("## extension 0.19.0 … · fleet unchanged at 0.20.0") both carry
# it right there. The bounded [^0-9] run tolerates the "unchanged at" phrasing without letting the
# match wander off into the next number on the line.
CHANGELOG_EXT=$(grep -m1 '^## ' "$REPO_DIR/CHANGELOG.md" \
  | grep -oE 'extension[^0-9]{0,24}[0-9]+\.[0-9]+\.[0-9]+' \
  | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | tail -1) || true
if [ "$CHANGELOG_EXT" != "$EXT_VER" ]; then
  echo "    CHANGELOG SKEW: top heading names extension '${CHANGELOG_EXT:-<none>}' but extension/manifest.json is $EXT_VER." >&2
  echo "    Name it in the heading — '· fleet $CORE_VER, extension $EXT_VER' when it shipped, or" >&2
  echo "    '· extension unchanged at $EXT_VER' when it did not. A version nobody asserts is the one that goes stale." >&2
  exit 1
fi
echo "    extension track at $EXT_VER (CHANGELOG heading agrees; its 3 literals in lockstep per extension/src/version.test.ts)"

echo "==> §5.5 endpoint-agnostic docs (no reference-instance hostname in current-facing docs)"
# Published clients bake no tailnet hostname (§5.5 of docs/design/2026-07-15-multi-tenant-endpoints.md,
# "Baked-default swap + tailnet-leak removal"). The client halves of that gate are
# pinned — web/src/ui/Devices.test.ts, extension/src/serverurl.test.ts — but prose had no gate at
# all, which is how a checked-in user guide came to tell strangers the product needs a private
# Tailscale network and hardcoded two of the reference instance's tailnet hosts (audit F30). Docs
# are the surface a stranger reads FIRST, so they are held to the same rule as the clients.
# Scope is the current-facing prose surface: docs/** PLUS the root-level and module prose a
# stranger actually reads first (README, SECURITY, CONTRIBUTING, LICENSING, extension/README) —
# a gate whose rationale names that surface has to scan it, not assume it. Exactly three
# exemptions, each for a stated reason:
#   docs/design/**  — dated point-in-time design records. They describe the pre-pivot tailnet
#                     topology because that is what was true on their date; "fixing" them would
#                     make the history wrong.
#   wave4-endpoint-promotion.md — the tailnet front IS the subject of that migration runbook.
#   CHANGELOG.md    — dated historical entries; a 0.3.x entry legitimately names the pre-pivot
#                     tailnet because that is what shipped then. Exempting the file beats
#                     teaching the gate to date-parse it.
# The guide that triggered this gate is NOT exempt: it was rewritten instance-neutral in the same
# change, and the point of a gate is to hold the file that already got this wrong once.
DOC_LEAKS=$(cd "$REPO_DIR" && grep -rlE 'taila2dff2|\.ts\.net|192\.168\.2\.122' \
    docs README.md SECURITY.md CONTRIBUTING.md LICENSING.md extension/README.md --include='*.md' \
  | grep -vE '^docs/design/|^docs/runbooks/wave4-endpoint-promotion\.md$') || true
if [ -n "$DOC_LEAKS" ]; then
  echo "    §5.5 DOC LEAK: reference-instance hostname baked into current-facing docs:" >&2
  printf '%s\n' "$DOC_LEAKS" | sed 's/^/      /' >&2
  echo "    name the instance generically, or use example.com — docs outlive an endpoint." >&2
  exit 1
fi
echo "    docs + root/module prose carry no reference-instance hostname (3 stated exemptions)"

echo "==> Kotlin: :core + :server + :app-desktop + the tools/ CLIs (RFC pins, vectors, full server integration)"
# :app-desktop:test was missing until 0.20.x — the desktop suites (endpoint-switch token isolation,
# originKey byte-parity, trust gate) had gone 2.5 days stale behind HEAD and, worse, the module was
# never even COMPILED by the gate: a desktop-only regression once got through and was caught by a
# hand-run :app-desktop:classes. `test` compiles it transitively, so that hole closes with it.
#
# :tools:backup-cli and :tools:update-signer were the same hole, found again (audit F39). Nothing
# in the build depends on them — `grep -rn 'project(":tools' --include=*.kts` is empty — so neither
# their main nor their test sources were compiled by any automated path, and 16 real tests sat inert
# behind a green banner: the extractor's path-separator sanitizer (`..\..\pwn.bin` must not escape
# outDir), the dump-redacts-secrets default, the no-network-classes-on-the-classpath assert for an
# offline tool, and update-signer's 0600-and-refuse-to-clobber guards over the ONE copy of the H2
# Ed25519 release-signing root. The harm had already materialized: backup-cli's TestBackups.kt was
# edited 2026-07-16 and had never once been through a compiler in this clone.
#
# :tools:vector-gen ships no suite, so it joins by `classes` — it authors 16 of the 22 shared
# vector files, and a generator that no longer compiles is a generator nobody can regenerate from.
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :core:jvmTest :server:test :app-desktop:test \
  :tools:recovery-cli:test :tools:backup-cli:test :tools:update-signer:test :tools:vector-gen:classes \
  --console=plain -q)

echo "==> Android: :app-android:testDebugUnitTest (originKey byte-parity pins) + assembleDebug (app/autofill compile gate)"
(cd "$REPO_DIR" && flock "$LOCK" ./gradlew :app-android:testDebugUnitTest :app-android:assembleDebug --console=plain -q)

echo "==> TypeScript: web vitest (RFC pins + vector consumption) + typecheck"
(cd "$REPO_DIR/web" && npx vitest run --silent && npx tsc --noEmit)

echo "==> Extension: typecheck + node --test (the LIVE browser fill path runs the same shared vectors)"
# `node --test` EXITS 0 WHEN IT COLLECTED NOTHING. Probed on the node this gate runs (v22.23.1):
# `node --test "src/**/*.nosuchtest.ts"` and `node --test "test/**/*.test.ts"` (wrong directory)
# both print `1..0` and exit 0. vitest, one leg above, fails that same case ("No test files found"),
# so the two JS legs of one gate disagree about what "collected nothing" means — and the one that
# stays quiet is the one guarding the browser. Move the suites to a sibling test/ dir (the layout
# every other module uses), rename them off *.test.ts, or land on a node whose glob semantics
# shifted, and all 271 extension tests leave the gate with the final green banner still printing —
# including the extension's ONLY cross-engine crypto proof (crypto.vectors.test.ts) and its entire
# signed-update suite (updateverify.test.ts). Neither the file count nor the runner's own count is
# something the exit code will tell you, so assert both. Floors are set well under the current
# 23 files / 271 tests: they catch a suite that vanished, not one that was pruned.
EXT_FILES=$(find "$REPO_DIR/extension/src" -maxdepth 1 -name '*.test.ts' 2>/dev/null | wc -l) || true
if [ "${EXT_FILES:-0}" -lt 20 ]; then
  echo "    EXT SUITE MISSING: ${EXT_FILES:-0} *.test.ts files under extension/src, expected 20+ — did the suites move?" >&2
  exit 1
fi
EXT_OUT=$( (cd "$REPO_DIR/extension" && npm run typecheck && npm test) 2>&1 ) || { printf '%s\n' "$EXT_OUT" >&2; exit 1; }
EXT_PASS=$(printf '%s\n' "$EXT_OUT" | grep -m1 -oE '^# pass [0-9]+' | grep -oE '[0-9]+') || true
if [ "${EXT_PASS:-0}" -lt 200 ]; then
  printf '%s\n' "$EXT_OUT" >&2
  echo "    EXT SUITE NOT COLLECTED: node --test reported ${EXT_PASS:-0} passing tests over $EXT_FILES files, expected 200+ — the glob found (nearly) nothing." >&2
  exit 1
fi
echo "    $EXT_PASS tests passed across $EXT_FILES files"

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
