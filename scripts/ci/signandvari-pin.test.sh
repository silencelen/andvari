#!/usr/bin/env bash
# Scratch-repo test for signandvari.ps1's tag verification and last-signed baseline (security review 2026-10, c03
# and its review RF1/RF7).
#
# The signing workstation runs the release tag's tree - its scripts and its gradle build - with the update-signing
# key openable by the same account. So before anything is checked out:
#   * `-Commit <40-hex>` is REQUIRED, and the tag must resolve to exactly that commit;
#   * only the release tag is fetched, never with --force: a release tag that moved is refused, naming both commits,
#     and an UNRELATED tag that moved on the remote does not block the ceremony;
#   * the commit must descend from the last commit this workstation signed (a record outside the repo, under
#     LOCALAPPDATA, written only after a successful ceremony), the changes since then are printed, and a human
#     types the version to confirm. A non-interactive run never gets past that confirmation. On the first run the
#     baseline is the commit in this box's own most recent signed bundle (dist/release-bundle-*/bundle.json beside
#     its manifest.json.sig, highest seq), or an explicit -Baseline, which must be a strict ancestor; a tag is never
#     the seed, and no seed is taken while git tracks anything under dist/ in any case (A14 review R2-3, R2-4; A14
#     review 3, C4);
#   * the review shows EVERY changed path except a short list of trees that never run on the signing box, whose
#     changes are counted instead; build inputs and git attribute files are shown wherever they are (A14 review 3,
#     C1, C3); the stat is printed before the commit list, and then the full diff, printed by signandvari itself
#     before checkout, with git's textconv, external diff and colour off, through no pager but its own (C2); every
#     line taken from git is escaped, a CR included, so a CR cannot fake a line (R2-2, C2);
#   * a tree with two paths that are one file on a case-insensitive disk is refused before checkout; the checkout
#     runs no hook and no LFS smudge, a checkout that leaves the tree dirty is refused, and every reviewed file must
#     then be on disk exactly as git holds it (CRLF from git's own conversion allowed), all before the confirmation
#     (C3); any way out between the checkout and the confirmation puts HEAD back (C5);
#   * what the build host sends back after signing (the drop's sha256sum, the read-back manifest) prints escaped (C6).
#
# This drives the real script under pwsh against a scratch "remote" and a scratch "workstation" clone. The ceremony
# itself needs Windows, signtool and the key, so the scratch tree carries a stub prestige-release.ps1 (it writes a
# bundle recording the pin, or fails on request), a `powershell.exe` on PATH that runs it under pwsh, a placeholder
# signtool, a local HTTP server standing in for the download origin, and (for the drop tests only) `scp`/`ssh` stubs
# that deliver into a local directory and publish a chosen manifest. Confirmations are typed through a pty (`script`),
# the way a human at a console would type them.
#
# Skips (green, loudly) without pwsh, like powershell-gate.sh; needs python3 and util-linux `script` when pwsh is
# present. SIGNANDVARI=<path> points it at another copy of the script (used to show the test failing against the
# pre-fix version); PIN_TEST_LOG=<file> appends every console session's raw output to that file.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
S="${SIGNANDVARI:-$ROOT/scripts/signandvari.ps1}"
command -v pwsh >/dev/null 2>&1 || { echo "    SKIP: pwsh not installed - signandvari tag-pin test not run."; exit 0; }
for tool in python3 script sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "    signandvari tag-pin test needs $tool (pwsh is present)" >&2; exit 1; }
done
REAL_GIT="$(command -v git)"

FAILED=0
fail() { echo "    FAIL: $*" >&2; FAILED=1; }

W="$(mktemp -d)"
SRV_PID=""
cleanup() { [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
g() { git -c user.name=t -c user.email=t@example.invalid -c init.defaultBranch=main -c advice.detachedHead=false "$@"; }

# --- the stand-in download origin: /downloads/manifest.json at seq 5 ----------------------------------------------
mkdir -p "$W/www/downloads"
LIVE='{"seq": 5, "signedAt": "2026-10-01T00:00:00Z"}'
printf '%s\n' "$LIVE" > "$W/www/downloads/manifest.json"
python3 -u -m http.server 0 --bind 127.0.0.1 --directory "$W/www" > "$W/srv.log" 2>&1 &
SRV_PID=$!
PORT=""
for _ in $(seq 1 50); do
  PORT="$(grep -oE 'port [0-9]+' "$W/srv.log" 2>/dev/null | grep -oE '[0-9]+' | head -1)"
  [ -n "$PORT" ] && break
  sleep 0.1
done
[ -n "$PORT" ] || { echo "    could not start the stand-in download origin" >&2; cat "$W/srv.log" >&2; exit 1; }

# --- powershell.exe (the ceremony launcher), a placeholder signtool, and diff tools that must never run -------------
mkdir -p "$W/bin"
printf '#!/bin/sh\nexec pwsh -NoProfile "$@"\n' > "$W/bin/powershell.exe"; chmod 755 "$W/bin/powershell.exe"
printf 'placeholder\n' > "$W/signtool.exe"
printf '#!/bin/sh\necho EXT-DIFF-RAN\n' > "$W/bin/extdiff"; chmod 755 "$W/bin/extdiff"

# --- the drop stubs (scp delivers into $W/drop and, on the signature, publishes $W/publish.json; ssh hashes there) --
mkdir -p "$W/dropbin" "$W/drop"
cat > "$W/dropbin/scp" <<EOF
#!/bin/sh
prev=""; src=""
for a in "\$@"; do src="\$prev"; prev="\$a"; done
cp "\$src" "$W/drop/" || exit 1
case "\$src" in
  *manifest.json.sig)
    sha=\$(sha256sum "$W/drop/andvari-9.9.9.msi" | cut -d' ' -f1)
    sed "s/@MSISHA@/\$sha/" "$W/publish.json" > "$W/www/downloads/manifest.json" ;;
esac
exit 0
EOF
cat > "$W/dropbin/ssh" <<EOF
#!/bin/sh
for a in "\$@"; do last="\$a"; done
name=\$(printf '%s' "\$last" | sed -E "s/.*'\\/drop\\/(.*)'\$/\\1/")
if [ -n "\${SSH_HOSTILE:-}" ]; then printf '\\033[2KDEADBEEF  /drop/%s\\n' "\$name"; exit 0; fi
sha256sum "$W/drop/\$name"
EOF
chmod 755 "$W/dropbin/scp" "$W/dropbin/ssh"

# --- the scratch release history ------------------------------------------------------------------------------------
# P0 (v9.9.0) -> C0 (v9.9.8) -> E1 -> C1 (v9.9.9) -> C2 on main.
#   E1 has a hostile subject (ESC sequences that would hide lines, a bidi override, an 8-bit CSI). It touches a
#   core/src/jvmMain file outside core's crypto (A14 review R2-1) whose content carries ESC sequences and a CR that
#   would fake a "diff --git" header, a case-variant GRADLE.PROPERTIES, a NEW module outside every old allowlist
#   (tools/hook), a web/ file (a tree that never runs on the signing box), git attribute files inside excluded trees,
#   an android build script, and an in-tree hooks directory (A14 review 3, C1-C3).
# S1 (v9.9.10) on a side branch off C0, NOT a descendant of C1.
# K1 (v9.9.11) off C1 adds Scripts/prestige-release.ps1 beside scripts/prestige-release.ps1: one file on NTFS.
# The stub prints "stub ceremony RAN" built at run time, so the string is in its output but never in its source (the
# full diff of scripts/prestige-release.ps1 is printed too).
STUB='param([string]$Version, [string]$Ref, [string]$Commit, [string]$SignToolPath, [switch]$DryRun)
if ($env:STUB_CEREMONY -eq "fail") { Write-Host ("stub " + "ceremony RAN: failing on request"); exit 1 }
if ($DryRun) { Write-Host ("stub " + "ceremony RAN: dry run"); exit 0 }
$d = Join-Path (Split-Path -Parent $PSScriptRoot) "dist/release-bundle-$Version"
New-Item -ItemType Directory -Force -Path $d | Out-Null
$c = if ($env:STUB_CEREMONY -eq "wrongcommit") { "0" * 40 } else { $Commit }
Set-Content -LiteralPath (Join-Path $d "andvari-$Version.msi") -Value "msi"
Set-Content -LiteralPath (Join-Path $d "manifest.json") -Value "{""seq"": 6, ""signedAt"": ""2026-10-22T00:00:00Z""}"
Set-Content -LiteralPath (Join-Path $d "release-spec.json") -Value "{}"
Set-Content -LiteralPath (Join-Path $d "manifest.json.sig") -Value "sig"
Set-Content -LiteralPath (Join-Path $d "bundle.json") -Value ("{""seq"": 6, ""commit"": """ + $c + """}")
Write-Host ("stub " + "ceremony RAN: bundle written")
exit 0'
HOSTILE="$(printf 'evil: \033[8mhidden\033[1A\033[2K rlo:\342\200\256 csi:\302\233 end')"
HIJACK=core/src/jvmMain/kotlin/io/silencelen/andvari/core/client/Hijack.kt
NEWMOD=tools/hook/src/main/kotlin/Evil.kt

g init -q --bare "$W/remote.git"
g clone -q "$W/remote.git" "$W/build" 2>/dev/null
mkdir -p "$W/build/scripts"
printf '%s\n' "$STUB" > "$W/build/scripts/prestige-release.ps1"
printf 'dist/\n' > "$W/build/.gitignore"
printf '// build v00\n' > "$W/build/build.gradle.kts"
g -C "$W/build" add .gitignore build.gradle.kts scripts/prestige-release.ps1; g -C "$W/build" commit -qm 'pre: the oldest release'
P0="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" tag -a v9.9.0 -m 'release 9.9.0'
printf '// build v0\n' > "$W/build/build.gradle.kts"
g -C "$W/build" add build.gradle.kts; g -C "$W/build" commit -qm 'zero: the release before'
C0="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" tag -a v9.9.8 -m 'release 9.9.8'
mkdir -p "$W/build/$(dirname "$HIJACK")" "$W/build/$(dirname "$NEWMOD")" "$W/build/web/src" "$W/build/web/sub" \
  "$W/build/docs" "$W/build/deploy" "$W/build/app-android" "$W/build/.githooks"
printf 'package io.silencelen.andvari.updatesigner\nfun java.io.File.readText(): String = "HIJACKED"\n// \033[2KHIDDEN-IN-CONTENT\n// SAFE\rdiff --git a/web/fake.ts b/web/fake.ts\n// AFTER-FAKE-HEADER-MARKER\n' > "$W/build/$HIJACK"
printf 'org.gradle.jvmargs=-javaagent:x.jar\n' > "$W/build/GRADLE.PROPERTIES"
printf '// NEW-MODULE-MARKER: linked by a build script, under no old allowlist\n' > "$W/build/$NEWMOD"
printf '// WEB-CONTENT-MARKER\n' > "$W/build/web/src/app.ts"
printf '*.txt text\n' > "$W/build/web/sub/.gitattributes"
printf '[lfs]\n\turl = https://lfs.invalid/\n' > "$W/build/docs/.lfsconfig"
printf '[submodule "x"]\n\tpath = x\n' > "$W/build/deploy/.gitmodules"
printf '// android build\n' > "$W/build/app-android/build.gradle.kts"
printf '#!/bin/sh\n[ -n "${HOOK_MARKER:-}" ] && touch "$HOOK_MARKER"\nexit 0\n' > "$W/build/.githooks/post-checkout"
chmod 755 "$W/build/.githooks/post-checkout"
g -C "$W/build" add "$HIJACK" GRADLE.PROPERTIES "$NEWMOD" web/src/app.ts web/sub/.gitattributes docs/.lfsconfig \
  deploy/.gitmodules app-android/build.gradle.kts .githooks/post-checkout
g -C "$W/build" commit -qm "$HOSTILE"
E1="$(git -C "$W/build" rev-parse HEAD)"
printf '%s\n# ceremony script changed in 9.9.9\n' "$STUB" > "$W/build/scripts/prestige-release.ps1"
printf '// build v1\n' > "$W/build/build.gradle.kts"
g -C "$W/build" add scripts/prestige-release.ps1 build.gradle.kts; g -C "$W/build" commit -qm 'one: the 9.9.9 change'
C1="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" tag -a v9.9.9 -m 'release 9.9.9'
printf 'x\n' > "$W/build/later.txt"; g -C "$W/build" add later.txt; g -C "$W/build" commit -qm 'two: after the release'
C2="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" checkout -q -b side "$C0"
printf 'side\n' > "$W/build/side.txt"; g -C "$W/build" add side.txt; g -C "$W/build" commit -qm 'side: off the old release'
S1="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" tag -a v9.9.10 -m 'release 9.9.10'
g -C "$W/build" checkout -q -b collide "$C1"
mkdir -p "$W/build/Scripts"; printf 'Write-Host "the other one"\n' > "$W/build/Scripts/prestige-release.ps1"
g -C "$W/build" add Scripts/prestige-release.ps1; g -C "$W/build" commit -qm 'collide: a second ceremony script'
K1="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" tag -a v9.9.11 -m 'release 9.9.11'
g -C "$W/build" checkout -q main
g -C "$W/build" push -q origin main side collide v9.9.0 v9.9.8 v9.9.9 v9.9.10 v9.9.11 2>/dev/null

# fresh_ws - a new workstation checkout at C2 on main that holds v9.9.0 and v9.9.8 but has not seen the newer tags.
fresh_ws() {
  rm -rf "$W/ws"
  g clone -q "$W/remote.git" "$W/ws" 2>/dev/null
  git -C "$W/ws" tag -d v9.9.9 v9.9.10 v9.9.11 >/dev/null
}
# at_old - the workstation on a branch `old` at C0, so a checkout of C1 rewrites every file that changed since.
at_old() { g -C "$W/ws" checkout -q -b old "$C0"; }
# bundle <dirname-suffix> <commit> <seq> [nosig] - a bundle this box's ceremony left under dist/ (sig = it completed).
bundle() {
  local d="$W/ws/dist/release-bundle-$1"; mkdir -p "$d"
  printf '{\n    "version":  "%s",\n    "seq":  %s,\n    "commit":  "%s"\n}\n' "${1%%[!0-9.]*}" "$3" "$2" > "$d/bundle.json"
  [ "${4:-}" = nosig ] || printf 'sig\n' > "$d/manifest.json.sig"
}
# record <commit> <version> - this workstation's last-signed record, as a previous successful run would leave it.
LAD="$W/localappdata"
REC="$LAD/andvari/signandvari-last-signed.json"
record() { rm -rf "$LAD"; mkdir -p "$LAD/andvari"; printf '{"commit": "%s", "version": "%s", "recordedAt": "2026-10-01T00:00:00Z"}\n' "$1" "$2" > "$REC"; }
no_record() { rm -rf "$LAD"; mkdir -p "$LAD"; }
recorded() { grep -oE '"commit": *"[0-9a-f]{40}"' "$REC" 2>/dev/null | grep -oE '[0-9a-f]{40}' || echo none; }

EXTRA_PATH=""
envs() {
  env ANDVARI_REPO="$W/ws" ANDVARI_RELEASE_DROP='drop@host.invalid:/drop/' ANDVARI_SIGNTOOL="$W/signtool.exe" \
      ANDVARI_BASE_URL="http://127.0.0.1:$PORT" LOCALAPPDATA="$LAD" PATH="${EXTRA_PATH:+$EXTRA_PATH:}$W/bin:$PATH" \
      HOOK_MARKER="$W/hook-ran" GIT_TERMINAL_PROMPT=0 NO_COLOR=1 TERM=dumb COLUMNS=4000 SHELL=/bin/bash "$@"
}
# pwsh word-wraps an error record to the console width behind a "     | " gutter, and a pty adds CRs and escape
# sequences; flatten all of it so a message can be matched whole.
flatten() { sed -E 's/\x1b\[[0-9;?]*[A-Za-z]//g; s/\x1b[=>]//g; s/\r//g; s/^ +\| //' | tr '\n' ' ' | tr -s ' '; }
run() { # run <args...> - NON-interactive (stdin redirected, -NonInteractive). Output in $OUT, exit code in $RC.
  OUT="$(cd "$W" && envs pwsh -NoProfile -NonInteractive -File "$S" "$@" < /dev/null 2>&1)"; RC=$?
  OUT="$(printf '%s\n' "$OUT" | flatten)"
}
runpty() { # runpty <typed answer lines> <args...> - a console session (a pty, ROWS rows); the answers are typed in turn.
  local answer="$1"; shift
  local cmd; cmd="stty rows ${ROWS:-1000} cols 4000; $(printf '%q ' pwsh -NoProfile -File "$S" "$@")"
  RAW="$(cd "$W" && printf '%s\n' "$answer" | envs timeout 120 script -qec "$cmd" /dev/null 2>&1)"; RC=$?
  OUT="$(printf '%s\n' "$RAW" | flatten)"
  # PIN_TEST_LOG=<file> keeps every console session's raw output, for reading what an operator would see.
  [ -z "${PIN_TEST_LOG:-}" ] || printf '===== runpty %s (exit %s)\n%s\n' "$*" "$RC" "$RAW" >> "$PIN_TEST_LOG"
}
before() { # before <a> <b> - <a> is printed before <b> in $OUT
  case "$OUT" in *"$1"*"$2"*) return 0 ;; *) return 1 ;; esac
}
has() { printf '%s\n' "$OUT" | grep -qF -- "$1"; }
no_raw() { # no_raw <what> <byte sequences...> - none of them reached the console raw
  local what="$1"; shift
  for seq in "$@"; do
    case "$RAW" in *"$seq"*) fail "a raw control sequence from $what reached the console ($(printf '%q' "$seq"))" ;; esac
  done
}
head_of() { git -C "$W/ws" rev-parse HEAD; }
tag_of()  { git -C "$W/ws" rev-parse -q --verify "refs/tags/$1^{commit}" 2>/dev/null || echo none; }

# ===================================================================== the pin (c03) =================================
fresh_ws; record "$C0" 9.9.8
echo "==> signandvari tag pin: -Commit is required"
run 9.9.9
[ "$RC" -ne 0 ] || fail "ran without -Commit (exit 0)"
[ "$(head_of)" = "$C2" ] || fail "HEAD moved on a run without -Commit"

echo "==> signandvari tag pin: a short or non-hex -Commit is refused"
run 9.9.9 -Commit "${C1:0:12}"
[ "$RC" -ne 0 ] || fail "accepted a 12-character -Commit"
[ "$(head_of)" = "$C2" ] || fail "HEAD moved on a short -Commit"

echo "==> signandvari tag pin: a tag that is not the pinned commit is refused BEFORE checkout"
run 9.9.9 -Commit "$C2"
[ "$RC" -ne 0 ] || fail "signed a tag ($C1) that is not the pinned commit ($C2)"
has "resolves to $C1, but -Commit is $C2" || fail "refusal does not name both commits:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "the tree was checked out although the pin did not match"

# ===================================================================== the baseline (RF1) ===========================
echo "==> signandvari baseline: a -Commit that does not descend from the last signed commit is refused"
fresh_ws; record "$C1" 9.9.9
run 9.9.10 -Commit "$S1"
[ "$RC" -ne 0 ] || fail "signed $S1, which does not descend from the last signed commit $C1"
has "does not descend from $C1" || fail "the non-descendant refusal does not name the last signed commit:
$OUT"
has "$S1" || fail "the non-descendant refusal does not name the -Commit:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "the tree was checked out although -Commit does not descend from the last signed commit"
[ "$(recorded)" = "$C1" ] || fail "a refused run changed the record (now $(recorded))"

echo "==> signandvari baseline: a non-interactive run never skips the confirmation, and checks out nothing"
fresh_ws; record "$C0" 9.9.8
run 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a -NonInteractive run with redirected stdin got past the confirmation"
has "needs a human confirmation" || fail "the unattended refusal does not say why:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "an unattended run checked the tree out"
[ "$(recorded)" = "$C0" ] || fail "an unattended run changed the record"

echo "==> signandvari review: every changed path but the excluded trees, escaped, stat then log then the full diff, before checkout"
fresh_ws; record "$C0" 9.9.8
# What the workstation's own git would do to a diff (A14 review 3, C2): -diff turns a file into "Binary files differ",
# a textconv driver rewrites it, an external diff tool replaces it, colour adds SGR sequences. None may apply.
printf '*.kt -diff\n*.kts diff=conv\n' > "$W/ws/.git/info/attributes"
git -C "$W/ws" config diff.conv.textconv 'sed s/^/CONV:/'
git -C "$W/ws" config diff.external "$W/bin/extdiff"
git -C "$W/ws" config color.ui always
runpty 9.9.8 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a confirmation that typed the wrong version (9.9.8) was accepted"
# A14 review R2-1: a core file outside core's crypto runs beside the key (the signer is a shadowJar of ALL of :core).
has "$HIJACK" || fail "the stat does not show a changed core/src/jvmMain file outside core's crypto (A14 review R2-1):
$OUT"
has "GRADLE.PROPERTIES" || fail "the stat does not show a case-variant gradle.properties:
$OUT"
has "scripts/prestige-release.ps1" || fail "the stat does not show the ceremony script that changed:
$OUT"
has " build.gradle.kts" || fail "the stat does not show the build file that changed:
$OUT"
# A14 review 3, C1: default-include. A new module outside every old allowlist is shown; so are build inputs and git
# attribute files inside the excluded trees; the rest of an excluded tree is counted, not shown.
for p in "$NEWMOD" web/sub/.gitattributes docs/.lfsconfig deploy/.gitmodules app-android/build.gradle.kts .githooks/post-checkout; do
  has "$p" || fail "the stat does not show $p (A14 review 3, C1/C3):
$OUT"
done
has "web/src/app.ts" && fail "the stat shows web/src/app.ts, in a tree that never runs on the signing box:
$OUT"
has "1 changed file(s) in trees that never run on this box (web/ 1)" || fail "the stat does not count the excluded change (A14 review 3, C1):
$OUT"
has "${C1:0:7} one: the 9.9.9 change" || fail "the log of $C0..$C1 was not shown:
$OUT"
before "---- changed since the last signed release" "---- commits" || fail "the commit list is printed before the stat (A14 review R2-2):
$OUT"
# A14 review R2-2: the hostile subject is printed escaped, never raw.
has 'evil: \u001B[8mhidden\u001B[1A\u001B[2K rlo:\u202E csi:\u009B end' \
  || fail "the hostile commit subject is not printed escaped:
$OUT"
# A14 review 3, C2: the full diff, printed by signandvari, BEFORE the checkout, escaped (a CR included), unaltered
# by the workstation's diff attributes and config, and with no advice to run a raw git diff.
has "NEW-MODULE-MARKER" || fail "the full diff of the review set is not shown (A14 review 3, C2):
$OUT"
before "AFTER-FAKE-HEADER-MARKER" "detached HEAD at v9.9.9" || fail "the full diff is not shown before the checkout (C2), or a CR faked a header and hid the rest of a reviewed file:
$OUT"
has '// SAFE\u000Ddiff --git a/web/fake.ts' || fail "a CR in a changed line is not shown escaped inside its own line (C2):
$OUT"
has '// \u001B[2KHIDDEN-IN-CONTENT' || fail "an ESC sequence in a changed line is not shown escaped (C2):
$OUT"
has "WEB-CONTENT-MARKER" && fail "the full diff shows a file of an excluded tree:
$OUT"
has "Binary files" && fail "the full diff honoured the workstation's -diff attribute (no --text):
$OUT"
has "CONV:" && fail "the full diff ran the workstation's textconv driver (no --no-textconv):
$OUT"
has "EXT-DIFF-RAN" && fail "the full diff ran the workstation's external diff tool (no --no-ext-diff):
$OUT"
has '\u001B[1mdiff' && fail "the full diff carries colour (no --no-color):
$OUT"
has "read it in full in another window" && fail "the old advice to run a raw git diff is still printed (C2):
$OUT"
no_raw "a commit subject or a changed line" $'\e[8m' $'\e[1A' $'\e[2K' $'\xe2\x80\xae' $'\xc2\x9b'
has "not confirmed" || fail "the wrong-answer refusal does not say why:
$OUT"
has "HEAD is back at main" || fail "the wrong-answer refusal does not say HEAD was put back:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "a refused confirmation left the tree checked out (HEAD $(head_of))"
[ ! -e "$W/ws/dist/release-bundle-9.9.9" ] || fail "the stub ceremony ran without a confirmation"

echo "==> signandvari review: a long diff is paged by signandvari itself; 'q' stops the reading, not the run"
fresh_ws; record "$C0" 9.9.8
ROWS=12 runpty $'q\n9.9.9' 9.9.9 -Commit "$C1" -DryRun
[ "$RC" -eq 0 ] || fail "a confirmed dry run after stopping the pager failed:
$OUT"
has "stopped reading the diff at line" || fail "signandvari did not page the full diff on a 12-row console (C2):
$OUT"
has "stub ceremony RAN: dry run" || fail "the dry run's stub ceremony did not run after the pager and the confirmation:
$OUT"

echo "==> signandvari baseline: the record moves only after a successful ceremony"
fresh_ws; record "$C0" 9.9.8
runpty 9.9.9 9.9.9 -Commit "$C1" -DryRun
[ "$RC" -eq 0 ] || fail "the confirmed dry run failed:
$OUT"
[ "$(recorded)" = "$C0" ] || fail "a DRY RUN moved the record to $(recorded)"
git -C "$W/ws" checkout -q main
STUB_CEREMONY=fail runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a failing ceremony reported success"
[ "$(recorded)" = "$C0" ] || fail "a FAILED ceremony moved the record to $(recorded)"
git -C "$W/ws" checkout -q main
STUB_CEREMONY=wrongcommit runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a bundle recording another commit was accepted"
[ "$(recorded)" = "$C0" ] || fail "a bundle that records another commit moved the record to $(recorded)"
rm -rf "$W/ws/dist"; git -C "$W/ws" checkout -q main
runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -eq 0 ] || fail "a confirmed ceremony failed:
$OUT"
[ "$(head_of)" = "$C1" ] || fail "HEAD is $(head_of) after a successful run, expected $C1"
[ "$(recorded)" = "$C1" ] || fail "a SUCCESSFUL ceremony did not record $C1 (record: $(recorded))"
grep -q '"version": *"9.9.9"' "$REC" || fail "the record does not carry the version: $(cat "$REC" 2>/dev/null)"

# ===================================================================== the first-run seed (A14 review R2-3) ==========
echo "==> signandvari seed: a first run is seeded from this box's own most recent signed bundle, its path escaped"
fresh_ws; no_record
bundle 9.9.0 "$P0" 3
bundle "$(printf '9.9.8\033[2K')" "$C0" 4   # an NTFS name can carry a control character: printed escaped (C6)
bundle 9.9.7 "$C1" 99 nosig                  # incomplete (no signature): never a seed
runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -eq 0 ] || fail "the seeded first run failed:
$OUT"
has 'release-bundle-9.9.8\u001B[2K' || fail "the first run did not name the bundle it was seeded from, escaped (C6):
$OUT"
no_raw "a seed bundle's path" $'\e[2K'
has "seq 4" || fail "the first run was not seeded from the highest-seq signed bundle (9.9.8, seq 4):
$OUT"
has "zero: the release before" || fail "the first run did not print the seed commit's subject:
$OUT"
has "${C1:0:7} one: the 9.9.9 change" || fail "the first run did not show the log since the seed:
$OUT"
[ "$(recorded)" = "$C1" ] || fail "the first successful run did not write the record (record: $(recorded))"

echo "==> signandvari seed: no seed while git tracks anything under dist/, in any case (A14 review 3, C4)"
fresh_ws; no_record
bundle 9.9.8 "$C0" 4
mkdir -p "$W/ws/Dist/release-bundle-9.9.6"
printf '{"version": "9.9.6", "seq": 50, "commit": "%s"}\n' "$C1" > "$W/ws/Dist/release-bundle-9.9.6/bundle.json"
printf 'sig\n' > "$W/ws/Dist/release-bundle-9.9.6/manifest.json.sig"
g -C "$W/ws" add -f Dist/release-bundle-9.9.6/bundle.json Dist/release-bundle-9.9.6/manifest.json.sig
g -C "$W/ws" commit -qm 'a bundle in the tree, in another case'
WSHEAD="$(head_of)"
runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a first run was seeded although git tracks Dist/ (NTFS writes it at dist\\):
$OUT"
has "-Baseline" || fail "the tracked-dist refusal does not point at -Baseline:
$OUT"
has "tracks" || fail "the tracked-dist refusal does not say git tracks files under dist/:
$OUT"
[ "$(head_of)" = "$WSHEAD" ] || fail "the tree was checked out with no usable seed"
[ "$(recorded)" = none ] || fail "a refused first run wrote a record"

echo "==> signandvari seed: no signed bundle means -Baseline, even when older release tags are held (never a tag)"
fresh_ws; no_record
bundle 9.9.8 "$C0" 4 nosig
run 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a first run with no signed bundle went ahead (seeded from a tag?)"
has "-Baseline" || fail "the no-baseline refusal does not point at -Baseline:
$OUT"
has "A tag is never used as the baseline" || fail "the no-baseline refusal does not say tags are never the seed:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "the tree was checked out with no baseline"
[ "$(recorded)" = none ] || fail "a refused first run wrote a record"

echo "==> signandvari seed: -Baseline must be a strict ancestor of -Commit (A14 review R2-4)"
run 9.9.9 -Commit "$C1" -Baseline "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "-Baseline equal to -Commit was accepted"
has "compares the release with itself" || fail "the -Baseline == -Commit refusal does not say why:
$OUT"
run 9.9.9 -Commit "$C1" -Baseline "$S1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a -Baseline that is not an ancestor of -Commit was accepted"
has "does not descend from $S1" || fail "the non-ancestor -Baseline refusal does not name it:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "the tree was checked out with a refused -Baseline"
runpty 9.9.9 9.9.9 -Commit "$C1" -Baseline "$C0" -SkipDrop
[ "$RC" -eq 0 ] || fail "a first run with -Baseline failed:
$OUT"
has "${C1:0:7} one: the 9.9.9 change" || fail "the -Baseline run did not show the log since $C0:
$OUT"
[ "$(recorded)" = "$C1" ] || fail "the -Baseline run did not write the record"

echo "==> signandvari baseline: -Baseline is refused once a record exists"
fresh_ws; record "$C0" 9.9.8
run 9.9.9 -Commit "$C1" -Baseline "$C0" -SkipDrop
[ "$RC" -ne 0 ] || fail "-Baseline was accepted beside an existing record"
has "first run only" || fail "the -Baseline-with-record refusal does not say why:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "the tree was checked out with -Baseline beside a record"

# ===================================================================== the NTFS case (A14 review 2) =================
echo "==> signandvari tree: two paths that are one file on a case-insensitive disk are refused before checkout"
fresh_ws; record "$C1" 9.9.9
run 9.9.11 -Commit "$K1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a tree with Scripts/ beside scripts/ was accepted"
has "Scripts/prestige-release.ps1 <-> scripts/prestige-release.ps1" || fail "the collision refusal does not name both paths:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "a colliding tree was checked out"

# ===================================================================== the checkout (A14 review 3, C3, C5) ===========
echo "==> signandvari checkout: a checkout that leaves the tree dirty is refused before the confirmation"
fresh_ws; record "$C0" 9.9.8; at_old
# A filter on this box that leaves a file behind while it checks out (a stand-in for anything that writes the tree).
printf '*.kts filter=side\n' > "$W/ws/.git/info/attributes"
git -C "$W/ws" config filter.side.smudge "sh -c 'touch untracked-by-filter.txt; cat'"
runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a tree that was dirty after the checkout went ahead"
has "working tree is NOT clean" || fail "the dirty-after-checkout refusal does not say why:
$OUT"
has "stub ceremony RAN" && fail "the stub ceremony ran after a dirty checkout"
[ ! -e "$W/ws/dist/release-bundle-9.9.9" ] || fail "the stub ceremony ran on a tree that was dirty after the checkout"
[ "$(recorded)" = "$C0" ] || fail "a dirty-checkout refusal changed the record"
[ "$(head_of)" = "$C0" ] || fail "a dirty-checkout refusal left HEAD at $(head_of), not back at old ($C0)"

echo "==> signandvari checkout: no hook runs, even one the repo config points into the release tree (C3)"
fresh_ws; record "$C0" 9.9.8
git -C "$W/ws" config core.hooksPath .githooks
rm -f "$W/hook-ran"
runpty 9.9.9 9.9.9 -Commit "$C1" -DryRun
[ "$RC" -eq 0 ] || fail "the confirmed dry run failed:
$OUT"
[ ! -e "$W/hook-ran" ] || fail "the release tree's own post-checkout hook ran during signandvari's checkout, before the confirmation"
git -C "$W/ws" config --unset core.hooksPath

echo "==> signandvari checkout: no LFS smudge - the reviewed bytes land on disk, not what the filter would write (C3)"
fresh_ws; record "$C0" 9.9.8; at_old
# Git for Windows installs a system LFS filter; this stands in for it. Its clean undoes its smudge, as LFS's does,
# so git status stays clean over the smudged file.
printf '*.kt filter=lfs\n' > "$W/ws/.git/info/attributes"
git -C "$W/ws" config filter.lfs.smudge 'sed s/readText/SMUDGED/'
git -C "$W/ws" config filter.lfs.clean 'sed s/SMUDGED/readText/'
git -C "$W/ws" config filter.lfs.required true
runpty 9.9.9 9.9.9 -Commit "$C1" -DryRun
[ "$RC" -eq 0 ] || fail "the confirmed dry run with an LFS filter configured failed:
$OUT"
grep -q SMUDGED "$W/ws/$HIJACK" && fail "the checkout ran the LFS smudge filter: $HIJACK on disk is not the reviewed blob"
has "files the review covers are on disk exactly as git holds them" || fail "the post-checkout byte check did not report:
$OUT"

echo "==> signandvari checkout: a reviewed file that is not, byte for byte, what git holds stops the run (C3)"
fresh_ws; record "$C0" 9.9.8; at_old
# Any other filter on this box: its clean undoes its smudge, so git status is clean, but the bytes on disk differ.
printf '*.kts filter=taint\n' > "$W/ws/.git/info/attributes"
git -C "$W/ws" config filter.taint.smudge 'sed s/build/TAINT/'
git -C "$W/ws" config filter.taint.clean 'sed s/TAINT/build/'
runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a checked-out tree whose bytes differ from git's went ahead"
has "not, on disk, what git holds" || fail "the byte-check refusal does not say why:
$OUT"
has "DIFFERS build.gradle.kts" || fail "the byte-check refusal does not name the file:
$OUT"
has "stub ceremony RAN" && fail "the stub ceremony ran on a tree whose bytes differ from git's"
[ "$(recorded)" = "$C0" ] || fail "a byte-check refusal changed the record"
[ "$(head_of)" = "$C0" ] || fail "a byte-check refusal left HEAD at $(head_of), not back at old ($C0)"
has "HEAD is back at old" || fail "the byte-check refusal does not say HEAD was put back:
$OUT"

echo "==> signandvari checkout: the CRLF git's own Windows checkout writes (core.autocrlf) passes the byte check"
fresh_ws; record "$C0" 9.9.8; at_old
git -C "$W/ws" config core.autocrlf true
runpty 9.9.9 9.9.9 -Commit "$C1" -DryRun
[ "$RC" -eq 0 ] || fail "a core.autocrlf=true checkout was refused:
$OUT"
grep -q $'\r' "$W/ws/build.gradle.kts" || fail "the scratch checkout did not write CRLF (core.autocrlf=true): the test proves nothing"
has "with the CRLF line endings git's own Windows checkout writes" || fail "the byte check did not report the CRLF files:
$OUT"

echo "==> signandvari checkout: a git command that dies between the checkout and the confirmation puts HEAD back (C5)"
fresh_ws; record "$C0" 9.9.8
mkdir -p "$W/gitwrap"
cat > "$W/gitwrap/git" <<EOF
#!/bin/sh
case " \$* " in
  *" status "*) [ "\$("$REAL_GIT" -C "$W/ws" rev-parse HEAD 2>/dev/null)" = "$C1" ] && { echo "injected: git status fails after the checkout" >&2; exit 128; } ;;
esac
exec "$REAL_GIT" "\$@"
EOF
chmod 755 "$W/gitwrap/git"
EXTRA_PATH="$W/gitwrap" runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a run whose git status failed after the checkout went ahead"
has "injected: git status fails" || fail "the injected failure did not happen - the test proves nothing:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "a die between the checkout and the confirmation left the unconfirmed tree checked out (HEAD $(head_of))"
has "HEAD is back at main" || fail "the die does not say HEAD was put back:
$OUT"
has "stub ceremony RAN" && fail "the stub ceremony ran after a failure before the confirmation"

# ===================================================================== after signing (A14 review 3, C6) =============
echo "==> signandvari drop: the build host's sha256sum answer prints escaped"
fresh_ws; record "$C0" 9.9.8
rm -rf "$W/drop"; mkdir -p "$W/drop"
SSH_HOSTILE=1 EXTRA_PATH="$W/dropbin" runpty 9.9.9 9.9.9 -Commit "$C1"
[ "$RC" -ne 0 ] || fail "a drop whose remote checksum did not match went ahead"
has "REMOTE CHECKSUM MISMATCH" || fail "the hostile checksum was not reported as a mismatch:
$OUT"
has 'remote \u001B[2kdeadbeef' || fail "the remote checksum is not printed escaped (C6):
$OUT"
no_raw "the drop host's sha256sum" $'\e[2k' $'\e[2K'
[ ! -e "$W/drop/manifest.json.sig" ] || fail "the signature was dropped after a checksum mismatch"

echo "==> signandvari read-back: a served manifest that does not describe this release prints escaped"
fresh_ws; record "$C0" 9.9.8
rm -rf "$W/drop"; mkdir -p "$W/drop"
printf '{"seq": 6, "signedAt": "2026-10-22T00:00:00Z", "linux": {"version": "9.9.9\\u001b[2K"}, "linuxArch": {"version": "9.9.9"}, "windows": {"version": "9.9.9", "sha256": "\\u001b[1Aab"}, "browserExtension": {"version": "1.0"}}\n' > "$W/publish.json"
EXTRA_PATH="$W/dropbin" runpty 9.9.9 9.9.9 -Commit "$C1"
[ "$RC" -ne 0 ] || fail "a served manifest naming another linux version passed the read-back:
$OUT"
has 'linux.version is 9.9.9\u001B[2K, expected 9.9.9' || fail "the served version is not printed escaped (C6):
$OUT"
has 'windows.sha256 is \u001B[1aab' || fail "the served windows.sha256 is not printed escaped (C6):
$OUT"
no_raw "the served manifest" $'\e[2K' $'\e[1a' $'\e[1A'
printf '%s\n' "$LIVE" > "$W/www/downloads/manifest.json"

echo "==> signandvari read-back: a served manifest that passes still prints its signedAt and extension version escaped"
fresh_ws; record "$C0" 9.9.8
rm -rf "$W/drop"; mkdir -p "$W/drop"
printf '{"seq": 6, "signedAt": "2026-10-22T00:00:00Z\033[2K", "linux": {"version": "9.9.9"}, "linuxArch": {"version": "9.9.9"}, "windows": {"version": "9.9.9", "sha256": "@MSISHA@"}, "browserExtension": {"version": "1.0\\u001b[8m"}}\n' > "$W/publish.json"
EXTRA_PATH="$W/dropbin" runpty 9.9.9 9.9.9 -Commit "$C1"
[ "$RC" -eq 0 ] || fail "a ceremony whose served manifest matches failed:
$OUT"
has 'signedAt 2026-10-22T00:00:00Z\u001B[2K' || fail "the served signedAt is not printed escaped (C6):
$OUT"
has 'browserExtension stays at 1.0\u001B[8m' || fail "the served extension version is not printed escaped (C6):
$OUT"
no_raw "the served manifest" $'\e[2K' $'\e[8m'
printf '%s\n' "$LIVE" > "$W/www/downloads/manifest.json"

# ===================================================================== the fetch (RF7) ==============================
echo "==> signandvari fetch: an unrelated tag that moved on the remote does not block the ceremony"
fresh_ws; record "$C0" 9.9.8
g -C "$W/build" tag -f -a v9.9.0 -m 'moved' "$C2" >/dev/null
g -C "$W/build" push -q --force origin v9.9.0 2>/dev/null
runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -eq 0 ] || fail "a moved UNRELATED tag (v9.9.0) blocked the v9.9.9 ceremony:
$OUT"
[ "$(tag_of v9.9.0)" = "$P0" ] || fail "the unrelated local tag v9.9.0 was moved to $(tag_of v9.9.0)"
[ "$(head_of)" = "$C1" ] || fail "HEAD is $(head_of), expected $C1"

echo "==> signandvari fetch: a release tag moved on the remote is refused, naming both commits, never adopted"
g -C "$W/build" tag -f -a v9.9.9 -m 'moved' "$C2" >/dev/null
g -C "$W/build" push -q --force origin v9.9.9 2>/dev/null
rm -rf "$W/ws/dist"; git -C "$W/ws" checkout -q main
run 9.9.9 -Commit "$C1"
[ "$RC" -ne 0 ] || fail "a moved remote tag did not stop the run"
[ "$(tag_of v9.9.9)" = "$C1" ] || fail "the local tag was replaced by the remote's (now $(tag_of v9.9.9)) - a --force fetch is back"
has "remote's v9.9.9 ($C2) DIFFERS from this machine's v9.9.9 ($C1)" \
  || fail "the moved-tag refusal does not name both commits:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "the tree was checked out although the tag moved"

if [ "$FAILED" = 0 ]; then
  echo "    signandvari tag-pin test OK"
else
  echo "    signandvari tag-pin test FAILED ($S)" >&2
  exit 1
fi
