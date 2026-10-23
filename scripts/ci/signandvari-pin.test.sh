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
#     baseline is the newest local release tag below the version that the checkout held before this run's fetch,
#     or an explicit -Baseline when there is none.
#
# This drives the real script under pwsh against a scratch "remote" and a scratch "workstation" clone. The ceremony
# itself needs Windows, signtool and the key, so the scratch tree carries a stub prestige-release.ps1 (it writes a
# bundle recording the pin, or fails on request), a `powershell.exe` on PATH that runs it under pwsh, a placeholder
# signtool, and a local HTTP server standing in for the download origin. Every successful run uses -SkipDrop.
# Confirmations are typed through a pty (`script`), the way a human at a console would type them.
#
# Skips (green, loudly) without pwsh, like powershell-gate.sh; needs python3 and util-linux `script` when pwsh is
# present. SIGNANDVARI=<path> points it at another copy of the script (used to show the test failing against the
# pre-fix version).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
S="${SIGNANDVARI:-$ROOT/scripts/signandvari.ps1}"
command -v pwsh >/dev/null 2>&1 || { echo "    SKIP: pwsh not installed - signandvari tag-pin test not run."; exit 0; }
for tool in python3 script; do
  command -v "$tool" >/dev/null 2>&1 || { echo "    signandvari tag-pin test needs $tool (pwsh is present)" >&2; exit 1; }
done

FAILED=0
fail() { echo "    FAIL: $*" >&2; FAILED=1; }

W="$(mktemp -d)"
SRV_PID=""
cleanup() { [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
g() { git -c user.name=t -c user.email=t@example.invalid -c init.defaultBranch=main -c advice.detachedHead=false "$@"; }

# --- the stand-in download origin: /downloads/manifest.json at seq 5 ----------------------------------------------
mkdir -p "$W/www/downloads"
printf '{"seq": 5, "signedAt": "2026-10-01T00:00:00Z"}\n' > "$W/www/downloads/manifest.json"
python3 -u -m http.server 0 --bind 127.0.0.1 --directory "$W/www" > "$W/srv.log" 2>&1 &
SRV_PID=$!
PORT=""
for _ in $(seq 1 50); do
  PORT="$(grep -oE 'port [0-9]+' "$W/srv.log" 2>/dev/null | grep -oE '[0-9]+' | head -1)"
  [ -n "$PORT" ] && break
  sleep 0.1
done
[ -n "$PORT" ] || { echo "    could not start the stand-in download origin" >&2; cat "$W/srv.log" >&2; exit 1; }

# --- powershell.exe (the ceremony launcher) and a placeholder signtool ---------------------------------------------
mkdir -p "$W/bin"
printf '#!/bin/sh\nexec pwsh -NoProfile "$@"\n' > "$W/bin/powershell.exe"; chmod 755 "$W/bin/powershell.exe"
printf 'placeholder\n' > "$W/signtool.exe"

# --- the scratch release history ------------------------------------------------------------------------------------
# C0 (v9.9.0, v9.9.8) -> C1 (v9.9.9) -> C2 on main; S1 (v9.9.10) on a side branch off C0, NOT a descendant of C1.
STUB='param([string]$Version, [string]$Ref, [string]$Commit, [string]$SignToolPath, [switch]$DryRun)
if ($env:STUB_CEREMONY -eq "fail") { Write-Host "stub ceremony: failing on request"; exit 1 }
if ($DryRun) { Write-Host "stub ceremony: dry run"; exit 0 }
$d = Join-Path (Split-Path -Parent $PSScriptRoot) "dist/release-bundle-$Version"
New-Item -ItemType Directory -Force -Path $d | Out-Null
$c = if ($env:STUB_CEREMONY -eq "wrongcommit") { "0" * 40 } else { $Commit }
Set-Content -LiteralPath (Join-Path $d "andvari-$Version.msi") -Value "msi"
Set-Content -LiteralPath (Join-Path $d "manifest.json") -Value "{""seq"": 6, ""signedAt"": ""2026-10-22T00:00:00Z""}"
Set-Content -LiteralPath (Join-Path $d "release-spec.json") -Value "{}"
Set-Content -LiteralPath (Join-Path $d "manifest.json.sig") -Value "sig"
Set-Content -LiteralPath (Join-Path $d "bundle.json") -Value ("{""seq"": 6, ""commit"": """ + $c + """}")
Write-Host "stub ceremony: bundle written"
exit 0'

g init -q --bare "$W/remote.git"
g clone -q "$W/remote.git" "$W/build" 2>/dev/null
mkdir -p "$W/build/scripts"
printf '%s\n' "$STUB" > "$W/build/scripts/prestige-release.ps1"
printf 'dist/\n' > "$W/build/.gitignore"
printf '// build v0\n' > "$W/build/build.gradle.kts"
g -C "$W/build" add -A; g -C "$W/build" commit -qm 'zero: the release before'
C0="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" tag -a v9.9.0 -m 'release 9.9.0'
g -C "$W/build" tag -a v9.9.8 -m 'release 9.9.8'
printf '%s\n# ceremony script changed in 9.9.9\n' "$STUB" > "$W/build/scripts/prestige-release.ps1"
printf '// build v1\n' > "$W/build/build.gradle.kts"
g -C "$W/build" add -A; g -C "$W/build" commit -qm 'one: the 9.9.9 change'
C1="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" tag -a v9.9.9 -m 'release 9.9.9'
printf 'x\n' > "$W/build/later.txt"; g -C "$W/build" add -A; g -C "$W/build" commit -qm 'two: after the release'
C2="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" checkout -q -b side "$C0"
printf 'side\n' > "$W/build/side.txt"; g -C "$W/build" add -A; g -C "$W/build" commit -qm 'side: off the old release'
S1="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" tag -a v9.9.10 -m 'release 9.9.10'
g -C "$W/build" checkout -q main
g -C "$W/build" push -q origin main side v9.9.0 v9.9.8 v9.9.9 v9.9.10 2>/dev/null

# fresh_ws - a new workstation checkout at C2 on main that holds v9.9.0 and v9.9.8 but has not seen v9.9.9 / v9.9.10.
fresh_ws() {
  rm -rf "$W/ws"
  g clone -q "$W/remote.git" "$W/ws" 2>/dev/null
  git -C "$W/ws" tag -d v9.9.9 v9.9.10 >/dev/null
}
# record <commit> <version> - this workstation's last-signed record, as a previous successful run would leave it.
LAD="$W/localappdata"
REC="$LAD/andvari/signandvari-last-signed.json"
record() { rm -rf "$LAD"; mkdir -p "$LAD/andvari"; printf '{"commit": "%s", "version": "%s", "recordedAt": "2026-10-01T00:00:00Z"}\n' "$1" "$2" > "$REC"; }
no_record() { rm -rf "$LAD"; mkdir -p "$LAD"; }
recorded() { grep -oE '"commit": *"[0-9a-f]{40}"' "$REC" 2>/dev/null | grep -oE '[0-9a-f]{40}' || echo none; }

envs() {
  env ANDVARI_REPO="$W/ws" ANDVARI_RELEASE_DROP='drop@host.invalid:/drop/' ANDVARI_SIGNTOOL="$W/signtool.exe" \
      ANDVARI_BASE_URL="http://127.0.0.1:$PORT" LOCALAPPDATA="$LAD" PATH="$W/bin:$PATH" \
      GIT_TERMINAL_PROMPT=0 NO_COLOR=1 TERM=dumb COLUMNS=4000 SHELL=/bin/bash "$@"
}
# pwsh word-wraps an error record to the console width behind a "     | " gutter, and a pty adds CRs and escape
# sequences; flatten all of it so a message can be matched whole.
flatten() { sed -E 's/\x1b\[[0-9;?]*[A-Za-z]//g; s/\x1b[=>]//g; s/\r//g; s/^ +\| //' | tr '\n' ' ' | tr -s ' '; }
run() { # run <args...> - NON-interactive (stdin redirected, -NonInteractive). Output in $OUT, exit code in $RC.
  OUT="$(cd "$W" && envs pwsh -NoProfile -NonInteractive -File "$S" "$@" < /dev/null 2>&1)"; RC=$?
  OUT="$(printf '%s\n' "$OUT" | flatten)"
}
runpty() { # runpty <typed answer> <args...> - a console session (a pty); the answer is typed at the prompt.
  local answer="$1"; shift
  local cmd; cmd="$(printf '%q ' pwsh -NoProfile -File "$S" "$@")"
  OUT="$(cd "$W" && printf '%s\n' "$answer" | envs timeout 120 script -qec "$cmd" /dev/null 2>&1)"; RC=$?
  OUT="$(printf '%s\n' "$OUT" | flatten)"
}
has() { printf '%s\n' "$OUT" | grep -qF -- "$1"; }
head_of() { git -C "$W/ws" rev-parse HEAD; }
tag_of()  { git -C "$W/ws" rev-parse -q --verify "refs/tags/$1^{commit}" 2>/dev/null || echo none; }

# ===================================================================== the pin (c03) =================================
fresh_ws; no_record
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

echo "==> signandvari baseline: a non-interactive run never skips the confirmation"
fresh_ws; record "$C0" 9.9.8
run 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a -NonInteractive run with redirected stdin got past the confirmation"
has "needs a human confirmation" || fail "the unattended refusal does not say why:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "an unattended run checked the tree out"
[ "$(recorded)" = "$C0" ] || fail "an unattended run changed the record"

echo "==> signandvari baseline: the changes since the last signed commit are shown, and a wrong answer stops the run"
fresh_ws; record "$C0" 9.9.8
runpty 9.9.8 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a confirmation that typed the wrong version (9.9.8) was accepted"
has "${C1:0:7} one: the 9.9.9 change" || fail "the log of $C0..$C1 was not shown:
$OUT"
has "scripts/prestige-release.ps1" || fail "the diff stat does not show the ceremony script that changed:
$OUT"
has "build.gradle.kts" || fail "the diff stat does not show the build file that changed:
$OUT"
has "not confirmed" || fail "the wrong-answer refusal does not say why:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "the tree was checked out without a confirmation"

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

echo "==> signandvari baseline: the first run is seeded from the newest older local tag held before the fetch"
fresh_ws; no_record
runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -eq 0 ] || fail "the seeded first run failed:
$OUT"
has "local tag v9.9.8" || fail "the first run did not say it compared against the local v9.9.8:
$OUT"
has "${C1:0:7} one: the 9.9.9 change" || fail "the first run did not show the log since v9.9.8:
$OUT"
[ "$(recorded)" = "$C1" ] || fail "the first successful run did not write the record (record: $(recorded))"

echo "==> signandvari baseline: a first run with no older local tag needs -Baseline"
fresh_ws; no_record
git -C "$W/ws" tag -d v9.9.0 v9.9.8 >/dev/null
run 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -ne 0 ] || fail "a first run with nothing to compare against went ahead"
has "-Baseline" || fail "the no-baseline refusal does not point at -Baseline:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "the tree was checked out with no baseline"
[ "$(recorded)" = none ] || fail "a refused first run wrote a record"
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

# ===================================================================== the fetch (RF7) ==============================
echo "==> signandvari fetch: an unrelated tag that moved on the remote does not block the ceremony"
fresh_ws; record "$C0" 9.9.8
g -C "$W/build" tag -f -a v9.9.0 -m 'moved' "$C2" >/dev/null
g -C "$W/build" push -q --force origin v9.9.0 2>/dev/null
runpty 9.9.9 9.9.9 -Commit "$C1" -SkipDrop
[ "$RC" -eq 0 ] || fail "a moved UNRELATED tag (v9.9.0) blocked the v9.9.9 ceremony:
$OUT"
[ "$(tag_of v9.9.0)" = "$C0" ] || fail "the unrelated local tag v9.9.0 was moved to $(tag_of v9.9.0)"
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
