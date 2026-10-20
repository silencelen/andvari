#!/usr/bin/env bash
# Scratch-repo test for signandvari.ps1's tag verification (security review 2026-10, c03).
#
# The signing workstation runs the release tag's tree - its scripts and its gradle build - with
# the update-signing key openable by the same account. So the tag must be proven to be the release
# the operator was handed BEFORE anything is checked out:
#   * `-Commit <40-hex>` is REQUIRED, and the tag must resolve to exactly that commit;
#   * the fetch never force-updates a tag: a remote tag that moved is refused, naming both commits,
#     and the local tag is left where it was.
#
# This drives the real script under pwsh against a scratch "remote" and a scratch "workstation"
# clone. It cannot run the ceremony itself (that needs Windows, signtool and the key), so the
# success case is "got past the checkout with HEAD on the pinned commit"; the script then stops at
# signtool discovery, which is the expected end of the road on Linux.
#
# Skips (green, loudly) without pwsh, like powershell-gate.sh. SIGNANDVARI=<path> points it at
# another copy of the script (used to show the test failing against the pre-fix version).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
S="${SIGNANDVARI:-$ROOT/scripts/signandvari.ps1}"
command -v pwsh >/dev/null 2>&1 || { echo "    SKIP: pwsh not installed - signandvari tag-pin test not run."; exit 0; }

FAILED=0
fail() { echo "    FAIL: $*" >&2; FAILED=1; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
g() { git -c user.name=t -c user.email=t@example.invalid -c init.defaultBranch=main -c advice.detachedHead=false "$@"; }

g init -q --bare "$W/remote.git"
g clone -q "$W/remote.git" "$W/build" 2>/dev/null
mkdir -p "$W/build/scripts"
printf 'exit 0\n' > "$W/build/scripts/prestige-release.ps1"
g -C "$W/build" add -A; g -C "$W/build" commit -qm one
C1="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" tag -a v9.9.9 -m 'release 9.9.9'
printf 'x\n' > "$W/build/later.txt"; g -C "$W/build" add -A; g -C "$W/build" commit -qm two
C2="$(git -C "$W/build" rev-parse HEAD)"
g -C "$W/build" push -q origin main v9.9.9 2>/dev/null

g clone -q "$W/remote.git" "$W/ws" 2>/dev/null   # the workstation checkout, HEAD = C2 on main
git -C "$W/ws" tag -d v9.9.9 >/dev/null           # this box has not seen the tag yet

run() { # run <args...> - output in $OUT, exit code in $RC
  OUT="$(cd "$W" && ANDVARI_REPO="$W/ws" ANDVARI_RELEASE_DROP='drop@host.invalid:/drop/' \
         ANDVARI_SIGNTOOL="" GIT_TERMINAL_PROMPT=0 NO_COLOR=1 TERM=dumb COLUMNS=4000 \
         pwsh -NoProfile -NonInteractive -File "$S" "$@" 2>&1)"; RC=$?
  # pwsh word-wraps an error record to the console width behind a "     | " gutter; unwrap it so
  # a message can be matched whole.
  OUT="$(printf '%s\n' "$OUT" | sed -E 's/\x1b\[[0-9;]*m//g; s/^ +\| //' | tr '\n' ' ' | tr -s ' ')"
}
head_of() { git -C "$W/ws" rev-parse HEAD; }
tag_of()  { git -C "$W/ws" rev-parse -q --verify 'refs/tags/v9.9.9^{commit}' 2>/dev/null || echo none; }

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
printf '%s\n' "$OUT" | grep -q "resolves to $C1, but -Commit is $C2" || fail "refusal does not name both commits:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "the tree was checked out although the pin did not match"

echo "==> signandvari tag pin: the pinned commit gets through the checkout"
run 9.9.9 -Commit "$C1"
printf '%s\n' "$OUT" | grep -q "v9.9.9 -> $C1 (matches -Commit)" || fail "the matching pin was not accepted:
$OUT"
[ "$(head_of)" = "$C1" ] || fail "HEAD is $(head_of) after a matching run, expected $C1"
printf '%s\n' "$OUT" | grep -q 'Resolve signtool' || fail "the run did not reach the step after the checkout:
$OUT"

echo "==> signandvari tag pin: a tag moved on the remote is refused, never adopted"
g -C "$W/build" tag -f -a v9.9.9 -m 'moved' "$C2" >/dev/null
g -C "$W/build" push -q --force origin v9.9.9 2>/dev/null
git -C "$W/ws" checkout -q main
run 9.9.9 -Commit "$C1"
[ "$RC" -ne 0 ] || fail "a moved remote tag did not stop the run"
[ "$(tag_of)" = "$C1" ] || fail "the local tag was replaced by the remote's (now $(tag_of)) - a --force fetch is back"
printf '%s\n' "$OUT" | grep -q "remote's v9.9.9 ($C2) DIFFERS from this machine's v9.9.9 ($C1)" \
  || fail "the moved-tag refusal does not name both commits:
$OUT"
[ "$(head_of)" = "$C2" ] || fail "the tree was checked out although the tag moved"

if [ "$FAILED" = 0 ]; then
  echo "    signandvari tag-pin test OK"
else
  echo "    signandvari tag-pin test FAILED ($S)" >&2
  exit 1
fi
