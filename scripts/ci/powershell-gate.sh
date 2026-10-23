#!/usr/bin/env bash
# PowerShell release-script gate (audit H110).
#
# WHY THIS EXISTS. Three of the release scripts are PowerShell — prestige-release.ps1 (the
# ceremony), signandvari.ps1 (the wrapper around it) and build-windows.ps1 — and every one of them
# is edited on Linux and executed exactly once per release, on a Windows workstation, by hand,
# with the signing key already unlocked. Nothing in the build touched them: a typo introduced here
# surfaced at the worst possible moment on the only machine that can sign, and the recovery is a
# fresh signature, which burns a new signedAt for no reason (§0 "a wedge or failure after signing
# is never re-signed").
#
# So this gate does two cheap things, both of which are about the release channel and neither of
# which needs Windows:
#
#   1. PARSE every .ps1 with the real PowerShell parser (pwsh on this box). Syntax only — a parse
#      is not an execution and proves nothing about behaviour — but a parse error is the failure
#      mode that Linux editing actually produces, and it is 100 % detectable here.
#
#   2. Assert the post-publish READ-BACK invariants in signandvari.ps1 (audit H110). The ceremony
#      twice ended green on the signing box while the fielded channel still named an older
#      version, and the only tripwire either time was a hand-typed paragraph in a runbook. Step 9
#      is now that tripwire in code; these greps assert it is still there, still compares the
#      served seq AND version to what this run produced, and still fails hard rather than warning.
#      They are shape assertions, not a behavioural test — the loop itself cannot run without a
#      published channel to read — and they are deliberately anchored on the *decisions* (Die on
#      mismatch, Die on overtaken seq, Die on timeout) rather than on wording.
#
#   3. Assert the release-commit pin (security review 2026-10): signandvari.ps1 fetches only the
#      release tag and never forces it, both scripts take -Commit, the release must descend from the
#      workstation's last signed commit and be confirmed by a human (A13 review RF1/RF7), and
#      scripts/ci/signandvari-pin.test.sh drives signandvari against a scratch repo (wrong pin, moved
#      tag, missing pin, non-descendant, unattended run, record only on success, first-run seed).
#
# Skips (green, loudly) when pwsh is absent, because a contributor without PowerShell must still
# be able to run the release gate; CI and the maintainer's box have it.
set -euo pipefail
cd "$(dirname "$0")/../.."

fail() { echo "    POWERSHELL GATE FAILED: $*" >&2; exit 1; }

mapfile -t PS_FILES < <(find scripts -maxdepth 1 -name '*.ps1' | sort)
[ "${#PS_FILES[@]}" -gt 0 ] || fail "no .ps1 files found under scripts/ — this gate is pointed at nothing."

if command -v pwsh >/dev/null 2>&1; then
  for f in "${PS_FILES[@]}"; do
    # The path travels in the environment, not in argv: `pwsh -Command` treats a leading `--`
    # as PowerShell syntax, not as an argument separator.
    out=$(PS_TARGET="$f" pwsh -NoProfile -NonInteractive -Command '
      $errs = $null; $toks = $null
      [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $env:PS_TARGET), [ref]$toks, [ref]$errs) | Out-Null
      if ($errs) { $errs | ForEach-Object { "line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message }; exit 1 }
      exit 0
    ' 2>&1) || { echo "$out" >&2; fail "$f does not parse."; }
    echo "    parsed  $f"
  done
else
  echo "    SKIP: pwsh not installed — .ps1 files not parsed on this box."
fi

# --- signandvari read-back invariants (H110) -------------------------------------------------
S=scripts/signandvari.ps1
[ -f "$S" ] || fail "$S is missing."

grep -q '9\. PUBLISH READ-BACK' "$S" \
  || fail "$S has no post-publish read-back step. It was added for audit H110 because a ceremony can end green while the channel still serves the previous release; do not remove it without replacing the assertion."

# The read-back must compare BOTH halves. seq alone would pass a manifest that was published at the
# right sequence number while describing the wrong version (0.26.0's failure was version, not seq).
grep -q 'servedSeq -eq \$NewSeq' "$S" \
  || fail "$S no longer waits for the served seq to equal the minted \$NewSeq."
grep -q 'node.version -ne \$Version' "$S" \
  || fail "$S no longer asserts the served platform version equals the tag just signed."
grep -q 'windows.sha256' "$S" \
  || fail "$S no longer cross-checks the served windows.sha256 against the MSI this run hashed."

# Three distinct failures, all fatal: wrong content, overtaken channel, never published. A gate that
# warned instead would reproduce the exact defect — a green ceremony over an unpublished channel.
for pat in \
  'Die .the served manifest carries this run' \
  'Die (.the channel is at seq' \
  'Die (.the channel never reached seq'
do
  grep -qF "$(printf '%s' "$pat" | sed 's/^Die (\?\.//')" "$S" \
    || fail "$S lost one of the read-back's hard failures ($pat) — a read-back that only warns is not a tripwire."
done

# -SkipReadBack must stay an explicit, noisy opt-out rather than a default.
grep -q '\[switch\]\$SkipReadBack' "$S" || fail "$S lost the -SkipReadBack switch declaration."
grep -q 'if (\$SkipReadBack)' "$S"      || fail "$S no longer branches on -SkipReadBack."

echo "    signandvari.ps1 post-publish read-back present (seq + version + digest, three hard failures)"

# --- the release-commit pin (security review 2026-10, c03) -------------------------------------
# The workstation runs the tag's tree beside the signing key, so the tag is verified against an
# out-of-band -Commit pin before checkout, and a moved remote tag is refused rather than adopted.
# The behaviour is tested against a scratch repo below; these greps keep the two load-bearing
# decisions from being edited out of either script.
grep -qE "'fetch', '--tags', '--force'|fetch.*--tags.*--force" "$S" \
  && fail "$S force-fetches tags again — a moved remote tag would silently replace the local one."
for f in "$S" scripts/prestige-release.ps1; do
  grep -q '\[string\]\$Commit' "$f" || fail "$f lost its -Commit pin parameter."
done
grep -q "'-Commit', \$Commit" "$S" || fail "$S no longer hands the -Commit pin to prestige-release.ps1."
grep -q 'commit    = \$CommitPin' scripts/prestige-release.ps1 \
  || fail "prestige-release.ps1 no longer records the pinned commit in bundle.json."
# A13 review RF7: only the release tag is fetched. `fetch --tags` refuses on ANY moved tag, so one
# unrelated re-tag blocked every ceremony; and it must stay non-forced.
grep -qE "'fetch', '--tags'" "$S" && fail "$S fetches every tag again — an unrelated moved tag blocks the ceremony; fetch refs/tags/<tag> only."
grep -qF "'fetch', '--no-tags', 'origin', \"refs/tags/\${Tag}:refs/tags/\${Tag}\"" "$S" \
  || fail "$S no longer fetches exactly the release tag (refs/tags/<tag>:refs/tags/<tag>, --no-tags, no force)."
# A13 review RF1: the workstation-held baseline. The scratch-repo test below drives it; these keep the
# decisions from being edited out: ancestry from the last signed commit, a typed confirmation that
# fails closed, and a record written only after the bundle's commit check.
grep -qF "'merge-base', '--is-ancestor', \$BaseCommit, \$Commit" "$S" || fail "$S lost the ancestry check against the last signed commit."
grep -qF 'Read-Host' "$S" || fail "$S lost the typed confirmation."
grep -qF '[Console]::IsInputRedirected' "$S" || fail "$S no longer fails closed on redirected input at the confirmation."
check_pos=$(grep -n "bundle.json records commit" "$S" | head -1 | cut -d: -f1)
write_pos=$(grep -n 'Move-Item -LiteralPath \$recordTmp -Destination \$RecordPath' "$S" | head -1 | cut -d: -f1)
{ [ -n "$check_pos" ] && [ -n "$write_pos" ] && [ "$write_pos" -gt "$check_pos" ]; } \
  || fail "$S must write the last-signed record only AFTER the bundle.json commit check."
# The one-time install recipe (release-signing-keys.md §0) writes this file through PowerShell 5.1,
# which also reads a BOM-less .ps1 in the ANSI code page: it stays pure ASCII.
LC_ALL=C grep -nP '[^\x00-\x7F]' "$S" >&2 && fail "$S contains non-ASCII characters (lines above) — keep it pure ASCII."
bash scripts/ci/signandvari-pin.test.sh || fail "the signandvari tag-pin scratch-repo test failed."
echo "    signandvari.ps1 + prestige-release.ps1 verify the tag against -Commit; release tag fetched alone, unforced;"
echo "    the release descends from the workstation's last signed commit and is confirmed by a human"
