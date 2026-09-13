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
