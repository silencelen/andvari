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
#      tag, missing pin, non-descendant, unattended run, record only on success, first-run seed). Since
#      the A14 review: git output is escaped and the stat printed first (R2-2), the first-run seed is this
#      box's own signed bundle, never a tag (R2-3), -Baseline is a strict ancestor (R2-4), and the NTFS
#      case-collision belt. Since its third review: the review shows every changed path but a short list of
#      trees that never run on the signing box (C1; checked here against the projects the update-signer
#      and the MSI link), and the full diff, printed by signandvari before checkout (C2); the checkout runs
#      no hook and no LFS smudge, and every reviewed file must then hash to what git holds (C3); a way out
#      before the confirmation puts HEAD back (C5); prestige-release.ps1 rebuilds the signer jar every run.
#      Since its fifth review: the reviewed files are hashed in-process, so no native command reads a pipeline
#      (H1), every git command runs with the LFS filters blanked and, from the checkout on, with
#      --attr-source where git has it; a reviewed PowerShell file with a byte above 0x7F and no BOM, a reviewed
#      text file with a lone CR, and the CRLF form of a blob git would not convert are refused (S1, S2, S4);
#      a byte that is not UTF-8 prints as \xNN, U+FFFD and the invisible characters print escaped (S1, S5);
#      the pager counts console rows and caps long lines (S3).
#
#   4. For EVERY scripts/*.ps1|psm1|psd1 (A14 review 5): pure printable ASCII (H2: Windows PowerShell 5.1
#      reads a script without a byte-order mark in the ANSI code page, where the UTF-8 bytes of an em dash
#      hold 0x94, a closing double quote to its tokenizer), and NO PIPELINE INTO A NATIVE COMMAND (H1: 5.1
#      writes a pipeline into a native program's stdin in $OutputEncoding, and a profile's UTF-8 puts a
#      byte-order mark in front of it) unless the enclosing script block sets an ASCII $OutputEncoding.
#      Found with the PowerShell parser: every pipeline element after the first that is a native program,
#      an `&`/`.` call of anything but an inline script block, or a command this box cannot resolve.
#
# Skips (green, loudly) when pwsh is absent, because a contributor without PowerShell must still
# be able to run the release gate; CI and the maintainer's box have it.
set -euo pipefail
cd "$(dirname "$0")/../.."

fail() { echo "    POWERSHELL GATE FAILED: $*" >&2; exit 1; }

mapfile -t PS_FILES < <(find scripts -maxdepth 1 \( -name '*.ps1' -o -name '*.psm1' -o -name '*.psd1' \) | sort)
[ "${#PS_FILES[@]}" -gt 0 ] || fail "no .ps1 files found under scripts/ — this gate is pointed at nothing."

# H2 (A14 review 5): every PowerShell file is pure printable ASCII - no byte above 0x7F, no control character but
# tab and line ends, no CR that an LF does not follow.
for f in "${PS_FILES[@]}"; do
  LC_ALL=C grep -nP '[^\x00-\x7F]' "$f" >&2 && fail "$f contains non-ASCII characters (lines above): Windows PowerShell 5.1 reads a script without a byte-order mark in the ANSI code page (A14 review 5, H2)."
  LC_ALL=C grep -nP '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]' "$f" >&2 && fail "$f contains a control character (lines above)."
  LC_ALL=C grep -nP '\r(?!$)' "$f" >&2 && fail "$f contains a CR that no LF follows (lines above): PowerShell ends a line there."
done
echo "    pure printable ASCII: ${PS_FILES[*]}"

if command -v pwsh >/dev/null 2>&1; then
  for f in "${PS_FILES[@]}"; do
    # The path travels in the environment, not in argv: `pwsh -Command` treats a leading `--`
    # as PowerShell syntax, not as an argument separator.
    out=$(PS_TARGET="$f" pwsh -NoProfile -NonInteractive -Command '
      $errs = $null; $toks = $null
      $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $env:PS_TARGET), [ref]$toks, [ref]$errs)
      if ($errs) { $errs | ForEach-Object { "line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message }; exit 1 }
      # H1 (A14 review 5): no pipeline feeds a native command, unless its script block sets an ASCII $OutputEncoding.
      $defined = @{}
      foreach ($fd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $defined[$fd.Name.ToLowerInvariant()] = $true }
      $bad = @()
      foreach ($pl in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.PipelineAst] }, $true)) {
        $els = $pl.PipelineElements
        for ($k = 1; $k -lt $els.Count; $k++) {
          $el = $els[$k]
          if ($el -isnot [System.Management.Automation.Language.CommandAst]) { continue }
          $native = $false
          if ($el.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown) {
            $native = -not ($el.CommandElements[0] -is [System.Management.Automation.Language.ScriptBlockExpressionAst])
          }
          else {
            $name = $el.GetCommandName()
            if (-not $name) { $native = $true }
            elseif (-not $defined.ContainsKey($name.ToLowerInvariant())) {
              $cmd = Get-Command -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
              $native = ($null -eq $cmd) -or ($cmd.CommandType -eq "Application") -or ($cmd.CommandType -eq "ExternalScript")
            }
          }
          if (-not $native) { continue }
          $sb = $el.Parent
          while ($sb -and $sb -isnot [System.Management.Automation.Language.ScriptBlockAst]) { $sb = $sb.Parent }
          $ascii = $false
          if ($sb) {
            foreach ($as in $sb.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
              if ($as.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and ($as.Left.VariablePath.UserPath -replace "^(script|global|local|private):", "") -eq "OutputEncoding" -and $as.Right.Extent.Text -match "ASCIIEncoding") { $ascii = $true }
            }
          }
          if (-not $ascii) { $bad += ("line {0}: a pipeline feeds the stdin of {1}" -f $el.Extent.StartLineNumber, $el.Extent.Text) }
        }
      }
      if ($bad) { $bad; exit 2 }
      exit 0
    ' 2>&1) || { echo "$out" >&2; fail "$f does not parse, or pipes into a native command (A14 review 5, H1: set a local ASCII \$OutputEncoding or drop the pipe)."; }
    echo "    parsed  $f (no pipeline into a native command)"
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
check_pos=$(grep -n "bundle.json records commit" "$S" | head -1 | cut -d: -f1) || true
write_pos=$(grep -n 'Move-Item -LiteralPath \$recordTmp -Destination \$RecordPath' "$S" | head -1 | cut -d: -f1) || true
{ [ -n "$check_pos" ] && [ -n "$write_pos" ] && [ "$write_pos" -gt "$check_pos" ]; } \
  || fail "$S must write the last-signed record only AFTER the bundle.json commit check."
# The one-time install recipe (release-signing-keys.md §0) writes this file through PowerShell 5.1,
# which also reads a BOM-less .ps1 in the ANSI code page: it stays pure ASCII. And PRINTABLE ASCII
# (A14 review 3): the operator reads that install as a raw `git diff --no-index`, so no control
# character but tab and line ends may be in it - an ESC would reach the console unescaped. (Both are
# now checked for every scripts/*.ps1|psm1|psd1 at the top of this gate, A14 review 5, H2.)
# A14 review 3, C1: default-include. The review shows every changed path except $ExcludedTrees, a short list of trees
# that never run on the signing box. None of them may hold a module the update-signer or the MSI links (the signer is
# a shadowJar of tools/update-signer and every module it links, ALL of each: an unqualified call resolves to a
# same-package declaration in any module on the classpath; the MSI is the Windows client, which runs on the signing
# box's account once installed), so walk both projects' project(":...") dependencies transitively.
excl_block=$(sed -n '/^\$ExcludedTrees = @(/p' "$S") || true
[ -n "$excl_block" ] || fail "$S has no one-line \$ExcludedTrees = @(...) - what does the review leave out?"
mapfile -t EXCLUDED < <(printf '%s\n' "$excl_block" | grep -oE "'[^']+'" | tr -d "'")
[ "${#EXCLUDED[@]}" -gt 0 ] && [ "${#EXCLUDED[@]}" -le 10 ] || fail "$S \$ExcludedTrees must be a short explicit list (found ${#EXCLUDED[@]})."
excluded_prefix() { # excluded_prefix <dir/> - the entry that excludes it, case-insensitively (NTFS), or nothing
  local d="${1,,}" e
  for e in "${EXCLUDED[@]}"; do case "$d" in "${e,,}"*) echo "$e"; return ;; esac; done
}
for need in core/ tools/ tools/update-signer/ scripts/ gradle/ app-desktop/ buildSrc/ build-logic/ .githooks/; do
  hit=$(excluded_prefix "$need")
  [ -z "$hit" ] || fail "$S \$ExcludedTrees hides $need (via '$hit'): that runs on the signing box (A14 review 3, C1)."
done
seen=" tools/update-signer app-desktop "; queue=(tools/update-signer app-desktop)
while [ "${#queue[@]}" -gt 0 ]; do
  m="${queue[0]}"; queue=("${queue[@]:1}")
  [ -f "$m/build.gradle.kts" ] || fail "module $m (linked by the update-signer or the MSI) has no build.gradle.kts"
  for dep in $(grep -oE 'project\("(:[A-Za-z0-9_.-]+)+"\)' "$m/build.gradle.kts" | grep -oE '(:[A-Za-z0-9_.-]+)+'); do
    d="${dep#:}"; d="${d//://}"
    case "$seen" in *" $d "*) continue ;; esac
    seen="$seen$d "; queue+=("$d")
  done
done
for d in $seen; do
  hit=$(excluded_prefix "$d/")
  [ -z "$hit" ] || fail "the update-signer or the MSI links $d, which \$ExcludedTrees in $S hides (via '$hit') (A14 review 3, C1)."
done
grep -qF '[System.StringComparison]::OrdinalIgnoreCase' "$S" || fail "$S no longer matches the excluded trees case-insensitively."
pat_line=$(grep -m1 '^\$AlwaysShownPattern = ' "$S") || true
for need in 'gradle' 'kts' 'jar' 'ps1' 'bat' 'gradle\.properties' 'gradle-wrapper' '\.gitattributes' '\.lfsconfig' '\.gitmodules'; do
  printf '%s\n' "$pat_line" | grep -qF -- "$need" || fail "$S \$AlwaysShownPattern lost '$need' (build inputs and git attribute files are shown inside excluded trees too)."
done
grep -qF "':(icase)dist/'" "$S" || fail "$S no longer refuses a first-run seed while git tracks dist/ in any case (A14 review 3, C4)."
# A14 review R2-2: git output is escaped before it is printed, and the stat comes before the commit list; since the
# third review the log and the diffs are read as bytes split at LF alone (a CR in a subject or a changed line used to
# start a new console line), through Get-GitLines.
grep -qF '[System.Text.RegularExpressions.MatchEvaluator]' "$S" || fail "$S lost the MatchEvaluator escape of git output."
grep -nE 'Write-Host .*\$(log|stat|status|after|l)\b|Write-Host \$fetch|Write-Host \$anc|\| ForEach-Object \{ Write-Host "   \$_" \}' "$S" >&2 \
  && fail "$S prints git output raw (lines above): route it through Write-GitText."
grep -qF '"--output=$tmp"' "$S" || fail "$S no longer reads the log and diffs through git --output (CR-safe)."
grep -nE "Invoke-Git -Arguments @\('(log|diff)'|Invoke-Git -Arguments @\('-c', 'core\.quotePath=true', 'diff'" "$S" >&2 \
  && fail "$S reads a log or a diff through PowerShell's line splitting again (lines above): use Get-GitLines."
stat_pos=$(grep -n -- '---- changed since the last signed release' "$S" | head -1 | cut -d: -f1) || true
log_pos=$(grep -n -- '---- commits {0} ----' "$S" | head -1 | cut -d: -f1) || true
{ [ -n "$stat_pos" ] && [ -n "$log_pos" ] && [ "$stat_pos" -lt "$log_pos" ]; } \
  || fail "$S must print the escaped stat BEFORE the escaped commit list."
# A14 review 3, C2: the full diff of the review set, printed by signandvari itself before checkout, with git's
# textconv, external diff and colour off, through its own pager; no advice to run a raw git diff.
grep -qF "'diff', '--text', '--no-textconv', '--no-ext-diff', '--no-color'" "$S" \
  || fail "$S no longer prints the full diff with --text --no-textconv --no-ext-diff --no-color (A14 review 3, C2)."
grep -qiE 'read it in full in another window|core\.pager|less -R"|\| *less\b' "$S" && fail "$S points the operator at a raw git diff or an external pager again (A14 review 3, C2)."
# A14 review R2-3: never a tag as the first-run seed.
grep -qE "for-each-ref.*refs/tags|Get-SeedTag" "$S" && fail "$S seeds the first-run baseline from tags again (A14 review R2-3)."
# The NTFS case and A14 review 3, C3/C5: collisions refused before the checkout; the full diff shown before it; the
# checkout runs with no hook and no LFS smudge; the tree checked clean and every reviewed file hashed against the
# index after it, before the confirmation; and a finally puts HEAD back on every way out before the confirmation.
coll_pos=$(grep -n '^\$collisions = Find-CaseCollisions' "$S" | head -1 | cut -d: -f1) || true
page_pos=$(grep -n '^Show-Paged -Lines \$FullDiff' "$S" | head -1 | cut -d: -f1) || true
attr_pos=$(grep -n '\$script:GitPrefix = @("--attr-source=\$EmptyTree") + \$SafeGit' "$S" | head -1 | cut -d: -f1) || true
co_pos=$(grep -n "Invoke-Git -Arguments @('checkout', '--detach', \$Commit)" "$S" | head -1 | cut -d: -f1) || true
clean_pos=$(grep -n "\$after = (Invoke-Git -Arguments @('status', '--porcelain'))" "$S" | head -1 | cut -d: -f1) || true
bytes_pos=$(grep -n '^    Assert-ReviewedFilesOnDisk$' "$S" | head -1 | cut -d: -f1) || true
ask_pos=$(grep -n 'Read-Host ("   Type the version' "$S" | head -1 | cut -d: -f1) || true
{ [ -n "$coll_pos" ] && [ -n "$page_pos" ] && [ -n "$attr_pos" ] && [ -n "$co_pos" ] && [ -n "$clean_pos" ] && [ -n "$bytes_pos" ] && [ -n "$ask_pos" ] \
  && [ "$coll_pos" -lt "$page_pos" ] && [ "$page_pos" -lt "$attr_pos" ] && [ "$attr_pos" -lt "$co_pos" ] && [ "$co_pos" -lt "$clean_pos" ] \
  && [ "$clean_pos" -lt "$bytes_pos" ] && [ "$bytes_pos" -lt "$ask_pos" ]; } \
  || fail "$S must refuse collisions, then show the full diff, then take --attr-source where git has it, then check out, then check the tree clean and every reviewed file's bytes, then ask."
safe_line=$(grep -m1 '^\$SafeGit = ' "$S") || true
for need in 'core.hooksPath=$($script:NoHooks)' "'core.fsmonitor='"; do
  printf '%s\n' "$safe_line" | grep -qF -- "$need" || fail "$S \$SafeGit lost $need (A14 review 3, C3)."
done
grep -qF "'-c', 'filter.lfs.clean=', '-c', 'filter.lfs.smudge=', '-c', 'filter.lfs.process=', '-c', 'filter.lfs.required=false'" "$S" || fail "$S no longer blanks every LFS filter, clean included (A14 review 3, C3; review 5)."
grep -qF "\$env:GIT_LFS_SKIP_SMUDGE = '1'" "$S" || fail "$S no longer sets GIT_LFS_SKIP_SMUDGE for the checkout (A14 review 3, C3)."
# A14 review 5: every git command carries $script:GitPrefix (from the first, with $SafeGit), and from the checkout on
# --attr-source=<the empty tree> where this git has it.
grep -qF '$gitArgs = @($script:GitPrefix) + @($Arguments)' "$S" || fail "$S no longer puts \$script:GitPrefix in front of every git command (A14 review 5)."
grep -qF '$script:GitPrefix = $SafeGit' "$S" || fail "$S no longer starts every git command with \$SafeGit (A14 review 5)."
grep -qF "\$EmptyTree = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'" "$S" || fail "$S lost the empty tree id for --attr-source (A14 review 5)."
[ "$(grep -cE '& git( |$)' "$S")" = 1 ] || fail "$S runs git outside Invoke-Git (A14 review 5: every git command carries \$script:GitPrefix)."
# A14 review 5, H1: the reviewed files are hashed in-process; nothing feeds git (or any native command) a pipeline.
grep -nE -- "--stdin|InputLines|RedirectStandardInput|StandardInput" "$S" | grep -vE '^[0-9]+:[[:space:]]*#' >&2 && fail "$S feeds a native command's standard input again (lines above; A14 review 5, H1)."
grep -qF '[System.IO.File]::ReadAllBytes((Join-Path $Repo $paths[$i]))' "$S" && grep -qF '(Get-BlobId $bytes) -ne $want[$i]' "$S" \
  || fail "$S no longer hashes every reviewed file in-process against the index (A14 review 3, C3; review 5, H1)."
grep -qF "\$sshOpts = @('-n', " "$S" || fail "$S runs ssh without -n: it would read this console (A14 review 5, H1)."
# A14 review 5, S1-S5: the shape of each fix; the scratch-repo test below drives each one.
grep -qF '$script:PowerShellFilePattern' "$S" && grep -qF 'NOT ASCII, NO BOM' "$S" || fail "$S no longer refuses a reviewed PowerShell file with a byte above 0x7F and no BOM (A14 review 5, S1)."
grep -qF "\$text -match '\\r(?!\\n)'" "$S" && grep -qF 'LONE CR' "$S" || fail "$S no longer refuses a reviewed text file with a lone CR (A14 review 5, S2)."
grep -qF "if (\$lf.IndexOf([char]0) -ge 0 -or \$lf.IndexOf([char]13) -ge 0) { return 'forced' }" "$S" || fail "$S allows the CRLF form of a blob holding a NUL or a CR again (A14 review 5, S4)."
grep -qF '$script:MaxDisplayChars = 400' "$S" && grep -qF '$r = Get-DisplayRows $shown $width' "$S" || fail "$S no longer caps displayed lines and pages by console rows (A14 review 5, S3)."
pat_u=$(grep -m1 -A1 '^\$script:UnsafeTextPattern = ' "$S") || true
for need in '\p{Cf}' '\uDB40[\uDC00-\uDC7F' '\u00AD' '\u115F\u1160' '\u2000-\u200F' '\u205F-\u206F' '\u3164' '\uFE00-\uFE0F' '\uFEFF' '\uFFF9-\uFFFD' '(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]'; do
  printf '%s\n' "$pat_u" | grep -qF -- "$need" || fail "$S \$UnsafeTextPattern lost $need (A14 review 5, S1/S5)."
done
grep -qF '$script:StrictUtf8.GetString(' "$S" && grep -qF '[char](0xDC00 + $b)' "$S" || fail "$S no longer keeps a byte that is not UTF-8 as a byte for display (A14 review 5, S1)."
grep -qF 'if (-not $confirmed -and $checkedOut) {' "$S" || fail "$S no longer puts HEAD back in a finally on every way out before the confirmation (A14 review 3, C5)."
# A14 review 3 (suspected): the update-signer jar is deleted and rebuilt from the tree on every real run.
P=scripts/prestige-release.ps1
del_pos=$(grep -n 'Remove-Item -LiteralPath \$SignerJar -Force' "$P" | head -1 | cut -d: -f1) || true
build_pos=$(grep -n "':tools:update-signer:shadowJar', '--console=plain'" "$P" | head -1 | cut -d: -f1) || true
{ [ -n "$del_pos" ] && [ -n "$build_pos" ] && [ "$del_pos" -lt "$build_pos" ]; } \
  || fail "$P must delete the update-signer jar before it builds it (A14 review 3)."
guard_pos=$(grep -nE 'if \(-not \(Test-Path -LiteralPath \$SignerJar' "$P" | head -1 | cut -d: -f1) || true
{ [ -z "$guard_pos" ] || [ "$guard_pos" -gt "$build_pos" ]; } \
  || fail "$P builds the update-signer only when the jar is missing again: a stale jar would be handed the key (A14 review 3)."
bash scripts/ci/signandvari-pin.test.sh || fail "the signandvari tag-pin scratch-repo test failed."
echo "    signandvari.ps1 + prestige-release.ps1 verify the tag against -Commit; release tag fetched alone, unforced;"
echo "    the release descends from the workstation's last signed commit and is confirmed by a human;"
echo "    the review shows every changed path but the trees that never run there, escaped, stat first, then the full"
echo "    diff before checkout; a hook-less, filter-less checkout whose reviewed files hash (in-process) to git's; HEAD put back on refusal;"
echo "    no pipeline into a native command; reviewed PowerShell ASCII or BOM-marked, no lone CR, CRLF only where git converts"
