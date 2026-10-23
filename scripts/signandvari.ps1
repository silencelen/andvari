# andvari - the whole PRESTIGE release ceremony as one command.
#
#   signandvari 0.24.0 -Commit <sha>            # build + sign + assemble + ordered drop
#   signandvari 0.24.0 -Commit <sha> -DryRun    # preflight, seq arithmetic and manifest preview only
#   signandvari 0.24.0 -Commit <sha> -SkipDrop  # produce the bundle, deliver it by hand
#   signandvari 0.24.0 -Commit <sha> -SkipReadBack  # ... and do not assert the channel afterwards (rare)
#   signandvari 0.24.0 -Commit <sha> -Baseline <sha> # FIRST RUN ONLY, when this box holds no signed bundle
#
# -Commit is REQUIRED: the full 40-hex commit the build host cut the tag at, copied from the
# handover line the build host prints. See "THE TAG IS NOT TRUSTED" and "THE LAST SIGNED COMMIT"
# below. Every run, -DryRun included, stops for one typed confirmation before the tree's code runs,
# and once confirmed every run, -DryRun included, runs the tree's prestige-release.ps1 on this
# account, beside the key: a dry run signs nothing, but it is not a run in which no tree code runs.
#
# WHY THIS EXISTS. scripts\prestige-release.ps1 already does the signing correctly. What it does
# NOT do is the handling around it: fetching tags, checking out the ref it then asserts you are on,
# finding signtool, clearing the leftovers a previous ceremony dropped in the repo root, and
# delivering the bundle in the one order the build-host watcher tolerates. Those steps were run by
# hand, and each of them has cost a release at least once. This wraps them. It reimplements NOTHING
# of the ceremony itself - the signing, the seq arithmetic and the manifest assembly all still
# happen inside prestige-release.ps1, which stays the single source of truth for them.
#
# THIS TOOL RUNS FROM OUTSIDE THE REPO - installed at %USERPROFILE%\bin\signandvari.ps1. That is
# load-bearing, not tidiness: step 3 git-checkouts the release tag, which swaps out the entire
# working tree. A copy living in scripts\ would be checking out a commit that may not contain it,
# and would be replaced (or deleted) underneath its own execution. It finds the repo through
# ANDVARI_REPO instead of through its own location.
#
# NOTHING INSTANCE-SPECIFIC IS HARDCODED HERE. The repo is public and internal hostnames have
# leaked into it before, so the checkout path and the drop destination are read from the
# environment and appear in this file only as variable names.
#
# THE TAG IS NOT TRUSTED (security review 2026-10). This box runs the tag's tree - its scripts and
# its gradle build - with the update-signing key openable by the same account. A tag is a mutable
# ref on a remote the build host can write to, so "whatever v<Version> points at today" is not a
# fact this machine can rely on. Two rules narrow that:
#   * only the release tag is fetched, and never with --force. A remote v<Version> that disagrees
#     with the local one is a hard stop that names both commits, never a silent replacement; any
#     OTHER tag that moved on the remote is not fetched at all, so it cannot block a ceremony;
#   * the operator passes -Commit <sha>, the commit the build host's handover line names. The tag
#     must resolve to exactly that commit BEFORE anything is checked out, HEAD must equal it after
#     the checkout, and again immediately before prestige-release.ps1 starts - which is handed the
#     same pin and records it in bundle.json.
# What the pin closes: a tag moved by anyone other than the build host, a tag moved after the
# handover line was printed, and an accidental re-tag. What it does NOT close: the handover line
# reads the build host's own local tag, so a compromised build host chooses both the tag and the
# pin. That is what the next rule is for.
#
# THE LAST SIGNED COMMIT (security review 2026-10, A13 review RF1). This workstation keeps its own
# record of the commit its last SUCCESSFUL ceremony signed, outside the repo and out of the tree's
# reach before it runs: %LOCALAPPDATA%\andvari\signandvari-last-signed.json. Before any of the
# tree's code runs, the release commit must DESCEND from that commit (git merge-base
# --is-ancestor), a stat, the commits and the full diff since it are printed (WHAT THE REVIEW
# SHOWS, below), and the operator types the version to confirm. A run with no human at a console
# (-NonInteractive, redirected input, a service) fails closed before anything is checked out. The
# record moves only after prestige-release.ps1 succeeded AND bundle.json records the pinned
# commit; a dry run, a refused run or a failed ceremony leaves it where it was. This is a review
# aid that rests on the operator reading the diff, not a proof: a compromised build host can still
# cut a descendant commit, but it can no longer swap the tree silently, rewrite history under the
# last release, or skip the moment a human looks at what changed in the build.
#
# WHAT THE REVIEW SHOWS (A14 review 3, C1 and C2; see $ExcludedTrees in step 3). EVERY path that
# changed since the last signed commit, first as a stat and then as the full diff, except the
# files under a short list of trees that never run on this box (the phone app, the browser code,
# the server and its deployment, prose and test vectors, CI); those are counted instead. Even
# inside those trees, what gradle, git or Windows reads as code or as checkout instructions is
# shown: build scripts, gradle properties and wrapper files, jars, PowerShell and batch files,
# .gitattributes, .lfsconfig and .gitmodules. So whatever a build script newly links - a module, a
# source or resource directory, a buildscript classpath file, an agent jar - is in the review
# wherever it lives, unless it lives inside one of those trees; a build-script line that links a
# file there is a reason to stop, because from then on that file's changes would not be shown.
# app-desktop/ is shown: the MSI it is compiled into runs here once it is installed on this
# account. The full diff is printed by this script BEFORE checkout, through its own pager, never
# an external one, with --text --no-textconv --no-ext-diff --no-color, so neither this box's diff
# settings nor the tree's attributes can hide or recolour a change. Not covered: the third-party
# artifacts gradle downloads (only the catalog that names them) and the JDK. Every printed line
# from git is escaped (A14 review R2-2; the invisible characters too, review 5) and read from git
# as bytes split at LF alone, so a CR cannot start a fake line; a byte that is not UTF-8 prints as
# \xNN and a real U+FFFD as \uFFFD, so neither hides behind a replacement character; no displayed
# line is longer than $MaxDisplayChars (a longer one is cut, marked and counted, and is whole in
# the review copy), and the pager counts the console rows a line wraps to; paths are matched
# case-insensitively; and a tree with two paths that are equal on a case-insensitive disk is
# refused before checkout (NTFS would write one over the other).
#
# THE CHECKOUT (A14 review 3, C3 and C5; review 5). Every git command this script runs uses no hook
# (core.hooksPath is an empty directory, whatever the repo config names), no fsmonitor hook and no
# LFS filter at all (clean, smudge and process blanked). From the checkout on, where this git has
# --attr-source (2.42 and later), the release tree's own .gitattributes are not read either, so the
# tree cannot name a filter this box defines. Afterwards the tree must be clean and every file the
# review covers must be, byte for byte, what git holds for it: this script hashes the bytes on disk
# itself, as git hashes a blob, and compares them with git ls-files -s. The one difference allowed
# is the CRLF git's own end-of-line conversion writes on a Windows checkout, and only for a blob
# git would convert (no NUL, no CR). Anything else - an LFS object, a filter's output, a file changed
# after the checkout - stops the run before the confirmation, and so does a reviewed PowerShell file
# with a byte above 0x7F and no byte-order mark (Windows PowerShell 5.1 would read it in the ANSI
# code page, not as the UTF-8 the review showed) and a reviewed text file with a CR that no LF
# follows (Kotlin, Java and PowerShell end a line there; the review does not). Every way out
# between the checkout and the confirmation (a refusal, a git command that dies, Ctrl+C at the
# prompt) puts HEAD back. Closing the window is the one exit that cannot.
#
# NO STANDARD INPUT TO A NATIVE PROGRAM (A14 review 5, H1). Windows PowerShell writes a pipeline
# into a native program's stdin in $OutputEncoding, and a profile that sets it to UTF-8 puts a
# byte-order mark in front of the first line. Nothing in this script pipes into git, ssh or scp;
# the one place that used to (git hash-object --stdin-paths) hashes in-process now, and ssh runs
# with -n. powershell-gate.sh refuses a pipeline into a native command in any scripts/*.ps1.
#
# FIRST RUN (no record yet, A14 review R2-3): the baseline is the commit in this box's OWN most
# recent signed bundle - dist\release-bundle-<version>\bundle.json beside its manifest.json.sig,
# which prestige-release.ps1 writes only after a signature it verified; the highest seq wins. No
# seed is taken while git tracks anything under dist\ in any case (A14 review 3, C4: on NTFS a
# tracked Dist/... lands at dist\, and it is the tree's content, not this box's). With no such
# bundle the run stops and asks for -Baseline <40-hex>, a commit the operator has reviewed (the last
# release they signed); -Baseline may also be passed on any first run to choose the comparison, it
# must be a STRICT ancestor of -Commit (never -Commit itself), and it is refused once a record
# exists. Tags are never the seed: a plain `git fetch` or `git pull` auto-follows new tags, so a
# planted intermediate tag would become the baseline and hide every change up to it. Deleting the
# record is the deliberate reset (history rewritten on purpose, a new checkout): the next run is a
# first run again.
#
# THE KEYS ARE NEVER TOUCHED. The update-signing key and the Authenticode cert live on this machine
# and only on this machine. This tool never reads, prints, copies, exports or relocates either, and
# deliberately offers no flag that could. prestige-release.ps1 hands the signer a PATH and the
# workstation cert store handles the rest; neither ever passes through this script.

[CmdletBinding()]
param(
    # Fleet version being released. The tag v<Version> must already exist on the remote.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    # The full 40-hex commit the release tag must resolve to. REQUIRED. It comes from the build
    # host's handover line (`signandvari <ver> -Commit <sha>`), which reads the build host's own
    # local tag: it closes a tag moved by anyone other than the build host, a tag moved after the
    # handover line was printed, and an accidental re-tag. A compromised build host chooses both
    # the tag and this pin; THE LAST SIGNED COMMIT (above) is the layer aimed at that.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$Commit,

    # FIRST RUN ONLY: the commit to compare this release against when this workstation has no
    # last-signed record (required when it also holds no signed bundle under dist\). A commit the
    # operator reviewed (the last release they signed), never one read off the build host. It must
    # be a strict ancestor of -Commit. Refused once a record exists.
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$Baseline,

    # Preflight, fetch, seq arithmetic and a manifest preview. No build, no signing, no drop.
    [switch]$DryRun,

    # Produce the bundle but do not deliver it. Use when the drop will be done by hand.
    [switch]$SkipDrop,

    # Skip the post-publish read-back (step 9). Only for a run whose channel effect is
    # deliberately not being asserted - a re-drop of an already-published seq, or a network
    # that cannot reach the public origin from this box. A normal ceremony always reads back.
    [switch]$SkipReadBack
)

$ErrorActionPreference = 'Stop'

$Tag = "v$Version"
$Commit = $Commit.ToLowerInvariant()

# The public download origin - the same value clients pin and prestige-release.ps1 defaults to.
# Public by design, but still overridable so nothing here is welded to one deployment.
$BaseUrl = if ($env:ANDVARI_BASE_URL) { $env:ANDVARI_BASE_URL.TrimEnd('/') } else { 'https://andvari.monahanhosting.com' }

# The bundle contract: four PAYLOAD files, then the signature that signals completion.
$PayloadNames = @("andvari-$Version.msi", 'manifest.json', 'release-spec.json', 'bundle.json')
$SigName      = 'manifest.json.sig'

# ---------------------------------------------------------------------------- output helpers ----

$script:StepNo = 0
function Write-Step  { param([string]$Text) $script:StepNo++; Write-Host ''; Write-Host ("== {0}. {1}" -f $script:StepNo, $Text) -ForegroundColor Cyan }
function Write-Info  { param([string]$Text) Write-Host "   $Text" }
function Write-Ok    { param([string]$Text) Write-Host "   OK   $Text" -ForegroundColor Green }
function Write-Warn2 { param([string]$Text) Write-Host "   WARN $Text" -ForegroundColor Yellow }
# The empty hooks directory every git command points core.hooksPath at (step 2) goes with any
# refusal, so a run that stops leaves nothing behind in the temporary directory.
$script:NoHooks = $null
function Die {
    param([string]$Text)
    if ($script:NoHooks) { Remove-Item -LiteralPath $script:NoHooks -Recurse -Force -ErrorAction SilentlyContinue }
    throw "signandvari: $Text"
}

function Get-Sha256Lower {
    param([string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# Windows PowerShell 5.1 wraps every stderr line from a NATIVE program in an ErrorRecord, and under
# $ErrorActionPreference = 'Stop' that ErrorRecord is a TERMINATING error - even when the program
# exited 0. git announces "HEAD is now at ..." on stderr, gradle logs its whole build there, and ssh
# uses it for banners; all three would abort a perfectly healthy run. Native commands report failure
# through their EXIT CODE, which every caller below checks, so relax the preference around them.
function Invoke-Native {
    param([scriptblock]$Body)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Body } finally { $ErrorActionPreference = $prev }
}

# EVERY LINE PRINTED FROM GIT GOES THROUGH HERE (A14 review R2-2): commit subjects, paths, a
# refusal's git output. git passes a subject's bytes through untouched, ESC included, and on a VT
# console (Windows Terminal is the Windows 11 default) a subject can move the cursor and erase or
# redraw the lines above it - hide the stat, or draw a fake "(no changes)". Every C0 control (tab,
# CR and LF too: one line stays one line), DEL, every C1 control (0x80-0x9F, which holds the 8-bit
# CSI), the line and paragraph separators and the bidi controls become a visible \uXXXX. So do the
# characters that print as nothing or as a plain space (A14 review 5, S5): every format character
# (\p{Cf}: the zero-width space, joiners and word joiner, U+FEFF, the soft hyphen, the invisible
# operators), the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0 (letters, so valid inside an
# identifier), the variation selectors, the combining grapheme joiner, the Mongolian and Khmer
# invisibles, the non-ASCII spaces, U+FFF9-U+FFFD (U+FFFD so a real one is not taken for a byte
# that is not UTF-8), and the tag characters and supplementary variation selectors (U+E0000-U+E007F,
# U+E0100-U+E01EF; outside the BMP they print as \U000Exxxx). A byte that is not UTF-8 reaches this
# as a lone low surrogate U+DC80-U+DCFF (ConvertFrom-Utf8Bytes, below) and prints as \xNN; any other
# lone surrogate prints as \uXXXX. The pattern is spelled with \u escapes so this file stays pure
# ASCII, and the replacement is a MatchEvaluator, which Windows PowerShell 5.1 runs.
$script:UnsafeTextPattern = '\uDB40[\uDC00-\uDC7F\uDD00-\uDDEF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]|\p{Cf}|' +
    '[\u0000-\u001F\u007F-\u00A0\u00AD\u034F\u061C\u115F\u1160\u1680\u17B4\u17B5\u180B-\u180F\u2000-\u200F\u2028-\u202F\u205F-\u206F\u3000\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFD]'
function ConvertTo-Printable {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [regex]::Replace($Text, $script:UnsafeTextPattern, [System.Text.RegularExpressions.MatchEvaluator] {
        param($m)
        $v = $m.Value
        if ($v.Length -eq 2) { return ('\U{0:X8}' -f [char]::ConvertToUtf32($v[0], $v[1])) }
        $c = [int][char]$v
        if ($c -ge 0xDC80 -and $c -le 0xDCFF) { return ('\x{0:X2}' -f ($c - 0xDC00)) }
        return ('\u{0:X4}' -f $c)
    })
}

# BYTES TO TEXT FOR DISPLAY (A14 review 5, S1). A strict UTF-8 decode when the bytes are UTF-8 (the
# usual case, and fast); otherwise each byte that does not belong to a well-formed UTF-8 sequence
# becomes the lone low surrogate U+DC00 + byte, which ConvertTo-Printable shows as \xNN. The plain
# decoder turned every such byte into U+FFFD, so the review could not say WHICH byte it was - and
# Windows PowerShell 5.1 reads a script without a byte-order mark in the ANSI code page, where
# 0x91-0x94 are the curly quotes PowerShell takes for real ones.
$script:StrictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
function ConvertFrom-Utf8Bytes {
    param([byte[]]$Bytes, [int]$Offset = 0, [int]$Count = -1)
    if ($Count -lt 0) { $Count = $Bytes.Length - $Offset }
    if ($Count -le 0) { return '' }
    try { return $script:StrictUtf8.GetString($Bytes, $Offset, $Count) } catch { }
    $sb = New-Object System.Text.StringBuilder ($Count)
    $i = $Offset; $end = $Offset + $Count
    while ($i -lt $end) {
        $b = [int]$Bytes[$i]
        if ($b -lt 0x80) { [void]$sb.Append([char]$b); $i++; continue }
        $need = 0; $lo = 0x80; $hi = 0xBF; $cp = 0
        if ($b -ge 0xC2 -and $b -le 0xDF) { $need = 1; $cp = $b -band 0x1F }
        elseif ($b -ge 0xE0 -and $b -le 0xEF) {
            $need = 2; $cp = $b -band 0x0F
            if ($b -eq 0xE0) { $lo = 0xA0 } elseif ($b -eq 0xED) { $hi = 0x9F }
        }
        elseif ($b -ge 0xF0 -and $b -le 0xF4) {
            $need = 3; $cp = $b -band 0x07
            if ($b -eq 0xF0) { $lo = 0x90 } elseif ($b -eq 0xF4) { $hi = 0x8F }
        }
        $ok = ($need -gt 0) -and (($i + $need) -lt $end)
        for ($k = 1; $ok -and $k -le $need; $k++) {
            $c = [int]$Bytes[$i + $k]
            $min = if ($k -eq 1) { $lo } else { 0x80 }
            $max = if ($k -eq 1) { $hi } else { 0xBF }
            if ($c -lt $min -or $c -gt $max) { $ok = $false }
            else { $cp = ($cp -shl 6) -bor ($c -band 0x3F) }
        }
        if ($ok) {
            if ($cp -ge 0x10000) { [void]$sb.Append([char]::ConvertFromUtf32($cp)) } else { [void]$sb.Append([char]$cp) }
            $i += $need + 1
        }
        else { [void]$sb.Append([char](0xDC00 + $b)); $i++ }
    }
    return $sb.ToString()
}

# NO DISPLAYED LINE IS LONGER THAN THIS (A14 review 5, S3). One long line wraps over many console
# rows, and enough of them push what came before out of the scrollback unseen. A longer line is cut
# here with a visible marker; step 3 counts the lines it cut, and the review copy holds every
# reviewed line whole.
$script:MaxDisplayChars = 400
function Limit-DisplayLine {
    param([string]$Text, [string]$Where = '')
    if ($Text.Length -le $script:MaxDisplayChars) { return $Text }
    $cut = $script:MaxDisplayChars
    if ([char]::IsHighSurrogate($Text[$cut - 1])) { $cut-- }
    return ('{0} <<CAPPED: {1} of {2} characters shown{3}>>' -f $Text.Substring(0, $cut), $cut, $Text.Length, $Where)
}
function Write-GitText {
    param([AllowNull()][AllowEmptyString()][string]$Text, [string]$Indent = '   ')
    if ($null -eq $Text) { return }
    foreach ($line in ($Text -split "`r?`n")) { Write-Host ($Indent + (Limit-DisplayLine (ConvertTo-Printable $line))) }
}

# ============================================================ 1. ENVIRONMENT ====================

Write-Step 'Environment'

if (-not $env:ANDVARI_REPO) {
    Die 'ANDVARI_REPO is not set - point it at the andvari checkout this ceremony runs in.'
}
if (-not $env:ANDVARI_RELEASE_DROP) {
    Die 'ANDVARI_RELEASE_DROP is not set - point it at the build-host drop, as user@host:/path/.'
}

$Repo = $env:ANDVARI_REPO
if (-not (Test-Path -LiteralPath $Repo -PathType Container)) {
    Die "ANDVARI_REPO points at '$Repo', which is not a directory."
}
$Repo = (Resolve-Path -LiteralPath $Repo).Path

$Ceremony = Join-Path $Repo 'scripts\prestige-release.ps1'
if (-not (Test-Path -LiteralPath $Ceremony -PathType Leaf)) {
    Die "no scripts\prestige-release.ps1 under ANDVARI_REPO ($Repo) - is that an andvari checkout?"
}

$DropTarget = $env:ANDVARI_RELEASE_DROP
# user@host:/path/ - split on the FIRST colon, which separates the ssh host spec from the path.
if ($DropTarget -notmatch '^(?<hostspec>[^:]+):(?<path>.+)$') {
    Die "ANDVARI_RELEASE_DROP must look like user@host:/path/ (got '$DropTarget')."
}
$DropHost = $matches['hostspec']
$DropPath = $matches['path']
if (-not $DropPath.EndsWith('/')) { $DropPath += '/' }

# THE LAST SIGNED COMMIT lives under the account's local app data: outside the repo (no checkout
# replaces it, no tree writes it before a confirmation) and per account, like the key itself.
if (-not $env:LOCALAPPDATA) {
    Die 'LOCALAPPDATA is not set - the last-signed record lives under %LOCALAPPDATA%\andvari\.'
}
$RecordDir  = Join-Path $env:LOCALAPPDATA 'andvari'
$RecordPath = Join-Path $RecordDir 'signandvari-last-signed.json'

Write-Ok "repo $Repo"
Write-Ok "drop $DropTarget"
Write-Ok "last-signed record $RecordPath"
Write-Info "version $Version   tag $Tag   commit $Commit"
Write-Info "dry-run $([bool]$DryRun)   skip-drop $([bool]$SkipDrop)"

# ============================================================ 2. TAG, TREE, LEFTOVERS ===========

Write-Step 'Tag, working tree, leftovers'

# EVERY GIT COMMAND THIS SCRIPT RUNS goes through Invoke-Git, with $script:GitPrefix in front of its
# arguments (A14 review 3, C3; review 5):
#   * core.hooksPath = a new, empty directory: no hook runs, whatever core.hooksPath this repo's
#     config names - a config that points it into the work tree would otherwise run the release
#     tree's own post-checkout hook here, before the confirmation;
#   * core.fsmonitor off: no fsmonitor hook either;
#   * no LFS filter at all: an empty filter.lfs.clean, .smudge and .process, not required. Git for
#     Windows installs a system LFS filter, and a tree whose .gitattributes says filter=lfs would
#     otherwise have git-lfs write, for a pointer, LFS content no review saw at the checkout, and run
#     git-lfs clean on the files git status re-reads after it (review 5, the clean-filter belt);
#   * from the checkout on, where this git has it, --attr-source=<the empty tree>: the release
#     tree's .gitattributes are not read at all, so the tree can name no filter (LFS or any other
#     this box defines) and no conversion. This box's own attribute files still apply.
# And NO STANDARD INPUT (A14 review 5, H1): git is never fed a pipeline. Windows PowerShell writes
# one in $OutputEncoding, and a profile that sets UTF-8 puts a byte-order mark in front of the first
# line, so git read a path that does not exist and every honest ceremony died after the checkout.
$script:NoHooks = Join-Path ([System.IO.Path]::GetTempPath()) ('signandvari-nohooks-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:NoHooks -Force | Out-Null
$SafeGit = @('-c', "core.hooksPath=$($script:NoHooks)", '-c', 'core.fsmonitor=',
    '-c', 'filter.lfs.clean=', '-c', 'filter.lfs.smudge=', '-c', 'filter.lfs.process=', '-c', 'filter.lfs.required=false')
$script:GitPrefix = $SafeGit
function Invoke-Git {
    param([string[]]$Arguments, [switch]$AllowFailure)
    $gitArgs = @($script:GitPrefix) + @($Arguments)
    $out = Invoke-Native { & git -C $Repo @gitArgs 2>&1 }
    $code = $LASTEXITCODE
    if ($code -ne 0 -and -not $AllowFailure) {
        Write-GitText ($out | Out-String)
        Die "git $($Arguments -join ' ') failed (exit $code)"
    }
    [pscustomobject]@{ ExitCode = $code; Output = ($out | Out-String) }
}

# GIT OUTPUT THAT IS SHOWN FOR REVIEW is read as bytes and split at LF alone (A14 review 3).
# PowerShell splits a native program's output at a lone CR as well as at LF, so a CR inside a
# commit subject or a changed line used to start a NEW console line before any escaping could see
# it: a fake commit in the log, or a fake "diff --git" header that would end a reviewed file early.
# git writes the log and the diffs through --output into a temporary file instead, read here as
# UTF-8 whatever the console's code page, so a CR stays inside its line and prints as \u000D. A
# byte that is not UTF-8 stays a byte (ConvertFrom-Utf8Bytes) and prints as \xNN (A14 review 5).
# $Arguments is a log or diff command with no "--" and no pathspec.
function Get-GitLines {
    param([string[]]$Arguments)
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('signandvari-' + [guid]::NewGuid().ToString('N') + '.txt')
    $bytes = [byte[]]@()
    try {
        $r = Invoke-Git -Arguments (@('--no-pager') + $Arguments + @("--output=$tmp", '--')) -AllowFailure
        if ($r.ExitCode -ne 0) {
            Write-GitText $r.Output
            Die "git $($Arguments -join ' ') failed (exit $($r.ExitCode))"
        }
        if (Test-Path -LiteralPath $tmp -PathType Leaf) { $bytes = [System.IO.File]::ReadAllBytes($tmp) }
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    $n = $bytes.Length
    if ($n -gt 0 -and $bytes[$n - 1] -eq 10) { $n-- }
    if ($n -eq 0) { return }
    # The usual case: all of it is UTF-8, decoded at once.
    $text = $null
    try { $text = $script:StrictUtf8.GetString($bytes, 0, $n) } catch { $text = $null }
    if ($null -ne $text) { return $text.Split([char]10) }
    # Otherwise line by line, so only the lines with a byte that is not UTF-8 take the slow path.
    $lines = New-Object System.Collections.Generic.List[string]
    $start = 0
    while ($true) {
        $j = [Array]::IndexOf($bytes, [byte]10, $start, $n - $start)
        $stop = if ($j -lt 0) { $n } else { $j }
        $lines.Add((ConvertFrom-Utf8Bytes -Bytes $bytes -Offset $start -Count ($stop - $start)))
        if ($j -lt 0) { break }
        $start = $j + 1
    }
    return $lines.ToArray()
}

# What the LOCAL tag points at before the fetch (empty when this box has never seen the tag).
function Get-LocalTagCommit {
    $r = Invoke-Git -Arguments @('rev-parse', '-q', '--verify', "refs/tags/$Tag^{commit}") -AllowFailure
    if ($r.ExitCode -ne 0) { return '' }
    return $r.Output.Trim().ToLowerInvariant()
}
$LocalBefore = Get-LocalTagCommit

# --- the last-signed record, and the first-run seed -- read BEFORE the fetch ----------------------
# The record is this workstation's own memory of the last commit it signed (see THE LAST SIGNED
# COMMIT). It is parsed out of the raw text, never through ConvertFrom-Json (which would coerce
# recordedAt into a [DateTime]), and a record that exists but cannot be read is a hard stop: it is
# never silently treated as "first run", which would let a damaged file widen what gets compared.
function Read-LastSigned {
    if (-not (Test-Path -LiteralPath $RecordPath)) { return $null }
    $raw = [string](Get-Content -LiteralPath $RecordPath -Raw)
    $c = $null; $v = $null
    if ($raw -match '"commit"\s*:\s*"([0-9a-f]{40})"') { $c = $matches[1] }
    if ($raw -match '"version"\s*:\s*"(\d+\.\d+\.\d+)"') { $v = $matches[1] }
    if (-not $c) {
        Die "the last-signed record at $RecordPath exists but names no 40-hex commit - refusing. Inspect it; delete it only to re-bootstrap on purpose (the next run is then a first run)."
    }
    return [pscustomobject]@{ Commit = $c; Version = $v }
}

# FIRST RUN: the commit in this box's OWN most recent signed bundle (A14 review R2-3), never a tag.
# prestige-release.ps1 writes dist\release-bundle-<version>\ (dist\ is gitignored, so no checkout
# replaces it), records the commit it built (H103) and the seq it minted in bundle.json, and
# renames manifest.json.sig into place LAST, after the signature verified. So a directory holding
# both files is a ceremony this box completed, and the highest seq is the most recent one. A
# bundle.json that git TRACKS is the tree's content, not this box's. git matches a pathspec by case
# even where the disk does not (A14 review 3, C4), and on NTFS a tracked Dist/... or .../Bundle.json
# lands at the very path read here, so while git tracks ANYTHING under dist/ in any case there is
# no seed at all; each candidate is also checked on its own, case-insensitively. A tag is never a
# seed: a plain `git fetch` or `git pull` auto-follows new tags, so a planted intermediate tag would
# become the baseline and hide every change up to it.
$script:SeedRefusal = $null
function Get-SeedBundle {
    $dist = Join-Path $Repo 'dist'
    if (-not (Test-Path -LiteralPath $dist -PathType Container)) { return $null }
    $trackedDist = (Invoke-Git -Arguments @('-c', 'core.quotePath=true', 'ls-files', '--', ':(icase)dist/')).Output.Trim()
    if ($trackedDist) {
        Write-GitText $trackedDist -Indent '   TRACKED '
        $script:SeedRefusal = 'git tracks files under dist/ in this checkout (above, in some case), so no bundle there can be told from the tree''s own content'
        return $null
    }
    $best = $null
    foreach ($dir in @(Get-ChildItem -LiteralPath $dist -Directory -Filter 'release-bundle-*' -ErrorAction SilentlyContinue)) {
        $meta = Join-Path $dir.FullName 'bundle.json'
        $sig  = Join-Path $dir.FullName 'manifest.json.sig'
        if (-not (Test-Path -LiteralPath $meta -PathType Leaf) -or -not (Test-Path -LiteralPath $sig -PathType Leaf)) { continue }
        $rel = 'dist/' + $dir.Name + '/bundle.json'
        $tracked = (Invoke-Git -Arguments @('ls-files', '--', ":(icase,literal)$rel")).Output.Trim()
        if ($tracked) {
            Write-Warn2 ("not a seed: {0} is tracked by git, so it is the tree's content, not this box's" -f (ConvertTo-Printable $rel))
            continue
        }
        $raw = [string](Get-Content -LiteralPath $meta -Raw)
        if ($raw -notmatch '"commit"\s*:\s*"([0-9a-fA-F]{40})"') { continue }
        $c = $matches[1].ToLowerInvariant()
        if ($raw -notmatch '"seq"\s*:\s*(\d{1,18})\b') { continue }
        $s = [long]$matches[1]
        $v = if ($raw -match '"version"\s*:\s*"(\d+\.\d+\.\d+)"') { $matches[1] } else { 'version not recorded' }
        $when = (Get-Item -LiteralPath $sig).LastWriteTimeUtc
        if ($null -eq $best -or $s -gt $best.Seq -or ($s -eq $best.Seq -and $when -gt $best.When)) {
            $best = [pscustomobject]@{ Commit = $c; Seq = $s; Version = $v; When = $when; Path = $meta }
        }
    }
    return $best
}

$LastSigned = Read-LastSigned
$SeedBundle = $null
if ($LastSigned) {
    if ($Baseline) {
        Die "-Baseline is for the first run only, and $RecordPath already records $($LastSigned.Commit). Nothing was fetched or checked out. To re-bootstrap on purpose, delete that record first."
    }
    $BaseCommit = $LastSigned.Commit
    $BaseWhat   = "the last commit this workstation signed ($(if ($LastSigned.Version) { $LastSigned.Version } else { 'version not recorded' }), from $RecordPath)"
}
elseif ($Baseline) {
    $BaseCommit = $Baseline.ToLowerInvariant()
    # A14 review R2-4: the release compared against itself shows no commit and no change at all.
    if ($BaseCommit -eq $Commit) {
        Die "-Baseline is -Commit itself ($Commit): that compares the release with itself and shows nothing. Pass the last release you signed. Nothing was fetched or checked out."
    }
    $BaseWhat   = "-Baseline $BaseCommit (FIRST RUN: no record at $RecordPath yet)"
}
else {
    $SeedBundle = Get-SeedBundle
    if (-not $SeedBundle) {
        $why = if ($script:SeedRefusal) { $script:SeedRefusal } else { "there is no signed bundle (bundle.json beside manifest.json.sig) under $(Join-Path $Repo 'dist')" }
        Die "FIRST RUN and nothing to compare against: there is no record at $RecordPath and $why. Nothing was fetched or checked out. Re-run with -Baseline <40-hex>, a commit you have reviewed (the last release you signed), never one read off the build host. A tag is never used as the baseline."
    }
    $BaseCommit = $SeedBundle.Commit
    # The path is a directory name on this disk, and an NTFS name can hold a control character (C6).
    $BaseWhat   = "the commit this box's most recent signed bundle records, $(ConvertTo-Printable $SeedBundle.Path) (seq $($SeedBundle.Seq), $($SeedBundle.Version)) (FIRST RUN: no record at $RecordPath yet)"
}
Write-Ok "baseline: $BaseWhat"
# The baseline's own date and subject, so the operator can tell it is the release they last signed.
if ((Invoke-Git -Arguments @('cat-file', '-e', "$BaseCommit^{commit}") -AllowFailure).ExitCode -eq 0) {
    foreach ($l in @(Get-GitLines -Arguments @('log', '-1', '--no-color', '--no-show-signature', '--format=%ci  %s', $BaseCommit))) { Write-GitText $l -Indent '        ' }
}
else { Write-Info "     ($BaseCommit is not in this checkout)" }

# --- fetch ONLY the release tag, never forced ---------------------------------------------------
# NO --force: git refuses to replace an existing local tag with a different remote one ("would
# clobber existing tag") and exits non-zero; with --force it would adopt the moved tag silently,
# and everything after this line would then build and sign the remote's choice of tree.
# ONLY v<Version>, with --no-tags (no auto-following): a plain `fetch --tags` also refuses on ANY
# other tag that moved on the remote, so one unrelated re-tag used to block every ceremony.
$fetch = Invoke-Git -Arguments @('fetch', '--no-tags', 'origin', "refs/tags/${Tag}:refs/tags/${Tag}") -AllowFailure
if ($fetch.ExitCode -ne 0) {
    Write-GitText $fetch.Output
    # Name both commits, so the operator can tell a moved tag from a network failure.
    $remoteLine = (Invoke-Git -Arguments @('ls-remote', '--tags', 'origin', "refs/tags/$Tag", "refs/tags/$Tag^{}") -AllowFailure).Output
    $remoteCommit = ''
    foreach ($line in ($remoteLine -split "`n")) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -ge 2) {
            # The peeled ^{} line (an annotated tag's commit) wins over the tag-object line.
            if ($parts[1] -eq "refs/tags/$Tag^{}" -or -not $remoteCommit) { $remoteCommit = $parts[0].ToLowerInvariant() }
        }
    }
    if ($LocalBefore -and $remoteCommit -and $remoteCommit -ne $LocalBefore) {
        Die "the remote's $Tag ($(ConvertTo-Printable $remoteCommit)) DIFFERS from this machine's $Tag ($LocalBefore). A tag that moved is never adopted here. Find out why it moved before signing anything; -Commit is $Commit."
    }
    if (-not $remoteCommit) { Die "the remote has no $Tag (git fetch exit $($fetch.ExitCode)) - push the tag from the build host first; nothing was checked out." }
    Die "git fetch of $Tag failed (exit $($fetch.ExitCode)) - nothing was checked out."
}
Write-Ok "git fetch $Tag only (no force: a moved release tag is refused, never adopted; other tags are not fetched)"

$tagRes = Invoke-Git -Arguments @('rev-parse', '--verify', "$Tag^{commit}") -AllowFailure
if ($tagRes.ExitCode -ne 0) { Die "tag $Tag does not exist (after fetching it) - nothing to sign." }
$TagCommit = $tagRes.Output.Trim().ToLowerInvariant()
if ($LocalBefore -and $TagCommit -ne $LocalBefore) {
    # Belt and braces: a git that DID move the tag despite the missing --force.
    Die "the fetch moved $Tag from $LocalBefore to $TagCommit - refusing."
}

# THE PIN. Checked before anything is checked out: a tag that resolves anywhere but the commit the
# operator was handed never gets its tree onto this disk.
if ($TagCommit -ne $Commit) {
    Die "$Tag resolves to $TagCommit, but -Commit is $Commit. The tag is not the release you were handed - nothing was checked out. Do not re-run with the tag's commit unless the build host confirms it."
}
Write-Ok "$Tag -> $TagCommit (matches -Commit)"

# The known ceremony leftovers. Older hand-runs assembled the manifest in the repo root; the files
# survive in the working tree and the next run then dies on "working tree is not clean". They are
# build output, never tracked content - so clear them BEFORE judging the tree, not after.
foreach ($leftover in @('manifest.json', 'manifest.json.sig')) {
    $p = Join-Path $Repo $leftover
    if (Test-Path -LiteralPath $p -PathType Leaf) {
        # Refuse to delete anything git actually tracks - that would be destroying real content.
        $tracked = Invoke-Git -Arguments @('ls-files', '--error-unmatch', $leftover) -AllowFailure
        if ($tracked.ExitCode -eq 0) { Die "$leftover is TRACKED in this repo - refusing to delete it; investigate by hand." }
        Remove-Item -LiteralPath $p -Force
        Write-Ok "removed ceremony leftover $leftover from the repo root"
    }
}

$status = (Invoke-Git -Arguments @('status', '--porcelain')).Output.Trim()
if ($status.Length -gt 0) {
    Write-GitText $status
    Die 'working tree is not clean - commit, stash or clean before cutting a release.'
}
Write-Ok 'working tree clean'

# ============================================================ 3. REVIEW, CHECKOUT, CONFIRM ======

Write-Step "Changes since the last signed release, checkout $Tag, confirm"

# WHAT THE REVIEW SHOWS (A14 review 3, C1: default-include). EVERY path that changed since the
# baseline, except under these trees. Each was checked against what prestige-release.ps1 builds and
# runs on this account (the update-signer: tools/update-signer plus all of :core; the MSI:
# app-desktop plus :core; the gradle build that configures every project) and against what else
# runs on this box: no file in them is compiled into the signer, the MSI or the build, and none
# runs here outside a browser's sandbox.
#   app-android/      the phone app. Gradle configures its build script here (that file is shown,
#                     below) and runs no Android task in the ceremony.
#   web/ extension/   browser code, built on the build host; on this box it runs only inside a
#                     browser.
#   server/ deploy/   the server and its deployment, run on the server host (deploy/ also rides
#                     inside the server jar). Gradle configures server's build script (shown).
#   docs/ spec/       prose, and test vectors that only test tasks read; the ceremony runs no test.
#   .github/          CI workflows, run on GitHub's runners.
# NOT on the list, deliberately: app-desktop/. Its sources are compiled into the MSI this box
# builds, and that MSI is the household's Windows client: installed here, it runs on the very
# account that can open update-signing.key. core/, tools/, scripts/, gradle/, buildSrc/, the root
# files and any NEW top-level directory are shown because they are not on the list - a module or
# source directory a build script links later is in the review from the day it appears.
$ExcludedTrees = @('app-android/', 'web/', 'extension/', 'server/', 'deploy/', 'docs/', 'spec/', '.github/')
# Shown wherever they are, inside those trees too: what gradle, git or Windows reads as code or as
# checkout instructions. So a build script in an excluded tree is shown, and a line in it (or in any
# build script) that links a file from one of those trees is in front of the operator - which is a
# reason to stop, since from then on that file's own changes would not be shown.
$AlwaysShownPattern = '(?i)(\.gradle|\.kts|\.jar|\.ps1|\.psm1|\.psd1|\.bat|\.cmd)$|(^|/)(gradle\.properties|gradle-wrapper\.[^/]*|\.gitattributes|\.lfsconfig|\.gitmodules)$'

# NTFS ignores a trailing dot or space in every name, so a path is classified as NTFS will write it.
function Get-NtfsPath {
    param([string]$Path)
    return ((@($Path.Split('/')) | ForEach-Object { $_.TrimEnd([char[]]@('.', ' ')) }) -join '/')
}
# The excluded tree a path lies in, whether or not it is shown anyway; '' for none. Case-insensitive,
# as NTFS matches names.
function Get-TreeOf {
    param([string]$Path)
    $p = Get-NtfsPath $Path
    foreach ($t in $ExcludedTrees) {
        if ($p.StartsWith($t, [System.StringComparison]::OrdinalIgnoreCase)) { return $t }
    }
    return ''
}
# '' when the review shows this path; otherwise the excluded tree that hides it.
function Get-HiddenBy {
    param([string]$Path)
    $t = Get-TreeOf $Path
    if ($t -and -not ((Get-NtfsPath $Path) -match $AlwaysShownPattern)) { return $t }
    return ''
}

# Unattended runs fail closed BEFORE anything is checked out: with no human at a console nobody
# reads the lines below, so the run stops instead of skipping the question. Piped input counts as
# unattended too - a pipe that types the version is an automation that never looked.
function Assert-Attended {
    $why = $null
    if (-not [Environment]::UserInteractive) { $why = 'this session is not interactive' }
    elseif ([Console]::IsInputRedirected) { $why = 'standard input is redirected (a pipe or a file cannot confirm a release)' }
    elseif (@([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^[-/]noni' }).Count -gt 0) { $why = 'PowerShell was started with -NonInteractive' }
    if ($why) {
        Die "this release needs a human confirmation and $why - nothing was checked out. Run signandvari from an interactive console."
    }
}

# git prints a path with an unusual byte as a C-quoted string ("a\303\244b", octal per byte) under
# core.quotePath=true, which keeps its output pure ASCII whatever the console's code page. Undo the
# quoting so the case comparison below sees the real name.
function ConvertFrom-GitQuotedPath {
    param([string]$Text)
    if ($Text.Length -lt 2 -or $Text[0] -ne '"' -or $Text[$Text.Length - 1] -ne '"') { return $Text }
    $bytes = New-Object System.Collections.Generic.List[byte]
    $i = 1; $end = $Text.Length - 1
    while ($i -lt $end) {
        $code = [int]$Text[$i]
        if ($code -eq 92 -and ($i + 1) -lt $end) {
            $n = [int]$Text[$i + 1]
            if ($n -ge 48 -and $n -le 55 -and ($i + 3) -lt ($end + 1)) {
                $bytes.Add([byte]([Convert]::ToInt32($Text.Substring($i + 1, 3), 8) -band 0xFF)); $i += 4; continue
            }
            $esc = switch ($n) { 97 { 7 } 98 { 8 } 116 { 9 } 110 { 10 } 118 { 11 } 102 { 12 } 114 { 13 } default { $n } }
            $bytes.Add([byte]($esc -band 0xFF)); $i += 2; continue
        }
        if ($code -lt 128) { $bytes.Add([byte]$code) }
        else { foreach ($b in [System.Text.Encoding]::UTF8.GetBytes([string]$Text[$i])) { $bytes.Add($b) } }
        $i++
    }
    # A byte that is not UTF-8 stays a byte (\xNN when printed), never a U+FFFD (A14 review 5, S1).
    return (ConvertFrom-Utf8Bytes -Bytes $bytes.ToArray())
}

# The path a "diff --git a/P b/P" header names (a and b are the same path: renames are off), or null
# when the header cannot be read - and then the section is SHOWN, never hidden.
function Get-DiffHeaderPath {
    param([string]$Line)
    $rest = $Line.Substring(11)
    if (($rest.Length % 2) -ne 1) { return $null }
    $half = [int](($rest.Length - 1) / 2)
    if ($rest[$half] -ne ' ') { return $null }
    $a = $rest.Substring(0, $half); $b = $rest.Substring($half + 1)
    if ($a.StartsWith('"a/') -and $b.StartsWith('"b/')) {
        if ($a.Substring(3) -cne $b.Substring(3)) { return $null }
        return (ConvertFrom-GitQuotedPath ('"' + $a.Substring(3)))
    }
    if ($a.StartsWith('a/') -and $b.StartsWith('b/')) {
        if ($a.Substring(2) -cne $b.Substring(2)) { return $null }
        return $a.Substring(2)
    }
    return $null
}

# The console rows a line takes once the console wraps it (A14 review 5, S3), counted on the safe
# side: every character outside ASCII counts as two columns (a wide character takes two), so a page
# can only come out shorter than the console, never longer.
function Get-DisplayRows {
    param([string]$Text, [int]$Width)
    $cols = $Text.Length + ($Text -replace '[\x00-\x7F]', '').Length
    if ($cols -le $Width) { return 1 }
    return [int][Math]::Ceiling($cols / $Width)
}

# The full diff is paged HERE, never by an external pager (Git for Windows pages through less -R,
# which passes SGR sequences that can hide text): one console height at a time, every line already
# escaped. A page is counted in CONSOLE ROWS, not in lines (A14 review 5, S3): a long line wraps
# over several rows, and counting it as one let a page scroll its own top out of sight. No line is
# longer than $MaxDisplayChars here (Limit-DisplayLine); a longer one is cut with a marker, and the
# review copy holds it whole. Enter shows the next page, 'a' the rest without stopping, 'q' stops
# reading (the run goes on to the confirmation, which is the operator's call). A console whose
# height cannot be read gets the whole diff at once.
function Show-Paged {
    param([string[]]$Lines)
    $height = 0; $width = 0
    try { $height = [Console]::WindowHeight; $width = [Console]::WindowWidth } catch { $height = 0; $width = 0 }
    if ($width -lt 20) { $width = 80 }
    $ask = "   -- line {0} of {1}: Enter for the next page, 'a' for all the rest, 'q' to stop reading --"
    # The prompt and the answer typed under it take rows of the page too.
    $page = $height - 1 - (Get-DisplayRows ($ask -f $Lines.Count, $Lines.Count) $width)
    $all = $page -lt 3
    $i = 0
    while ($i -lt $Lines.Count) {
        $used = 0
        while ($i -lt $Lines.Count) {
            $shown = '   ' + (Limit-DisplayLine $Lines[$i] ' - the review copy holds the whole line')
            $r = Get-DisplayRows $shown $width
            if (-not $all -and $used -gt 0 -and ($used + $r) -gt $page) { break }
            Write-Host $shown
            $used += $r
            $i++
        }
        if ($i -lt $Lines.Count) {
            $k = Read-Host ($ask -f $i, $Lines.Count)
            if ($null -eq $k) { $k = 'q' }
            if ($k.Trim() -eq 'q') {
                Write-Host ("   (stopped reading the diff at line {0} of {1})" -f $i, $Lines.Count) -ForegroundColor Yellow
                return
            }
            if ($k.Trim() -eq 'a') { $all = $true }
        }
    }
}

# NTFS CASE COLLISIONS (A14 review 2). NTFS compares names case-insensitively, and ignores a
# trailing dot or space, so two tree paths that differ only that way are ONE file on this disk:
# the checkout writes one over the other, and a case-sensitive pathspec in the review would not
# have shown the second (Scripts/prestige-release.ps1 beside scripts/prestige-release.ps1). The
# release tree is refused when any two of its paths - files or the directories above them - are
# equal once folded both ways.
function Find-CaseCollisions {
    param([string]$At)
    $r = Invoke-Git -Arguments @('-c', 'core.quotePath=true', 'ls-tree', '-r', '--name-only', '--full-tree', $At)
    $byUpper = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::Ordinal)
    $byLower = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::Ordinal)
    $seen    = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $hits    = New-Object System.Collections.ArrayList
    $trim    = [char[]]@('.', ' ')
    foreach ($line in ($r.Output -split "`r?`n")) {
        if (-not $line) { continue }
        $parts = (ConvertFrom-GitQuotedPath $line).Split('/')
        $acc = ''; $norm = ''
        for ($j = 0; $j -lt $parts.Length; $j++) {
            if ($j -eq 0) { $acc = $parts[0]; $norm = $parts[0].TrimEnd($trim) }
            else { $acc = $acc + '/' + $parts[$j]; $norm = $norm + '/' + $parts[$j].TrimEnd($trim) }
            if (-not $seen.Add($acc)) { continue }
            foreach ($pair in @(@($byUpper, $norm.ToUpperInvariant()), @($byLower, $norm.ToLowerInvariant()))) {
                $map = $pair[0]; $key = $pair[1]
                $other = $null
                if ($map.TryGetValue($key, [ref]$other)) {
                    if ($other -cne $acc) { [void]$hits.Add(('{0}  <->  {1}' -f $other, $acc)) }
                }
                else { $map[$key] = $acc }
            }
        }
    }
    return @($hits | Select-Object -Unique)
}

# The git object id of these bytes as a blob - what `git hash-object --no-filters` computes.
function Get-BlobId {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try {
        $head = [System.Text.Encoding]::ASCII.GetBytes(('blob {0}' -f $Bytes.Length) + [char]0)
        [void]$sha.TransformBlock($head, 0, $head.Length, $null, 0)
        [void]$sha.TransformFinalBlock($Bytes, 0, $Bytes.Length)
        return ([System.BitConverter]::ToString($sha.Hash) -replace '-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

# Whether the bytes on disk are the blob with every LF written as CRLF - the one change git's own
# end-of-line conversion makes on a Windows checkout (core.autocrlf=true, the Git for Windows
# default, or an eol=crlf attribute). Every LF must carry its CR, and the bytes with each CRLF
# turned back into LF must be the blob. Read as Latin-1, which maps every byte to one character and
# back. ONLY FOR A BLOB GIT WOULD CONVERT (A14 review 5, S4): one with no NUL and no CR. git's own
# text=auto leaves a blob holding either alone (it reads it as binary, or as one whose CRs would not
# survive the round trip); the CRLF form of such a blob is a conversion an attribute FORCED - a
# binary rewritten by "text eol=crlf" - so it is not git's ordinary checkout and is refused.
# 'crlf' = that conversion of the blob; 'forced' = the CRLF form of a blob git would not convert;
# '' = neither.
$script:Latin1 = [System.Text.Encoding]::GetEncoding(28591)
function Test-CrlfCheckout {
    param([byte[]]$Bytes, [string]$WantId)
    $text = $script:Latin1.GetString($Bytes)
    if ($text.IndexOf("`n") -lt 0 -or $text -match '(?<!\r)\n') { return '' }
    $lf = $text.Replace("`r`n", "`n")
    if ((Get-BlobId $script:Latin1.GetBytes($lf)) -ne $WantId) { return '' }
    if ($lf.IndexOf([char]0) -ge 0 -or $lf.IndexOf([char]13) -ge 0) { return 'forced' }
    return 'crlf'
}

# Read as text by the tools that run here whatever bytes they hold (A14 review 5, S2): sources,
# scripts and build, config and git files. Any other file is text too unless it holds a NUL.
$script:TextFilePattern = '(?i)\.(kt|kts|java|groovy|gradle|properties|ps1|psm1|psd1|ps1xml|bat|cmd|sh|py|toml|xml|json|ya?ml|wxs|wxi|pro|cfg|conf|ini)$|(^|/)(gradlew|\.gitattributes|\.gitignore|\.gitmodules|\.lfsconfig)$'
# Read by Windows PowerShell 5.1 in the ANSI code page unless it starts with a byte-order mark (S1).
$script:PowerShellFilePattern = '(?i)\.(ps1|psm1|psd1)$'

# EVERY FILE THE REVIEW COVERS IS ON DISK AS GIT HOLDS IT (A14 review 3, C3). git status judges a
# checked-out file by its stat data and through the clean filter, so whatever a smudge filter wrote
# - LFS content for a pointer, any other filter's output - leaves the tree "clean". This reads the
# bytes on disk and hashes them HERE, as git hashes a blob, with no filter and no git process at all
# (A14 review 5, H1: git hash-object --stdin-paths used to read the paths from a pipeline, which a
# UTF-8 $OutputEncoding starts with a byte-order mark), and compares them with the index (git
# ls-files -s), allowing only the CRLF git's own checkout writes (S4). A symlink or a submodule among
# those paths is refused: neither is a file the review could have read. Then two things the review
# could not have shown as the tools here read them:
#   * a PowerShell file with a byte above 0x7F and no UTF-8 byte-order mark (S1). Windows PowerShell
#     5.1 reads such a script in the ANSI code page, where 0x91-0x94 are curly quotes that PowerShell
#     takes for real ones: one line can read as an inert string in the review and run code on 5.1;
#   * a text file with a CR that no LF follows (S2). The review splits lines at LF alone and prints
#     that CR as \u000D inside its line; Kotlin, Java and PowerShell end a line there, so text after
#     a // can read as a comment and compile as code.
function Assert-ReviewedFilesOnDisk {
    $ls = Invoke-Git -Arguments @('-c', 'core.quotePath=true', 'ls-files', '-s')
    $quoted   = New-Object System.Collections.Generic.List[string]
    $want     = New-Object System.Collections.Generic.List[string]
    $paths    = New-Object System.Collections.Generic.List[string]
    $notFiles = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($ls.Output -split "`r?`n")) {
        if (-not $line) { continue }
        if ($line -notmatch '^(\d{6}) ([0-9a-f]{40}) \d\t(.+)$') {
            Die "unexpected line from git ls-files -s: $(ConvertTo-Printable $line). None of the tree's code ran."
        }
        $mode = $matches[1]; $id = $matches[2]; $q = $matches[3]
        $p = ConvertFrom-GitQuotedPath $q
        if (Get-HiddenBy $p) { continue }
        if ($mode -ne '100644' -and $mode -ne '100755') { $notFiles.Add("$mode $q"); continue }
        $quoted.Add($q); $want.Add($id); $paths.Add($p)
    }
    if ($notFiles.Count -gt 0) {
        foreach ($n in $notFiles) { Write-GitText $n -Indent '   NOT A FILE ' }
        Die "the release tree has a symlink or a submodule among the paths the review covers (above): neither is a file the review could have read. Refused - none of the tree's code ran."
    }
    $bad      = New-Object System.Collections.Generic.List[string]
    $ansiPs   = New-Object System.Collections.Generic.List[string]
    $loneCr   = New-Object System.Collections.Generic.List[string]
    $crlf = 0
    for ($i = 0; $i -lt $quoted.Count; $i++) {
        $bytes = $null
        try { $bytes = [System.IO.File]::ReadAllBytes((Join-Path $Repo $paths[$i])) }
        catch { $bad.Add(('{0}  (cannot be read: {1})' -f $quoted[$i], $_.Exception.Message)); continue }
        if ((Get-BlobId $bytes) -ne $want[$i]) {
            $form = Test-CrlfCheckout -Bytes $bytes -WantId $want[$i]
            if ($form -eq 'crlf') { $crlf++ }
            elseif ($form -eq 'forced') { $bad.Add(('{0}  (the CRLF form of a blob holding a NUL or a CR: git''s own conversion never writes that, an attribute forced it)' -f $quoted[$i])); continue }
            else { $bad.Add($quoted[$i]); continue }
        }
        $ntfs = Get-NtfsPath $paths[$i]
        $text = $script:Latin1.GetString($bytes)
        if ($ntfs -match $script:PowerShellFilePattern -and $text -match '[\x80-\xFF]' -and
            -not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) {
            $ansiPs.Add($quoted[$i])
        }
        if ($text -match '\r(?!\n)' -and ($ntfs -match $script:TextFilePattern -or $text.IndexOf([char]0) -lt 0)) {
            $loneCr.Add($quoted[$i])
        }
    }
    if ($bad.Count -gt 0) {
        foreach ($b in @($bad | Select-Object -First 20)) { Write-GitText $b -Indent '   DIFFERS ' }
        if ($bad.Count -gt 20) { Write-Host ('   ... and {0} more' -f ($bad.Count - 20)) }
        Die ("{0} file(s) the review covers are not, on disk, what git holds for them (above): a filter, an LFS object, an attribute or something else wrote them, so what would run is not what was reviewed. None of the tree's code ran." -f $bad.Count)
    }
    if ($ansiPs.Count -gt 0) {
        foreach ($b in $ansiPs) { Write-GitText $b -Indent '   NOT ASCII, NO BOM ' }
        Die ("{0} PowerShell file(s) the review covers hold a byte above 0x7F and no UTF-8 byte-order mark (above). Windows PowerShell 5.1 reads such a script in the ANSI code page, not as the UTF-8 the review showed, so what it would run is not what was reviewed. Refused - none of the tree's code ran." -f $ansiPs.Count)
    }
    if ($loneCr.Count -gt 0) {
        foreach ($b in $loneCr) { Write-GitText $b -Indent '   LONE CR ' }
        Die ("{0} text file(s) the review covers hold a CR that no LF follows (above, shown as \u000D in the diff). Kotlin, Java and PowerShell end a line there and the review did not, so what would compile or run is not what was reviewed. Refused - none of the tree's code ran." -f $loneCr.Count)
    }
    $note = if ($crlf -gt 0) { " ($crlf of them with the CRLF line endings git's own Windows checkout writes)" } else { '' }
    Write-Ok ("all {0} files the review covers are on disk exactly as git holds them{1}, hashed here" -f $quoted.Count, $note)
}

# Ancestry first: a release that does not descend from the last one signed here is not built on
# what was reviewed then (a rewritten history, a branch nobody merged, a substituted tree).
$anc = Invoke-Git -Arguments @('merge-base', '--is-ancestor', $BaseCommit, $Commit) -AllowFailure
if ($anc.ExitCode -eq 1) {
    Die "$Tag ($Commit) does not descend from $BaseCommit, $BaseWhat. A release that is not a descendant of the last one signed here is refused - nothing was checked out. Merge the release line into the history the last release came from; if history was rewritten on purpose, see the runbook's reset step."
}
if ($anc.ExitCode -ne 0) {
    Write-GitText $anc.Output
    Die "could not test whether $Commit descends from $BaseCommit (git exit $($anc.ExitCode)) - is that commit in this checkout? Nothing was checked out."
}
Write-Ok "$Commit descends from $BaseCommit"
Write-Info "compared against $BaseWhat"

$collisions = Find-CaseCollisions -At $Commit
if ($collisions.Count -gt 0) {
    foreach ($c in $collisions) { Write-GitText $c -Indent '   COLLIDES ' }
    Die "$Tag ($Commit) has paths that are the same file on a case-insensitive disk (above): the checkout would write one over the other, and the review could miss one. Refused - nothing was checked out."
}
Write-Ok 'no two paths in the release tree collide on a case-insensitive disk'

# The stat FIRST, then the commits (A14 review R2-2), then the full diff (A14 review 3, C2). All three
# are read through Get-GitLines (bytes, split at LF alone) and printed escaped. Every line of the
# review is also kept, escaped and whole, for the review copy saved before the diff is paged; on
# screen a line longer than $MaxDisplayChars is cut at a marker, and the cut lines are counted
# (A14 review 5, S3).
$ReviewText = New-Object System.Collections.Generic.List[string]
$script:ReviewCapped = 0
function Write-Review {
    param([AllowEmptyString()][string]$Text, [switch]$FromGit, [string]$Color)
    $line = if ($FromGit) { ConvertTo-Printable $Text } else { $Text }
    $ReviewText.Add($line)
    if ($line.Length -gt $script:MaxDisplayChars) { $script:ReviewCapped++ }
    $shown = '   ' + (Limit-DisplayLine $line ' - the review copy holds the whole line')
    if ($Color) { Write-Host $shown -ForegroundColor $Color } else { Write-Host $shown }
}
$Range = "$BaseCommit..$Commit"
$RangeShort = '{0}..{1}' -f $BaseCommit.Substring(0, 12), $Commit.Substring(0, 12)
$numLines = @(Get-GitLines -Arguments @('-c', 'core.quotePath=true', 'diff', '--numstat', '--summary', '--no-renames', '--text',
    '--no-color', '--no-ext-diff', '--no-textconv', $Range))
$created = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
$deleted = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
$changes = New-Object System.Collections.ArrayList
foreach ($l in $numLines) {
    if (-not $l) { continue }
    if ($l -match '^ (create|delete) mode \d{6} (.+)$') {
        if ($matches[1] -eq 'create') { [void]$created.Add($matches[2]) } else { [void]$deleted.Add($matches[2]) }
        continue
    }
    if ($l -match '^ mode change ') { continue }
    if ($l -notmatch '^(\d+|-)\t(\d+|-)\t(.+)$') { Die "unexpected line from git diff --numstat: $(ConvertTo-Printable $l). Nothing was checked out." }
    [void]$changes.Add([pscustomobject]@{ Added = $matches[1]; Removed = $matches[2]; Shown = $matches[3]; Path = (ConvertFrom-GitQuotedPath $matches[3]) })
}
$hiddenCount = @{}
$shownRows = New-Object System.Collections.ArrayList
foreach ($c in $changes) {
    $by = Get-HiddenBy $c.Path
    if ($by) {
        if ($hiddenCount.ContainsKey($by)) { $hiddenCount[$by] = $hiddenCount[$by] + 1 } else { $hiddenCount[$by] = 1 }
        continue
    }
    [void]$shownRows.Add($c)
}
Write-Host ''
Write-Review ("---- changed since the last signed release, {0}: every path except the trees that never run here ----" -f $RangeShort)
foreach ($c in $shownRows) {
    $st = if ($created.Contains($c.Shown)) { 'new    ' } elseif ($deleted.Contains($c.Shown)) { 'deleted' } else { '       ' }
    # git counts no lines in a file it takes for binary (by content or a -diff attribute); the full
    # diff below still shows it as text.
    $counts = if ($c.Added -eq '-') { ' (git: binary)' } else { '{0,6} {1,6}' -f ('+' + $c.Added), ('-' + $c.Removed) }
    $inTree = Get-TreeOf $c.Path
    $note = if ($inTree) { "   (a build or git file inside $inTree, which is otherwise not shown)" } else { '' }
    Write-Review -FromGit ('{0} {1}  {2}{3}' -f $st, $counts, $c.Shown, $note)
}
if ($shownRows.Count -eq 0) { Write-Review '(no changes outside those trees)' }
else { Write-Review ('{0} changed file(s) shown' -f $shownRows.Count) }
$hiddenTotal = 0
foreach ($v in $hiddenCount.Values) { $hiddenTotal += $v }
if ($hiddenTotal -gt 0) {
    $perTree = @($ExcludedTrees | Where-Object { $hiddenCount.ContainsKey($_) } | ForEach-Object { '{0} {1}' -f $_, $hiddenCount[$_] })
    Write-Review ('NOT shown: {0} changed file(s) in trees that never run on this box ({1})' -f $hiddenTotal, ($perTree -join ', '))
}
else { Write-Review 'NOT shown: nothing (no change in the trees that never run on this box)' }
Write-Review ('the trees not shown: {0} - their build scripts, gradle files, jars, PowerShell and batch files and git attribute files are shown above' -f ($ExcludedTrees -join ' '))
Write-Review 'a build-script line that links a file in one of those trees is a reason to stop: from then on that file''s changes would not be shown.' -Color Yellow

$log = @(Get-GitLines -Arguments @('log', '--no-color', '--no-show-signature', '--format=%h %s', $Range))
Write-Host ''
Write-Review ("---- commits {0} ----" -f $RangeShort)
if ($log.Count -gt 0) { foreach ($l in $log) { Write-Review -FromGit $l } } else { Write-Review '(none: -Commit is the baseline commit itself)' }

Assert-Attended

# THE FULL DIFF of every path shown above (A14 review 3, C2), printed here BEFORE anything is
# checked out. --text: a -diff or binary attribute (this box's, or the checkout's .gitattributes)
# cannot turn a file into "Binary files differ"; --no-textconv and --no-ext-diff: no configured
# program rewrites it; --no-color: no SGR. The prefixes are fixed so a diff.noprefix setting cannot
# change the headers this filter reads; a header it cannot read is shown, never hidden.
$diffLines = @(Get-GitLines -Arguments @('-c', 'core.quotePath=true', 'diff', '--text', '--no-textconv', '--no-ext-diff', '--no-color',
    '--no-renames', '--src-prefix=a/', '--dst-prefix=b/', $Range))
$FullDiff = New-Object System.Collections.Generic.List[string]
$keep = $true
foreach ($l in $diffLines) {
    if ($l.StartsWith('diff --git ', [System.StringComparison]::Ordinal)) {
        $p = Get-DiffHeaderPath $l
        $keep = ($null -eq $p) -or -not (Get-HiddenBy $p)
    }
    if ($keep) { $FullDiff.Add((ConvertTo-Printable $l)) }
}
$diffHead = "---- the full diff of every path shown above, {0}, {1} lines (git diff --text --no-textconv --no-ext-diff --no-color, escaped) ----" -f $RangeShort, $FullDiff.Count
$diffCapped = 0
foreach ($l in $FullDiff) { if ($l.Length -gt $script:MaxDisplayChars) { $diffCapped++ } }
$capped = $script:ReviewCapped + $diffCapped
# The same escaped text - the stat, the commits and the diff, every line whole - for reading in an
# editor: outside the repo, beside the record. A line cut on screen can be read nowhere else, so
# when one is cut and the copy cannot be saved, the run stops here.
$ReviewCopy = Join-Path $RecordDir ('signandvari-review-{0}.txt' -f $Commit.Substring(0, 12))
try {
    if (-not (Test-Path -LiteralPath $RecordDir -PathType Container)) { New-Item -ItemType Directory -Path $RecordDir -Force | Out-Null }
    [System.IO.File]::WriteAllLines($ReviewCopy, [string[]](@($ReviewText.ToArray()) + @('', $diffHead) + @($FullDiff.ToArray())), (New-Object System.Text.UTF8Encoding($false)))
}
catch {
    if ($capped -gt 0) { Die "could not save the review copy at $ReviewCopy ($($_.Exception.Message)), and $capped line(s) of this review are too long to show here whole. Nothing was checked out." }
    Write-Warn2 "could not save an escaped copy of the review ($($_.Exception.Message)); read it here"
    $ReviewCopy = $null
}
$cappedNote = if ($capped -gt 0) { '{0} line(s) of this review are longer than {1} characters: each is cut on screen at a <<CAPPED>> marker and is whole in the review copy' -f $capped, $script:MaxDisplayChars } else { '' }
Write-Host ''
Write-Host ('   ' + $diffHead)
if ($ReviewCopy) { Write-Info "the same escaped text, every line whole, is saved at $ReviewCopy (open it in Notepad to read it there)" }
if ($cappedNote) { Write-Warn2 $cappedNote }
Show-Paged -Lines $FullDiff.ToArray()
Write-Host '   ---- end of the diff ----'
if ($cappedNote) { Write-Warn2 $cappedNote }

# prestige-release.ps1 ASSERTS HEAD == -Ref and dies otherwise; it does not check out for you.
# Detached HEAD at the tag is the expected state for the rest of this run. The checkout comes
# BEFORE the confirmation so the tree it leaves can be checked first (below); it runs none of the
# tree's code. Where HEAD was is remembered, so a run that stops before the confirmation puts it back.
$origBranch = (Invoke-Git -Arguments @('symbolic-ref', '-q', '--short', 'HEAD') -AllowFailure)
$OrigHead   = (Invoke-Git -Arguments @('rev-parse', 'HEAD')).Output.Trim().ToLowerInvariant()
$OrigName   = if ($origBranch.ExitCode -eq 0 -and $origBranch.Output.Trim()) { $origBranch.Output.Trim() } else { $null }

# The checkout, the git status after it, a checkout back and every git command after them run like
# every other git command here ($script:GitPrefix: no hook, no fsmonitor, no LFS filter at all; A14
# review 3, C3 and review 5) and, with GIT_LFS_SKIP_SMUDGE=1, no LFS smudge. From here on, where
# this git has --attr-source (Git 2.42 and later), they also read the attributes from the empty
# tree instead of the release tree's .gitattributes: the tree cannot name a filter (git-lfs or any
# other this box's config defines), an ident or an encoding for the checkout to apply. This box's
# own attribute files (info/attributes, core.attributesFile) still apply; the byte check after the
# checkout catches what they do. An older git keeps the LFS filters blanked and says so.
$EmptyTree = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
$attrProbe = Invoke-Git -Arguments @("--attr-source=$EmptyTree", 'check-attr', '-a', '--', '.gitattributes') -AllowFailure
if ($attrProbe.ExitCode -eq 0) {
    $script:GitPrefix = @("--attr-source=$EmptyTree") + $SafeGit
    Write-Ok 'the checkout and every git command after it read no .gitattributes from the release tree (--attr-source)'
}
else {
    Write-Warn2 "this git has no --attr-source (Git 2.42 and later have it): the checkout reads the release tree's .gitattributes, with the LFS filters blanked, but a filter of any other name that this box's git config defines would run. Update Git for Windows."
}
function Restore-OriginalHead {
    $back = if ($OrigName) { @('checkout', '-q', $OrigName) } else { @('checkout', '-q', '--detach', $OrigHead) }
    $r = Invoke-Git -Arguments $back -AllowFailure
    $where = if ($OrigName) { ConvertTo-Printable $OrigName } else { $OrigHead }
    if ($r.ExitCode -eq 0) { return "HEAD is back at $where" }
    Write-GitText $r.Output
    return "HEAD could NOT be put back at $where (above): this checkout holds the unconfirmed tree, so do not open it in an IDE that runs gradle"
}

# FROM THE CHECKOUT TO THE CONFIRMATION (A14 review 3, C5): every way out but a confirmed answer -
# a refusal, a git command that dies, Ctrl+C at the prompt (PowerShell runs no catch on a stopped
# pipeline, but it runs finally) - puts HEAD back, so the unconfirmed tree is never left checked
# out for an IDE to run gradle on, or for a later first run to take a seed from.
$confirmed  = $false
$checkedOut = $false
$lfsBefore  = $env:GIT_LFS_SKIP_SMUDGE
$env:GIT_LFS_SKIP_SMUDGE = '1'
try {
    if ($OrigHead -eq $Commit) {
        Write-Ok "already at $Tag ($($OrigHead.Substring(0, 12)))"
    }
    else {
        # Check out the PINNED COMMIT, not the tag name: the two are proven equal above, and naming
        # the commit leaves nothing for a ref to change between that proof and this line.
        $checkedOut = $true
        Invoke-Git -Arguments @('checkout', '--detach', $Commit) | Out-Null
        $head = (Invoke-Git -Arguments @('rev-parse', 'HEAD')).Output.Trim().ToLowerInvariant()
        if ($head -ne $Commit) { Die "checkout of $Commit left HEAD at $head - aborting." }
        Write-Ok "detached HEAD at $Tag ($($head.Substring(0, 12))) - no hook ran, no LFS filter ran"
    }

    # The checked-out tree must be exactly the commit (A14 review 2, the NTFS case): a file written
    # over another, or anything else that left the tree differing from what git holds, is a hard
    # stop before the confirmation, because what would run is then not what was reviewed.
    $after = (Invoke-Git -Arguments @('status', '--porcelain')).Output.Trim()
    if ($after.Length -gt 0) {
        Write-GitText $after
        Die "after the checkout of $Commit the working tree is NOT clean (above), so the tree on disk is not the commit that was reviewed. None of its code ran, and HEAD is put back (the line above says where). Investigate by hand."
    }
    Write-Ok 'working tree clean after the checkout'
    Assert-ReviewedFilesOnDisk

    Write-Host ''
    Write-Host '   Read the lines above. The next step runs this tree''s scripts and its gradle build on this' -ForegroundColor Yellow
    Write-Host '   account, beside update-signing.key (a dry run too). A change you did not expect is a reason to stop.' -ForegroundColor Yellow
    Write-Host ''
    $answer = $null
    try {
        $answer = Read-Host ("   Type the version you are releasing ({0}) to run this tree beside the signing key; anything else stops" -f $Version)
    }
    catch {
        Die "this release needs a human confirmation and it could not be read ($($_.Exception.Message)) - none of the tree's code ran."
    }
    if ($null -eq $answer -or $answer.Trim() -ne $Version) {
        Die "not confirmed (typed '$(ConvertTo-Printable $answer)', expected '$Version') - none of the tree's code ran."
    }
    $confirmed = $true
}
finally {
    if (-not $confirmed -and $checkedOut) {
        $put = Restore-OriginalHead
        Write-Host "   $put" -ForegroundColor Yellow
    }
    $env:GIT_LFS_SKIP_SMUDGE = $lfsBefore
    Remove-Item -LiteralPath $script:NoHooks -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Ok "confirmed by the operator: $Version"

# ============================================================ 4. RESOLVE SIGNTOOL ===============

Write-Step 'Resolve signtool'

# signtool.exe is not on PATH - it ships in the Windows SDK bin tree. Discovering it walks a few
# thousand files, so the answer is cached in ANDVARI_SIGNTOOL for subsequent runs.
$SignTool = $null
if ($env:ANDVARI_SIGNTOOL) {
    if (Test-Path -LiteralPath $env:ANDVARI_SIGNTOOL -PathType Leaf) {
        $SignTool = (Resolve-Path -LiteralPath $env:ANDVARI_SIGNTOOL).Path
        Write-Ok "signtool (cached) $SignTool"
    }
    else {
        Write-Warn2 "ANDVARI_SIGNTOOL points at '$($env:ANDVARI_SIGNTOOL)', which no longer exists - rediscovering."
    }
}

if (-not $SignTool) {
    $kitRoots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin')
        (Join-Path $env:ProgramFiles         'Windows Kits\10\bin')
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\8.1\bin')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }

    if (-not $kitRoots) { Die 'no Windows Kits bin tree found - install the Windows SDK signing tools, or set ANDVARI_SIGNTOOL.' }

    $found = foreach ($root in $kitRoots) {
        Get-ChildItem -LiteralPath $root -Recurse -Filter 'signtool.exe' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' }
    }
    if (-not $found) { Die 'no x64 signtool.exe under the Windows Kits bin tree - set ANDVARI_SIGNTOOL to its full path.' }

    # Newest SDK wins: sort on the version directory (...\bin\10.0.26100.0\x64\signtool.exe).
    $SignTool = ($found | Sort-Object -Property @{ Expression = {
        if ($_.FullName -match '\\bin\\(\d+(?:\.\d+)+)\\x64\\') { [version]$matches[1] } else { [version]'0.0.0.0' }
    } } -Descending | Select-Object -First 1).FullName

    Write-Ok "signtool (discovered) $SignTool"
    # Cache for next time. This is a tool path - not a secret, not instance-specific material.
    [Environment]::SetEnvironmentVariable('ANDVARI_SIGNTOOL', $SignTool, 'User')
    $env:ANDVARI_SIGNTOOL = $SignTool
    Write-Info 'cached in ANDVARI_SIGNTOOL for subsequent runs'
}

# ============================================================ 5. LIVE SEQ =======================

Write-Step 'Live manifest'

# Cache-busted: a CDN-stale manifest here would mint a seq the fielded clients silently refuse.
$manifestUrl = "$BaseUrl/downloads/manifest.json?cb=$([guid]::NewGuid().ToString('N'))"
try {
    $liveRaw = (Invoke-WebRequest -Uri $manifestUrl -UseBasicParsing -TimeoutSec 30).Content
}
catch {
    Die "could not fetch the live manifest from $BaseUrl/downloads/manifest.json - $($_.Exception.Message)"
}

# Read seq out of the raw bytes rather than a deserialized object: ConvertFrom-Json coerces the
# ISO-8601 fields into [DateTime], and what is on the wire is what matters here.
if ($liveRaw -notmatch '"seq"\s*:\s*(\d+)') { Die 'the live manifest has no readable "seq" field.' }
$LiveSeq = [int]$matches[1]
$NextSeq = $LiveSeq + 1

Write-Host ''
Write-Host ("   live seq {0} -> will mint {1}" -f $LiveSeq, $NextSeq) -ForegroundColor Yellow
Write-Host ''

# ============================================================ 6. THE CEREMONY ===================

Write-Step 'prestige-release.ps1'

$ceremonyArgs = @(
    '-ExecutionPolicy', 'Bypass',
    '-File', $Ceremony,
    '-Version', $Version,
    '-Ref', $Tag,
    '-Commit', $Commit,
    '-SignToolPath', $SignTool
)
if ($DryRun) { $ceremonyArgs += '-DryRun' }

Write-Info "scripts\prestige-release.ps1 -Version $Version -Ref $Tag -Commit $Commit -SignToolPath <resolved>$(if ($DryRun) { ' -DryRun' })"
Write-Host ''

# Streamed, not captured: this is a long build and the operator should see it happen. The ceremony
# owns its own failure modes - including `signtool verify` exiting 1 with an UnknownError chain
# status, which is EXPECTED here (the household cert is self-signed and deliberately not in Trusted
# Root) and which it already classifies as a pass. We judge only its final exit code.
#
# NOT `& powershell.exe ...`. The call operator makes THIS process read the child's stdout until
# end-of-stream, and end-of-stream means "every holder of the write handle has closed it" - not
# "the child exited". The MSI build starts a GRADLE DAEMON, which deliberately outlives the build
# and inherits that handle. So whenever our own output is a pipe or a file rather than a console,
# the ceremony finishes, the daemon keeps the pipe open, and the read blocks forever - the run
# hangs AFTER signing but BEFORE the drop. Starting the child as a plain process hands it our
# handles directly and reads nothing here; WaitForExit() waits on the child alone, not on its
# descendants. (`Start-Process -PassThru` is also wrong: it does not keep the process handle open,
# so .ExitCode reads back EMPTY once the child is gone and a good ceremony is reported as failed.)
# LAST CHECK before the tree's own code runs: HEAD and the tag are still the pinned commit. Steps 4
# and 5 ran nothing from the tree, but they took time, and this is the line after which the tree
# is executing beside the key.
$headNow = (Invoke-Git -Arguments @('rev-parse', 'HEAD')).Output.Trim().ToLowerInvariant()
$tagNow  = (Invoke-Git -Arguments @('rev-parse', '--verify', "$Tag^{commit}")).Output.Trim().ToLowerInvariant()
if ($headNow -ne $Commit -or $tagNow -ne $Commit) {
    Die "before the ceremony: HEAD is $headNow and $Tag is $tagNow, but -Commit is $Commit - refusing to run the tree."
}

$quotedArgs = $ceremonyArgs | ForEach-Object {
    if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
}
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName         = 'powershell.exe'
$psi.Arguments        = ($quotedArgs -join ' ')
$psi.WorkingDirectory = $Repo
# UseShellExecute = false WITH NO redirection: the child inherits our stdout/stderr, so its output
# streams straight through and this process never reads a handle the gradle daemon is holding open.
$psi.UseShellExecute  = $false
$proc = [System.Diagnostics.Process]::Start($psi)
$proc.WaitForExit()
$ceremonyExit = $proc.ExitCode

Write-Host ''
if ($ceremonyExit -ne 0) { Die "prestige-release.ps1 exited $ceremonyExit - nothing was dropped." }
Write-Ok 'prestige-release.ps1 completed'

if ($DryRun) {
    Write-Step 'Dry run complete'
    Write-Info "live seq $LiveSeq -> would mint $NextSeq for $Version"
    Write-Info 'no MSI was built, nothing was signed, nothing was dropped; the last-signed record did not move.'
    Write-Host ''
    Write-Host "   repo is at $Tag (detached HEAD) - the expected state for the real run." -ForegroundColor Green
    Write-Host ''
    return
}

# ============================================================ 7. BUNDLE ASSERTIONS ==============

Write-Step 'Bundle'

$BundleDir = Join-Path $Repo "dist\release-bundle-$Version"
if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
    Die "no bundle directory at $BundleDir - prestige-release.ps1 reported success but produced nothing."
}

$missing = @()
foreach ($n in ($PayloadNames + $SigName)) {
    if (-not (Test-Path -LiteralPath (Join-Path $BundleDir $n) -PathType Leaf)) { $missing += $n }
}
if ($missing) { Die "bundle at $BundleDir is incomplete - missing: $($missing -join ', ')" }

$MsiName = $PayloadNames[0]
$MsiPath = Join-Path $BundleDir $MsiName
$MsiSha  = Get-Sha256Lower -Path $MsiPath
$MsiSize = (Get-Item -LiteralPath $MsiPath).Length

$bundleMeta = Get-Content -LiteralPath (Join-Path $BundleDir 'bundle.json') -Raw | ConvertFrom-Json
$NewSeq     = [int]$bundleMeta.seq

# The bundle must record the pinned commit: it is what the build-host watcher compares to the tag
# (H103), and a bundle from any other tree is not this release.
if (([string]$bundleMeta.commit).ToLowerInvariant() -ne $Commit) {
    Die "bundle.json records commit '$(ConvertTo-Printable ([string]$bundleMeta.commit))', not the pinned $Commit - nothing was dropped."
}

# signedAt straight out of the raw manifest bytes - never through ConvertFrom-Json, which would
# turn it into a [DateTime] and lose the exact string that was signed.
$manRaw   = Get-Content -LiteralPath (Join-Path $BundleDir 'manifest.json') -Raw
$SignedAt = if ($manRaw -match '"signedAt"\s*:\s*"([^"]+)"') { ConvertTo-Printable $matches[1] } else { '(unreadable)' }

if ($NewSeq -ne $NextSeq) {
    Write-Warn2 "bundle seq is $NewSeq but the live manifest implied $NextSeq - the channel moved under this run."
}

Write-Ok "all five files present in $BundleDir"
Write-Info ("seq {0}   signedAt {1}" -f $NewSeq, $SignedAt)
Write-Info ("{0}  {1} bytes" -f $MsiName, $MsiSize)
Write-Info ("sha256 {0}" -f $MsiSha)

# THE LAST SIGNED COMMIT moves HERE and nowhere else: prestige-release.ps1 exited 0, the bundle is
# complete and records the pinned commit, so this commit has now been signed on this box. A dry run
# returned before this point, and every refusal above died before it. Written to a temporary name
# and renamed, so a crash mid-write leaves the old record (or none), never half of a new one.
if (-not (Test-Path -LiteralPath $RecordDir -PathType Container)) { New-Item -ItemType Directory -Path $RecordDir -Force | Out-Null }
$recordText = '{{"commit": "{0}", "version": "{1}", "recordedAt": "{2}"}}' -f $Commit, $Version,
    [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [cultureinfo]::InvariantCulture)
$recordTmp = "$RecordPath.partial"
[System.IO.File]::WriteAllText($recordTmp, $recordText + "`n", (New-Object System.Text.UTF8Encoding($false)))
Move-Item -LiteralPath $recordTmp -Destination $RecordPath -Force
Write-Ok "recorded $Commit as the last signed commit ($RecordPath)"

if ($SkipDrop) {
    Write-Step 'Drop skipped (-SkipDrop)'
    Write-Info "deliver by hand: the four payload files first, then $SigName ALONE, last."
    Write-Info 'then read the channel back yourself - this run cannot do it for you:'
    Write-Info ("  curl -s '{0}/downloads/manifest.json?cb=1' | jq '{{seq,signedAt,linux:.linux.version,windows:.windows.version,ext:.browserExtension.version}}'" -f $BaseUrl)
    Write-Info ("  expect  seq {0}  linux {1}  windows {1}" -f $NewSeq, $Version)
    Write-Host ''
    return
}

# ============================================================ 8. THE ORDERED DROP ===============

Write-Step 'Drop'

# ORDERING IS THE CORRECTNESS PROPERTY. The build-host watcher treats the appearance of
# manifest.json.sig as "bundle complete" and publishes on a ~5-minute cron. A single recursive copy
# gives no ordering guarantee, and against a ~117 MB MSI that is a real race - the watcher can see
# the signature while the installer is still in flight and publish a manifest pointing at a
# truncated file. So: every payload file lands first, each one is re-hashed REMOTELY to prove it
# arrived intact, and only then does the signature go, alone.

# ssh -n: its standard input is not this console (A14 review 5, H1: no native command here reads
# anything from this script or from the operator's keyboard).
$sshOpts = @('-n', '-o', 'BatchMode=yes', '-o', 'RequestTTY=no', '-o', 'ConnectTimeout=20')
$scpOpts = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=20')

function Send-One {
    param([string]$Name)
    $local = Join-Path $BundleDir $Name
    $bytes = (Get-Item -LiteralPath $local).Length
    Write-Info ("-> {0} ({1} bytes)" -f $Name, $bytes)
    Invoke-Native { & scp @scpOpts -- $local "${DropHost}:${DropPath}" }
    if ($LASTEXITCODE -ne 0) { Die "scp of $Name to the drop host failed (exit $LASTEXITCODE) - nothing further was sent." }
}

function Confirm-Remote {
    param([string]$Name)
    $local  = Join-Path $BundleDir $Name
    $want   = Get-Sha256Lower -Path $local
    $remote = "$DropPath$Name"
    $out    = Invoke-Native { & ssh @sshOpts -- $DropHost "sha256sum -- '$remote'" 2>&1 }
    if ($LASTEXITCODE -ne 0) {
        Write-GitText ($out | Out-String)
        Die "could not sha256sum $Name on the drop host (exit $LASTEXITCODE) - ABORTING BEFORE THE SIGNATURE."
    }
    # The build host's own answer: escaped wherever it is printed (A14 review 3, C6).
    $got = ((($out | Out-String).Trim()) -split '\s+')[0].ToLowerInvariant()
    if ($got -ne $want) {
        Write-Host ''
        Write-Host "   REMOTE CHECKSUM MISMATCH on $Name" -ForegroundColor Red
        Write-Host "     local  $want" -ForegroundColor Red
        Write-Host "     remote $(ConvertTo-Printable $got)"  -ForegroundColor Red
        Die "$Name did not arrive intact - ABORTING BEFORE THE SIGNATURE. Nothing will be published."
    }
    Write-Ok ("verified remotely  {0}  {1}" -f $Name, $got)
}

Write-Info "payload first, to $DropTarget"
Write-Host ''
foreach ($n in $PayloadNames) { Send-One -Name $n }

Write-Host ''
Write-Info 'verifying every payload file on the build host before the signature goes'
Write-Host ''
foreach ($n in $PayloadNames) { Confirm-Remote -Name $n }

Write-Host ''
Write-Info "all payload verified - sending $SigName ALONE, last (the completion signal)"
Write-Host ''
Send-One -Name $SigName
Confirm-Remote -Name $SigName

Write-Ok 'drop complete, in payload-then-signature order'

# ============================================================ 9. PUBLISH READ-BACK ==============
#
# WHY THIS EXISTS (audit H110, and the two releases before it).
#
# Signing is not publishing. This script hands a bundle to the build host and a watcher there
# verifies the signature and copies it into /downloads. Everything after the drop is somebody
# else's machine, so a ceremony could - and twice did - end with every green check on this box
# while the fielded channel still named an older version:
#
#   * 0.25.0 was signed and delivered; the channel sat a release behind until someone read the
#     manifest by hand and noticed.
#   * 0.26.0 was tagged, released, and published to devstore and the server - and NEVER signed.
#     0.26.1 superseded it before the ceremony ran. The manifest went seq 8 -> 9 with exactly one
#     signing, and again the only detection was a human re-reading prose.
#
# Both times the runbook's channel-state paragraph was the sole tripwire, and a hand-typed
# paragraph is stale the moment the next ceremony runs. This is that tripwire in code: after the
# drop, poll the PUBLIC origin (the same URL a client reads, cache-busted) until the watcher has
# published, then assert the served manifest names THIS seq and THIS version. A mismatch is a
# hard failure with the observed values printed, because "the release is out" is exactly the
# belief that must not survive an unpublished manifest.
#
# It asserts what this run is responsible for and nothing more: seq, the platform versions, and
# the MSI digest this box just produced. It does NOT re-verify the Ed25519 signature - the watcher
# does that before it publishes, and re-implementing the check here would give the ceremony two
# disagreeing verifiers instead of one.

if ($SkipReadBack) {
    Write-Step 'Publish read-back SKIPPED (-SkipReadBack)'
    Write-Warn2 'nothing has asserted that the served channel names this release. Read it back by hand:'
    Write-Info ("  curl -s '{0}/downloads/manifest.json?cb=1' | jq '{{seq,signedAt,linux:.linux.version,windows:.windows.version,ext:.browserExtension.version}}'" -f $BaseUrl)
    Write-Info ("  expect  seq {0}  linux {1}  windows {1}" -f $NewSeq, $Version)
}
else {
    Write-Step 'Publish read-back'

    # The watcher publishes "within ~5 minutes". Twelve gives it two cron ticks plus a slow copy
    # before this run calls it a failure; each poll is cheap and the loop prints what it sees, so
    # an operator watching the console can tell "not yet" from "wrong".
    $ReadBackDeadline = (Get-Date).AddMinutes(12)
    $attempt   = 0
    $servedRaw = $null

    Write-Info ("polling {0}/downloads/manifest.json for seq {1} (up to 12 min)" -f $BaseUrl, $NewSeq)

    while ($true) {
        $attempt++
        # Cache-busted every attempt: a CDN-cached copy of the OLD manifest would otherwise make a
        # successful publish look like a timeout, and a cached copy of the new one could mask a
        # rollback at the origin.
        $rbUrl = "$BaseUrl/downloads/manifest.json?cb=$([guid]::NewGuid().ToString('N'))"
        $raw   = $null
        try { $raw = (Invoke-WebRequest -Uri $rbUrl -UseBasicParsing -TimeoutSec 30).Content }
        catch { Write-Info ("attempt {0}: fetch failed - {1}" -f $attempt, $_.Exception.Message) }

        if ($raw) {
            # seq out of the raw bytes, same discipline as step 5.
            $servedSeq = if ($raw -match '"seq"\s*:\s*(\d+)') { [int]$matches[1] } else { -1 }
            if ($servedSeq -eq $NewSeq) { $servedRaw = $raw; break }
            if ($servedSeq -gt $NewSeq) {
                # Someone else published past us while this ceremony ran. Do not keep polling for a
                # seq that can never come back: the fielded clients refuse a seq <= lastAccepted, so
                # this bundle is now unpublishable and the operator has to know immediately.
                Die ("the channel is at seq {0}, PAST the {1} this run minted - another publish overtook this ceremony. This bundle can no longer be published (clients refuse a non-increasing seq). Investigate before re-signing." -f $servedSeq, $NewSeq)
            }
            Write-Info ("attempt {0}: channel still at seq {1}, waiting for {2}" -f $attempt, $servedSeq, $NewSeq)
        }

        if ((Get-Date) -gt $ReadBackDeadline) {
            Die ("the channel never reached seq {0} within 12 minutes of the drop (last seen seq {1}). The bundle is delivered and signed; the watcher on the build host has not published it. Check the watcher log there BEFORE re-signing anything - a fresh signature burns a new signedAt for no reason." -f $NewSeq, $servedSeq)
        }
        Start-Sleep -Seconds 20
    }

    Write-Ok ("channel reached seq {0}" -f $NewSeq)

    # Versions and digests through ConvertFrom-Json: these are plain strings, so the [DateTime]
    # coercion that forced the raw-bytes reads above does not apply to them. Every value read back
    # from the served manifest is the build host's text, and prints escaped (A14 review 3, C6): a
    # control sequence in it could otherwise hide a MISMATCH line.
    $served  = $servedRaw | ConvertFrom-Json
    $rbFail  = @()

    # linuxArch (the Arch pacman package) shares the fleet version with the deb and the MSI, and
    # release-spec.sh emits it on every release, so an absent entry is as loud as an absent linux.
    foreach ($plat in @('linux', 'linuxArch', 'windows')) {
        $node = $served.$plat
        if (-not $node -or -not $node.version) {
            Write-Warn2 ("the served manifest names no '{0}' version - that platform reads as unpublished in every client's downloads hub." -f $plat)
            continue
        }
        if ($node.version -ne $Version) {
            $rbFail += ("{0}.version is {1}, expected {2}" -f $plat, (ConvertTo-Printable ([string]$node.version)), $Version)
        }
    }

    # The MSI is the artifact this box produced and signed; if the served digest is not the one
    # step 7 hashed, the published channel points at different bytes than the ones just signed.
    if ($served.windows -and $served.windows.sha256 -and ($served.windows.sha256.ToLowerInvariant() -ne $MsiSha)) {
        $rbFail += ("windows.sha256 is {0}, expected {1}" -f (ConvertTo-Printable $served.windows.sha256.ToLowerInvariant()), $MsiSha)
    }

    if ($rbFail.Count -gt 0) {
        Write-Host ''
        foreach ($f in $rbFail) { Write-Host "   MISMATCH  $f" -ForegroundColor Red }
        Die 'the served manifest carries this run''s seq but does NOT describe this release. The channel is now serving something other than what was just signed - stop and reconcile /downloads on the build host.'
    }

    $servedSignedAt = if ($servedRaw -match '"signedAt"\s*:\s*"([^"]+)"') { ConvertTo-Printable $matches[1] } else { '(unreadable)' }
    Write-Ok ("served manifest names {0} on linux + linuxArch + windows, signedAt {1}" -f $Version, $servedSignedAt)
    if ($served.browserExtension -and $served.browserExtension.version) {
        Write-Info ("browserExtension stays at {0} (this ceremony does not move it)" -f (ConvertTo-Printable ([string]$served.browserExtension.version)))
    }
}

# ============================================================ 10. SUMMARY ========================

Write-Step 'Done'

Write-Host ''
Write-Host "   andvari $Version - seq $NewSeq - commit $Commit" -ForegroundColor Green
Write-Host ''
Write-Host ("     MSI        {0}" -f $MsiName)
Write-Host ("     sha256     {0}" -f $MsiSha)
Write-Host ("     size       {0} bytes" -f $MsiSize)
Write-Host ("     seq        {0}  (was {1} live)" -f $NewSeq, $LiveSeq)
Write-Host ("     signedAt   {0}" -f $SignedAt)
Write-Host ("     bundle     {0}" -f $BundleDir)
Write-Host ("     dropped to {0}" -f $DropTarget)
Write-Host ''
if ($SkipReadBack) {
    Write-Host '   The watcher on the build host verifies the signature against the pinned key and'
    Write-Host '   publishes within ~5 minutes, then sends a Telegram. Do not publish from this machine.'
    Write-Host '   NOTHING here has confirmed that it did (-SkipReadBack) - read the channel back.' -ForegroundColor Yellow
}
else {
    Write-Host '   The watcher on the build host published it; step 9 read the served manifest back and'
    Write-Host '   confirmed it names this seq and this version. Do not publish from this machine.'
}
Write-Host ''
Write-Host "   The repo is left detached at $Tag - 'git checkout main' when you are done." -ForegroundColor DarkGray
Write-Host ''
