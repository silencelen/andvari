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
# --is-ancestor), a diff --stat of the code that runs beside the key and the commits since it are
# printed, and the operator types the version to confirm. A run with no human at a console
# (-NonInteractive, redirected input, a service) fails closed before anything is checked out. The
# record moves only after prestige-release.ps1 succeeded AND bundle.json records the pinned
# commit; a dry run, a refused run or a failed ceremony leaves it where it was. This is a review
# aid that rests on the operator reading the diff, not a proof: a compromised build host can still
# cut a descendant commit, but it can no longer swap the tree silently, rewrite history under the
# last release, or skip the moment a human looks at what changed in the build.
#
# WHAT THE STAT COVERS (A14 review R2-1; see $ReviewPaths in step 3). The tree's scripts, its
# whole gradle build (wrapper, catalog, properties, every build script, buildSrc) and the
# update-signer, which is handed the key's path and is a shadowJar of tools/update-signer plus ALL
# of :core - not only core's crypto, which is all an earlier version listed. It does NOT cover the
# third-party artifacts gradle downloads (only the catalog that names them), the JDK, or the
# sources compiled into the MSI and never run here (app-desktop's, whose changes the commit list
# names). Every printed line from git is escaped (A14 review R2-2), the paths are matched
# case-insensitively, and a tree with two paths that are equal on a case-insensitive disk is
# refused before checkout (NTFS would write one over the other).
#
# FIRST RUN (no record yet, A14 review R2-3): the baseline is the commit in this box's OWN most
# recent signed bundle - dist\release-bundle-<version>\bundle.json beside its manifest.json.sig,
# which prestige-release.ps1 writes only after a signature it verified; the highest seq wins, and a
# bundle.json git tracks is skipped (that is the tree's content, not this box's). With no such
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
function Die         { param([string]$Text) throw "signandvari: $Text" }

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
# CSI), the line and paragraph separators and the bidi controls become a visible \uXXXX. The
# pattern is spelled with \u escapes so this file stays pure ASCII, and the replacement is a
# MatchEvaluator, which Windows PowerShell 5.1 runs.
$script:UnsafeTextPattern = '[\u0000-\u001F\u007F-\u009F\u061C\u200E\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069]'
function ConvertTo-Printable {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [regex]::Replace($Text, $script:UnsafeTextPattern, [System.Text.RegularExpressions.MatchEvaluator] {
        param($m)
        '\u{0:X4}' -f [int][char]$m.Value
    })
}
function Write-GitText {
    param([AllowNull()][AllowEmptyString()][string]$Text, [string]$Indent = '   ')
    if ($null -eq $Text) { return }
    foreach ($line in ($Text -split "`r?`n")) { Write-Host ($Indent + (ConvertTo-Printable $line)) }
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

function Invoke-Git {
    param([string[]]$Arguments, [switch]$AllowFailure)
    $out  = Invoke-Native { & git -C $Repo @Arguments 2>&1 }
    $code = $LASTEXITCODE
    if ($code -ne 0 -and -not $AllowFailure) {
        Write-GitText ($out | Out-String)
        Die "git $($Arguments -join ' ') failed (exit $code)"
    }
    [pscustomobject]@{ ExitCode = $code; Output = ($out | Out-String) }
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
# bundle.json that git TRACKS is the tree's content, not this box's, and is skipped. A tag is never
# a seed: a plain `git fetch` or `git pull` auto-follows new tags, so a planted intermediate tag
# would become the baseline and hide every change up to it.
function Get-SeedBundle {
    $dist = Join-Path $Repo 'dist'
    if (-not (Test-Path -LiteralPath $dist -PathType Container)) { return $null }
    $best = $null
    foreach ($dir in @(Get-ChildItem -LiteralPath $dist -Directory -Filter 'release-bundle-*' -ErrorAction SilentlyContinue)) {
        $meta = Join-Path $dir.FullName 'bundle.json'
        $sig  = Join-Path $dir.FullName 'manifest.json.sig'
        if (-not (Test-Path -LiteralPath $meta -PathType Leaf) -or -not (Test-Path -LiteralPath $sig -PathType Leaf)) { continue }
        $rel = 'dist/' + $dir.Name + '/bundle.json'
        $tracked = Invoke-Git -Arguments @('ls-files', '--error-unmatch', '--', $rel) -AllowFailure
        if ($tracked.ExitCode -eq 0) {
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
        Die "FIRST RUN and nothing to compare against: there is no record at $RecordPath and no signed bundle (bundle.json beside manifest.json.sig) under $(Join-Path $Repo 'dist'). Nothing was fetched or checked out. Re-run with -Baseline <40-hex>, a commit you have reviewed (the last release you signed), never one read off the build host. A tag is never used as the baseline."
    }
    $BaseCommit = $SeedBundle.Commit
    $BaseWhat   = "the commit this box's most recent signed bundle records, $($SeedBundle.Path) (seq $($SeedBundle.Seq), $($SeedBundle.Version)) (FIRST RUN: no record at $RecordPath yet)"
}
Write-Ok "baseline: $BaseWhat"
# The baseline's own date and subject, so the operator can tell it is the release they last signed.
$baseShow = Invoke-Git -Arguments @('log', '-1', '--no-color', '--no-show-signature', '--format=%ci  %s', $BaseCommit, '--') -AllowFailure
if ($baseShow.ExitCode -eq 0) { Write-GitText $baseShow.Output.Trim() -Indent '        ' }
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
        Die "the remote's $Tag ($remoteCommit) DIFFERS from this machine's $Tag ($LocalBefore). A tag that moved is never adopted here. Find out why it moved before signing anything; -Commit is $Commit."
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

# WHAT THE STAT COVERS (A14 review R2-1). Worked out from what prestige-release.ps1 builds and runs
# on this account beside the key:
#   * its scripts: itself and build-windows.ps1 (scripts/);
#   * a gradle build: gradlew.bat and the wrapper jar and properties, the version catalog and
#     daemon settings (gradle/), gradle.properties (which can also set JVM flags and agents),
#     settings.gradle.kts and every other build script, buildSrc/ and build-logic/ should one
#     appear, and the project caches and machine-local files gradle would read if a tree ever
#     tracked them (.gradle/, .kotlin/, local.properties);
#   * the update-signer, which is handed the key's path: a shadowJar of tools/update-signer/ plus
#     ALL of :core. ALL of it, not core's crypto: Kotlin resolves an unqualified call to a
#     declaration in the caller's own package ahead of its default imports, from any module on the
#     classpath, so one core file that declares the signer's package and a same-named function (an
#     extension File.readText, say) replaces the signer's own call. A stat over core's crypto
#     directories alone printed "(no changes)" over exactly that.
# Not covered: the third-party artifacts gradle downloads (only the catalog that names them), the
# JDK, and the sources compiled into the MSI but never run here (app-desktop/src); the commit list
# names those. A new module the signer links shows here through the build scripts that add it.
# Matched case-insensitively (:(icase)), as NTFS matches names.
$ReviewPaths = @(
    'core/', 'tools/update-signer/',
    'scripts/', 'gradlew*', 'gradle/', '*gradle.properties', 'settings.gradle.kts', '*.gradle.kts', '*.gradle',
    'buildSrc/', 'build-logic/', '.gradle/', '.kotlin/', 'local.properties'
)
$ReviewSpecs = @($ReviewPaths | ForEach-Object { ":(icase)$_" })

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
    return [System.Text.Encoding]::UTF8.GetString($bytes.ToArray())
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

# The stat FIRST, then the commits (A14 review R2-2): a hostile subject printed above the stat is
# escaped anyway, but the code that runs beside the key is the part to read before anything else.
$stat = (Invoke-Git -Arguments (@('-c', 'core.quotePath=true', 'diff', '--stat=4000,3900', '--stat-graph-width=40',
    '--no-renames', '--no-color', '--no-ext-diff', '--no-textconv', "$BaseCommit..$Commit", '--') + $ReviewSpecs)).Output.TrimEnd()
$log  = (Invoke-Git -Arguments @('log', '--no-color', '--no-show-signature', '--format=%h %s', "$BaseCommit..$Commit", '--')).Output.TrimEnd()
Write-Host ''
Write-Host ("   ---- changed code that runs beside the key, {0}..{1} (git diff --stat) ----" -f $BaseCommit.Substring(0, 12), $Commit.Substring(0, 12))
Write-Host ("   paths (any case): {0}" -f ($ReviewPaths -join ' '))
if ($stat) { Write-GitText $stat } else { Write-Host '   (no changes in those paths)' }
Write-Host ("   read it in full in another window: git -C `"{0}`" diff {1}..{2} -- {3}" -f $Repo, $BaseCommit, $Commit, (($ReviewSpecs | ForEach-Object { "'$_'" }) -join ' '))
Write-Host ''
Write-Host ("   ---- commits {0}..{1} ----" -f $BaseCommit.Substring(0, 12), $Commit.Substring(0, 12))
if ($log) { Write-GitText $log } else { Write-Host '   (none: -Commit is the baseline commit itself)' }

Assert-Attended

# prestige-release.ps1 ASSERTS HEAD == -Ref and dies otherwise; it does not check out for you.
# Detached HEAD at the tag is the expected state for the rest of this run. The checkout comes
# BEFORE the confirmation so the tree it leaves can be checked first (below); it runs none of the
# tree's code. Where HEAD was is remembered, so a run that stops here puts it back.
$origBranch = (Invoke-Git -Arguments @('symbolic-ref', '-q', '--short', 'HEAD') -AllowFailure)
$OrigHead   = (Invoke-Git -Arguments @('rev-parse', 'HEAD')).Output.Trim().ToLowerInvariant()
$OrigName   = if ($origBranch.ExitCode -eq 0 -and $origBranch.Output.Trim()) { $origBranch.Output.Trim() } else { $null }
function Restore-OriginalHead {
    $back = if ($OrigName) { @('checkout', '-q', $OrigName) } else { @('checkout', '-q', '--detach', $OrigHead) }
    $r = Invoke-Git -Arguments $back -AllowFailure
    $where = if ($OrigName) { ConvertTo-Printable $OrigName } else { $OrigHead }
    if ($r.ExitCode -eq 0) { return "HEAD is back at $where" }
    Write-GitText $r.Output
    return "HEAD could NOT be put back at $where (above): this checkout holds the unconfirmed tree, so do not open it in an IDE that runs gradle"
}

$head = $OrigHead
if ($head -eq $Commit) {
    Write-Ok "already at $Tag ($($head.Substring(0, 12)))"
}
else {
    # Check out the PINNED COMMIT, not the tag name: the two are proven equal above, and naming the
    # commit leaves nothing for a ref to change between that proof and this line.
    Invoke-Git -Arguments @('checkout', '--detach', $Commit) | Out-Null
    $head = (Invoke-Git -Arguments @('rev-parse', 'HEAD')).Output.Trim().ToLowerInvariant()
    if ($head -ne $Commit) { Die "checkout of $Commit left HEAD at $head - aborting." }
    Write-Ok "detached HEAD at $Tag ($($head.Substring(0, 12)))"
}

# The checked-out tree must be exactly the commit (A14 review 2, the NTFS case): a file written over
# another, or anything else that left the tree differing from what git holds, is a hard stop
# before the confirmation, because what would run is then not what was reviewed.
$after = (Invoke-Git -Arguments @('status', '--porcelain')).Output.Trim()
if ($after.Length -gt 0) {
    Write-GitText $after
    $put = Restore-OriginalHead
    Die "after the checkout of $Commit the working tree is NOT clean (above), so the tree on disk is not the commit that was reviewed. None of its code ran; $put. Investigate by hand."
}
Write-Ok 'working tree clean after the checkout'

Write-Host ''
Write-Host '   Read the lines above. The next step runs this tree''s scripts and its gradle build on this' -ForegroundColor Yellow
Write-Host '   account, beside update-signing.key (a dry run too). A change you did not expect is a reason to stop.' -ForegroundColor Yellow
Write-Host ''
$answer = $null
try {
    $answer = Read-Host ("   Type the version you are releasing ({0}) to run this tree beside the signing key; anything else stops" -f $Version)
}
catch {
    $put = Restore-OriginalHead
    Die "this release needs a human confirmation and it could not be read ($($_.Exception.Message)) - none of the tree's code ran; $put."
}
if ($null -eq $answer -or $answer.Trim() -ne $Version) {
    $put = Restore-OriginalHead
    Die "not confirmed (typed '$(ConvertTo-Printable $answer)', expected '$Version') - none of the tree's code ran; $put."
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
    Die "bundle.json records commit '$($bundleMeta.commit)', not the pinned $Commit - nothing was dropped."
}

# signedAt straight out of the raw manifest bytes - never through ConvertFrom-Json, which would
# turn it into a [DateTime] and lose the exact string that was signed.
$manRaw   = Get-Content -LiteralPath (Join-Path $BundleDir 'manifest.json') -Raw
$SignedAt = if ($manRaw -match '"signedAt"\s*:\s*"([^"]+)"') { $matches[1] } else { '(unreadable)' }

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

$sshOpts = @('-o', 'BatchMode=yes', '-o', 'RequestTTY=no', '-o', 'ConnectTimeout=20')
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
    $got = ((($out | Out-String).Trim()) -split '\s+')[0].ToLowerInvariant()
    if ($got -ne $want) {
        Write-Host ''
        Write-Host "   REMOTE CHECKSUM MISMATCH on $Name" -ForegroundColor Red
        Write-Host "     local  $want" -ForegroundColor Red
        Write-Host "     remote $got"  -ForegroundColor Red
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
    # coercion that forced the raw-bytes reads above does not apply to them.
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
            $rbFail += ("{0}.version is {1}, expected {2}" -f $plat, $node.version, $Version)
        }
    }

    # The MSI is the artifact this box produced and signed; if the served digest is not the one
    # step 7 hashed, the published channel points at different bytes than the ones just signed.
    if ($served.windows -and $served.windows.sha256 -and ($served.windows.sha256.ToLowerInvariant() -ne $MsiSha)) {
        $rbFail += ("windows.sha256 is {0}, expected {1}" -f $served.windows.sha256.ToLowerInvariant(), $MsiSha)
    }

    if ($rbFail.Count -gt 0) {
        Write-Host ''
        foreach ($f in $rbFail) { Write-Host "   MISMATCH  $f" -ForegroundColor Red }
        Die 'the served manifest carries this run''s seq but does NOT describe this release. The channel is now serving something other than what was just signed - stop and reconcile /downloads on the build host.'
    }

    $servedSignedAt = if ($servedRaw -match '"signedAt"\s*:\s*"([^"]+)"') { $matches[1] } else { '(unreadable)' }
    Write-Ok ("served manifest names {0} on linux + linuxArch + windows, signedAt {1}" -f $Version, $servedSignedAt)
    if ($served.browserExtension -and $served.browserExtension.version) {
        Write-Info ("browserExtension stays at {0} (this ceremony does not move it)" -f $served.browserExtension.version)
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
