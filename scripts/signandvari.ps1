# andvari - the whole PRESTIGE release ceremony as one command.
#
#   signandvari 0.24.0            # build + sign + assemble + ordered drop
#   signandvari 0.24.0 -DryRun    # preflight, seq arithmetic and manifest preview only
#   signandvari 0.24.0 -SkipDrop  # produce the bundle, deliver it by hand
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

    # Preflight, fetch, seq arithmetic and a manifest preview. No build, no signing, no drop.
    [switch]$DryRun,

    # Produce the bundle but do not deliver it. Use when the drop will be done by hand.
    [switch]$SkipDrop
)

$ErrorActionPreference = 'Stop'

$Tag = "v$Version"

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

Write-Ok "repo $Repo"
Write-Ok "drop $DropTarget"
Write-Info "version $Version   tag $Tag   dry-run $([bool]$DryRun)   skip-drop $([bool]$SkipDrop)"

# ============================================================ 2. TAG, TREE, LEFTOVERS ===========

Write-Step 'Tag, working tree, leftovers'

function Invoke-Git {
    param([string[]]$Arguments, [switch]$AllowFailure)
    $out  = Invoke-Native { & git -C $Repo @Arguments 2>&1 }
    $code = $LASTEXITCODE
    if ($code -ne 0 -and -not $AllowFailure) {
        Write-Host ($out | Out-String)
        Die "git $($Arguments -join ' ') failed (exit $code)"
    }
    [pscustomobject]@{ ExitCode = $code; Output = ($out | Out-String) }
}

Invoke-Git -Arguments @('fetch', '--tags', '--force') | Out-Null
Write-Ok 'git fetch --tags'

$tagRes = Invoke-Git -Arguments @('rev-parse', '--verify', "$Tag^{commit}") -AllowFailure
if ($tagRes.ExitCode -ne 0) { Die "tag $Tag does not exist (after fetching tags) - nothing to sign." }
$TagCommit = $tagRes.Output.Trim()
Write-Ok "$Tag -> $($TagCommit.Substring(0, 12))"

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
    Write-Host $status
    Die 'working tree is not clean - commit, stash or clean before cutting a release.'
}
Write-Ok 'working tree clean'

# ============================================================ 3. CHECKOUT THE TAG ===============

Write-Step "Checkout $Tag"

# prestige-release.ps1 ASSERTS HEAD == -Ref and dies otherwise; it does not check out for you.
# Detached HEAD at the tag is the expected state for the rest of this run.
$head = (Invoke-Git -Arguments @('rev-parse', 'HEAD')).Output.Trim()
if ($head -eq $TagCommit) {
    Write-Ok "already at $Tag ($($head.Substring(0, 12)))"
}
else {
    Invoke-Git -Arguments @('checkout', '--detach', $Tag) | Out-Null
    $head = (Invoke-Git -Arguments @('rev-parse', 'HEAD')).Output.Trim()
    if ($head -ne $TagCommit) { Die "checkout of $Tag left HEAD at $head - aborting." }
    Write-Ok "detached HEAD at $Tag ($($head.Substring(0, 12)))"
}

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
    '-SignToolPath', $SignTool
)
if ($DryRun) { $ceremonyArgs += '-DryRun' }

Write-Info "scripts\prestige-release.ps1 -Version $Version -Ref $Tag -SignToolPath <resolved>$(if ($DryRun) { ' -DryRun' })"
Write-Host ''

# Streamed, not captured: this is a long build and the operator should see it happen. The ceremony
# owns its own failure modes - including `signtool verify` exiting 1 with an UnknownError chain
# status, which is EXPECTED here (the household cert is self-signed and deliberately not in Trusted
# Root) and which it already classifies as a pass. We judge only its final exit code.
Invoke-Native { & powershell.exe @ceremonyArgs }
$ceremonyExit = $LASTEXITCODE

Write-Host ''
if ($ceremonyExit -ne 0) { Die "prestige-release.ps1 exited $ceremonyExit - nothing was dropped." }
Write-Ok 'prestige-release.ps1 completed'

if ($DryRun) {
    Write-Step 'Dry run complete'
    Write-Info "live seq $LiveSeq -> would mint $NextSeq for $Version"
    Write-Info 'no MSI was built, nothing was signed, nothing was dropped.'
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

if ($SkipDrop) {
    Write-Step 'Drop skipped (-SkipDrop)'
    Write-Info "deliver by hand: the four payload files first, then $SigName ALONE, last."
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
        Write-Host ($out | Out-String)
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

# ============================================================ 9. SUMMARY ========================

Write-Step 'Done'

Write-Host ''
Write-Host "   andvari $Version - seq $NewSeq" -ForegroundColor Green
Write-Host ''
Write-Host ("     MSI        {0}" -f $MsiName)
Write-Host ("     sha256     {0}" -f $MsiSha)
Write-Host ("     size       {0} bytes" -f $MsiSize)
Write-Host ("     seq        {0}  (was {1} live)" -f $NewSeq, $LiveSeq)
Write-Host ("     signedAt   {0}" -f $SignedAt)
Write-Host ("     bundle     {0}" -f $BundleDir)
Write-Host ("     dropped to {0}" -f $DropTarget)
Write-Host ''
Write-Host '   The watcher on the build host verifies the signature against the pinned key and'
Write-Host '   publishes within ~5 minutes, then sends a Telegram. Do not publish from this machine.'
Write-Host ''
Write-Host "   The repo is left detached at $Tag - 'git checkout main' when you are done." -ForegroundColor DarkGray
Write-Host ''
