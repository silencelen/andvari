# andvari - the whole PRESTIGE release ceremony as one command.
#
#   signandvari 0.24.0            # build + sign + assemble + ordered drop
#   signandvari 0.24.0 -DryRun    # preflight, seq arithmetic and manifest preview only
#   signandvari 0.24.0 -SkipDrop  # produce the bundle, deliver it by hand
#   signandvari 0.24.0 -SkipReadBack  # ... and do not assert the channel afterwards (rare)
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
    [switch]$SkipDrop,

    # Skip the post-publish read-back (step 9). Only for a run whose channel effect is
    # deliberately not being asserted - a re-drop of an already-published seq, or a network
    # that cannot reach the public origin from this box. A normal ceremony always reads back.
    [switch]$SkipReadBack
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

    foreach ($plat in @('linux', 'windows')) {
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
    Write-Ok ("served manifest names {0} on linux + windows, signedAt {1}" -f $Version, $servedSignedAt)
    if ($served.browserExtension -and $served.browserExtension.version) {
        Write-Info ("browserExtension stays at {0} (this ceremony does not move it)" -f $served.browserExtension.version)
    }
}

# ============================================================ 10. SUMMARY ========================

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
