# andvari - the PRESTIGE-side release ceremony, as one script.
#
#   powershell -ExecutionPolicy Bypass -File scripts\prestige-release.ps1 -Version 0.21.0 -Ref v0.21.0
#   powershell -ExecutionPolicy Bypass -File scripts\prestige-release.ps1 -Version 0.21.0 -Ref v0.21.0 -DryRun
#
# WHY THIS EXISTS. The update-manifest signing key lives ONLY on this machine - deliberately, so a
# build-host compromise cannot forge a signed update to every armed client. That means the last mile
# of every release is done by hand here, and until now it was driven by a prompt re-authored per
# release. That prompt is where a `seq` or a checksum goes wrong. This script does the same steps
# with the numbers read from the wire instead of typed.
#
# WHAT IT DOES
#   1. Preflight    - Windows, signing key present, signtool/java, clean tree on the expected ref,
#                     the live manifest + release spec are reachable and agree with -Version, the
#                     spec and live manifest agree on chromeStoreUrl, and - because the live
#                     manifest is the SIGNING BASE - its own detached signature verifies against
#                     the pinned public key before a single field of it is trusted.
#   2. MSI          - clear stale build outputs, scripts\build-windows.ps1, prove the produced MSI
#                     is THIS version (embedded ProductVersion), then Authenticode-sign + verify.
#   3. seq          - new seq = live seq + 1, read from the wire. Validate the release spec.
#   4. Manifest     - LIVE manifest as the base; replace only the fields the spec and the MSI supply.
#   5. Signature    - update-signer sign, then verify against the PINNED public key.
#   6. Bundle       - dist\release-bundle-<version>\ incl. the exact release-spec bytes this run
#                     consumed, with the .sig written LAST.
#   7. Handover     - how to deliver the bundle.
#
# THE THREE CONSTRAINTS THAT HAVE BURNED A RELEASE BEFORE
#   * EXACT BYTES. The signature is detached over the literal bytes of manifest.json - no canonical
#     JSON, no re-serialization. Once step 5 signs the file, NOTHING may rewrite it. That is why the
#     manifest is assembled and written ONCE, in step 4, and only read afterwards.
#   * SEQ ARITHMETIC. Clients enforce an anti-rollback floor (core MIN_SEQ = 1 refuses seq < floor;
#     the extension's MIN_SEQ = 0 refuses seq <= lastAccepted - different numbers, same semantics).
#     A replayed or equal seq is silently refused by every fielded client, so seq is computed from a
#     cache-busted fetch of the live manifest, never from a number in a prompt.
#   * SIG LAST. The build-host watcher treats the appearance of manifest.json.sig as "bundle
#     complete". Everything else lands first; the sig is signed to a .partial name and RENAMED into
#     place (rename is atomic - the watcher can never see a half-written signature).
#
# The private key is only ever passed to the signer AS A PATH. This script never reads, prints,
# copies or hashes its contents. Its OWN output shows the path in unexpanded %USERPROFILE% form so
# a shoulder or a pasted log does not leak the account name - but the expanded path does appear on
# the signer's command line (unavoidable; visible to local process listing on this machine only).

[CmdletBinding()]
param(
    # Fleet version being released - must match app-desktop/build.gradle.kts packageVersion,
    # the release spec, and the MSI that build-windows.ps1 drops in dist\.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    # Tag or commit this release is cut from. The working tree must be clean AND at this commit;
    # signing whatever happened to be checked out is how an unreviewed change ships.
    [Parameter(Mandatory = $true)]
    [string]$Ref,

    # Public download origin. Same value the clients pin as the default origin.
    [string]$BaseUrl = 'https://andvari.monahanhosting.com',

    # signtool.exe is frequently NOT on PATH (it lives in the Windows SDK bin dir). Preflight
    # requires it on PATH per the ceremony, but accepts an explicit path instead.
    [string]$SignToolPath,

    # Bundle output directory. Default dist\release-bundle-<version> (dist\ is gitignored).
    [string]$OutDir,

    # scp/rsync destination for the handover message, e.g. user@buildhost:~/andvari-release-drop.
    # Nothing host-specific is baked into this public repo; set it here or via ANDVARI_RELEASE_DROP.
    [string]$DropTarget = $env:ANDVARI_RELEASE_DROP,

    # BOOTSTRAP/RECOVERY ONLY. The live manifest is the SIGNING BASE, and preflight refuses to use
    # it unless its own signature (manifest.json.sig, served beside it) verifies against the pinned
    # public key. On the first-ever release, or when the channel's sig is genuinely missing/broken,
    # pass this - deliberately - to skip that one gate. It warns loudly; never routine.
    [switch]$AllowUnsignedBase,

    # Everything except signing and emitting: preflight, fetch, seq arithmetic, spec validation and
    # a full manifest preview. Skips the gradle MSI build, Authenticode signing, manifest signing
    # and the bundle. Safe to run any time.
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# The pinned update-signing PUBLIC key (core UpdateVerify.PINNED / extension PINNED_UPDATE_KEYS).
# Public material by design - this is the value fielded clients check against, so verifying with it
# here is the same check the clients will make.
$PinnedPubKey = 'e_2TpyoQG4ygtbdVO9RUWbUW4MTHGPO8eXL7Jqc_tHI'

$CertSubjectPattern = 'CN=andvari household releases'
$TimestampUrl       = 'http://timestamp.digicert.com'

# The ONLY manifest fields this ceremony is allowed to change. Anything else in the live manifest -
# notably browserExtension.chromeStoreUrl, which no build produces - must survive untouched, and
# step 4 asserts exactly that against this list.
$ReplaceablePaths = @(
    'seq'
    'signedAt'
    'linux.version'
    'linux.url'
    'linux.sha256'
    'browserExtension.version'
    'browserExtension.chromeUrl'
    'browserExtension.firefoxUrl'
    'windows.version'
    'windows.url'
    'windows.sha256'
)

# ---------------------------------------------------------------------------- output helpers ----

$script:StepNo = 0
function Write-Step {
    param([string]$Text)
    $script:StepNo++
    Write-Host ''
    Write-Host ("== {0}. {1}" -f $script:StepNo, $Text) -ForegroundColor Cyan
}
function Write-Info  { param([string]$Text) Write-Host "   $Text" }
function Write-Ok    { param([string]$Text) Write-Host "   OK   $Text" -ForegroundColor Green }
function Write-Would { param([string]$Text) Write-Host "   WOULD $Text" -ForegroundColor DarkGray }
function Write-Warn2 { param([string]$Text) Write-Host "   WARN $Text" -ForegroundColor Yellow }
function Die {
    param([string]$Text)
    # Fail loudly and early. Nothing in this script leaves partial state behind that a re-run
    # cannot simply overwrite, so aborting mid-way is always safe.
    throw "prestige-release: $Text"
}

# ------------------------------------------------------------------------------ json helpers ----

# Exact-bytes JSON writer. PowerShell's own ConvertTo-Json is NOT usable for the manifest: 5.1
# escapes characters 7.x does not, emits a different indent, and Set-Content -Encoding UTF8 on 5.1
# writes a BOM (which a strict client-side parser rejects). The signature is over whatever bytes
# land on disk, so the bytes are produced here, deterministically, and are pure ASCII (every
# non-ASCII char is \u-escaped) - no encoding ambiguity is possible.
function ConvertTo-JsonStringLiteral {
    param([AllowEmptyString()][string]$Text)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if     ($ch -eq '"')  { [void]$sb.Append('\"') }
        elseif ($ch -eq '\')  { [void]$sb.Append('\\') }
        elseif ($code -eq 8)  { [void]$sb.Append('\b') }
        elseif ($code -eq 9)  { [void]$sb.Append('\t') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 12) { [void]$sb.Append('\f') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
        elseif ($code -lt 32 -or $code -gt 126) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# ConvertFrom-Json SILENTLY COERCES ISO-8601 strings into [DateTime] - signedAt comes back as a
# DateTime object, not the string that was in the file. Left unhandled that either crashes the
# emitter or, worse, re-emits the value in a different (culture-dependent!) format. Everything that
# touches a parsed manifest therefore normalizes dates back to the one format this channel uses.
function Format-JsonDateTime {
    param($Value)
    if ($Value -is [DateTimeOffset]) { $Value = $Value.UtcDateTime }
    $dt = [DateTime]$Value
    # A parsed DateTime can arrive with Kind=Unspecified (ConvertFrom-Json does this on some
    # PowerShell builds); ToUniversalTime() would then treat it as LOCAL time and shift it by this
    # workstation's UTC offset. Every date in this channel is UTC - pin the Kind before converting.
    if ($dt.Kind -eq [System.DateTimeKind]::Unspecified) {
        $dt = [DateTime]::SpecifyKind($dt, [System.DateTimeKind]::Utc)
    }
    return $dt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [cultureinfo]::InvariantCulture)
}

# Paths (dotted) at which a parsed manifest holds a coerced [DateTime]. Used to refuse to re-emit a
# date-typed field this ceremony does not own, since the round trip could reformat it.
function Get-JsonDateTimePaths {
    param($Node, [string]$Prefix = '', $Acc = $null)
    if ($null -eq $Acc) { $Acc = New-Object System.Collections.ArrayList }
    if ($Node -is [DateTime] -or $Node -is [DateTimeOffset]) { [void]$Acc.Add($Prefix) }
    elseif ($Node -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Node.PSObject.Properties) {
            $childPath = if ($Prefix) { $Prefix + '.' + $p.Name } else { $p.Name }
            [void](Get-JsonDateTimePaths -Node $p.Value -Prefix $childPath -Acc $Acc)
        }
    }
    elseif ($Node -isnot [string] -and $Node -is [System.Collections.IEnumerable]) {
        $i = 0
        foreach ($item in $Node) { [void](Get-JsonDateTimePaths -Node $item -Prefix ("{0}[{1}]" -f $Prefix, $i) -Acc $Acc); $i++ }
    }
    return $Acc
}

function ConvertTo-ManifestJson {
    param($Node, [int]$Depth = 0)
    $pad  = ' ' * (2 * $Depth)
    $pad2 = ' ' * (2 * ($Depth + 1))

    if ($null -eq $Node) { return 'null' }
    if ($Node -is [string]) { return (ConvertTo-JsonStringLiteral -Text $Node) }
    if ($Node -is [DateTime] -or $Node -is [DateTimeOffset]) {
        return (ConvertTo-JsonStringLiteral -Text (Format-JsonDateTime -Value $Node))
    }
    if ($Node -is [bool])   { if ($Node) { return 'true' } else { return 'false' } }
    if ($Node -is [int] -or $Node -is [long] -or $Node -is [int16] -or $Node -is [byte]) {
        return ([long]$Node).ToString([cultureinfo]::InvariantCulture)
    }
    if ($Node -is [double] -or $Node -is [decimal] -or $Node -is [single]) {
        return ([double]$Node).ToString('R', [cultureinfo]::InvariantCulture)
    }
    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        $parts = @()
        foreach ($p in $Node.PSObject.Properties) {
            $parts += ($pad2 + (ConvertTo-JsonStringLiteral -Text $p.Name) + ': ' +
                       (ConvertTo-ManifestJson -Node $p.Value -Depth ($Depth + 1)))
        }
        if ($parts.Count -eq 0) { return '{}' }
        return ("{`n" + ($parts -join ",`n") + "`n" + $pad + '}')
    }
    if ($Node -is [System.Collections.IEnumerable]) {
        $parts = @()
        foreach ($item in $Node) {
            $parts += ($pad2 + (ConvertTo-ManifestJson -Node $item -Depth ($Depth + 1)))
        }
        if ($parts.Count -eq 0) { return '[]' }
        return ("[`n" + ($parts -join ",`n") + "`n" + $pad + ']')
    }
    Die "cannot serialize a $($Node.GetType().FullName) into the manifest"
}

# Flatten a parsed JSON tree to dotted-path -> string so the assembled manifest can be diffed
# against the live one field by field. Cheaper and far more legible than a structural comparer.
function Get-JsonLeafMap {
    param($Node, [string]$Prefix = '', $Acc = $null)
    if ($null -eq $Acc) { $Acc = @{} }
    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Node.PSObject.Properties) {
            $childPath = if ($Prefix) { $Prefix + '.' + $p.Name } else { $p.Name }
            [void](Get-JsonLeafMap -Node $p.Value -Prefix $childPath -Acc $Acc)
        }
    }
    elseif ($Node -isnot [string] -and $Node -is [System.Collections.IEnumerable]) {
        $i = 0
        foreach ($item in $Node) {
            [void](Get-JsonLeafMap -Node $item -Prefix ("{0}[{1}]" -f $Prefix, $i) -Acc $Acc)
            $i++
        }
    }
    elseif ($Node -is [DateTime] -or $Node -is [DateTimeOffset]) {
        # NOT [string]$Node - that renders "07/24/2026 19:43:00" in the box's locale and would make
        # the live-vs-assembled diff below both culture- and timezone-dependent.
        $Acc[$Prefix] = Format-JsonDateTime -Value $Node
    }
    else {
        if ($null -eq $Node) { $Acc[$Prefix] = '<null>' } else { $Acc[$Prefix] = [string]$Node }
    }
    return $Acc
}

function Test-JsonMember {
    param($Node, [string]$Name)
    if ($null -eq $Node) { return $false }
    return ($null -ne $Node.PSObject.Properties[$Name])
}

function Get-RequiredMember {
    param($Node, [string]$Name, [string]$Where)
    if (-not (Test-JsonMember -Node $Node -Name $Name)) { Die "$Where is missing required field '$Name'" }
    $v = $Node.$Name
    if ($null -eq $v) { Die "$Where field '$Name' is null" }
    return $v
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Text)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Get-Sha256Lower {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# The ProductVersion embedded in an MSI's Property table, via the Windows Installer COM API. The
# filename proves nothing about what is inside the file; this does. Read-only open (mode 0).
function Get-MsiProductVersion {
    param([string]$Path)
    $ver = $null
    $installer = $null; $db = $null; $view = $null; $rec = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $db   = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
        $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db,
                    @('SELECT `Value` FROM `Property` WHERE `Property` = ''ProductVersion'''))
        # [void] on the two value-less calls is load-bearing: an unassigned InvokeMember emits $null
        # onto the output stream, and a PowerShell function returns EVERYTHING it emitted. Without
        # it this returns @($null, $null, '0.21.0'), which interpolates as '  0.21.0' and makes the
        # version assertion below compare an ARRAY (where -ne filters and yields a truthy result)
        # instead of a string - failing on a perfectly correct MSI.
        [void]$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
        $rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if ($null -ne $rec) {
            $ver = [string]$rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, @(1))
        }
        [void]$view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
    }
    catch { Die "could not read ProductVersion from $Path - $($_.Exception.Message)" }
    finally {
        # Closing the VIEW is not enough. The database and installer COM objects keep the .msi file
        # open for the remaining life of this process, so the very next step - signtool writing the
        # Authenticode signature into that same file - fails with "The file is being used by another
        # process". Release them explicitly and let the finalizers run. This also unwinds correctly
        # when the catch above throws, so a failed read cannot leave the MSI locked either.
        foreach ($o in @($rec, $view, $db, $installer)) {
            if ($null -ne $o) {
                try { [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($o) } catch { }
            }
        }
        $rec = $null; $view = $null; $db = $null; $installer = $null
        [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
    }
    if ([string]::IsNullOrWhiteSpace($ver)) { Die "MSI at $Path carries no ProductVersion property" }
    return $ver
}

# --------------------------------------------------------------------------- native + fetch ----

# $ErrorActionPreference = 'Stop' does NOT make a native exe's non-zero exit throw. Every external
# call goes through here so a failed build/sign can never be mistaken for success.
function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments, [string]$What, [switch]$Capture, [switch]$AllowFailure)
    $out = $null
    if ($Capture) {
        # Windows PowerShell 5.1 surfaces native stderr as ErrorRecords, so a merged 2>&1 stream
        # under $ErrorActionPreference = 'Stop' THROWS NativeCommandError before the exit code is
        # ever read - which would defeat -AllowFailure and turn "signtool says the chain is
        # untrusted" into a crash. This assignment is function-scoped: it relaxes the preference
        # for this call only, and Die's `throw` is unaffected by it.
        $ErrorActionPreference = 'Continue'
        $out = & $Exe @Arguments 2>&1 | ForEach-Object { [string]$_ }
    }
    else { & $Exe @Arguments }
    $code = $LASTEXITCODE
    if ($code -ne 0 -and -not $AllowFailure) {
        if ($Capture -and $out) { $out | ForEach-Object { Write-Host "     | $_" } }
        Die "$What failed (exit $code)"
    }
    return [pscustomobject]@{ ExitCode = $code; Output = (@($out) -join "`n") }
}

# Fetch a URL's EXACT BYTES into a temp file (returned path). The live manifest's bytes get
# signature-verified and its sibling .sig is raw binary/base64 - both must land byte-identical to
# what the server sent, so everything is fetched with -OutFile, never through a decoded .Content.
#
# GET only. HEAD 404s on /downloads/* through the CDN (ktor static route) - a HEAD probe here
# would report the file missing when it is perfectly fine.
#
# Cache-buster first: a CDN-cached stale manifest would hand back a too-low seq, and a manifest
# published at an already-used seq is silently refused by every armed client. If the query string
# upsets the static route we retry the plain URL - but that fallback FAILS OPEN to whatever a CDN
# edge has cached, so it is taken LOUDLY, never silently.
function Get-FileFromUrl {
    param([string]$Url, [string]$What)
    $headers = @{ 'Cache-Control' = 'no-cache'; 'Pragma' = 'no-cache' }
    $bust = $Url + '?cb=' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $dest = Join-Path ([System.IO.Path]::GetTempPath()) ('andvari-fetch-' + [Guid]::NewGuid().ToString('N'))
    try {
        Invoke-WebRequest -Uri $bust -Headers $headers -UseBasicParsing -TimeoutSec 30 -OutFile $dest | Out-Null
    }
    catch {
        $bustErr = $_.Exception.Message
        try   { Invoke-WebRequest -Uri $Url -Headers $headers -UseBasicParsing -TimeoutSec 30 -OutFile $dest | Out-Null }
        catch { Die "could not fetch $What from $Url - $($_.Exception.Message)" }
        Write-Warn2 "cache-busted fetch of $What FAILED ($bustErr); fell back to the plain URL."
        Write-Warn2 'a CDN edge may have served a STALE copy - if seq or any value below looks old, distrust this fetch first.'
    }
    if (-not (Test-Path -LiteralPath $dest -PathType Leaf) -or (Get-Item -LiteralPath $dest).Length -eq 0) {
        Die "$What at $Url was empty"
    }
    return $dest
}

function Get-JsonFromUrl {
    param([string]$Url, [string]$What)
    $path = Get-FileFromUrl -Url $Url -What $What
    $body = [System.IO.File]::ReadAllText($path, (New-Object System.Text.UTF8Encoding($false)))
    if ([string]::IsNullOrWhiteSpace($body)) { Die "$What at $Url was empty" }
    try   { $parsed = $body | ConvertFrom-Json }
    catch { Die "$What at $Url is not valid JSON - $($_.Exception.Message)" }
    # TempPath carries the exact on-the-wire bytes for signature checks / byte-exact copies.
    return [pscustomobject]@{ Text = [string]$body; Json = $parsed; TempPath = $path }
}

# ======================================================================== 1. PREFLIGHT ==========

$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Step 'Preflight'
Write-Host "   version $Version   ref $Ref   dry-run $([bool]$DryRun)"

# --- platform -----------------------------------------------------------------------------------
if ($env:OS -ne 'Windows_NT' -or [System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    Die 'this ceremony only runs on Windows (it builds an MSI and uses the workstation cert store)'
}
if ($PSVersionTable.PSVersion.Major -lt 5) { Die "PowerShell 5.1+ required (found $($PSVersionTable.PSVersion))" }
Write-Ok "Windows, PowerShell $($PSVersionTable.PSVersion)"

# --- repo ---------------------------------------------------------------------------------------
foreach ($rel in @('gradlew.bat', 'scripts\build-windows.ps1', 'app-desktop\build.gradle.kts')) {
    if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot $rel))) { Die "not an andvari checkout: missing $rel under $RepoRoot" }
}
Write-Ok "repo $RepoRoot"

# --- signing key: existence ONLY. Never read, never hash, never print its contents. --------------
$KeyPath        = Join-Path $env:USERPROFILE '.andvari\update-signing.key'
$KeyPathDisplay = '%USERPROFILE%\.andvari\update-signing.key'
if (-not (Test-Path -LiteralPath $KeyPath -PathType Leaf)) {
    Die "update-signing key not found at $KeyPathDisplay - this ceremony can only run on the workstation that holds it"
}
Write-Ok "update-signing key present at $KeyPathDisplay"

# --- tools --------------------------------------------------------------------------------------
$javaCmd = Get-Command java.exe -CommandType Application -ErrorAction SilentlyContinue
if (-not $javaCmd) { $javaCmd = Get-Command java -ErrorAction SilentlyContinue }
if (-not $javaCmd) { Die 'java is not on PATH (JDK/JRE 17+ required for the update-signer)' }
$JavaExe = $javaCmd.Source
Write-Ok "java $JavaExe"

if ($SignToolPath) {
    if (-not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) { Die "-SignToolPath '$SignToolPath' does not exist" }
    $SignTool = (Resolve-Path -LiteralPath $SignToolPath).Path
}
else {
    $stCmd = Get-Command signtool.exe -CommandType Application -ErrorAction SilentlyContinue
    if (-not $stCmd) {
        Die 'signtool is not on PATH - open a "Developer Command Prompt"/SDK shell, or pass -SignToolPath "C:\Program Files (x86)\Windows Kits\10\bin\<ver>\x64\signtool.exe"'
    }
    $SignTool = $stCmd.Source
}
Write-Ok "signtool $SignTool"

# --- git: clean tree, at the expected ref -------------------------------------------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Die 'git is not on PATH' }

$status = Invoke-Native -Exe 'git' -Arguments @('-C', $RepoRoot, 'status', '--porcelain') -What 'git status' -Capture
if ($status.Output.Trim().Length -gt 0) {
    Write-Host $status.Output
    Die 'working tree is not clean - commit or stash before cutting a release (the MSI is built from what is on disk, not from the ref)'
}
$head    = (Invoke-Native -Exe 'git' -Arguments @('-C', $RepoRoot, 'rev-parse', 'HEAD') -What 'git rev-parse HEAD' -Capture).Output.Trim()
$wantRes = Invoke-Native -Exe 'git' -Arguments @('-C', $RepoRoot, 'rev-parse', '--verify', "$Ref^{commit}") -What "git rev-parse $Ref" -Capture -AllowFailure
if ($wantRes.ExitCode -ne 0) { Die "ref '$Ref' does not resolve in this checkout (fetch tags first: git fetch --tags)" }
$want = $wantRes.Output.Trim()
if ($head -ne $want) { Die "HEAD is $head but -Ref $Ref is $want - check out the release ref first" }
Write-Ok "clean tree at $Ref ($($head.Substring(0, 12)))"

# --- the version in the build file drives the MSI filename; a skew here breaks step 2 ------------
$pkgLine = Select-String -Path (Join-Path $RepoRoot 'app-desktop\build.gradle.kts') -Pattern 'packageVersion\s*=\s*"([^"]+)"'
if (-not $pkgLine) { Die 'could not read packageVersion from app-desktop\build.gradle.kts' }
$pkgVersion = $pkgLine.Matches[0].Groups[1].Value
if ($pkgVersion -ne $Version) {
    Die "app-desktop packageVersion is $pkgVersion but -Version is $Version - the tree at $Ref does not build the version you asked for"
}
Write-Ok "app-desktop packageVersion $pkgVersion"

# --- fetch live manifest + release spec NOW ------------------------------------------------------
# Deliberately ahead of the MSI build: a typo'd -Version or an unpublished spec should fail in
# seconds, not after a multi-minute gradle run. Step 3 does the arithmetic on what is fetched here.
$liveUrl = "$BaseUrl/downloads/manifest.json"
$specUrl = "$BaseUrl/downloads/release-spec.json"
$live = Get-JsonFromUrl -Url $liveUrl -What 'live manifest'
$spec = Get-JsonFromUrl -Url $specUrl -What 'release spec'
Write-Ok "live manifest fetched (seq $($live.Json.seq))"
Write-Ok "release spec fetched"

# The live manifest's own detached signature, served beside it. It is verified below (the
# update-signer jar may still need building first); fetching it here makes a missing/broken sig
# fail in seconds. -AllowUnsignedBase is the deliberate, loud bootstrap escape hatch.
$LiveSigPath = $null
if (-not $AllowUnsignedBase) {
    $LiveSigPath = Get-FileFromUrl -Url "$liveUrl.sig" -What 'live manifest signature'
    Write-Ok "live manifest signature fetched"
}

# The spec is emitted by scripts/release-spec.sh on the build host, alongside the artifacts it has
# already uploaded, so the operator never types a checksum. Its shape (specVersion 1) is:
#   { specVersion, generatedAt, intendedKeys[], linux{version,url,sha256},
#     browserExtension{version,chromeStoreUrl,chromeUrl,firefoxUrl}, artifacts{...} }
# NOTE: specVersion is the SCHEMA version, not the release version, and there is no top-level
# `version` key - the fleet version lives at .linux.version.
$specSchema = Get-RequiredMember -Node $spec.Json -Name 'specVersion' -Where 'release spec'
if ([int]$specSchema -ne 1) {
    Die "release spec is schema specVersion $specSchema; this script understands 1 only - reconcile it with scripts/release-spec.sh before releasing"
}

# intendedKeys is the spec's own allow-list of the manifest keys it claims authority over. If it
# ever disagrees with the set this script actually splices, the two halves of the ceremony have
# drifted apart - and the failure mode is a release that quietly rewrites an entry nobody meant to
# touch. Fail instead.
$intendedKeys   = @(Get-RequiredMember -Node $spec.Json -Name 'intendedKeys' -Where 'release spec')
$expectIntended = @('linux', 'browserExtension')
$keysExtra   = @($intendedKeys   | Where-Object { $expectIntended -notcontains $_ })
$keysMissing = @($expectIntended | Where-Object { $intendedKeys   -notcontains $_ })
if ($keysExtra.Count -or $keysMissing.Count) {
    Die "release spec intendedKeys is [$($intendedKeys -join ', ')] but this script splices exactly [$($expectIntended -join ', ')] - reconcile with scripts/release-spec.sh"
}

$specFleetVersion = [string](Get-RequiredMember -Node (Get-RequiredMember -Node $spec.Json -Name 'linux' -Where 'release spec') -Name 'version' -Where 'release spec .linux')
if ($specFleetVersion -ne $Version) {
    Die "release spec is for version $specFleetVersion but -Version is $Version - the build host has not published a spec for this release yet (or you typed the wrong version)"
}
Write-Ok "release spec schema $specSchema, version $specFleetVersion matches -Version"

# --- chromeStoreUrl: the spec and the live manifest must AGREE, and preflight is where a
# disagreement has to surface. The publish-side watcher compares the manifest's browserExtension
# object against ITS authoritative copy of the spec, so a divergence discovered after the MSI is
# built and signed guarantees a quarantined bundle. This ceremony never splices chromeStoreUrl
# (the store listing is not a per-release artifact) - it refuses to start while the views differ.
$preExt     = Get-RequiredMember -Node $live.Json -Name 'browserExtension' -Where 'live manifest'
$preSpecExt = Get-RequiredMember -Node $spec.Json -Name 'browserExtension' -Where 'release spec'
$specHasStore = Test-JsonMember -Node $preSpecExt -Name 'chromeStoreUrl'
$liveHasStore = Test-JsonMember -Node $preExt     -Name 'chromeStoreUrl'
if ($specHasStore -ne $liveHasStore) {
    $whichWay = if ($specHasStore) { 'in the release spec but NOT in the live manifest' } else { 'in the live manifest but NOT in the release spec' }
    Die "browserExtension.chromeStoreUrl is $whichWay - the publish-side watcher would quarantine this release. Reconcile the spec and the manifest deliberately, then re-run."
}
if ($specHasStore) {
    $specStore = [string]$preSpecExt.chromeStoreUrl
    $liveStore = [string]$preExt.chromeStoreUrl
    if ($specStore -ne $liveStore) {
        Write-Warn2 'release spec chromeStoreUrl DIFFERS from the live manifest:'
        Write-Warn2 "  live: $liveStore"
        Write-Warn2 "  spec: $specStore"
        Die 'chromeStoreUrl diverges between the release spec and the live manifest - the publish-side watcher would quarantine this release. If the store listing really moved, change the manifest deliberately (out of band), then re-run.'
    }
    Write-Ok 'chromeStoreUrl agrees between the release spec and the live manifest'
}

# --- update-signer jar (built here so a missing jar fails before the MSI build, not after) -------
$SignerJar = Join-Path $RepoRoot 'tools\update-signer\build\libs\andvari-update-signer.jar'
if (-not (Test-Path -LiteralPath $SignerJar -PathType Leaf)) {
    if ($DryRun) {
        Write-Would "build the update-signer: gradlew.bat :tools:update-signer:shadowJar"
    }
    else {
        Write-Info 'update-signer jar missing - building it (gradlew :tools:update-signer:shadowJar)'
        Push-Location $RepoRoot
        try { Invoke-Native -Exe (Join-Path $RepoRoot 'gradlew.bat') -Arguments @(':tools:update-signer:shadowJar', '--console=plain') -What 'gradle :tools:update-signer:shadowJar' | Out-Null }
        finally { Pop-Location }
        if (-not (Test-Path -LiteralPath $SignerJar -PathType Leaf)) { Die "update-signer jar still missing at $SignerJar" }
    }
}
if (Test-Path -LiteralPath $SignerJar -PathType Leaf) { Write-Ok "update-signer $SignerJar" }

# --- the signing base must itself be signed ------------------------------------------------------
# The live manifest is about to become the BASE of the next signed manifest: every field outside
# $ReplaceablePaths is carried into it verbatim, and step 5 puts the household signature over the
# result. Verify the live manifest's own signature against the SAME pinned key the fielded clients
# check, so this ceremony can never launder tampered or wrong-origin content into a fresh
# signature. (Staleness is a separate risk - seq and the cache-buster handle that.)
if ($AllowUnsignedBase) {
    Write-Warn2 '-AllowUnsignedBase: SKIPPING signature verification of the live manifest.'
    Write-Warn2 'the SIGNING BASE is unverified - every carried-over field is being taken on trust.'
    Write-Warn2 'this switch is for the first-ever release or a knowingly-broken channel ONLY.'
}
elseif (Test-Path -LiteralPath $SignerJar -PathType Leaf) {
    $baseVer = Invoke-Native -Exe $JavaExe -What 'update-signer verify (live manifest)' -Capture -AllowFailure -Arguments @(
        '-jar', $SignerJar, 'verify', $live.TempPath, $LiveSigPath, $PinnedPubKey
    )
    if ($baseVer.ExitCode -ne 0 -or $baseVer.Output -notmatch 'OK: signature valid') {
        $baseVer.Output -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "     | $_" }
        Die "the LIVE manifest's signature does NOT verify against the pinned key - refusing to use it as the signing base. Investigate the channel before anything else; if this is a genuine bootstrap, re-run with -AllowUnsignedBase, deliberately."
    }
    Write-Ok 'live manifest signature verifies against the pinned key - safe to use as the base'
}
else {
    # Only reachable under -DryRun: a real run either found the jar above or just built it (or died).
    Write-Would 'verify the live manifest signature against the pinned key (update-signer jar not built yet)'
}

# --- paths --------------------------------------------------------------------------------------
if (-not $OutDir) { $OutDir = Join-Path $RepoRoot "dist\release-bundle-$Version" }
$MsiName      = "andvari-$Version.msi"
$MsiBuilt     = Join-Path $RepoRoot "dist\$MsiName"
$BundleMsi    = Join-Path $OutDir $MsiName
$BundleMan    = Join-Path $OutDir 'manifest.json'
$BundleSig    = Join-Path $OutDir 'manifest.json.sig'
$BundleSigTmp = Join-Path $OutDir 'manifest.json.sig.partial'
$BundleMeta   = Join-Path $OutDir 'bundle.json'
$BundleSpec   = Join-Path $OutDir 'release-spec.json'

# ======================================================================== 2. MSI ================

Write-Step 'Build and Authenticode-sign the Windows MSI'

$msiSha  = ('0' * 64)
$msiSize = 0
$msiIsReal = $false

if ($DryRun) {
    Write-Would "run scripts\build-windows.ps1 (gradlew :app-desktop:packageMsi) -> dist\$MsiName"
    Write-Would "Authenticode-sign it (cert '$CertSubjectPattern', SHA256, RFC-3161 $TimestampUrl)"
    Write-Would "verify with: signtool verify /pa /v dist\$MsiName"
    if (Test-Path -LiteralPath $MsiBuilt -PathType Leaf) {
        $msiSha  = Get-Sha256Lower -Path $MsiBuilt
        $msiSize = (Get-Item -LiteralPath $MsiBuilt).Length
        $msiIsReal = $true
        Write-Info "an MSI from a previous run exists; using its sha256 for the preview: $msiSha"
    }
    else {
        Write-Warn2 "no dist\$MsiName on disk - the preview below uses a PLACEHOLDER windows.sha256"
    }
}
else {
    # --- no stale inputs. build-windows.ps1 selects its MSI with a wildcard (first match), so an
    # MSI left over from an EARLIER build could be picked up, signed, hashed into the manifest and
    # shipped as this release. Delete the target and every intermediate MSI up front - after this,
    # the only way step 2 can succeed is with an MSI this very run produced.
    $MsiWorkDir = Join-Path $RepoRoot 'app-desktop\build\compose\binaries\main\msi'
    if (Test-Path -LiteralPath $MsiBuilt) {
        Remove-Item -LiteralPath $MsiBuilt -Force
        Write-Info "removed stale dist\$MsiName from an earlier run"
    }
    if (Test-Path -LiteralPath $MsiWorkDir) {
        $staleMsis = @(Get-ChildItem -LiteralPath $MsiWorkDir -Filter '*.msi')
        if ($staleMsis.Count) {
            $staleMsis | Remove-Item -Force
            Write-Info "removed $($staleMsis.Count) stale intermediate MSI(s) from the compose build dir"
        }
    }

    # build-windows.ps1 does its own Set-Location; bracket it so our paths stay valid afterwards.
    Push-Location $RepoRoot
    try { & (Join-Path $RepoRoot 'scripts\build-windows.ps1') }
    finally { Pop-Location }

    # The intermediate dir was empty going in, so exactly ONE msi there proves the wildcard pick
    # was unambiguous and freshly built. Zero means the build silently produced nothing; more than
    # one means the pick is a guess - refuse either way.
    $builtMsis = @()
    if (Test-Path -LiteralPath $MsiWorkDir) { $builtMsis = @(Get-ChildItem -LiteralPath $MsiWorkDir -Filter '*.msi') }
    if ($builtMsis.Count -ne 1) {
        Die "expected exactly 1 MSI in the compose build dir after packageMsi, found $($builtMsis.Count) - refusing to guess which artifact is this release"
    }
    if (-not (Test-Path -LiteralPath $MsiBuilt -PathType Leaf)) { Die "build-windows.ps1 did not produce dist\$MsiName" }

    # And the MSI itself must claim the version being released - its filename proves nothing.
    $msiProductVersion = Get-MsiProductVersion -Path $MsiBuilt
    if ($msiProductVersion -ne $Version) {
        Die "the built MSI's embedded ProductVersion is '$msiProductVersion' but -Version is $Version - a stale or wrong artifact was about to be signed"
    }
    Write-Ok "MSI embedded ProductVersion $msiProductVersion matches -Version"

    # --- pick the household code-signing cert ---------------------------------------------------
    # -CodeSigningCert filters to certs with the code-signing EKU *and* a usable private key, which
    # is what we want; fall back to a subject match so a cert minted without an explicit EKU (which
    # still signs fine) does not stall the ceremony.
    $certs = @(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert |
               Where-Object { $_.Subject -match $CertSubjectPattern })
    if ($certs.Count -eq 0) {
        $certs = @(Get-ChildItem -Path Cert:\CurrentUser\My |
                   Where-Object { $_.Subject -match $CertSubjectPattern -and $_.HasPrivateKey })
        if ($certs.Count -gt 0) { Write-Warn2 'cert matched by subject only (no code-signing EKU advertised)' }
    }
    $certs = @($certs | Where-Object { $_.NotAfter -gt (Get-Date) })
    if ($certs.Count -eq 0) { Die "no unexpired signing cert with a private key matching '$CertSubjectPattern' in Cert:\CurrentUser\My" }
    if ($certs.Count -gt 1) {
        $certs | ForEach-Object { Write-Info "candidate $($_.Thumbprint)  expires $($_.NotAfter.ToString('yyyy-MM-dd'))" }
        Die "$($certs.Count) certs match '$CertSubjectPattern' - remove the stale one from Cert:\CurrentUser\My"
    }
    $cert = $certs[0]
    Write-Ok "cert $($cert.Thumbprint) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"

    Write-Info 'Authenticode-signing the MSI...'
    Invoke-Native -Exe $SignTool -What 'signtool sign' -Arguments @(
        'sign',
        '/sha1', $cert.Thumbprint,
        '/fd',   'SHA256',
        '/tr',   $TimestampUrl,
        '/td',   'SHA256',
        $MsiBuilt
    ) | Out-Null

    # --- verify. An unsigned MSI has shipped before; this is the gate that stops it. -------------
    # signtool verify /pa walks the chain to a trusted root. The household cert is self-signed, so
    # on a box where it was never imported into Trusted Root this legitimately fails while the
    # signature itself is perfectly good. So: run it and show the output, but make the hard gate
    # the two facts that actually matter - a signature exists, it is OURS, and it is timestamped.
    $verify = Invoke-Native -Exe $SignTool -Arguments @('verify', '/pa', '/v', $MsiBuilt) -What 'signtool verify' -Capture -AllowFailure
    $verify.Output -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "     | $_" }

    $auth = Get-AuthenticodeSignature -LiteralPath $MsiBuilt
    if ($auth.Status -eq 'NotSigned' -or $null -eq $auth.SignerCertificate) {
        Die "the MSI is NOT signed after signtool sign (status $($auth.Status))"
    }
    if ($auth.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
        Die "the MSI is signed by $($auth.SignerCertificate.Thumbprint), not the household cert $($cert.Thumbprint)"
    }
    if ($null -eq $auth.TimeStamperCertificate) {
        Die 'the MSI signature carries no RFC-3161 timestamp - it would stop validating the day the cert expires; re-run when the timestamp server is reachable'
    }
    if ($verify.ExitCode -ne 0 -or $auth.Status -ne 'Valid') {
        Write-Warn2 "signature present, by the household cert, timestamped - but chain status is '$($auth.Status)' (signtool exit $($verify.ExitCode))."
        Write-Warn2 'expected on a box where the self-signed household cert is not in Trusted Root. NOT a signing failure.'
    }
    else {
        Write-Ok 'signature valid and chain-trusted on this machine'
    }

    $msiSha  = Get-Sha256Lower -Path $MsiBuilt
    $msiSize = (Get-Item -LiteralPath $MsiBuilt).Length
    $msiIsReal = $true
    Write-Ok "$MsiName  sha256 $msiSha  ($msiSize bytes)"
}

# ======================================================================== 3. SEQ + SPEC =========

Write-Step 'Manifest inputs: seq arithmetic and release-spec validation'

$liveJson = $live.Json
foreach ($k in @('seq', 'signedAt', 'linux', 'browserExtension', 'windows')) {
    if (-not (Test-JsonMember -Node $liveJson -Name $k)) { Die "live manifest has no '$k' - refusing to guess its shape" }
}
if ($liveJson.seq -isnot [int] -and $liveJson.seq -isnot [long]) { Die "live manifest seq is not an integer (got '$($liveJson.seq)')" }

$liveSeq = [long]$liveJson.seq
if ($liveSeq -lt 1) { Die "live manifest seq is $liveSeq - below the core MIN_SEQ floor of 1; something is wrong upstream" }
$newSeq = $liveSeq + 1
Write-Ok "seq $liveSeq (live) -> $newSeq (new)"

# --- validate the spec's fields ------------------------------------------------------------------
$specLinux = Get-RequiredMember -Node $spec.Json -Name 'linux'            -Where 'release spec'
$specExt   = Get-RequiredMember -Node $spec.Json -Name 'browserExtension' -Where 'release spec'

$linuxVersion = [string](Get-RequiredMember -Node $specLinux -Name 'version' -Where 'release spec .linux')
$linuxUrl     = [string](Get-RequiredMember -Node $specLinux -Name 'url'     -Where 'release spec .linux')
$linuxSha     = ([string](Get-RequiredMember -Node $specLinux -Name 'sha256' -Where 'release spec .linux')).ToLowerInvariant()
$extVersion   = [string](Get-RequiredMember -Node $specExt -Name 'version'    -Where 'release spec .browserExtension')
$extChromeUrl = [string](Get-RequiredMember -Node $specExt -Name 'chromeUrl'  -Where 'release spec .browserExtension')
$extFirefoxUrl= [string](Get-RequiredMember -Node $specExt -Name 'firefoxUrl' -Where 'release spec .browserExtension')

# linux and windows share the fleet version; the extension versions independently.
if ($linuxVersion -ne $Version) { Die "release spec .linux.version is $linuxVersion but -Version is $Version" }
if ($extVersion -notmatch '^\d+\.\d+\.\d+$') { Die "release spec .browserExtension.version '$extVersion' is not X.Y.Z" }
if ($linuxSha -notmatch '^[0-9a-f]{64}$') { Die "release spec .linux.sha256 is not a 64-char hex digest" }
foreach ($pair in @(@('linux.url', $linuxUrl), @('browserExtension.chromeUrl', $extChromeUrl), @('browserExtension.firefoxUrl', $extFirefoxUrl))) {
    if ($pair[1] -notmatch '^/downloads/[A-Za-z0-9._-]+$') { Die "release spec $($pair[0]) '$($pair[1])' is not a /downloads/<file> path" }
}
# The spec may also carry a windows block; it is IGNORED. The only authoritative source for the
# MSI's checksum is the MSI this script just built and signed.
if (Test-JsonMember -Node $spec.Json -Name 'windows') { Write-Info 'release spec has a windows block - ignored; the locally built MSI is authoritative' }
# Likewise .artifacts (local build paths + extension checksums) is advisory operator detail; the
# manifest has no sha256 for the extension entries and nothing from it is spliced.

# The spec DOES carry chromeStoreUrl, but the store listing is not a per-release artifact and this
# ceremony must leave it byte-identical to what is live. Preflight already refused to run unless
# the spec and the live manifest agree on it, so keeping the live value here is keeping BOTH.

Write-Ok "linux   $linuxVersion  $linuxUrl"
Write-Ok "linux   sha256 $linuxSha"
Write-Ok "ext     $extVersion  $extChromeUrl / $extFirefoxUrl"
Write-Ok "windows $Version  /downloads/$MsiName  sha256 $msiSha$(if (-not $msiIsReal) { '  (PLACEHOLDER)' })"

# ======================================================================== 4. ASSEMBLE ===========

Write-Step 'Assemble the new manifest (live manifest as the base)'

# Two independent parses of the SAME fetched bytes: one pristine reference to diff against, one to
# mutate. Mutating in place preserves key order and every field this ceremony does not own.
$baseObj = $live.Text | ConvertFrom-Json
$newObj  = $live.Text | ConvertFrom-Json

# ConvertFrom-Json turned every ISO-8601-looking string into a [DateTime]. signedAt is ours and is
# overwritten below, so its round trip is harmless. Any OTHER date-typed field would be re-emitted
# from a parsed DateTime rather than carried across verbatim, which could quietly change its text -
# unacceptable for a field we are supposed to leave alone. Refuse rather than reformat.
$datePaths = @(Get-JsonDateTimePaths -Node $baseObj | Where-Object { $ReplaceablePaths -notcontains $_ })
if ($datePaths.Count) {
    Die "live manifest has date-like value(s) at $($datePaths -join ', ') that this ceremony does not own; re-emitting them could change their formatting. Update the script before releasing."
}

$signedAt = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [cultureinfo]::InvariantCulture)

$newObj.seq                           = $newSeq
$newObj.signedAt                      = $signedAt
$newObj.linux.version                 = $linuxVersion
$newObj.linux.url                     = $linuxUrl
$newObj.linux.sha256                  = $linuxSha
$newObj.browserExtension.version      = $extVersion
$newObj.browserExtension.chromeUrl    = $extChromeUrl
$newObj.browserExtension.firefoxUrl   = $extFirefoxUrl
$newObj.windows.version               = $Version
$newObj.windows.url                   = "/downloads/$MsiName"
$newObj.windows.sha256                = $msiSha
# browserExtension.chromeStoreUrl is deliberately NOT assigned - no build produces it and the store
# listing does not move per release. The assertion below proves it survived.

$manifestText = (ConvertTo-ManifestJson -Node $newObj) + "`n"

# --- prove the emitter did what we meant --------------------------------------------------------
# Re-parse the exact text that will be signed and diff it, leaf by leaf, against the live manifest.
# Any changed path outside $ReplaceablePaths, or any added/removed key, aborts the ceremony.
$roundTrip = $manifestText | ConvertFrom-Json
$baseLeaves = Get-JsonLeafMap -Node $baseObj
$newLeaves  = Get-JsonLeafMap -Node $roundTrip

$added   = @($newLeaves.Keys  | Where-Object { -not $baseLeaves.ContainsKey($_) })
$removed = @($baseLeaves.Keys | Where-Object { -not $newLeaves.ContainsKey($_) })
if ($added.Count)   { Die "assembled manifest ADDS key(s) the live manifest does not have: $($added -join ', ')" }
if ($removed.Count) { Die "assembled manifest DROPS key(s) present in the live manifest: $($removed -join ', ')" }

$changed = @($baseLeaves.Keys | Where-Object { $baseLeaves[$_] -ne $newLeaves[$_] } | Sort-Object)
$illegal = @($changed | Where-Object { $ReplaceablePaths -notcontains $_ })
if ($illegal.Count) { Die "assembled manifest changed field(s) this ceremony does not own: $($illegal -join ', ')" }

# And that each field we do own carries the value we intended.
$expected = @{
    'seq'                          = [string]$newSeq
    'signedAt'                     = $signedAt
    'linux.version'                = $linuxVersion
    'linux.url'                    = $linuxUrl
    'linux.sha256'                 = $linuxSha
    'browserExtension.version'     = $extVersion
    'browserExtension.chromeUrl'   = $extChromeUrl
    'browserExtension.firefoxUrl'  = $extFirefoxUrl
    'windows.version'              = $Version
    'windows.url'                  = "/downloads/$MsiName"
    'windows.sha256'               = $msiSha
}
foreach ($path in $expected.Keys) {
    if (-not $newLeaves.ContainsKey($path)) { Die "assembled manifest is missing '$path'" }
    if ($newLeaves[$path] -ne $expected[$path]) {
        Die "assembled manifest '$path' is '$($newLeaves[$path])' but should be '$($expected[$path])'"
    }
}

Write-Ok "changed: $($changed -join ', ')"
Write-Ok "carried over untouched: $(@($baseLeaves.Keys | Where-Object { $changed -notcontains $_ } | Sort-Object) -join ', ')"
Write-Host ''
Write-Host '   ---------------- manifest.json (exact bytes to be signed) ----------------'
$manifestText.TrimEnd("`n") -split "`n" | ForEach-Object { Write-Host "   $_" }
Write-Host '   -------------------------------------------------------------------------'

if ($DryRun) {
    Write-Step 'Sign + emit - SKIPPED (-DryRun)'
    Write-Would "write $BundleMan and sign it with the key at $KeyPathDisplay"
    Write-Would "verify the signature against the pinned public key $PinnedPubKey"
    Write-Would "emit the bundle to $OutDir incl. the exact release-spec bytes consumed (manifest.json.sig written LAST)"
    if (-not $msiIsReal) { Write-Warn2 'the preview above is NOT signable as-is: windows.sha256 is a placeholder until the MSI is built.' }
    Write-Host ''
    Write-Host 'dry run complete - nothing was signed and nothing was written.' -ForegroundColor Cyan
    exit 0
}

# ======================================================================== 5. SIGN ===============

Write-Step 'Sign the manifest and verify against the pinned public key'

# Clean the bundle dir. Order matters: the .sig (and any leftover .partial) go FIRST, so a run that
# dies from here on can never leave a directory that the watcher reads as a complete bundle. This is
# also what makes a re-run after a failure safe - nothing here is append-only or seq-consuming.
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
foreach ($stale in @($BundleSig, $BundleSigTmp, $BundleMeta, $BundleSpec, $BundleMan, $BundleMsi)) {
    if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Force }
}

# Write the manifest ONCE, here. From this point the file is read-only by convention: the signature
# below is over these exact bytes, so a reformat, a re-serialization or even a line-ending fix
# invalidates it silently.
Write-Utf8NoBom -Path $BundleMan -Text $manifestText
$manifestSha = Get-Sha256Lower -Path $BundleMan
Write-Ok "manifest.json written ($((Get-Item -LiteralPath $BundleMan).Length) bytes, sha256 $manifestSha)"

Write-Info "signing with the key at $KeyPathDisplay (path only - this script never reads it)"
Invoke-Native -Exe $JavaExe -What 'update-signer sign' -Arguments @(
    '-jar', $SignerJar, 'sign', $BundleMan, '--key', $KeyPath, '--out', $BundleSigTmp
) | Out-Null
if (-not (Test-Path -LiteralPath $BundleSigTmp -PathType Leaf)) { Die 'update-signer reported success but produced no signature file' }

# The signer self-verifies before writing; this is the independent check that the signature matches
# the key the FIELDED CLIENTS pin, not merely the key that happened to be on disk. Positional args.
$ver = Invoke-Native -Exe $JavaExe -What 'update-signer verify' -Capture -Arguments @(
    '-jar', $SignerJar, 'verify', $BundleMan, $BundleSigTmp, $PinnedPubKey
)
if ($ver.Output -notmatch 'OK: signature valid') {
    Die "update-signer verify did not confirm the signature: $($ver.Output)"
}
Write-Ok "signature verifies against the pinned key $PinnedPubKey"

# Post-signature tripwire: confirm nothing touched manifest.json between signing and now.
if ((Get-Sha256Lower -Path $BundleMan) -ne $manifestSha) { Die 'manifest.json changed after it was signed - the signature is void' }

# ======================================================================== 6. BUNDLE =============

Write-Step 'Emit the bundle'

Copy-Item -LiteralPath $MsiBuilt -Destination $BundleMsi -Force
if ((Get-Sha256Lower -Path $BundleMsi) -ne $msiSha) { Die 'the MSI copied into the bundle does not match the one that was signed' }

# The EXACT release-spec bytes this ceremony consumed. The receiving watcher holds its own
# authoritative copy of the spec and byte-compares this one against it, so a run that somehow saw
# a different spec (stale edge, tamper, wrong channel) is caught there - before publication, not
# on the clients.
[System.IO.File]::WriteAllBytes($BundleSpec, [System.IO.File]::ReadAllBytes($spec.TempPath))
Write-Ok 'release-spec.json (exact consumed bytes) written into the bundle'

$sigSha  = Get-Sha256Lower -Path $BundleSigTmp
$sigSize = (Get-Item -LiteralPath $BundleSigTmp).Length

# bundle.json is metadata for the receiving watcher, not signed material - ConvertTo-Json is fine
# here (unlike the manifest, whose exact bytes are load-bearing).
$meta = [pscustomobject][ordered]@{
    version   = $Version
    seq       = $newSeq
    ref       = $Ref
    commit    = $head
    createdAt = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [cultureinfo]::InvariantCulture)
    files     = @(
        [pscustomobject][ordered]@{ name = $MsiName;             sha256 = $msiSha;      size = $msiSize }
        [pscustomobject][ordered]@{ name = 'manifest.json';      sha256 = $manifestSha; size = (Get-Item -LiteralPath $BundleMan).Length }
        [pscustomobject][ordered]@{ name = 'release-spec.json';  sha256 = (Get-Sha256Lower -Path $BundleSpec); size = (Get-Item -LiteralPath $BundleSpec).Length }
        [pscustomobject][ordered]@{ name = 'manifest.json.sig';  sha256 = $sigSha;      size = $sigSize }
    )
}
Write-Utf8NoBom -Path $BundleMeta -Text (($meta | ConvertTo-Json -Depth 6) + "`n")
Write-Ok "bundle.json written"

# THE COMPLETION SIGNAL, LAST. A rename within the same directory is atomic, so the watcher sees
# either no signature or the whole signature - never a partial one.
Move-Item -LiteralPath $BundleSigTmp -Destination $BundleSig -Force
Write-Ok "manifest.json.sig written LAST (completion signal)"

Write-Host ''
Write-Host "   bundle: $OutDir" -ForegroundColor Green
foreach ($f in @($MsiName, 'manifest.json', 'release-spec.json', 'bundle.json', 'manifest.json.sig')) {
    $p = Join-Path $OutDir $f
    Write-Host ("     {0,-28} {1,12} bytes  {2}" -f $f, (Get-Item -LiteralPath $p).Length, (Get-Sha256Lower -Path $p))
}

# ======================================================================== 7. HANDOVER ===========

Write-Step 'Next step - deliver the bundle'

$target = if ($DropTarget) { $DropTarget } else { '<user>@<build-host>:~/andvari-release-drop' }
Write-Host ''
Write-Host '   Copy the files INDIVIDUALLY, in this order. Copying the directory in one command'
Write-Host '   gives no ordering guarantee, and the watcher publishes as soon as the .sig lands.'
Write-Host ''
foreach ($f in @($MsiName, 'manifest.json', 'release-spec.json', 'bundle.json')) {
    Write-Host ("     scp `"{0}`" {1}/" -f (Join-Path $OutDir $f), $target)
}
Write-Host ("     scp `"{0}`" {1}/    # LAST - completion signal" -f $BundleSig, $target)
if (-not $DropTarget) {
    Write-Host ''
    Write-Host '   (set -DropTarget or $env:ANDVARI_RELEASE_DROP to have the real destination printed here)'
}
Write-Host ''
Write-Host "   The build host verifies the signature against the pinned key before publishing, then"
Write-Host "   puts manifest.json and manifest.json.sig on the server TOGETHER. Do not publish from"
Write-Host "   this machine."
Write-Host ''
Write-Host "release ceremony complete - version $Version, seq $newSeq." -ForegroundColor Green
