param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,
    [string]$OutputDirectory = "",
    [switch]$AllowDirtySource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    Write-Host "FAIL: $Message" -ForegroundColor Red
    throw $Message
}

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) { Fail $Message }
}
function Get-SafeRelativePath([string]$Root, [string]$Child) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $childFull = [IO.Path]::GetFullPath($Child)
    Require ($childFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) "Path escapes source root: $Child"
    return $childFull.Substring($rootFull.Length).Replace('\','/')
}

$SourceRoot = (Resolve-Path $SourceRoot).Path
Require (Test-Path -LiteralPath (Join-Path $SourceRoot ".git")) "SourceRoot must be a Git checkout"
$sourceTop = (& git -C $SourceRoot rev-parse --show-toplevel 2>$null).Trim()
Require ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($sourceTop)) "SourceRoot is not a valid Git checkout"
$sourceCommit = (& git -C $SourceRoot rev-parse HEAD 2>$null).Trim()
Require ($LASTEXITCODE -eq 0 -and $sourceCommit -match '^[0-9a-f]{40}$') "Unable to resolve source commit"
$sourceTree = (& git -C $SourceRoot rev-parse 'HEAD^{tree}' 2>$null).Trim()
Require ($LASTEXITCODE -eq 0 -and $sourceTree -match '^[0-9a-f]{40}$') "Unable to resolve source tree"
$dirtyEntries = @(& git -C $SourceRoot status --porcelain 2>$null)
Require ($LASTEXITCODE -eq 0) "Unable to inspect source tree status"
if ($dirtyEntries.Count -gt 0 -and -not $AllowDirtySource) {
    Fail "SourceRoot is dirty; pass -AllowDirtySource only for explicitly authorized development builds"
}
Write-Host "SOURCE_ROOT: $SourceRoot"
Write-Host "SOURCE_COMMIT: $sourceCommit"
Write-Host "SOURCE_TREE: $sourceTree"
if ($dirtyEntries.Count -gt 0) { Write-Host "WARNING: dirty source explicitly allowed" -ForegroundColor Yellow }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $SourceRoot "artifacts\lab-agent"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

$nativeRelative = "native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe"
$nativePath = Join-Path $SourceRoot ($nativeRelative -replace '/', '\')
$requirementsPath = Join-Path $SourceRoot "requirements.txt"
Require (Test-Path -LiteralPath $nativePath -PathType Leaf) "Pinned release native sensor is missing"
Require (Test-Path -LiteralPath $requirementsPath -PathType Leaf) "requirements.txt is missing"

$files = @(
    Get-ChildItem -LiteralPath (Join-Path $SourceRoot "agent") -Recurse -File |
        Where-Object { $_.FullName -notmatch "\\__pycache__\\|\.py[co]$" }
    Get-Item -LiteralPath $requirementsPath
    Get-Item -LiteralPath $nativePath
)
$entries = @{}
$forbidden = @(
    '(^|/)(control_plane|dashboard_owner)(/|$)',
    '(^|/)(owner|fleet)_?(credential|token|secret)',
    '(^|/)(storage_key|private_key|endpoint_id|fleet_token)',
    '\.(pem|pfx|key|b64|db|db-wal|db-shm|log|pyc|pyo)$',
    '(^|/)(state|logs|evidence|runtime_state|secrets)(/|$)',
    '(^|/)(__pycache__|\.git|\.venv)(/|$)'
)
foreach ($file in $files) {
    $relative = Get-SafeRelativePath $SourceRoot $file.FullName
    foreach ($pattern in $forbidden) {
        Require (-not ($relative -match $pattern)) "Forbidden package path: $relative"
    }
    $entries[$relative] = $file
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$version = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$packageName = "CyberDefender-AgentOnly-Lab-$version"
$stage = Join-Path $env:TEMP ($packageName + "-" + [guid]::NewGuid().ToString('N'))
$zipPath = Join-Path $OutputDirectory ($packageName + ".zip")
$manifestPath = Join-Path $OutputDirectory ($packageName + ".manifest.json")
$hashPath = Join-Path $OutputDirectory ($packageName + ".zip.sha256")

try {
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    $manifestFiles = @()
    foreach ($relative in ($entries.Keys | Sort-Object)) {
        $source = $entries[$relative]
        $target = Join-Path $stage ($relative -replace '/', '\')
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item -LiteralPath $source.FullName -Destination $target -Force
        $digest = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
        $manifestFiles += [ordered]@{ path = $relative; bytes = $source.Length; sha256 = $digest }
    }
    $manifest = [ordered]@{
        schema = 'cyberdefender.agent-only-lab-package.v1'
        package_name = $packageName
        source_root = $SourceRoot
        source_commit = $sourceCommit
        source_tree = $sourceTree
        payload_root = 'agent-only'
        files = @($manifestFiles)
        excluded_components = @('control_plane','dashboard_owner','owner_credentials','fleet_tokens','storage_keys','private_keys','databases','logs','runtime_state','endpoint_identities')
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 6
    $manifestJson | Set-Content -LiteralPath (Join-Path $stage 'MANIFEST.json') -Encoding UTF8
    $manifestJson | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -CompressionLevel Optimal
    $packageHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$packageHash  $([IO.Path]::GetFileName($zipPath))" | Set-Content -LiteralPath $hashPath -Encoding ASCII
    Write-Host "PASS: Agent-only package created"
    Write-Host "PACKAGE: $zipPath"
    Write-Host "SHA256: $packageHash"
    Write-Host "FILES: $($manifestFiles.Count)"
} catch {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    throw
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
