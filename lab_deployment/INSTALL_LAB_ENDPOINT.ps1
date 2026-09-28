param(
    [Parameter(Mandatory=$true)][ValidatePattern('^PC-JDU[3-9]$')][string]$LabLabel,
    [Parameter(Mandatory=$true)][ValidatePattern('^https?://[^/]+(?::\d+)?$')][string]$ControlPlaneUrl,
    [Parameter(Mandatory=$true)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$PackagePath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$PackageSha256,
    [Parameter(Mandatory=$true)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$EnrollmentCredentialPath,
    [string]$Python = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$Message) { Write-Host "FAIL: $Message" -ForegroundColor Red; throw $Message }
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { Fail $Message } }
function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { Fail "Command failed: $File exit=$LASTEXITCODE" }
}
function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Require $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) "Administrator rights required"
}
function Test-ServicePresent([string]$Name) { return $null -ne (Get-Service -Name $Name -ErrorAction SilentlyContinue) }
function Remove-AgentService {
    $service = Get-Service -Name 'CyberDefenderAgent' -ErrorAction SilentlyContinue
    if ($null -eq $service) { return }
    if ($service.Status -ne 'Stopped') { Stop-Service -Name 'CyberDefenderAgent' -Force; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
    Invoke-Checked 'sc.exe' @('delete','CyberDefenderAgent')
}
function Set-RestrictedAcl([string]$Path) {
    Invoke-Checked 'icacls.exe' @($Path,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
}

Assert-Administrator
$packageHash = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash
Require ($packageHash -ieq $PackageSha256) "Package SHA-256 mismatch"
Require ((Get-Item -LiteralPath $PackagePath).Length -gt 0) "Package is empty"
Require (-not (Test-ServicePresent 'CyberDefenderControlPlane')) "ControlPlane already exists on Agent-only endpoint"
Require (-not (Test-ServicePresent 'CyberDefenderOwnerUI')) "OwnerUI already exists on Agent-only endpoint"
$actualHostname = [Environment]::GetEnvironmentVariable('COMPUTERNAME')
Require (-not [string]::IsNullOrWhiteSpace($actualHostname)) "Actual Windows hostname is available"

$base = Join-Path $env:ProgramData 'CyberDefender'
$appParent = Join-Path $env:ProgramFiles 'CyberDefender'
$installRoot = Join-Path $appParent 'app'
$stateDir = Join-Path $base 'state'
$secretDir = Join-Path $base 'secrets'
$identityDir = Join-Path $base 'identity'
$keyFile = Join-Path $secretDir 'storage_key.b64'
$tokenFile = Join-Path $secretDir 'fleet_token.txt'
$endpointIdFile = Join-Path $identityDir 'endpoint_id.txt'
$labLabelFile = Join-Path $stateDir 'lab_label.txt'
$stage = Join-Path $env:TEMP ('CyberDefender-AgentOnly-' + [guid]::NewGuid().ToString('N'))
$previousRoot = Join-Path $appParent 'app.previous'
$created = @()

try {
    Write-Host 'PASS: preflight, hostname, and service boundary'
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $stage -Force
    $manifestPath = Join-Path $stage 'MANIFEST.json'
    Require (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'Package manifest missing'
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    Require ($manifest.schema -eq 'cyberdefender.agent-only-lab-package.v1') 'Unexpected package schema'
    $payloadRows = @($manifest.files)
    $payloadNames = @($payloadRows | ForEach-Object { [string]$_.path })
    foreach ($row in $payloadRows) {
        $name = [string]$row.path
        Require ($name -notmatch '(^|/)(control_plane|dashboard_owner|state|logs|secrets|runtime_state|evidence)(/|$)') "Forbidden payload path: $name"
        Require ($name -notmatch '\.(pem|pfx|key|b64|db|log|pyc|pyo)$') "Forbidden payload extension: $name"
        $payload = Join-Path $stage ($name -replace '/', '\')
        Require (Test-Path -LiteralPath $payload -PathType Leaf) "Manifest payload missing: $name"
        Require ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash -ieq ([string]$row.sha256)) "Payload hash mismatch: $name"
    }
    Require ($payloadNames -contains 'agent/windows_service.py') 'Agent service host missing'
    Require ($payloadNames -contains 'native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe') 'Pinned native sensor missing'

    New-Item -ItemType Directory -Force -Path $appParent,$stateDir,$secretDir,$identityDir | Out-Null
    Set-RestrictedAcl $secretDir
    Set-RestrictedAcl $identityDir
    if (-not (Test-Path -LiteralPath $keyFile)) {
        $bytes = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        [Convert]::ToBase64String($bytes) | Set-Content -LiteralPath $keyFile -Encoding ASCII -NoNewline
    }
    if (-not (Test-Path -LiteralPath $endpointIdFile)) { [guid]::NewGuid().ToString() | Set-Content -LiteralPath $endpointIdFile -Encoding ASCII -NoNewline }
    Set-Content -LiteralPath $labLabelFile -Value $LabLabel -Encoding ASCII -NoNewline
    Copy-Item -LiteralPath $EnrollmentCredentialPath -Destination $tokenFile -Force
    Set-RestrictedAcl $keyFile; Set-RestrictedAcl $tokenFile; Set-RestrictedAcl $identityDir
    Write-Host "PASS: identity preserved; LabLabel=$LabLabel; ActualHostname=$actualHostname"

    if (Test-Path -LiteralPath $previousRoot) { Remove-Item -LiteralPath $previousRoot -Recurse -Force }
    if (Test-Path -LiteralPath $installRoot) { Move-Item -LiteralPath $installRoot -Destination $previousRoot }
    New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
    foreach ($name in $payloadNames) {
        $source = Join-Path $stage ($name -replace '/', '\')
        $target = Join-Path $installRoot ($name -replace '/', '\')
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item -LiteralPath $source -Destination $target -Force
    }

    if ($Python) { $pythonExe = $Python; $pythonPrefix = @() }
    elseif (Get-Command py -ErrorAction SilentlyContinue) { $pythonExe = 'py'; $pythonPrefix = @('-3') }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { $pythonExe = 'python'; $pythonPrefix = @() }
    else { Fail 'Python 3 is unavailable' }
    Invoke-Checked $pythonExe ($pythonPrefix + @('-m','venv',(Join-Path $installRoot '.venv')))
    $venvPython = Join-Path $installRoot '.venv\Scripts\python.exe'
    Invoke-Checked $venvPython @('-m','pip','install','-r',(Join-Path $installRoot 'requirements.txt'))
    $env:CYBERDEFENDER_ROOT = $installRoot
    $env:CYBERDEFENDER_STATE_DIR = $stateDir
    $env:CYBERDEFENDER_STORAGE_KEY_B64 = (Get-Content -Raw -LiteralPath $keyFile).Trim()
    $env:CYBERDEFENDER_ENDPOINT_ID = (Get-Content -Raw -LiteralPath $endpointIdFile).Trim()
    $env:CYBERDEFENDER_FLEET_TOKEN_FILE = $tokenFile
    Invoke-Checked $venvPython @('-m','agent.service_crash_store','provision')
    Write-Host 'PASS: Python runtime and CrashGuard provisioning'

    $serviceCommand = '"' + $venvPython + '" -m agent.windows_service --service-run'
    if (Test-ServicePresent 'CyberDefenderAgent') { Remove-AgentService }
    New-Service -Name 'CyberDefenderAgent' -BinaryPathName $serviceCommand -DisplayName 'CyberDefender Endpoint Protection' -Description 'CyberDefender Agent-only laboratory endpoint' -StartupType Automatic | Out-Null
    $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\CyberDefenderAgent'
    New-Item -Path (Join-Path $serviceKey 'Parameters') -Force | Out-Null
    New-ItemProperty -Path $serviceKey -Name 'Environment' -PropertyType MultiString -Force -Value @('CYBERDEFENDER_DISTRIBUTION_URL=' + $ControlPlaneUrl) | Out-Null
    Write-Host 'PASS: CyberDefenderAgent installed with persistent Control Plane URL'

    Start-Service -Name 'CyberDefenderAgent'
    $service = Get-Service -Name 'CyberDefenderAgent'
    Require ($service.Status -eq 'Running') 'CyberDefenderAgent did not reach RUNNING'
    $runtimeFile = Join-Path $stateDir 'dashboard_runtime.json'
    $deadline = (Get-Date).AddSeconds(45)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $runtimeFile)) { Start-Sleep -Milliseconds 500 }
    Require (Test-Path -LiteralPath $runtimeFile) 'Runtime state was not published'
    $runtime = Get-Content -Raw -LiteralPath $runtimeFile | ConvertFrom-Json
    Require ($runtime.runtime.status -eq 'HEALTHY') 'Runtime health is not HEALTHY'
    Require ([int]$runtime.runtime.component_failures -eq 0) 'Runtime component failures detected'
    Write-Host 'PASS: local Agent runtime health'
    Write-Host 'PASS: Agent-only installation complete; run VERIFY_LAB_ENDPOINT.ps1 for central checks'
} catch {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    throw
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
