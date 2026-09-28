param(
    [Parameter(Mandatory=$true)][ValidatePattern('^PC-JDU[3-9]$')][string]$EndpointName,
    [Parameter(Mandatory=$true)][ValidatePattern('^https?://[^/]+(?::\d+)?$')][string]$ControlPlaneUrl,
    [switch]$SkipCentral
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Fail([string]$Message) { Write-Host "FAIL: $Message" -ForegroundColor Red; throw $Message }
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { Fail $Message }; Write-Host "PASS: $Message" }
function Wait-Heartbeat {
    param([string]$Url,[string]$Token,[string]$EndpointId,[string]$Hostname,[string]$RuntimeVersion)
    $body = @{ endpoint_id=$EndpointId; hostname=$Hostname; runtime_version=$RuntimeVersion; health_state='HEALTHY'; service_state='RUNNING'; resource_state='UNKNOWN' } | ConvertTo-Json -Compress
    $headers = @{ Authorization = 'Bearer ' + $Token }
    $response = Invoke-RestMethod -Method Post -Uri ($Url.TrimEnd('/') + '/api/v1/endpoints/heartbeat') -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 5
    return $true
}

Require ((hostname).Trim() -eq $EndpointName) 'hostname matches expected endpoint'
$base = Join-Path $env:ProgramData 'CyberDefender'
$app = Join-Path $env:ProgramFiles 'CyberDefender\app'
$state = Join-Path $base 'state'
$identity = Join-Path $base 'identity\endpoint_id.txt'
$tokenFile = Join-Path $base 'secrets\fleet_token.txt'
$runtimeFile = Join-Path $state 'dashboard_runtime.json'
Require (Test-Path -LiteralPath $identity -PathType Leaf) 'endpoint identity exists'
Require (Test-Path -LiteralPath $app -PathType Container) 'Agent application exists'
$service = Get-Service -Name 'CyberDefenderAgent' -ErrorAction SilentlyContinue
Require ($null -ne $service) 'CyberDefenderAgent service exists'
Require ($service.Status -eq 'Running') 'CyberDefenderAgent is RUNNING'
$cim = Get-CimInstance Win32_Service -Filter "Name='CyberDefenderAgent'"
Require ($cim.StartMode -eq 'Auto') 'CyberDefenderAgent startup is Automatic'
Require (-not (Get-Service -Name 'CyberDefenderControlPlane' -ErrorAction SilentlyContinue)) 'ControlPlane absent'
Require (-not (Get-Service -Name 'CyberDefenderOwnerUI' -ErrorAction SilentlyContinue)) 'OwnerUI absent'
Require (Test-Path -LiteralPath (Join-Path $app 'native\process_sensor_v0_5_1\target\release\cyberdefender-process-sensor.exe') -PathType Leaf) 'pinned native sensor present'
Require (Test-Path -LiteralPath $runtimeFile -PathType Leaf) 'runtime state exists'
$runtime = Get-Content -Raw -LiteralPath $runtimeFile | ConvertFrom-Json
Require ($runtime.runtime.status -eq 'HEALTHY') 'runtime health is HEALTHY'
Require ([int]$runtime.runtime.component_failures -eq 0) 'component failures are zero'
$environment = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CyberDefenderAgent' -Name Environment -ErrorAction SilentlyContinue).Environment
Require (@($environment) -match '^CYBERDEFENDER_DISTRIBUTION_URL=' + [regex]::Escape($ControlPlaneUrl) + '$') 'Control Plane URL is persistent in service environment'

if (-not $SkipCentral) {
    Require (Test-Path -LiteralPath $tokenFile -PathType Leaf) 'fleet credential is supplied outside the package'
    $token = (Get-Content -Raw -LiteralPath $tokenFile).Trim()
    Require (-not [string]::IsNullOrWhiteSpace($token)) 'fleet credential is non-empty'
    $endpointId = (Get-Content -Raw -LiteralPath $identity).Trim()
    $hostname = (hostname).Trim()
    $version = [string]$runtime.runtime.version
    Require (Wait-Heartbeat -Url $ControlPlaneUrl -Token $token -EndpointId $endpointId -Hostname $hostname -RuntimeVersion $version) 'central heartbeat sample 1'
    Start-Sleep -Seconds 2
    Require (Wait-Heartbeat -Url $ControlPlaneUrl -Token $token -EndpointId $endpointId -Hostname $hostname -RuntimeVersion $version) 'central heartbeat sample 2'
    Write-Host 'PASS: central registration/heartbeat progression'
} else { Write-Host 'WAIT: central registration and heartbeat checks were skipped' -ForegroundColor Yellow }

Write-Host 'PASS: Agent-only endpoint verification complete'
