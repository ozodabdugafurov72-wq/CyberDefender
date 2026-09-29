param(
    [Parameter(Mandatory=$true)][ValidatePattern('^PC-JDU([1-9])?$')][string]$LabLabel,
    [string]$OutputPath = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Require([bool]$Condition,[string]$Message) { if(-not $Condition){ throw $Message } }
function Get-SafeRelativePath([string]$Root,[string]$Child) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $childFull = [IO.Path]::GetFullPath($Child)
    Require ($childFull.StartsWith($rootFull,[StringComparison]::OrdinalIgnoreCase)) "Path escapes evidence root: $Child"
    return $childFull.Substring($rootFull.Length).Replace('\','/')
}
$hostName = [Environment]::GetEnvironmentVariable('COMPUTERNAME')
$base = Join-Path $env:ProgramData 'CyberDefender'
$app = Join-Path $env:ProgramFiles 'CyberDefender\app'
$state = Join-Path $base 'state'
$identity = Join-Path $base 'identity\endpoint_id.txt'
$runtime = Join-Path $state 'dashboard_runtime.json'
Require (-not [string]::IsNullOrWhiteSpace($hostName)) 'COMPUTERNAME unavailable'
Require (Test-Path -LiteralPath $app -PathType Container) 'Agent application missing'
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path (Get-Location) ($LabLabel + '_baseline_evidence.json') }
$service = Get-Service -Name 'CyberDefenderAgent' -ErrorAction SilentlyContinue
$cim = Get-CimInstance Win32_Service -Filter "Name='CyberDefenderAgent'" -ErrorAction SilentlyContinue
$files = @()
Get-ChildItem -LiteralPath $app -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
    $_.FullName -notmatch '\\(\.venv|state|logs|secrets|identity|evidence|__pycache__)\\' -and $_.Extension -notin @('.log','.db','.b64','.key','.pem','.pfx')
} | ForEach-Object {
    $rel = Get-SafeRelativePath $app $_.FullName
    $files += [ordered]@{ path=$rel; bytes=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$nativeRel='native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe'
$native=Join-Path $app ($nativeRel -replace '/', '\')
$envValue=(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CyberDefenderAgent' -Name Environment -ErrorAction SilentlyContinue).Environment
$url=(@($envValue) | Where-Object { $_ -like 'CYBERDEFENDER_DISTRIBUTION_URL=*' } | Select-Object -First 1)
$health=[ordered]@{status='UNAVAILABLE';component_failures=$null;version=$null}
if(Test-Path -LiteralPath $runtime -PathType Leaf){
    $r=Get-Content -Raw -LiteralPath $runtime | ConvertFrom-Json
    $health.status=[string]$r.runtime.status; $health.component_failures=[int]$r.runtime.component_failures; $health.version=[string]$r.runtime.version
}
$out=[ordered]@{
    schema='cyberdefender.agent-baseline-evidence.v1'; captured_utc=(Get-Date).ToUniversalTime().ToString('o'); lab_label=$LabLabel; actual_hostname=$hostName
    endpoint_id=if(Test-Path $identity){(Get-Content -Raw $identity).Trim()}else{$null}
    runtime_version=$health.version; health=$health; service=[ordered]@{present=($null -ne $service); state=if($service){[string]$service.Status}else{'ABSENT'}; start_mode=if($cim){[string]$cim.StartMode}else{'UNKNOWN'}}
    control_plane=[ordered]@{configured=(-not [string]::IsNullOrWhiteSpace($url)); url=if($url){([string]$url).Substring('CYBERDEFENDER_DISTRIBUTION_URL='.Length)}else{$null}}
    native_sensor=[ordered]@{path=$nativeRel; present=(Test-Path $native -PathType Leaf); sha256=if(Test-Path $native){(Get-FileHash $native -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}}
    requirements_sha256=if(Test-Path (Join-Path $app 'requirements.txt')){(Get-FileHash (Join-Path $app 'requirements.txt') -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
    file_count=$files.Count; files=$files
}
$out | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Host "PASS: read-only baseline evidence written to $OutputPath"
