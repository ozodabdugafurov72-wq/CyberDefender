param(
    [string]$LabLabel = "",
    [string]$OutputPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Safe-ReadText([string]$Path) {
    try { return [IO.File]::ReadAllText($Path) } catch { return $null }
}
function Safe-Json([string]$Path) {
    $text = Safe-ReadText $Path
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    try { return ($text | ConvertFrom-Json) } catch { return $null }
}
function Test-SystemAcl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        $rules = (Get-Acl -LiteralPath $Path).Access
        return @($rules | Where-Object {
            $_.IdentityReference -match '(^|\\)SYSTEM$' -and
            $_.AccessControlType -eq 'Allow' -and
            [bool]($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read)
        }).Count -gt 0
    } catch { return $false }
}
function Get-ValueOrNull($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

$base = Join-Path $env:ProgramData 'CyberDefender'
$app = Join-Path $env:ProgramFiles 'CyberDefender\app'
$state = Join-Path $base 'state'
$identityPath = Join-Path $base 'identity\endpoint_id.txt'
$tokenPath = Join-Path $base 'secrets\fleet_token.txt'
$runtimePath = Join-Path $state 'dashboard_runtime.json'
$crashRoot = Join-Path $env:ProgramData 'CyberDefenderCrashGuard'
$bootstrapLog = Join-Path $base 'logs\service_bootstrap.log'
$service = Get-Service -Name 'CyberDefenderAgent' -ErrorAction SilentlyContinue
$cim = Get-CimInstance Win32_Service -Filter "Name='CyberDefenderAgent'" -ErrorAction SilentlyContinue
$runtime = Safe-Json $runtimePath
$runtimeHealth = Get-ValueOrNull $runtime 'runtime'
$health = Get-ValueOrNull $runtime 'health'
$network = Get-ValueOrNull $health 'network_inventory'
$envEntries = @()
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\CyberDefenderAgent\Parameters'
try { $envEntries = @((Get-ItemProperty -Path $serviceKey -Name Environment -ErrorAction Stop).Environment) } catch { $envEntries = @() }
$urlEntry = @($envEntries | Where-Object { $_ -like 'CYBERDEFENDER_DISTRIBUTION_URL=*' } | Select-Object -First 1)
$url = $null
if ($urlEntry.Count -gt 0) { $url = ([string]$urlEntry[0]).Substring('CYBERDEFENDER_DISTRIBUTION_URL='.Length) }
$tcp = $false
if (-not [string]::IsNullOrWhiteSpace($url)) {
    try {
        $uri = New-Object Uri($url)
        $client = New-Object Net.Sockets.TcpClient
        $task = $client.BeginConnect($uri.Host, $uri.Port, $null, $null)
        $tcp = $task.AsyncWaitHandle.WaitOne(2000) -and $client.Connected
        $client.Close()
    } catch { $tcp = $false }
}
$crashFiles = @()
if (Test-Path -LiteralPath $crashRoot -PathType Container) {
    $crashFiles = @(Get-ChildItem -LiteralPath $crashRoot -File -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ name=$_.Name; bytes=$_.Length; last_write_utc=$_.LastWriteTimeUtc.ToString('o') }
    })
}
$endpointId = $null
if (Test-Path -LiteralPath $identityPath -PathType Leaf) { $endpointId = (Safe-ReadText $identityPath).Trim() }
$output = [ordered]@{
    schema = 'cyberdefender.fleet-heartbeat-diagnostic.v1'
    captured_utc = (Get-Date).ToUniversalTime().ToString('o')
    lab_label = $LabLabel
    actual_hostname = [Environment]::GetEnvironmentVariable('COMPUTERNAME')
    endpoint_id = $endpointId
    agent_service = [ordered]@{ state=if($service){[string]$service.Status}else{'ABSENT'}; pid=if($cim){$cim.ProcessId}else{$null}; start_mode=if($cim){[string]$cim.StartMode}else{'UNKNOWN'}; start_name=if($cim){[string]$cim.StartName}else{'UNKNOWN'} }
    service_environment = [ordered]@{ entries=(@($envEntries | Where-Object { $_ -like 'CYBERDEFENDER_DISTRIBUTION_URL=*' })); control_plane_url=$url }
    control_plane_tcp_8785 = $tcp
    runtime_file = [ordered]@{ path=$runtimePath; exists=(Test-Path -LiteralPath $runtimePath -PathType Leaf); last_write_utc=if(Test-Path $runtimePath){(Get-Item $runtimePath).LastWriteTimeUtc.ToString('o')}else{$null} }
    runtime = [ordered]@{ cycle_count=Get-ValueOrNull $runtimeHealth 'cycle_count'; status=Get-ValueOrNull $runtimeHealth 'status'; running=Get-ValueOrNull $runtimeHealth 'running'; component_failures=Get-ValueOrNull $runtimeHealth 'component_failures'; last_error=Get-ValueOrNull $runtimeHealth 'last_error' }
    resource_guard = [ordered]@{ state=Get-ValueOrNull (Get-ValueOrNull $health 'resource_guard') 'state'; status=Get-ValueOrNull (Get-ValueOrNull $health 'resource_guard') 'status' }
    network_collector = $network
    crashguard = [ordered]@{ root_exists=(Test-Path -LiteralPath $crashRoot -PathType Container); files=$crashFiles }
    lifecycle_diagnostics = [ordered]@{ bootstrap_log_exists=(Test-Path -LiteralPath $bootstrapLog -PathType Leaf); bootstrap_tail=if(Test-Path $bootstrapLog){@(Get-Content -LiteralPath $bootstrapLog -Tail 40)}else{@()} }
    protected_files = [ordered]@{ fleet_token_exists=(Test-Path -LiteralPath $tokenPath -PathType Leaf -ErrorAction SilentlyContinue); fleet_token_system_read_acl=Test-SystemAcl $tokenPath; endpoint_id_exists=(Test-Path -LiteralPath $identityPath -PathType Leaf); endpoint_id_system_read_acl=Test-SystemAcl $identityPath }
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path (Get-Location) 'fleet-heartbeat-diagnostic.json' }
$output | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Host "PASS: read-only heartbeat diagnostic written to $OutputPath"
