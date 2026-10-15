# CyberDefender Agent-only transactional release installer.
# Plan mode is read-only. -Apply changes only CyberDefenderAgent.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ReleaseZip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedZipSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ApprovedCommit,
    [switch]$Apply,
    [ValidateSet('','AGENT_ONLY_AUTHORIZED')][string]$HostAcknowledgement='',
    [switch]$RecoverStoppedAgent,
    [switch]$AuthorizeRecoveryProbe
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Revision=$ApprovedCommit.ToLowerInvariant()
$AgentName='CyberDefenderAgent'
$OtherServices=@('CyberDefenderControlPlane','CyberDefenderOwnerUI')
$ScriptRoot=Split-Path -Parent $MyInvocation.MyCommand.Path
$ToolsRoot=Join-Path $ScriptRoot 'agent_release'
$Manager=Join-Path $ToolsRoot 'release_manager.py'
$Provenance=Join-Path $ToolsRoot 'verify_git_zip_provenance.py'
$SourceRoot=Split-Path -Parent $ScriptRoot
$Bootstrap=Join-Path $ToolsRoot 'agent_service_bootstrap.py'
$Probe=Join-Path $ToolsRoot 'isolated_import_probe.py'
$AclVerifier=Join-Path $ScriptRoot 'verify_windows_acl.py'
$ProductRoot=Join-Path $env:ProgramFiles 'CyberDefender'
$OldApp=Join-Path $ProductRoot 'app'
$Python=Join-Path $OldApp '.venv\Scripts\python.exe'
$Releases=Join-Path $ProductRoot 'agent-releases'
$NewRoot=Join-Path $Releases $Revision
$StateBase=Join-Path $env:ProgramData 'CyberDefender'
$RuntimeFile=Join-Path $StateBase 'state\dashboard_runtime.json'
$ReceiptDir=Join-Path $StateBase 'deploy-receipts'
$OriginFile=Join-Path $StateBase 'identity\distribution_url.txt'
$RemoteToken=Join-Path $StateBase 'secrets\remote_fleet_token.txt'
$LocalToken=Join-Path $StateBase 'secrets\fleet_token.txt'

function Require([bool]$Condition,[string]$Message) {
    if(-not $Condition){ throw $Message }
}

function Run-Checked([string]$Executable,[string[]]$CommandArgs) {
    & $Executable @CommandArgs | Out-Host
    if($LASTEXITCODE -ne 0){ throw ('COMMAND_FAILED exit=' + $LASTEXITCODE) }
}

function Service-Info([string]$Name) {
    $service=Get-CimInstance Win32_Service -Filter ("Name='" + $Name + "'") -ErrorAction Stop
    Require ($null -ne $service) ('SERVICE_MISSING:' + $Name)
    return $service
}

function Recovery-Text([string]$Name) {
    $text=(& sc.exe qfailure $Name 2>&1 | Out-String).Trim()
    Require ($LASTEXITCODE -eq 0) ('SCM_RECOVERY_QUERY_FAILED:' + $Name)
    return $text
}

function Capture-Service([string]$Name) {
    $service=Service-Info $Name
    return [pscustomobject]@{
        Name=[string]$service.Name
        State=[string]$service.State
        ProcessId=[int]$service.ProcessId
        PathName=[string]$service.PathName
        StartMode=[string]$service.StartMode
        StartName=[string]$service.StartName
        Recovery=(Recovery-Text $Name)
    }
}

function Capture-Others() {
    $saved=@{}
    foreach($name in $OtherServices) {
        $service=Capture-Service $name
        Require ($service.State -eq 'Running') ('OTHER_SERVICE_UNHEALTHY:' + $name)
        $saved[$name]=$service
    }
    return $saved
}

function Verify-Others($Baseline) {
    foreach($name in $OtherServices) {
        $before=$Baseline[$name]
        $after=Capture-Service $name
        Require ($after.State -eq 'Running') ('OTHER_SERVICE_STOPPED:' + $name)
        Require ($after.ProcessId -eq $before.ProcessId) ('OTHER_SERVICE_RESTARTED:' + $name)
        Require ($after.PathName -eq $before.PathName) ('OTHER_SERVICE_PATH_CHANGED:' + $name)
        Require ($after.StartMode -eq $before.StartMode) ('OTHER_SERVICE_MODE_CHANGED:' + $name)
        Require ($after.StartName -eq $before.StartName) ('OTHER_SERVICE_IDENTITY_CHANGED:' + $name)
        Require ($after.Recovery -eq $before.Recovery) ('OTHER_SERVICE_RECOVERY_CHANGED:' + $name)
    }
}

function Verify-LocalCompanions() {
    $control=Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8785/health' -TimeoutSec 5
    Require ($control.StatusCode -eq 200) 'CONTROL_PLANE_HEALTH_FAILED'
    $owner=Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8775/owner/api/state' -TimeoutSec 5
    Require ($owner.StatusCode -eq 200) 'OWNER_UI_HEALTH_FAILED'
}

function Inspect-NoReparse([string]$Path) {
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor) {
        if(Test-Path -LiteralPath $cursor) {
            $entry=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){ throw ('REPARSE_PATH:' + $cursor) }
        }
        $parent=Split-Path $cursor -Parent
        if(!$parent -or $parent -eq $cursor){ break }
        $cursor=$parent
    }
}

function Inspect-ProtectedPath([string]$Path) {
    Require (Test-Path -LiteralPath $AclVerifier -PathType Leaf) 'ACL_VERIFIER_MISSING'
    & $Python $AclVerifier $Path | Out-Host
    Require ($LASTEXITCODE -eq 0) ('ACL_SECURITY_GATE_FAILED:' + $Path)
}

function Require-Administrator() {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMIN_REQUIRED'
}

function Stop-Agent() {
    $service=Get-Service -Name $AgentName -ErrorAction Stop
    if($service.Status -ne 'Stopped') {
        Stop-Service -Name $AgentName -ErrorAction Stop
        (Get-Service -Name $AgentName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(45))
    }
}

function Start-Agent() {
    Start-Service -Name $AgentName -ErrorAction Stop
    (Get-Service -Name $AgentName).WaitForStatus('Running',[TimeSpan]::FromSeconds(45))
}

function Set-AgentBinary([string]$Value) {
    $service=Service-Info $AgentName
    $result=Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{PathName=$Value} -ErrorAction Stop
    $returnCode=[int]$result.ReturnValue
    if($returnCode -ne 0){ throw ('SCM_BINARY_UPDATE_FAILED:' + $returnCode) }
    Require ((Service-Info $AgentName).PathName -eq $Value) 'SCM_BINARY_READBACK_MISMATCH'
}

function Authorize-AgentProbe() {
    $previous=Get-Location
    try {
        Set-Location -LiteralPath $OldApp
        Run-Checked $Python @('-m','agent.service_crash_store','authorize-probe','--service',$AgentName)
    } finally {
        Set-Location -LiteralPath $previous
    }
}

function Read-RuntimeSnapshot() {
    Require (Test-Path -LiteralPath $RuntimeFile -PathType Leaf) 'RUNTIME_STATE_MISSING'
    return Get-Content -LiteralPath $RuntimeFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}

function Runtime-IsHealthy($Snapshot) {
    if($null -eq $Snapshot.runtime){ return $false }
    $resource=$Snapshot.runtime.resource_snapshot
    return (
        $Snapshot.runtime.status -eq 'HEALTHY' -and
        $Snapshot.runtime.running -eq $true -and
        [int]$Snapshot.runtime.component_failures -eq 0 -and
        $null -ne $resource -and
        $resource.state -eq 'NORMAL'
    )
}

function Await-HealthyRuntime([datetime]$AfterUtc,[int]$TimeoutSeconds=240) {
    $deadline=(Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
    $observations=@()
    $lastStamp=[datetime]::MinValue
    while((Get-Date).ToUniversalTime() -lt $deadline) {
        Require ((Service-Info $AgentName).State -eq 'Running') 'AGENT_SERVICE_NOT_RUNNING'
        if(Test-Path -LiteralPath $RuntimeFile -PathType Leaf) {
            $item=Get-Item -LiteralPath $RuntimeFile
            $stamp=$item.LastWriteTimeUtc
            if($stamp -gt $AfterUtc -and $stamp -gt $lastStamp -and (((Get-Date).ToUniversalTime()-$stamp).TotalSeconds -le 30)) {
                $lastStamp=$stamp
                try {
                    $snapshot=Read-RuntimeSnapshot
                    if(Runtime-IsHealthy $snapshot) {
                        $observations+=,[pscustomobject]@{
                            observed_at=(Get-Date).ToUniversalTime().ToString('o')
                            file_timestamp=$stamp.ToString('o')
                            cycle_count=[int]$snapshot.runtime.cycle_count
                            component_failures=[int]$snapshot.runtime.component_failures
                            events_acked=[int]$snapshot.runtime.events_acked
                            deferred=[int]$snapshot.runtime.events_persisted_deferred
                            resource_state=[string]$snapshot.runtime.resource_snapshot.state
                        }
                        if($observations.Count -ge 3){ break }
                    } else {
                        $observations=@()
                    }
                } catch {
                    $observations=@()
                }
            }
        }
        Start-Sleep -Seconds 5
    }
    Require ($observations.Count -ge 3) 'RUNTIME_HEALTH_GATE_TIMEOUT'
    Start-Sleep -Seconds 20
    $finalItem=Get-Item -LiteralPath $RuntimeFile
    Require ((((Get-Date).ToUniversalTime()-$finalItem.LastWriteTimeUtc).TotalSeconds -le 30)) 'RUNTIME_SUSTAINED_STATE_STALE'
    $final=Read-RuntimeSnapshot
    Require (Runtime-IsHealthy $final) 'RUNTIME_SUSTAINED_HEALTH_FAILED'
    $last=$observations[-1]
    Require ([int]$final.runtime.cycle_count -gt [int]$last.cycle_count) 'RUNTIME_CYCLE_NOT_ADVANCING'
    Require ([int]$final.runtime.events_persisted_deferred -le ([int]$last.deferred + 1)) 'UNACKNOWLEDGED_OUTBOX_GROWTH'
    return [pscustomobject]@{ observations=$observations; final_cycle=[int]$final.runtime.cycle_count }
}

function Verify-AgentProcess([string]$ExpectedBin,[string]$ExpectedReleaseRoot='',[datetime]$StartedUtc=[datetime]::MinValue,[int]$TimeoutMilliseconds=5000) {
    $services=@(Get-CimInstance Win32_Process -Filter "Name='services.exe'" -ErrorAction Stop)
    Require ($services.Count -eq 1) 'SCM_PROCESS_IDENTITY_UNAVAILABLE'
    $servicesPid=[int]$services[0].ProcessId
    $deadline=(Get-Date).ToUniversalTime().AddMilliseconds([Math]::Max(250,$TimeoutMilliseconds))
    $staleObserved=$false
    do {
        $service=Service-Info $AgentName
        Require ($service.State -eq 'Running') 'AGENT_NOT_RUNNING'
        Require ($service.PathName -eq $ExpectedBin) 'AGENT_BINARY_UNEXPECTED'
        if($service.ProcessId -le 0) {
            Start-Sleep -Milliseconds 100
            continue
        }
        $process=Get-CimInstance Win32_Process -Filter ("ProcessId=" + $service.ProcessId) -ErrorAction SilentlyContinue
        if($null -eq $process) {
            Start-Sleep -Milliseconds 100
            continue
        }
        Require ($null -ne $process.CreationDate) 'AGENT_PROCESS_CREATION_MISSING'
        $createdUtc=([datetime]$process.CreationDate).ToUniversalTime()
        if($StartedUtc -ne [datetime]::MinValue -and $createdUtc -lt $StartedUtc.ToUniversalTime()) {
            $staleObserved=$true
            Start-Sleep -Milliseconds 100
            continue
        }
        Require ([string]$process.ExecutablePath -eq $Python) 'AGENT_PROCESS_EXECUTABLE_UNEXPECTED'
        Require ([int]$process.ParentProcessId -eq $servicesPid) 'AGENT_PROCESS_PARENT_UNEXPECTED'
        if($ExpectedReleaseRoot) {
            Require ([string]$process.CommandLine -like ('*' + $ExpectedReleaseRoot + '*agent_service_bootstrap.py*')) 'AGENT_PROCESS_COMMAND_UNEXPECTED'
        }
        return [int]$service.ProcessId
    } while((Get-Date).ToUniversalTime() -lt $deadline)
    if($staleObserved){ throw 'AGENT_PROCESS_STALE_TIMEOUT' }
    throw 'AGENT_PROCESS_MISSING_TIMEOUT'
}

function Write-Receipt($Original,$Others,$RuntimeEvidence,[int]$AgentPid,[string]$NewBin) {
    if(-not (Test-Path -LiteralPath $ReceiptDir)){ New-Item -ItemType Directory -Path $ReceiptDir | Out-Null }
    Inspect-NoReparse $ReceiptDir
    $receipt=[ordered]@{
        schema='cyberdefender.agent-release-receipt.v1'
        status='COMMITTED'
        commit=$Revision
        release_path=$NewRoot
        zip_sha256=$ApprovedZipSHA256.ToLowerInvariant()
        completed_at=(Get-Date).ToUniversalTime().ToString('o')
        agent_pid=$AgentPid
        agent_binpath=$NewBin
        original_agent_state=$Original.State
        original_agent_binpath=$Original.PathName
        other_services_unchanged=$true
        runtime=$RuntimeEvidence
    }
    $target=Join-Path $ReceiptDir ('agent-release-' + $Revision.Substring(0,8) + '.json')
    $temporary=$target + '.pending'
    $serialized=$receipt | ConvertTo-Json -Depth 8 -ErrorAction Stop
    $utf8NoBom=New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($temporary,$serialized,$utf8NoBom)
    Move-Item -LiteralPath $temporary -Destination $target -Force -ErrorAction Stop
    return $target
}

# Consolidated read-only precheck.
foreach($required in ($Python,$Manager,$Provenance,$Bootstrap,$Probe,$AclVerifier,$ReleaseZip,$LocalToken)) {
    Require (Test-Path -LiteralPath $required -PathType Leaf) ('REQUIRED_FILE_MISSING:' + $required)
    Inspect-NoReparse $required
}
$agentBaseline=Capture-Service $AgentName
$expectedInstalledBin='"' + $Python + '" -m agent.windows_service --service-run'
Require ($agentBaseline.PathName -eq $expectedInstalledBin) 'AGENT_ORIGINAL_PATH_NOT_RECOGNIZED'
Require ($agentBaseline.StartMode -eq 'Auto') 'AGENT_STARTMODE_NOT_AUTO'
Require ($agentBaseline.StartName -eq 'LocalSystem') 'AGENT_IDENTITY_UNEXPECTED'
if($agentBaseline.State -eq 'Running') {
    $baselineRuntime=Read-RuntimeSnapshot
    Require (Runtime-IsHealthy $baselineRuntime) 'AGENT_BASELINE_RUNTIME_UNHEALTHY'
} else {
    Require ($agentBaseline.State -eq 'Stopped') 'AGENT_STATE_UNSUPPORTED'
    Require ($RecoverStoppedAgent.IsPresent) 'RECOVER_STOPPED_AGENT_ACK_REQUIRED'
}
$otherBaseline=Capture-Others
Verify-LocalCompanions
Inspect-NoReparse $ProductRoot
Inspect-NoReparse $Releases
Inspect-ProtectedPath $ProductRoot
if(Test-Path -LiteralPath $OriginFile -PathType Leaf) {
    $url=(Get-Content -LiteralPath $OriginFile -Raw -Encoding Ascii).Trim().TrimEnd('/')
    Require ($url -eq 'https://cyberdefender-staging.up.railway.app' -or $url -eq 'http://127.0.0.1:8785') 'UNAPPROVED_DISTRIBUTION_ORIGIN'
    if($url -ne 'http://127.0.0.1:8785') {
        Require (Test-Path -LiteralPath $RemoteToken -PathType Leaf) 'REMOTE_FLEET_TOKEN_MISSING'
        Inspect-NoReparse $RemoteToken
        Inspect-ProtectedPath (Split-Path $RemoteToken -Parent)
    }
}
Run-Checked $Python @($Manager,'verify','--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision)
Run-Checked $Python @($Provenance,'--repo',$SourceRoot,'--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision)
Verify-Others $otherBaseline
Write-Host 'PLAN_PASS: pinned release, Agent baseline and companion services verified.' -ForegroundColor Green
if(-not $Apply) {
    Write-Host 'PLAN_ONLY: no release files or service settings changed.'
    exit 0
}

Require ($HostAcknowledgement -eq 'AGENT_ONLY_AUTHORIZED') 'HOST_ACKNOWLEDGEMENT_REQUIRED'
Require-Administrator
Require (-not (Test-Path -LiteralPath $NewRoot)) 'VERSION_ALREADY_STAGED_REFUSE_OVERWRITE'
New-Item -ItemType Directory -Path $Releases -Force | Out-Null
Inspect-NoReparse $Releases
Inspect-ProtectedPath $Releases
Run-Checked $Python @($Manager,'extract','--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision,'--dest',$NewRoot,'--bootstrap',$Bootstrap)
Run-Checked $Python @($Provenance,'--repo',$SourceRoot,'--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision,'--release-root',$NewRoot)
Inspect-NoReparse $NewRoot
Inspect-ProtectedPath $NewRoot
Run-Checked $Python @($Probe,$NewRoot,'--runtime')
Verify-Others $otherBaseline
Verify-LocalCompanions

$newBootstrap=Join-Path $NewRoot 'agent_service_bootstrap.py'
$newBin='"' + $Python + '" "' + $newBootstrap + '" --service-run'
$didSwitch=$false
$candidateStarted=$false
try {
    Stop-Agent
    if($AuthorizeRecoveryProbe) { Authorize-AgentProbe }
    $didSwitch=$true
    Set-AgentBinary $newBin
    $startedAt=(Get-Date).ToUniversalTime()
    Start-Agent
    $candidateStarted=$true
    $pid=Verify-AgentProcess $newBin $NewRoot $startedAt
    $runtimeEvidence=Await-HealthyRuntime $startedAt 240
    Verify-Others $otherBaseline
    Verify-LocalCompanions
    $agentAfter=Capture-Service $AgentName
    Require ($agentAfter.StartMode -eq $agentBaseline.StartMode) 'AGENT_STARTMODE_CHANGED'
    Require ($agentAfter.StartName -eq $agentBaseline.StartName) 'AGENT_IDENTITY_CHANGED'
    Require ($agentAfter.Recovery -eq $agentBaseline.Recovery) 'AGENT_RECOVERY_CHANGED'
    $receipt=Write-Receipt $agentBaseline $otherBaseline $runtimeEvidence $pid $newBin
    Write-Host ('AGENT_RELEASE_PASS: ' + $receipt) -ForegroundColor Green
    exit 0
} catch {
    $failure=$_.Exception.Message
    $rollbackFailures=@()
    try { Stop-Agent } catch { $rollbackFailures+=('stop-candidate:' + $_.Exception.Message) }
    if($didSwitch) {
        try { Set-AgentBinary $agentBaseline.PathName } catch { $rollbackFailures+=('restore-bin:' + $_.Exception.Message) }
    }
    if($agentBaseline.State -eq 'Running') {
        try {
            if($AuthorizeRecoveryProbe) { Authorize-AgentProbe }
            Start-Agent
            [void](Verify-AgentProcess $agentBaseline.PathName)
        } catch { $rollbackFailures+=('restore-running-state:' + $_.Exception.Message) }
    } else {
        try { Stop-Agent } catch { $rollbackFailures+=('restore-stopped-state:' + $_.Exception.Message) }
    }
    try {
        $rolled=Capture-Service $AgentName
        Require ($rolled.PathName -eq $agentBaseline.PathName) 'ROLLBACK_BINPATH_MISMATCH'
        Require ($rolled.StartMode -eq $agentBaseline.StartMode) 'ROLLBACK_STARTMODE_MISMATCH'
        Require ($rolled.StartName -eq $agentBaseline.StartName) 'ROLLBACK_IDENTITY_MISMATCH'
        Require ($rolled.Recovery -eq $agentBaseline.Recovery) 'ROLLBACK_RECOVERY_MISMATCH'
        Require ($rolled.State -eq $agentBaseline.State) 'ROLLBACK_START_STATE_MISMATCH'
    } catch { $rollbackFailures+=('rollback-readback:' + $_.Exception.Message) }
    try { Verify-Others $otherBaseline; Verify-LocalCompanions } catch { $rollbackFailures+=('companions:' + $_.Exception.Message) }
    if($rollbackFailures.Count -eq 0) {
        Write-Host ('AGENT_RELEASE_FAIL_ROLLBACK_PASS: ' + $failure) -ForegroundColor Yellow
    } else {
        Write-Host ('AGENT_RELEASE_FAIL_ROLLBACK_INCOMPLETE: ' + $failure) -ForegroundColor Red
        Write-Host ('Rollback issues: ' + ($rollbackFailures -join ' | '))
    }
    Write-Host 'Candidate release preserved for forensic review; original app remains intact.'
    exit 1
}
