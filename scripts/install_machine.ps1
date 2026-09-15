param(
    [string]$Python = "",
    [switch]$NoStart
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator huquqi kerak. PowerShell/Terminal'ni Run as administrator bilan oching."
    }
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$false)][string[]]$Arguments = @(),
        [Parameter(Mandatory=$false)][int[]]$AllowedExitCodes = @(0)
    )
    & $FilePath @Arguments
    $code = $LASTEXITCODE
    if ($AllowedExitCodes -notcontains $code) {
        throw "$FilePath failed with exit code $code"
    }
}

function Test-ServiceExists([string]$Name) {
    return $null -ne (Get-Service -Name $Name -ErrorAction SilentlyContinue)
}

function Remove-ServiceSafe([string]$Name) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return }
    if ($svc.Status -ne 'Stopped') {
        try { Stop-Service -Name $Name -Force -ErrorAction Stop } catch { }
        try { (Get-Service -Name $Name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20)) } catch { }
    }
    & sc.exe delete $Name | Out-Null
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060) {
        throw "Service delete failed: $Name exit=$LASTEXITCODE"
    }
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline -and (Test-ServiceExists $Name)) { Start-Sleep -Milliseconds 250 }
    if (Test-ServiceExists $Name) { throw "Service removal timed out: $Name" }
}

function Wait-ServiceRunning([string]$Name,[int]$TimeoutSeconds=30) {
    $deadline=(Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $svc=Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $svc) { throw "Service disappeared: $Name" }
        if ($svc.Status -eq 'Running') { return }
        if ($svc.Status -eq 'Stopped') {
            Start-Sleep -Milliseconds 250
        } else {
            Start-Sleep -Milliseconds 250
        }
    } while((Get-Date) -lt $deadline)
    throw "Service did not reach RUNNING within ${TimeoutSeconds}s: $Name"
}

function Wait-HttpHealthy([string]$Url,[int]$TimeoutSeconds=30) {
    $deadline=(Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $r=Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3
            if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300) { return }
        } catch { }
        Start-Sleep -Milliseconds 500
    } while((Get-Date) -lt $deadline)
    throw "HTTP health timeout: $Url"
}

function Test-PortAvailable([int]$Port) {
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback,$Port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $listener) { try { $listener.Stop() } catch { } }
    }
}

function Show-ServiceDiagnostics {
    param([string]$Base)
    Write-Host ""
    Write-Host "=== CyberDefender service diagnostics ===" -ForegroundColor Yellow
    foreach($name in @('CyberDefenderAgent','CyberDefenderControlPlane','CyberDefenderOwnerUI')) {
        $svc=Get-Service -Name $name -ErrorAction SilentlyContinue
        if($null -eq $svc){ Write-Host "$name : NOT_INSTALLED" } else { Write-Host "$name : $($svc.Status) | StartType=$($svc.StartType)" }
    }
    & (Join-Path $PSScriptRoot 'collect_service_diagnostics.ps1')
    Write-Host "--- Service Control Manager events (recent) ---"
    Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match 'CyberDefender' } |
      Select-Object -First 20 TimeCreated,Id,LevelDisplayName |
      Format-List
}

Assert-Administrator

$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$AppParent = Join-Path $env:ProgramFiles "CyberDefender"
$InstallRoot = Join-Path $AppParent "app"
$PreviousRoot = Join-Path $AppParent "app.previous"
$Base = Join-Path $env:ProgramData "CyberDefender"
$StateDir = Join-Path $Base "state"
$SecretDir = Join-Path $Base "secrets"
$IdentityDir = Join-Path $Base "identity"
$ControlPlaneDir = Join-Path $Base "control-plane"
$DistributionDir = Join-Path $Base "distribution"
$LogDir = Join-Path $Base "logs"
$CrashGuardDir = Join-Path $env:ProgramData 'CyberDefenderCrashGuard'
$DistributionArtifact = Join-Path $DistributionDir "CyberDefenderPackage.zip"
$KeyFile = Join-Path $SecretDir "storage_key.b64"
$FleetToken = Join-Path $SecretDir "fleet_token.txt"
$EndpointIdFile = Join-Path $IdentityDir "endpoint_id.txt"
$DistributionDb = Join-Path $ControlPlaneDir "distribution.db"
$Services=@('CyberDefenderAgent','CyberDefenderControlPlane','CyberDefenderOwnerUI')
$InstallStarted=Get-Date

try {
    Write-Host "[1/10] Existing services safely stopped/removed..."
    foreach($name in $Services){ Remove-ServiceSafe $name }

    if(-not (Test-PortAvailable 8775)){ throw "Port 8775 is already in use. Close the old Owner Dashboard/process before install." }
    if(-not (Test-PortAvailable 8785)){ throw "Port 8785 is already in use. Close the old Distribution process before install." }

    Write-Host "[2/10] Machine directories tayyorlanmoqda..."
    New-Item -ItemType Directory -Force -Path $AppParent,$StateDir,$SecretDir,$IdentityDir,$ControlPlaneDir,$DistributionDir,$LogDir | Out-Null

    Write-Host "[3/10] Previous application snapshot + clean copy..."
    if(Test-Path $PreviousRoot){ Remove-Item -Recurse -Force $PreviousRoot }
    if(Test-Path $InstallRoot){ Move-Item -Force $InstallRoot $PreviousRoot }
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
    $copyArgs=@($SourceRoot,$InstallRoot,'/E','/PURGE','/XD','.venv','__pycache__','state','logs','evidence','_backup_before_*','.git','.pytest_cache','.mypy_cache','.ruff_cache','node_modules','tests','/XF','*.pyc','*.pyo','*.db','*.db-wal','*.db-shm','test_*.py','*_test.py')
    & robocopy.exe @copyArgs | Out-Null
    if($LASTEXITCODE -gt 7){ throw "robocopy failed: $LASTEXITCODE" }
    # Root quarantine is runtime data; agent\quarantine is source code and MUST remain.
    $runtimeQuarantine=Join-Path $InstallRoot 'quarantine'
    if(Test-Path $runtimeQuarantine){ Remove-Item -Recurse -Force $runtimeQuarantine }
    if(-not (Test-Path (Join-Path $InstallRoot 'agent\quarantine\vault.py'))){ throw "Packaging invariant failed: agent\quarantine\vault.py missing" }

    Write-Host "[4/10] Distribution artifact staging..."
    $Stage = Join-Path $env:TEMP ("CyberDefenderDist_" + [guid]::NewGuid().ToString("N"))
    try {
        New-Item -ItemType Directory -Force -Path $Stage | Out-Null
        $stageArgs=@($SourceRoot,$Stage,'/E','/XD','.venv','__pycache__','state','logs','evidence','_backup_before_*','.git','.pytest_cache','.mypy_cache','.ruff_cache','node_modules','tests','/XF','*.pyc','*.pyo','*.db','*.db-wal','*.db-shm','test_*.py','*_test.py')
        & robocopy.exe @stageArgs | Out-Null
        if($LASTEXITCODE -gt 7){ throw "distribution staging failed: $LASTEXITCODE" }
        $stageRuntimeQuarantine=Join-Path $Stage 'quarantine'
        if(Test-Path $stageRuntimeQuarantine){ Remove-Item -Recurse -Force $stageRuntimeQuarantine }
        if(Test-Path $DistributionArtifact){ Remove-Item -Force $DistributionArtifact }
        Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $DistributionArtifact -CompressionLevel Optimal
    } finally {
        if(Test-Path $Stage){ Remove-Item -Recurse -Force $Stage }
    }

    if ($Python) { $PythonExe=$Python; $PythonPrefix=@() }
    elseif (Get-Command py -ErrorAction SilentlyContinue) { $PythonExe='py'; $PythonPrefix=@('-3') }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { $PythonExe='python'; $PythonPrefix=@() }
    else { throw 'Python 3.13+ topilmadi.' }

    Write-Host "[5/10] Machine virtual environment..."
    Set-Location $InstallRoot
    & $PythonExe @PythonPrefix -m venv .venv
    if($LASTEXITCODE -ne 0){ throw "venv creation failed: $LASTEXITCODE" }
    $VenvPython = Join-Path $InstallRoot '.venv\Scripts\python.exe'
    Invoke-NativeChecked $VenvPython @('-m','pip','install','--upgrade','pip')
    Invoke-NativeChecked $VenvPython @('-m','pip','install','-r','requirements.txt')

    # H1D trusted state is separate from broadly inherited runtime state/logs.
    # Reject substituted paths before provisioning; never adopt user-owned state.
    $guardAncestor = $CrashGuardDir
    while ($guardAncestor) {
        if (Test-Path -LiteralPath $guardAncestor) {
            $guardItem = Get-Item -Force -LiteralPath $guardAncestor
            if ($guardItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'CrashGuard reparse path rejected' }
        }
        $guardAncestor = Split-Path -Parent $guardAncestor
    }
    if (Test-Path -LiteralPath $CrashGuardDir) {
        $guardOwner = (Get-Acl -LiteralPath $CrashGuardDir).GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($guardOwner -notin @('S-1-5-18','S-1-5-32-544')) { throw 'CrashGuard existing owner rejected' }
    } else { New-Item -ItemType Directory -Path $CrashGuardDir | Out-Null }
    $guardAcl = New-Object Security.AccessControl.DirectorySecurity
    $guardAcl.SetAccessRuleProtection($true,$false)
    $guardAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($guardSid in @('S-1-5-18','S-1-5-32-544')) {
        $guardRule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($guardSid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $guardAcl.AddAccessRule($guardRule)
    }
    Set-Acl -LiteralPath $CrashGuardDir -AclObject $guardAcl
    Invoke-NativeChecked $VenvPython @('-m','agent.service_crash_store','provision')

    Write-Host "[6/10] Machine identity va secrets..."
    if (-not (Test-Path $KeyFile)) {
        $bytes=New-Object byte[] 32; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
        [Convert]::ToBase64String($bytes) | Set-Content $KeyFile -Encoding ascii -NoNewline
    }
    if (-not (Test-Path $FleetToken)) {
        $bytes=New-Object byte[] 32; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
        [Convert]::ToBase64String($bytes) | Set-Content $FleetToken -Encoding ascii -NoNewline
    }
    if (-not (Test-Path $EndpointIdFile)) { [guid]::NewGuid().ToString() | Set-Content $EndpointIdFile -Encoding ascii -NoNewline }
    Invoke-NativeChecked 'icacls.exe' @($SecretDir,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
    Invoke-NativeChecked 'icacls.exe' @($IdentityDir,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')

    Write-Host "[7/10] Import path + fail-closed service preflight..."
    $SitePackages = (& $VenvPython -c 'import site; print(site.getsitepackages()[0])').Trim()
    if($LASTEXITCODE -ne 0 -or -not $SitePackages){ throw 'site-packages resolution failed' }
    $InstallRoot | Set-Content (Join-Path $SitePackages 'cyberdefender_app.pth') -Encoding ascii

    $env:CYBERDEFENDER_ROOT=$InstallRoot
    $env:CYBERDEFENDER_STATE_DIR=$StateDir
    $env:CYBERDEFENDER_STORAGE_KEY_B64=(Get-Content -Raw $KeyFile).Trim()
    $env:CYBERDEFENDER_ENDPOINT_ID=(Get-Content -Raw $EndpointIdFile).Trim()
    $env:CYBERDEFENDER_DISTRIBUTION_DB=$DistributionDb
    $env:CYBERDEFENDER_FLEET_TOKEN_FILE=$FleetToken
    $env:CYBERDEFENDER_INSTALLER_PATH=$DistributionArtifact

    Invoke-NativeChecked $VenvPython @('-c',"import win32service,servicemanager; from agent.quarantine.vault import SecureQuarantineVault; from agent.main import CyberDefenderRuntime; print('Runtime',CyberDefenderRuntime.VERSION,'| pywin32 direct host OK | quarantine OK')")
    Invoke-NativeChecked $VenvPython @('-m','agent.windows_service','--preflight')
    Invoke-NativeChecked $VenvPython @('-m','control_plane.windows_service','--preflight')
    Invoke-NativeChecked $VenvPython @('-m','dashboard_owner.windows_service','--preflight')

    Write-Host "[8/10] Windows Services ro'yxatdan o'tkazilmoqda..."
    $agentBin='"' + $VenvPython + '" -m agent.windows_service --service-run'
    $controlBin='"' + $VenvPython + '" -m control_plane.windows_service --service-run'
    $ownerBin='"' + $VenvPython + '" -m dashboard_owner.windows_service --service-run'

    New-Service -Name 'CyberDefenderAgent' -BinaryPathName $agentBin -DisplayName 'CyberDefender Endpoint Protection' -Description 'CyberDefender security-first endpoint runtime service' -StartupType Automatic | Out-Null
    New-Service -Name 'CyberDefenderControlPlane' -BinaryPathName $controlBin -DisplayName 'CyberDefender Distribution Telemetry' -Description 'CyberDefender local distribution and fleet telemetry control plane' -StartupType Automatic | Out-Null
    New-Service -Name 'CyberDefenderOwnerUI' -BinaryPathName $ownerBin -DisplayName 'CyberDefender Owner Master Control' -Description 'CyberDefender loopback Owner Master Control dashboard' -StartupType Automatic | Out-Null
    . (Join-Path $PSScriptRoot 'service_recovery_policy.ps1')
    foreach($name in $Services){
        # Finite recovery: 5s, 15s, 60s, then SC_ACTION_NONE; read back via SCM API.
        [CyberDefenderRecoveryPolicy]::Configure($name)
        Invoke-NativeChecked 'sc.exe' @('failureflag',$name,'1')
    }

    Write-Host "[9/10] Service start + health verification..."
    if (-not $NoStart) {
        Start-Service 'CyberDefenderControlPlane'; Wait-ServiceRunning 'CyberDefenderControlPlane' 30
        Wait-HttpHealthy 'http://127.0.0.1:8785/health' 30

        Start-Service 'CyberDefenderOwnerUI'; Wait-ServiceRunning 'CyberDefenderOwnerUI' 30
        Wait-HttpHealthy 'http://127.0.0.1:8775/owner/api/state' 30

        Start-Service 'CyberDefenderAgent'; Wait-ServiceRunning 'CyberDefenderAgent' 30
        $runtimeFile=Join-Path $StateDir 'dashboard_runtime.json'
        $deadline=(Get-Date).AddSeconds(45)
        do {
            if((Get-Service 'CyberDefenderAgent').Status -ne 'Running'){ throw 'CyberDefenderAgent stopped during runtime verification' }
            if(Test-Path $runtimeFile){
                $item=Get-Item $runtimeFile
                if($item.LastWriteTime -ge $InstallStarted){ break }
            }
            Start-Sleep -Milliseconds 500
        } while((Get-Date) -lt $deadline)
        if(-not (Test-Path $runtimeFile) -or (Get-Item $runtimeFile).LastWriteTime -lt $InstallStarted){ throw 'Agent service did not publish fresh runtime state within 45s' }
        $runtimeState = Get-Content -Raw $runtimeFile | ConvertFrom-Json
        if($null -eq $runtimeState.runtime){ throw 'Agent runtime state missing runtime object' }
        if($runtimeState.runtime.status -ne 'HEALTHY'){ throw "Agent runtime health is not HEALTHY: $($runtimeState.runtime.status)" }
        if($runtimeState.runtime.running -ne $true){ throw 'Agent runtime published state but is not marked running under SCM lifecycle' }
        if([int]$runtimeState.runtime.component_failures -ne 0){ throw "Agent runtime component failures detected: $($runtimeState.runtime.component_failures)" }
        Start-Sleep -Seconds 2
        foreach($name in $Services){ if((Get-Service $name).Status -ne 'Running'){ throw "Service failed post-start stability check: $name" } }
    }

    Write-Host "[10/10] Final machine contract..."
    foreach($name in $Services){
        $svc=Get-Service $name
        if($svc.StartType -ne 'Automatic'){ throw "Service is not Automatic: $name" }
        if(-not $NoStart -and $svc.Status -ne 'Running'){ throw "Service is not Running: $name" }
    }

    Write-Host ""
    Write-Host "CyberDefender machine install VERIFIED." -ForegroundColor Green
    Write-Host "Application: $InstallRoot"
    Write-Host "Previous application: $PreviousRoot"
    Write-Host 'H1D outer recovery is finite. Terminal failure requires authenticated administrator repair.'
    Write-Host 'Stop the affected service, repair the cause, then use agent.service_crash_store authorize-probe --service NAME and start it explicitly. Never delete crash history.'
    Write-Host "Machine state: $StateDir"
    Write-Host "Endpoint ID: $EndpointIdFile"
    Write-Host "Fleet telemetry DB: $DistributionDb"
    Write-Host "Download artifact: $DistributionArtifact"
    Write-Host "Local download URL: http://127.0.0.1:8785/download/cyberdefender"
    Write-Host "Owner UI: http://127.0.0.1:8775/owner"
} catch {
    Write-Host ""
    Write-Host "CyberDefender machine install FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Show-ServiceDiagnostics $Base
    foreach($name in $Services){ try { Remove-ServiceSafe $name } catch { } }
    # Preserve failed application tree + previous version for diagnosis/recovery.
    throw
}
