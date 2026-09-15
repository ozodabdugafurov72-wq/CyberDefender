param(
    [ValidateSet('Admission','Preflight','Install','EnableCanary','Observe','CrashOnce','CleanRestart')]
    [string]$Phase='Preflight',
    [string]$GuestAuthorization='',
    [string]$Archive='',
    [string]$PackageSha256='',
    [string]$Python='',
    [string]$ActuatorTicket='',
    [ValidateSet('CyberDefenderAgent','CyberDefenderControlPlane','CyberDefenderOwnerUI')]
    [string]$Service='CyberDefenderAgent',
    [ValidateRange(1,600)][int]$Samples=1
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Every entry point is guest-only, including read-only collection. No bypass switch.
$identity=(Get-CimInstance Win32_ComputerSystemProduct).UUID.Trim().ToUpperInvariant()
$hash=[Security.Cryptography.SHA256]::Create()
$identityHash=[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity))).Replace('-','').ToLowerInvariant()
if($identityHash -eq '195d1d40f7e40d281fe8d46d33f4c4e13d44490ffa58edc6a1e2d634375b6732'){throw 'H1D9_PRODUCTION_HOST_DENIED'}
$package=(Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$source=Join-Path $package 'payload'
. (Join-Path $PSScriptRoot 'admission.ps1')
$computer=Get-CimInstance Win32_ComputerSystem
$os=Get-CimInstance Win32_OperatingSystem
$disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
if(-not $GuestAuthorization){throw 'H1D9_GUEST_AUTHORIZATION_REQUIRED'}
if((Get-Item -LiteralPath $GuestAuthorization).Length -gt 8192){throw 'H1D9_AUTHORIZATION_SIZE'}
$auth=Get-Content -Raw -LiteralPath $GuestAuthorization | ConvertFrom-Json
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$context=@{identity_hash=$identityHash;uuid_valid=($identity -match '^[0-9A-F-]{36}$' -and $identity -notmatch '^(0|-)+$|^(F|-)+$');
 vm_model=($computer.Manufacturer+' '+$computer.Model);admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
 now=[DateTimeOffset]::UtcNow;package_root=$package;os_build=[int]$os.BuildNumber;os_64bit=[Environment]::Is64BitOperatingSystem;
 total_ram=[long]$computer.TotalPhysicalMemory;free_ram=([long]$os.FreePhysicalMemory*1024);free_disk=[long]$disk.FreeSpace}
Assert-H1D9Identity $context $auth $PackageSha256
$metadata=Assert-H1D9Package $package $Archive $PackageSha256 $auth
$programFiles=[Environment]::GetFolderPath('ProgramFiles')
$programData=[Environment]::GetFolderPath('CommonApplicationData')
if($env:ProgramFiles -ine $programFiles -or $env:ProgramData -ine $programData){throw 'H1D9_REDIRECTED_SYSTEM_PATHS'}
# No machine mutation occurs above this line. The package/identity gates run for every phase.
if($Phase -eq 'Admission'){
    [pscustomobject]@{admitted=$true;machine=$identityHash;package=$PackageSha256;session=$auth.lab_nonce;boot=$os.LastBootUpTime.ToUniversalTime().ToString('o')}
    return
}
$services=@('CyberDefenderAgent','CyberDefenderControlPlane','CyberDefenderOwnerUI')
$installed=Join-Path $env:ProgramFiles 'CyberDefender/app'
$base=Join-Path $env:ProgramData 'CyberDefender'
$guard=Join-Path $env:ProgramData 'CyberDefenderCrashGuard'
function Checked([string]$exe,[string[]]$arguments){ & $exe @arguments; if($LASTEXITCODE -ne 0){throw 'H1D9_COMMAND_FAILED'} }
if($Phase -in @('Install','EnableCanary','CrashOnce','CleanRestart')){
    if(-not $Python -or -not $ActuatorTicket){throw 'H1D9_DURABLE_ACTUATOR_TICKET_REQUIRED'}
    $labRoot=Join-Path 'C:\H1D9\results' $auth.lab_nonce
    Checked $Python @((Join-Path $PSScriptRoot 'lab_ticket.py'),'--root',$labRoot,'--ticket',$ActuatorTicket,'--action',$Phase,'--service',$Service,'--package',$PackageSha256,'--machine',$identityHash,'--session',$auth.lab_nonce)
}
function OwnedService([string]$name){
    $s=Get-CimInstance Win32_Service -Filter "Name='$name'"
    $expected='"'+(Join-Path $installed '.venv\Scripts\python.exe')+'" -m '
    $modules=@{CyberDefenderAgent='agent.windows_service';CyberDefenderControlPlane='control_plane.windows_service';CyberDefenderOwnerUI='dashboard_owner.windows_service'}
    if(-not $s -or $s.PathName -ne ($expected+$modules[$name]+' --service-run') -or $s.StartName -ne 'LocalSystem'){throw 'H1D9_SERVICE_IDENTITY_MISMATCH'}
    return $s
}
if($Phase -eq 'Preflight' -or $Phase -eq 'Install'){
    foreach($s in $services){if(Get-Service $s -ErrorAction SilentlyContinue){throw 'H1D9_CLEAN_GUEST_REQUIRED'}}
    foreach($p in @((Join-Path $env:ProgramFiles 'CyberDefender'),$base,$guard)){
        if(Test-Path -LiteralPath $p){throw 'H1D9_EXISTING_INSTALLATION_OR_STATE'}
    }
    if(-not $Python -or -not (Test-Path -LiteralPath $Python)){throw 'H1D9_PYTHON_REQUIRED'}
    Checked $Python @('-c','import sys; assert sys.version_info >= (3,13)')
    Write-Output 'H1D9_GUEST_PREFLIGHT_PASS; installer dependency download must be available before Install'
    if($Phase -eq 'Install'){
        & (Join-Path $source 'scripts/install_machine.ps1') -Python $Python
        if(-not $?){throw 'H1D9_INSTALL_FAILED'}
    }
    return
}
foreach($s in $services){$null=OwnedService $s}
if($Phase -eq 'EnableCanary'){
    $binary=Join-Path $installed 'native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe'
    $rel='native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe'
    $entry=@($metadata.files | Where-Object path -eq $rel)
    if($entry.Count -ne 1 -or (Get-FileHash $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry[0].sha256){throw 'H1D9_BINARY_PIN_MISMATCH'}
    $config=Get-Content -Raw (Join-Path $source 'config/process_sensor_runtime.example.json') | ConvertFrom-Json
    $config.rust_v05.executable=$binary; $config.rust_v05.sha256=$entry[0].sha256
    $dir=Join-Path $base 'config'
    if(Test-Path (Join-Path $dir 'process_sensor_runtime.json')){throw 'H1D9_EXISTING_CANARY_CONFIG_REQUIRES_CHECKPOINT_RESTORE'}
    Stop-Service CyberDefenderAgent
    (Get-Service CyberDefenderAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $config | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $dir 'process_sensor_runtime.json') -Encoding Ascii
    Start-Service CyberDefenderAgent
    return
}
if($Phase -eq 'CleanRestart'){
    Stop-Service $Service
    (Get-Service $Service).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    Start-Service $Service
    return
}
if($Phase -eq 'CrashOnce'){
    # Exact SCM PID + creation time + executable verified twice; never name-wide kill.
    $s=OwnedService $Service
    if($s.State -ne 'Running' -or $s.ProcessId -le 0){throw 'H1D9_NO_RUNNING_TARGET'}
    $p=Get-Process -Id $s.ProcessId
    $started=$p.StartTime
    if($p.Path -ne (Join-Path $installed '.venv\Scripts\python.exe')){throw 'H1D9_PROCESS_PATH_MISMATCH'}
    $again=OwnedService $Service
    if($again.ProcessId -ne $p.Id -or $p.StartTime -ne $started){throw 'H1D9_PROCESS_CHANGED'}
    $p.Kill(); $p.WaitForExit(10000) | Out-Null
    if(-not $p.HasExited){throw 'H1D9_EXIT_UNVERIFIED'}
    Write-Output 'H1D9_SINGLE_FAULT_ISSUED; recovery has NOT been asserted'
    return
}
# Deliberately selected metadata only: never dump command lines, environment,
# tokens, protected record contents or complete runtime snapshots.
for($i=0;$i -lt $Samples;$i++){
    $rows=@()
    foreach($name in $services){
        $s=OwnedService $name; $p=$null
        if($s.ProcessId){$p=Get-Process -Id $s.ProcessId -ErrorAction SilentlyContinue}
        $rows+= [ordered]@{service=$name;state=$s.State;pid=$s.ProcessId;automatic=($s.StartMode -eq 'Auto');cpu_seconds=if($p){$p.CPU}else{$null};private_bytes=if($p){$p.PrivateMemorySize64}else{$null};handles=if($p){$p.HandleCount}else{$null}}
    }
    $agent=OwnedService 'CyberDefenderAgent'
    $children=@(Get-CimInstance Win32_Process -Filter "Name='cyberdefender-process-sensor.exe'" | Select-Object ProcessId,ParentProcessId)
    $runtime=Join-Path $base 'state/dashboard_runtime.json'
    $status=$null; $age=$null; $authority=$null; $canary=$null
    if(Test-Path $runtime){
        try {
            if((Get-Item $runtime).Length -gt 8MB){throw 'SNAPSHOT_SIZE'}
            $r=ConvertTo-H1D9RuntimeEvidence (Get-Content -Raw $runtime | ConvertFrom-Json)
            $status=$r.status; $authority=$r.authority; $canary=$r.canary
            $age=((Get-Date)-(Get-Item $runtime).LastWriteTime).TotalSeconds
        } catch {$status='INVALID'}
    }
    $guardBytes=$null
    if(Test-Path $guard){$guardBytes=(Get-ChildItem $guard -Recurse -File|Measure-Object Length -Sum).Sum}
    [ordered]@{utc=[DateTime]::UtcNow.ToString('o');services=$rows;rust_count=$children.Count;rust_bound_count=@($children|Where-Object ParentProcessId -eq $agent.ProcessId).Count;runtime_status=$status;runtime_age_seconds=$age;authority=$authority;canary=$canary;guard_bytes=$guardBytes} | ConvertTo-Json -Depth 6 -Compress
    if($i -lt $Samples-1){Start-Sleep -Seconds 2}
}
