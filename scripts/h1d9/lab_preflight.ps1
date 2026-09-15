param([switch]$AsObject)
$ErrorActionPreference='Stop'
function Get-H1D9LabPreflight {
    $blocks=@();$warnings=@();$facts=[ordered]@{schema='cd.h1d9.preflight.v1';utc=[DateTimeOffset]::UtcNow.ToString('o');powershell=$PSVersionTable.PSVersion.ToString()}
    try {
        $os=Get-CimInstance Win32_OperatingSystem;$cs=Get-CimInstance Win32_ComputerSystem
        $uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID.Trim().ToUpperInvariant()
        $hash=[Security.Cryptography.SHA256]::Create();$uuidHash=[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($uuid))).Replace('-','').ToLowerInvariant()
        $facts.hostname=[Environment]::MachineName;$facts.machine_uuid=$uuid;$facts.machine_uuid_sha256=$uuidHash
        $facts.os=$os.Caption;$facts.build=[int]$os.BuildNumber;$facts.architecture=$os.OSArchitecture;$facts.boot=$os.LastBootUpTime.ToUniversalTime().ToString('o')
        $facts.total_ram=[long]$cs.TotalPhysicalMemory;$facts.free_ram=[long]$os.FreePhysicalMemory*1024
        $facts.model=$cs.Manufacturer+' '+$cs.Model;$facts.hypervisor_present=$cs.HypervisorPresent
        $facts.cpu=@(Get-CimInstance Win32_Processor|Select-Object Name,NumberOfCores,NumberOfLogicalProcessors)
        $facts.disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|Select-Object DeviceID,Size,FreeSpace,FileSystem)
        $id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object Security.Principal.WindowsPrincipal($id)
        $facts.admin=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if($uuidHash -eq '195d1d40f7e40d281fe8d46d33f4c4e13d44490ffa58edc6a1e2d634375b6732'){$blocks+='PROTECTED_PRODUCTION_HOST'}
        if($facts.model -match 'Acer'){$blocks+='ACER_PERSONAL_DEVICE_NOT_APPROVED'}
        if(-not $facts.admin){$blocks+='ADMIN_REQUIRED'}
        if($facts.build -lt 26100 -or -not [Environment]::Is64BitOperatingSystem){$blocks+='WINDOWS_VERSION_ARCHITECTURE'}
        if($facts.total_ram -lt 8GB -or $facts.free_ram -lt 3GB){$blocks+='RAM_INSUFFICIENT'}
        $systemDisk=@($facts.disks|Where-Object DeviceID -eq 'C:')
        if($systemDisk.Count -ne 1 -or $systemDisk[0].FreeSpace -lt 20GB -or $systemDisk[0].FileSystem -ne 'NTFS'){$blocks+='SYSTEM_DISK_REQUIREMENT'}
    } catch {$blocks+='CORE_CAPABILITY_QUERY_FAILED'}
    try {$facts.disk_health=@(Get-PhysicalDisk|Select-Object HealthStatus,OperationalStatus,Size)}catch{$warnings+='DISK_HEALTH_UNAVAILABLE'}
    try {$facts.winre=@(& reagentc.exe /info 2>$null | Where-Object {$_ -match 'Windows RE status|Windows RE location'});if($LASTEXITCODE -ne 0){$warnings+='WINRE_QUERY_UNAVAILABLE'}}catch{$warnings+='WINRE_QUERY_UNAVAILABLE'}
    try {$facts.power_states=@(& powercfg.exe /a 2>$null);if($LASTEXITCODE -ne 0){$warnings+='POWER_QUERY_UNAVAILABLE'}}catch{$warnings+='POWER_QUERY_UNAVAILABLE'}
    try {
        $facts.pending_reboot=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        $pending=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        $facts.pending_reboot=$facts.pending_reboot -or ($null -ne $pending)
        if($facts.pending_reboot){$warnings+='PENDING_REBOOT_REVIEW'}
    }catch{$warnings+='REBOOT_INDICATORS_UNAVAILABLE'}
    $facts.python=@(Get-Command python.exe,py.exe -ErrorAction SilentlyContinue|Select-Object Name,Source)
    # Do not execute an unverified Python found via PATH (including Store aliases).
    if($facts.python.Count -eq 0){$warnings+='PYTHON_NOT_FOUND'}
    $facts.python_version='NOT_EXECUTED; explicit interpreter validated at admission'
    $warnings+='PYTHON_VERSION_REQUIRES_EXPLICIT_INTERPRETER_CHECK'
    $facts.services=@(Get-Service CyberDefenderAgent,CyberDefenderControlPlane,CyberDefenderOwnerUI -ErrorAction SilentlyContinue|Select-Object Name,Status,StartType)
    $facts.directories=@();foreach($path in @((Join-Path $env:ProgramFiles 'CyberDefender'),(Join-Path $env:ProgramData 'CyberDefender'),(Join-Path $env:ProgramData 'CyberDefenderCrashGuard'))){$facts.directories+=@{path=$path;exists=(Test-Path -LiteralPath $path)}}
    $facts.ports=@()
    try {$connections=@(Get-NetTCPConnection -ErrorAction Stop);foreach($port in @(8775,8785)){$facts.ports+=@{port=$port;listening=(@($connections|Where-Object {$_.State -eq 'Listen' -and $_.LocalPort -eq $port}).Count -gt 0)}}}catch{$warnings+='PORT_QUERY_UNAVAILABLE'}
    try {$facts.timezone=(Get-TimeZone).Id}catch{$warnings+='TIMEZONE_UNAVAILABLE'}
    if($facts.services.Count -gt 0 -or @($facts.directories|Where-Object exists).Count -gt 0){$warnings+='NOT_CLEAN_C0; RESUME_ONLY_AFTER_LEDGER_VALIDATION'}
    $facts.blocks=$blocks;$facts.warnings=$warnings;$facts.verdict=if($blocks.Count){'BLOCK'}elseif($warnings.Count){'WARN'}else{'PASS'}
    $facts.exit_code=if($blocks.Count){20}elseif($warnings.Count){10}else{0}
    return [pscustomobject]$facts
}
if($MyInvocation.InvocationName -ne '.'){
    $r=Get-H1D9LabPreflight
    if($AsObject){$r}else{$r|ConvertTo-Json -Depth 7;exit $r.exit_code}
}
