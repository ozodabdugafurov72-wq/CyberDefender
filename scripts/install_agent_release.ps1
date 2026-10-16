# CyberDefender Agent-only transactional release installer.
# Plan mode is read-only. -Apply changes only CyberDefenderAgent.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ReleaseZip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedZipSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ApprovedCommit,
    [Parameter(Mandatory=$true)][string]$RuntimeZip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedRuntimeZipSHA256,
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
$IdentityEvidenceDirectory=$env:TEMP

Add-Type -AssemblyName System.IO.Compression

function Require([bool]$Condition,[string]$Message) {
    if(-not $Condition){ throw $Message }
}

function Run-Checked([string]$Executable,[string[]]$CommandArgs) {
    & $Executable @CommandArgs | Out-Host
    if($LASTEXITCODE -ne 0){ throw ('COMMAND_FAILED exit=' + $LASTEXITCODE) }
}

function Get-Sha256Hex([byte[]]$Bytes) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-StreamSha256Hex($Stream) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Read-BoundedFile([string]$Path,[int64]$MaximumBytes) {
    $input=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        Require ($input.Length -le $MaximumBytes) 'RUNTIME_ZIP_OVERSIZED'
        $output=[IO.MemoryStream]::new()
        try {
            $buffer=New-Object byte[] 1048576
            $measured=0L
            while(($read=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
                $measured += $read
                Require ($measured -le $MaximumBytes) 'RUNTIME_ZIP_OVERSIZED'
                $output.Write($buffer,0,$read)
            }
            return ,$output.ToArray()
        } finally { $output.Dispose() }
    } finally { $input.Dispose() }
}

function Test-JsonInteger($Value) {
    return ($Value -is [int] -or $Value -is [long])
}

function Test-SafeRuntimePath([string]$Name) {
    if(-not $Name -or $Name -match '[\\:]' -or [IO.Path]::IsPathRooted($Name) -or $Name -match '[<>|?*\x00-\x1f]') { return $false }
    $reserved=@('CON','PRN','AUX','NUL','CONIN$','CONOUT$','COM1','COM2','COM3','COM4','COM5','COM6','COM7','COM8','COM9','LPT1','LPT2','LPT3','LPT4','LPT5','LPT6','LPT7','LPT8','LPT9')
    foreach($part in $Name.Split('/')) {
        if(-not $part -or $part -eq '.' -or $part -eq '..' -or $part.EndsWith('.') -or $part.EndsWith(' ')) { return $false }
        if($reserved -contains $part.Split('.')[0].ToUpperInvariant()) { return $false }
    }
    return $true
}

function Read-PinnedRuntimePackage([string]$Path,[string]$ApprovedSha256) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Require ($item.Length -le 67108864) 'RUNTIME_ZIP_OVERSIZED'
    $payload=Read-BoundedFile $item.FullName 67108864
    Require ($payload.Length -le 67108864) 'RUNTIME_ZIP_OVERSIZED'
    Require ((Get-Sha256Hex $payload) -eq $ApprovedSha256.ToLowerInvariant()) 'RUNTIME_ZIP_SHA256_MISMATCH'
    $memory=[IO.MemoryStream]::new($payload,$false)
    $archive=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Read,$false)
    try {
        $entries=@($archive.Entries)
        Require ($entries.Count -gt 1 -and $entries.Count -le 4000) 'RUNTIME_ENTRY_COUNT_INVALID'
        $byName=@{}
        foreach($entry in $entries) {
            $name=[string]$entry.FullName
            Require ($name -and -not $entry.Name.Equals('')) 'RUNTIME_DIRECTORY_ENTRY_FORBIDDEN'
            Require (-not $byName.ContainsKey($name)) 'RUNTIME_DUPLICATE_PATH'
            $byName[$name]=$entry
        }
        Require ($byName.ContainsKey('RUNTIME_MANIFEST.json')) 'RUNTIME_MANIFEST_MISSING'
        $manifestEntry=$byName['RUNTIME_MANIFEST.json']
        Require ($manifestEntry.Length -le 4194304) 'RUNTIME_MANIFEST_OVERSIZED'
        $reader=[IO.StreamReader]::new($manifestEntry.Open(),[Text.Encoding]::UTF8,$true,4096,$false)
        try { $meta=$reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop }
        finally { $reader.Dispose() }
        Require ($meta.schema -is [string] -and $meta.schema -eq 'cyberdefender.pinned-python-runtime.v1') 'RUNTIME_SCHEMA_INVALID'
        Require ($null -ne $meta.python -and $meta.python.name -is [string] -and $meta.python.sha256 -is [string]) 'RUNTIME_PYTHON_PROVENANCE_INVALID'
        Require ($meta.python.name -eq 'python-3.14.7-amd64.zip' -and $meta.python.sha256 -eq 'ac1a727a71738e11de80b76e975f9b8a258aea6412bfc31696b929d59c6aafd0') 'RUNTIME_PYTHON_PROVENANCE_INVALID'
        $expectedWheels=@(
            'cffi-2.1.1-cp314-cp314-win_amd64.whl=3222ba5d678f80a030e6afbcc33dc1ae5cb45facabb61cee2c7016b8432fde48',
            'cryptography-50.0.2-cp311-abi3-win_amd64.whl=7afa5a6602a9f29af1f3a2965f831bae7c9d5d597b7cbb716d41ab3b7d89879c',
            'psutil-7.2.2-cp37-abi3-win_amd64.whl=eb7e81434c8d223ec4a219b5fc1c47d0417b12be7ea866e24fb5ad6e84b3d988',
            'pycparser-3.11-py3-none-any.whl=51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260186c541e1729cd80',
            'pywin32-312-cp314-cp314-win_amd64.whl=a4dd3a848290ef724347b19f301045831d8e802fa4464f491b98b1e0a081432e'
        )
        Require ($meta.wheels -is [Object[]] -and @($meta.wheels).Count -eq 5) 'RUNTIME_WHEEL_PROVENANCE_INVALID'
        Require (@($meta.wheels | Where-Object { -not ($_.name -is [string]) -or -not ($_.sha256 -is [string]) }).Count -eq 0) 'RUNTIME_WHEEL_PROVENANCE_INVALID'
        $actualWheels=@($meta.wheels | ForEach-Object { $_.name + '=' + $_.sha256 } | Sort-Object)
        Require (($actualWheels -join '|') -eq (($expectedWheels | Sort-Object) -join '|')) 'RUNTIME_WHEEL_PROVENANCE_INVALID'
        Require ($meta.files -is [Object[]] -and (Test-JsonInteger $meta.file_count) -and (Test-JsonInteger $meta.total_bytes)) 'RUNTIME_MANIFEST_TYPE_INVALID'
        $files=@($meta.files)
        Require ($files.Count -gt 0 -and $files.Count -lt 4000 -and $entries.Count -eq $files.Count + 1) 'RUNTIME_MANIFEST_COUNT_INVALID'
        $seen=@{}
        $total=0L
        foreach($record in $files) {
            Require ($record.path -is [string] -and (Test-JsonInteger $record.length) -and $record.sha256 -is [string]) 'RUNTIME_RECORD_INVALID'
            $name=$record.path
            $length=[long]$record.length
            $digest=$record.sha256
            Require (Test-SafeRuntimePath $name) 'RUNTIME_PATH_INVALID'
            Require (-not $name.EndsWith('.') -and -not $name.EndsWith(' ') -and -not $name.ToLowerInvariant().EndsWith('.pth')) 'RUNTIME_PATH_INVALID'
            Require ($name -ne 'RUNTIME_MANIFEST.json') 'RUNTIME_MANIFEST_MEMBERSHIP_INVALID'
            Require (-not $seen.ContainsKey($name) -and $byName.ContainsKey($name)) 'RUNTIME_MANIFEST_MEMBERSHIP_INVALID'
            Require ($length -ge 0 -and $length -le 33554432 -and $digest -match '^[0-9a-f]{64}$') 'RUNTIME_RECORD_INVALID'
            $entry=$byName[$name]
            Require ([long]$entry.Length -eq $length) 'RUNTIME_MEMBER_LENGTH_INVALID'
            $fileType=(([int64]$entry.ExternalAttributes -shr 16) -band 0xF000)
            Require ($fileType -eq 0 -or $fileType -eq 0x8000) 'RUNTIME_MEMBER_TYPE_INVALID'
            $stream=$entry.Open()
            try { $actualDigest=Get-StreamSha256Hex $stream }
            finally { $stream.Dispose() }
            Require ($actualDigest -eq $digest) 'RUNTIME_MEMBER_HASH_INVALID'
            $total += $length
            Require ($total -le 188743680) 'RUNTIME_EXPANDED_SIZE_INVALID'
            $seen[$name]=$true
        }
        foreach($entryName in $byName.Keys) {
            if($entryName -ne 'RUNTIME_MANIFEST.json') { Require ($seen.ContainsKey($entryName)) 'RUNTIME_MANIFEST_MEMBERSHIP_INVALID' }
        }
        foreach($requiredName in @('python.exe','python314.dll','python3.dll','vcruntime140.dll','Lib/encodings/__init__.py','DLLs/_ctypes.pyd')) {
            Require ($seen.ContainsKey($requiredName)) 'RUNTIME_REQUIRED_FILE_MISSING'
        }
        Require ($total -eq [long]$meta.total_bytes -and $files.Count -eq [int]$meta.file_count) 'RUNTIME_MANIFEST_TOTAL_INVALID'
        return [pscustomobject]@{Payload=$payload;Manifest=$meta}
    } finally {
        $archive.Dispose()
        $memory.Dispose()
    }
}

function Expand-PinnedRuntimePackage($Package,[string]$Destination) {
    $destinationFull=[IO.Path]::GetFullPath($Destination)
    $approvedDestination=[IO.Path]::GetFullPath((Join-Path $NewRoot 'runtime'))
    Require ($destinationFull -eq $approvedDestination -and -not (Test-Path -LiteralPath $destinationFull)) 'RUNTIME_DESTINATION_INVALID'
    $prefix=$destinationFull.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $memory=[IO.MemoryStream]::new([byte[]]$Package.Payload,$false)
    $archive=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Read,$false)
    $made=$false
    try {
        New-Item -ItemType Directory -Path $destinationFull -ErrorAction Stop | Out-Null
        $made=$true
        foreach($record in @($Package.Manifest.files)) {
            $name=[string]$record.path
            $target=[IO.Path]::GetFullPath((Join-Path $destinationFull ($name -replace '/','\')))
            Require ($target.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) 'RUNTIME_EXTRACTION_ESCAPE'
            $parent=Split-Path -Parent $target
            if(-not (Test-Path -LiteralPath $parent)){ New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
            $entry=$archive.GetEntry($name)
            Require ($null -ne $entry) 'RUNTIME_EXTRACTION_MEMBER_MISSING'
            $input=$entry.Open()
            try {
                $output=[IO.FileStream]::new($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                try {
                    $buffer=New-Object byte[] 1048576
                    $written=0L
                    while(($read=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
                        $written += $read
                        Require ($written -le [long]$record.length) 'RUNTIME_EXTRACTION_LENGTH_INVALID'
                        $output.Write($buffer,0,$read)
                    }
                    $output.Flush($true)
                } finally { $output.Dispose() }
            } finally { $input.Dispose() }
            Require ($written -eq [long]$record.length) 'RUNTIME_EXTRACTION_LENGTH_INVALID'
            $writtenStream=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try { $writtenDigest=Get-StreamSha256Hex $writtenStream }
            finally { $writtenStream.Dispose() }
            Require ($writtenDigest -eq [string]$record.sha256) 'RUNTIME_POST_WRITE_HASH_INVALID'
        }
    } catch {
        if($made -and $destinationFull -eq $approvedDestination){ Remove-Item -LiteralPath $destinationFull -Recurse -Force -ErrorAction SilentlyContinue }
        throw
    } finally {
        $archive.Dispose()
        $memory.Dispose()
    }
}

function Inspect-ProtectedPathNative([string]$Path) {
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    Require (@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') -contains $owner) 'ACL_OWNER_NOT_PRIVILEGED'
    $privileged=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writeMask=0x00000002 -bor 0x00000004 -bor 0x00000010 -bor 0x00000040 -bor 0x00000100 -bor 0x00010000 -bor 0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000
    $rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    foreach($rule in $rules) {
        $sid=$rule.IdentityReference.Value
        if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $privileged -notcontains $sid) {
            Require (([int64]$rule.FileSystemRights -band $writeMask) -eq 0) 'ACL_BROAD_WRITE_OR_CONTROL'
        }
    }
}

function Verify-ExtractedRuntime($Package,[string]$Destination) {
    $destinationFull=[IO.Path]::GetFullPath($Destination)
    Require ($destinationFull -eq [IO.Path]::GetFullPath((Join-Path $NewRoot 'runtime'))) 'RUNTIME_DESTINATION_INVALID'
    foreach($record in @($Package.Manifest.files)) {
        $target=[IO.Path]::GetFullPath((Join-Path $destinationFull (([string]$record.path) -replace '/','\')))
        Require (Test-Path -LiteralPath $target -PathType Leaf) 'RUNTIME_POST_WRITE_FILE_MISSING'
        $stream=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try { $digest=Get-StreamSha256Hex $stream }
        finally { $stream.Dispose() }
        Require ($digest -eq [string]$record.sha256) 'RUNTIME_POST_WRITE_HASH_INVALID'
    }
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
    & $Python -I $AclVerifier $Path | Out-Host
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
    Run-Checked $newPython @('-I',$newBootstrap,'--authorize-probe')
}

function Assert-AgentPreStartGates() {
    Run-Checked $newPython @('-I',$newBootstrap,'--pre-start-check')
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

function Get-PathIdentityEvidence([string]$Path) {
    $raw=[string]$Path
    $full=$null
    try { if($raw){ $full=[IO.Path]::GetFullPath($raw) } } catch {}
    $pathHash=$null
    if($full) {
        $pathSha=[Security.Cryptography.SHA256]::Create()
        try {
            $pathBytes=[Text.Encoding]::UTF8.GetBytes($full.ToUpperInvariant())
            $pathHash=([BitConverter]::ToString($pathSha.ComputeHash($pathBytes))).Replace('-','').ToLowerInvariant()
        } finally { $pathSha.Dispose() }
    }
    $exists=[bool]($raw -and (Test-Path -LiteralPath $raw -PathType Leaf))
    $hash=$null
    $attributes=$null
    $length=$null
    if($exists) {
        try {
            $item=Get-Item -LiteralPath $raw -Force -ErrorAction Stop
            $attributes=[string]$item.Attributes
            $sha=[Security.Cryptography.SHA256]::Create()
            try {
                $stream=[IO.File]::Open($raw,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                try {
                    $length=[long]$stream.Length
                    $limit=134217728L
                    if($length -gt $limit) { $hash='FILE_TOO_LARGE' }
                    else {
                        $buffer=New-Object byte[] 65536
                        $total=0L
                        while($true) {
                            $remaining=($limit + 1L) - $total
                            $read=$stream.Read($buffer,0,[int][Math]::Min([long]$buffer.Length,$remaining))
                            if($read -eq 0) {
                                [void]$sha.TransformFinalBlock($buffer,0,0)
                                $hash=([BitConverter]::ToString($sha.Hash)).Replace('-','').ToLowerInvariant()
                                break
                            }
                            $total += $read
                            if($total -gt $limit) { $hash='FILE_TOO_LARGE'; break }
                            [void]$sha.TransformBlock($buffer,0,$read,$null,0)
                        }
                    }
                } finally { $stream.Dispose() }
            } finally { $sha.Dispose() }
        } catch { $hash='READ_FAILED' }
    }
    return [ordered]@{basename=if($full){[IO.Path]::GetFileName($full)}else{$null};path_sha256=$pathHash;length_chars=$raw.Length;rooted=[IO.Path]::IsPathRooted($raw);exists=$exists;file_length=$length;sha256=$hash;attributes=$attributes}
}

function Write-AgentIdentityEvidence($Process,[string]$ExpectedPath,[datetime]$StartedUtc,[string]$Reason) {
    try {
        $parent=$null
        if($null -ne $Process -and [int]$Process.ParentProcessId -gt 0) {
            $parent=Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$Process.ParentProcessId) -ErrorAction SilentlyContinue
        }
        $created=$null
        if($null -ne $Process -and $null -ne $Process.CreationDate){ $created=([datetime]$Process.CreationDate).ToUniversalTime().ToString('o') }
        $evidence=[ordered]@{
            schema='cyberdefender.agent-identity-evidence.v1'
            reason=$Reason
            captured_at=(Get-Date).ToUniversalTime().ToString('o')
            start_utc=$StartedUtc.ToUniversalTime().ToString('o')
            process_id=if($null -ne $Process){[int]$Process.ProcessId}else{$null}
            creation_utc=$created
            expected=(Get-PathIdentityEvidence $ExpectedPath)
            observed=(Get-PathIdentityEvidence $(if($null -ne $Process){[string]$Process.ExecutablePath}else{''}))
            parent=[ordered]@{pid=if($null -ne $Process){[int]$Process.ParentProcessId}else{$null};name=if($null -ne $parent){[string]$parent.Name}else{$null}}
            command_matches_release=$null
        }
        $json=$evidence | ConvertTo-Json -Depth 6 -Compress
        $path=Join-Path $IdentityEvidenceDirectory ('cyberdefender_agent_identity_' + $Revision + '_' + [Guid]::NewGuid().ToString('N') + '.json')
        $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($json)
        $stream=New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        $script:IdentityEvidencePath=$path
        Write-Host ('AGENT_IDENTITY_EVIDENCE_WRITTEN:' + $path)
    } catch {
        Write-Host 'AGENT_IDENTITY_EVIDENCE_WRITE_FAILED'
    }
}

function Verify-AgentProcess([string]$ExpectedBin,[string]$ExpectedReleaseRoot='',[datetime]$StartedUtc=[datetime]::MinValue,[int]$TimeoutMilliseconds=5000,[string]$ExpectedExecutable=$Python) {
    $services=@(Get-CimInstance Win32_Process -Filter "Name='services.exe'" -ErrorAction Stop)
    Require ($services.Count -eq 1) 'SCM_PROCESS_IDENTITY_UNAVAILABLE'
    $servicesPid=[int]$services[0].ProcessId
    $deadline=(Get-Date).ToUniversalTime().AddMilliseconds([Math]::Max(250,$TimeoutMilliseconds))
    $staleObserved=$false
    $lastProcess=$null
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
        $lastProcess=$process
        Require ($null -ne $process.CreationDate) 'AGENT_PROCESS_CREATION_MISSING'
        $createdUtc=([datetime]$process.CreationDate).ToUniversalTime()
        if($StartedUtc -ne [datetime]::MinValue -and $createdUtc -lt $StartedUtc.ToUniversalTime()) {
            $staleObserved=$true
            Start-Sleep -Milliseconds 100
            continue
        }
        if([string]$process.ExecutablePath -ne $ExpectedExecutable) {
            Write-AgentIdentityEvidence $process $ExpectedExecutable $StartedUtc 'EXECUTABLE_MISMATCH'
            throw 'AGENT_PROCESS_EXECUTABLE_UNEXPECTED'
        }
        if([int]$process.ParentProcessId -ne $servicesPid) {
            Write-AgentIdentityEvidence $process $ExpectedExecutable $StartedUtc 'PARENT_MISMATCH'
            throw 'AGENT_PROCESS_PARENT_UNEXPECTED'
        }
        if($ExpectedReleaseRoot) {
            if([string]$process.CommandLine -notlike ('*' + $ExpectedReleaseRoot + '*agent_service_bootstrap.py*')) {
                Write-AgentIdentityEvidence $process $ExpectedExecutable $StartedUtc 'COMMAND_MISMATCH'
                throw 'AGENT_PROCESS_COMMAND_UNEXPECTED'
            }
        }
        return [int]$service.ProcessId
    } while((Get-Date).ToUniversalTime() -lt $deadline)
    if($staleObserved){ Write-AgentIdentityEvidence $lastProcess $ExpectedExecutable $StartedUtc 'STALE_TIMEOUT'; throw 'AGENT_PROCESS_STALE_TIMEOUT' }
    Write-AgentIdentityEvidence $null $ExpectedExecutable $StartedUtc 'MISSING_TIMEOUT'
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
        runtime_zip_sha256=$ApprovedRuntimeZipSHA256.ToLowerInvariant()
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
foreach($required in ($Python,$Manager,$Provenance,$Bootstrap,$Probe,$AclVerifier,$ReleaseZip,$RuntimeZip,$LocalToken)) {
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
Run-Checked $Python @('-I',$Manager,'verify','--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision)
$runtimePackage=Read-PinnedRuntimePackage $RuntimeZip $ApprovedRuntimeZipSHA256
Run-Checked $Python @('-I',$Provenance,'--repo',$SourceRoot,'--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision)
Run-Checked $Python @('-I',$Bootstrap,'--recovery-plan-copy')
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
Run-Checked $Python @('-I',$Manager,'extract','--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision,'--dest',$NewRoot,'--bootstrap',$Bootstrap)
Run-Checked $Python @('-I',$Provenance,'--repo',$SourceRoot,'--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision,'--release-root',$NewRoot)
Inspect-NoReparse $NewRoot
Inspect-ProtectedPath $NewRoot
Run-Checked $Python @('-I',$Probe,$NewRoot,'--runtime')
$newRuntime=Join-Path $NewRoot 'runtime'
Expand-PinnedRuntimePackage $runtimePackage $newRuntime
Inspect-NoReparse $newRuntime
Inspect-ProtectedPathNative $newRuntime
Verify-ExtractedRuntime $runtimePackage $newRuntime
$newPython=Join-Path $newRuntime 'python.exe'
$pythonSignature=Get-AuthenticodeSignature -LiteralPath $newPython
Require ([string]$pythonSignature.Status -eq 'Valid') 'PINNED_RUNTIME_SIGNATURE_INVALID'
Require ([string]$pythonSignature.SignerCertificate.Subject -like '*Python Software Foundation*') 'PINNED_RUNTIME_SIGNER_INVALID'
$newBootstrap=Join-Path $NewRoot 'agent_service_bootstrap.py'
Run-Checked $newPython @('-I',$newBootstrap,'--dependency-probe')
Verify-Others $otherBaseline
Verify-LocalCompanions

$newBin='"' + $newPython + '" -I "' + $newBootstrap + '" --service-run'
$didSwitch=$false
$candidateStarted=$false
try {
    Stop-Agent
    if($AuthorizeRecoveryProbe) { Authorize-AgentProbe }
    Assert-AgentPreStartGates
    $didSwitch=$true
    Set-AgentBinary $newBin
    $startedAt=(Get-Date).ToUniversalTime()
    Start-Agent
    $candidateStarted=$true
    $agentPid=Verify-AgentProcess $newBin $NewRoot $startedAt 5000 $newPython
    $runtimeEvidence=Await-HealthyRuntime $startedAt 240
    Verify-Others $otherBaseline
    Verify-LocalCompanions
    $agentAfter=Capture-Service $AgentName
    Require ($agentAfter.StartMode -eq $agentBaseline.StartMode) 'AGENT_STARTMODE_CHANGED'
    Require ($agentAfter.StartName -eq $agentBaseline.StartName) 'AGENT_IDENTITY_CHANGED'
    Require ($agentAfter.Recovery -eq $agentBaseline.Recovery) 'AGENT_RECOVERY_CHANGED'
    $receipt=Write-Receipt $agentBaseline $otherBaseline $runtimeEvidence $agentPid $newBin
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
