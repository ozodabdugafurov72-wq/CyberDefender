# CyberDefender Agent-only transactional release installer.
# Plan mode is read-only. -Apply changes only CyberDefenderAgent.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ReleaseZip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedZipSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ApprovedCommit,
    [Parameter(Mandatory=$true)][string]$RuntimeZip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedRuntimeZipSHA256,
    [string]$BaselineReleaseZip='',
    [ValidatePattern('^$|^[a-fA-F0-9]{64}$')][string]$ApprovedBaselineZipSHA256='',
    [ValidatePattern('^$|^[a-fA-F0-9]{40}$')][string]$ApprovedBaselineCommit='',
    [switch]$Apply,
    [ValidateSet('','AGENT_ONLY_AUTHORIZED')][string]$HostAcknowledgement='',
    [switch]$RecoverStoppedAgent,
    [switch]$AuthorizeRecoveryProbe,
    [switch]$AcknowledgeCompanionDegraded
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
$ProductRoot=Join-Path $env:ProgramFiles 'CyberDefender'
$OldApp=Join-Path $ProductRoot 'app'
$LegacyPython=Join-Path $OldApp '.venv\Scripts\python.exe'
$Releases=Join-Path $ProductRoot 'agent-releases'
$NewRoot=Join-Path $Releases $Revision
$PinnedBaselineCommit='c5030219ba3a996013b8ab0dda48f60743e5c665'
$PinnedBaselineSourceSHA256='6240488d506d1fb7ebac264fa0a1dbc7c05e1a74c65d5a2667fc98603af346bf'
$PinnedBaselineRuntimeSHA256='7368ccfc91f605b3f3aa96de804a950d1797699021a5236b66a607e643878bb2'
$PinnedBaselineBootstrapSHA256='acbacc73207152b3c766e03cb52f0ae5496c73c93bff36c47e2a42f17f2e232e'
$PinnedBaselineRoot=Join-Path $Releases $PinnedBaselineCommit
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

function New-ProtectedDirectory([string]$Path) {
    Require (-not (Test-Path -LiteralPath $Path)) 'PROTECTED_DIRECTORY_ALREADY_EXISTS'
    [void](New-Item -ItemType Directory -Path $Path -ErrorAction Stop)
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity=New-Object Security.Principal.SecurityIdentifier($sid)
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    Inspect-NoReparse $Path
}

function Expand-PinnedRuntimePackage($Package,[string]$Destination,[string]$ApprovedDestination) {
    $destinationFull=[IO.Path]::GetFullPath($Destination)
    $approvedDestinationFull=[IO.Path]::GetFullPath($ApprovedDestination)
    Require ($destinationFull -eq $approvedDestinationFull) 'RUNTIME_DESTINATION_INVALID'
    Require (Test-Path -LiteralPath $destinationFull -PathType Container) 'RUNTIME_DESTINATION_INVALID'
    Require (@(Get-ChildItem -LiteralPath $destinationFull -Force).Count -eq 0) 'RUNTIME_DESTINATION_NOT_EMPTY'
    $prefix=$destinationFull.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $memory=[IO.MemoryStream]::new([byte[]]$Package.Payload,$false)
    $archive=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Read,$false)
    try {
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
    # OWNER RIGHTS (S-1-3-4) resolves to the object owner; the owner was
    # already required to be SYSTEM, Administrators, or TrustedInstaller.
    $privileged=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-3-4')
    $writeMask=0x00000002 -bor 0x00000004 -bor 0x00000010 -bor 0x00000040 -bor 0x00000100 -bor 0x00010000 -bor 0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000
    $rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    foreach($rule in $rules) {
        $sid=$rule.IdentityReference.Value
        if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $privileged -notcontains $sid) {
            Require (([int64]$rule.FileSystemRights -band $writeMask) -eq 0) 'ACL_BROAD_WRITE_OR_CONTROL'
        }
    }
}

function Verify-ExtractedRuntime($Package,[string]$Destination,[string]$ApprovedDestination) {
    $destinationFull=[IO.Path]::GetFullPath($Destination)
    Require ($destinationFull -eq [IO.Path]::GetFullPath($ApprovedDestination)) 'RUNTIME_DESTINATION_INVALID'
    $allowed=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach($record in @($Package.Manifest.files)) {
        [void]$allowed.Add(([string]$record.path).Replace('/','\'))
        $target=[IO.Path]::GetFullPath((Join-Path $destinationFull (([string]$record.path) -replace '/','\')))
        Require (Test-Path -LiteralPath $target -PathType Leaf) 'RUNTIME_POST_WRITE_FILE_MISSING'
        Inspect-ProtectedPath $target
        $stream=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try { $digest=Get-StreamSha256Hex $stream }
        finally { $stream.Dispose() }
        Require ($digest -eq [string]$record.sha256) 'RUNTIME_POST_WRITE_HASH_INVALID'
    }
    $prefix=$destinationFull.TrimEnd('\')+'\'
    foreach($file in Get-ChildItem -LiteralPath $destinationFull -Recurse -File -Force) {
        $relative=$file.FullName.Substring($prefix.Length)
        Require ($allowed.Contains($relative)) 'RUNTIME_POST_WRITE_FILE_SET_INVALID'
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

function Get-CompanionDefinition([string]$Name) {
    if($Name -eq 'CyberDefenderControlPlane') {
        return [pscustomobject]@{Port=8785;Uri='http://127.0.0.1:8785/health';Unreachable='COMPANION_CONTROLPLANE_UNREACHABLE'}
    }
    if($Name -eq 'CyberDefenderOwnerUI') {
        return [pscustomobject]@{Port=8775;Uri='http://127.0.0.1:8775/health';Unreachable='COMPANION_OWNERUI_UNREACHABLE'}
    }
    throw 'COMPANION_DEFINITION_MISSING'
}

function Capture-Companion([string]$Name) {
    $service=Capture-Service $Name
    $definition=Get-CompanionDefinition $Name
    $listener=$false
    try {
        $listener=@([Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() |
            Where-Object {$_.Port -eq $definition.Port}).Count -gt 0
    } catch {
        return [pscustomobject]@{
            Name=$service.Name;State=$service.State;ProcessId=$service.ProcessId;PathName=$service.PathName
            StartMode=$service.StartMode;StartName=$service.StartName;Recovery=$service.Recovery
            ListenerPresent=$false;HealthCode='COMPANION_LISTENER_QUERY_FAILED'
        }
    }
    $healthCode=$definition.Unreachable
    if($listener) {
        try {
            $response=Invoke-WebRequest -UseBasicParsing -Uri $definition.Uri -TimeoutSec 5 -ErrorAction Stop
            if($response.StatusCode -eq 200){$healthCode='COMPANION_OK'}
        } catch {
            $healthCode=$definition.Unreachable
        }
    }
    return [pscustomobject]@{
        Name=$service.Name;State=$service.State;ProcessId=$service.ProcessId;PathName=$service.PathName
        StartMode=$service.StartMode;StartName=$service.StartName;Recovery=$service.Recovery
        ListenerPresent=[bool]$listener;HealthCode=$healthCode
    }
}

function Capture-Others() {
    $saved=@{}
    foreach($name in $OtherServices) {
        $saved[$name]=Capture-Companion $name
    }
    return $saved
}

function Assert-CompanionBaseline($Baseline) {
    $degraded=@()
    foreach($name in $OtherServices) {
        $entry=$Baseline[$name]
        if($entry.Name -eq 'CyberDefenderOwnerUI') { continue }
        if($entry.State -ne 'Running' -or -not $entry.ListenerPresent -or $entry.HealthCode -ne 'COMPANION_OK') {
            $code=if($entry.HealthCode -ne 'COMPANION_OK'){$entry.HealthCode}else{'COMPANION_SERVICE_NOT_RUNNING'}
            $degraded+=($name + ':' + $code)
        }
    }
    if($degraded.Count -gt 0 -and -not $AcknowledgeCompanionDegraded.IsPresent) {
        throw ($degraded[0].Split(':',2)[1])
    }
    if($degraded.Count -gt 0) {
        Write-Host ('COMPANION_DEGRADED_ACKNOWLEDGED:' + ($degraded -join ',')) -ForegroundColor Yellow
    }
}

function Verify-Others($Baseline) {
    foreach($name in $OtherServices) {
        $before=$Baseline[$name]
        $after=Capture-Companion $name
        Require ($after.State -eq $before.State) ('COMPANION_STATE_CHANGED:' + $name)
        Require ($after.ProcessId -eq $before.ProcessId) ('COMPANION_PID_CHANGED:' + $name)
        Require ($after.ListenerPresent -eq $before.ListenerPresent) ('COMPANION_LISTENER_CHANGED:' + $name)
        Require ($after.HealthCode -eq $before.HealthCode) ('COMPANION_HEALTH_CHANGED:' + $name)
        Require ($after.PathName -eq $before.PathName) ('OTHER_SERVICE_PATH_CHANGED:' + $name)
        Require ($after.StartMode -eq $before.StartMode) ('OTHER_SERVICE_MODE_CHANGED:' + $name)
        Require ($after.StartName -eq $before.StartName) ('OTHER_SERVICE_IDENTITY_CHANGED:' + $name)
        Require ($after.Recovery -eq $before.Recovery) ('OTHER_SERVICE_RECOVERY_CHANGED:' + $name)
    }
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
    try {
        Inspect-NoReparse $Path
        Inspect-ProtectedPathNative $Path
    } catch {
        $reason=[string]$_.Exception.Message
        if($reason -eq 'ACL_OWNER_NOT_PRIVILEGED' -or
           $reason -eq 'ACL_BROAD_WRITE_OR_CONTROL' -or
           $reason.StartsWith('REPARSE_PATH:')) {
            throw ('ACL_VIOLATION:' + $Path)
        }
        throw 'ACL_GATE_UNAVAILABLE'
    }
}

function Resolve-AgentBaselineIdentity($Service) {
    $legacyBin='"' + $LegacyPython + '" -m agent.windows_service --service-run'
    if([string]$Service.PathName -eq $legacyBin) {
        return [pscustomobject]@{Kind='legacy';Executable=$LegacyPython;ReleaseRoot='';RuntimeRoot=''}
    }
    $runtimeRoot=Join-Path $PinnedBaselineRoot 'runtime'
    $python=Join-Path $runtimeRoot 'python.exe'
    $bootstrap=Join-Path $PinnedBaselineRoot 'agent_service_bootstrap.py'
    $pinnedBin='"' + $python + '" -I "' + $bootstrap + '" --service-run'
    Require ([string]$Service.PathName -eq $pinnedBin) 'AGENT_ORIGINAL_PATH_NOT_RECOGNIZED'
    Require ($ApprovedBaselineCommit.ToLowerInvariant() -eq $PinnedBaselineCommit) 'PINNED_BASELINE_COMMIT_MISMATCH'
    Require ($ApprovedBaselineZipSHA256.ToLowerInvariant() -eq $PinnedBaselineSourceSHA256) 'PINNED_BASELINE_SOURCE_SHA_MISMATCH'
    Require ($ApprovedRuntimeZipSHA256.ToLowerInvariant() -eq $PinnedBaselineRuntimeSHA256) 'PINNED_BASELINE_RUNTIME_SHA_MISMATCH'
    foreach($required in ($BaselineReleaseZip,$PinnedBaselineRoot,$runtimeRoot,$python,$bootstrap,(Join-Path $PinnedBaselineRoot 'source_commit.txt'))) {
        Require (Test-Path -LiteralPath $required) 'PINNED_BASELINE_FILE_MISSING'
        Inspect-NoReparse $required
    }
    foreach($protected in ($PinnedBaselineRoot,$runtimeRoot,$python,$bootstrap)) { Inspect-ProtectedPath $protected }
    Require ((Get-Content -LiteralPath (Join-Path $PinnedBaselineRoot 'source_commit.txt') -Raw -Encoding Ascii).Trim() -eq $PinnedBaselineCommit) 'PINNED_BASELINE_COMMIT_MARKER_MISMATCH'
    Require ((Get-FileHash -LiteralPath $bootstrap -Algorithm SHA256).Hash.ToLowerInvariant() -eq $PinnedBaselineBootstrapSHA256) 'PINNED_BASELINE_BOOTSTRAP_HASH_MISMATCH'
    return [pscustomobject]@{Kind='pinned';Executable=$python;ReleaseRoot=$PinnedBaselineRoot;RuntimeRoot=$runtimeRoot}
}

function Verify-InstalledPinnedBaseline([string]$Package,[string]$Root,[string]$ApprovedSha256) {
    $payload=Read-BoundedFile $Package (160MB)
    Require ((Get-Sha256Hex $payload) -eq $ApprovedSha256.ToLowerInvariant()) 'PINNED_BASELINE_SOURCE_SHA_MISMATCH'
    $memory=[IO.MemoryStream]::new($payload,$false)
    $archive=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Read,$false)
    try {
        $manifestEntry=$archive.GetEntry('PINNED_MANIFEST.json')
        Require ($null -ne $manifestEntry -and $manifestEntry.Length -le 1MB) 'PINNED_BASELINE_MANIFEST_INVALID'
        $reader=[IO.StreamReader]::new($manifestEntry.Open(),[Text.Encoding]::UTF8,$true,4096,$false)
        try { $manifest=$reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop } finally { $reader.Dispose() }
        Require ($manifest.schema -eq 'cyberdefender.pinned-review-source.v1' -and $manifest.commit -eq $PinnedBaselineCommit) 'PINNED_BASELINE_MANIFEST_INVALID'
        $allowed=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach($item in @($manifest.files)) {
            $relative=[string]$item.path; [void]$allowed.Add($relative)
            $target=Join-Path $Root ($relative.Replace('/','\'))
            Require (Test-Path -LiteralPath $target -PathType Leaf) 'PINNED_BASELINE_INSTALLED_FILE_MISSING'
            Inspect-ProtectedPath $target
            Require ((Get-Item -LiteralPath $target).Length -eq [int64]$item.length) 'PINNED_BASELINE_INSTALLED_LENGTH_MISMATCH'
            Require ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -eq [string]$item.sha256) 'PINNED_BASELINE_INSTALLED_HASH_MISMATCH'
        }
        [void]$allowed.Add('agent_service_bootstrap.py'); [void]$allowed.Add('source_commit.txt')
        $prefix=$Root.TrimEnd('\')+'\'; $runtimePrefix=(Join-Path $Root 'runtime').TrimEnd('\')+'\'
        foreach($file in Get-ChildItem -LiteralPath $Root -Recurse -File -Force) {
            if($file.FullName.StartsWith($runtimePrefix,[StringComparison]::OrdinalIgnoreCase)){continue}
            $relative=$file.FullName.Substring($prefix.Length).Replace('\','/')
            Require ($allowed.Contains($relative)) 'PINNED_BASELINE_FILE_SET_MISMATCH'
        }
    } finally { $archive.Dispose(); $memory.Dispose() }
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

function Await-HealthyRuntime([datetime]$AfterUtc,[int]$TimeoutSeconds=1200,[int]$MinimumSnapshotSpacingSeconds=60,[int]$StableSeconds=900) {
    $deadline=(Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
    $observations=@()
    $lastStamp=[datetime]::MinValue
    $initialPid=[int](Service-Info $AgentName).ProcessId
    Require ($initialPid -gt 0) 'AGENT_PID_MISSING'
    while((Get-Date).ToUniversalTime() -lt $deadline) {
        $service=Service-Info $AgentName
        Require ($service.State -eq 'Running') 'AGENT_SERVICE_NOT_RUNNING'
        Require ([int]$service.ProcessId -eq $initialPid) 'AGENT_PID_CHANGED_DURING_STABILITY'
        if(Test-Path -LiteralPath $RuntimeFile -PathType Leaf) {
            $item=Get-Item -LiteralPath $RuntimeFile
            $stamp=$item.LastWriteTimeUtc
            if($stamp -gt $AfterUtc -and $stamp -gt $lastStamp -and (((Get-Date).ToUniversalTime()-$stamp).TotalSeconds -le 30)) {
                $lastStamp=$stamp
                try {
                    $snapshot=Read-RuntimeSnapshot
                    if(Runtime-IsHealthy $snapshot) {
                        if($observations.Count -eq 0 -or ($stamp-$observations[-1].file_timestamp_utc).TotalSeconds -ge $MinimumSnapshotSpacingSeconds) {
                            $observations+=,[pscustomobject]@{
                                observed_at=(Get-Date).ToUniversalTime().ToString('o')
                                file_timestamp=$stamp.ToString('o')
                                file_timestamp_utc=$stamp
                                cycle_count=[int]$snapshot.runtime.cycle_count
                                component_failures=[int]$snapshot.runtime.component_failures
                                events_acked=[int]$snapshot.runtime.events_acked
                                deferred=[int]$snapshot.runtime.events_persisted_deferred
                                resource_state=[string]$snapshot.runtime.resource_snapshot.state
                            }
                            if($observations.Count -ge 3){ break }
                        }
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
    Require (($observations[1].file_timestamp_utc-$observations[0].file_timestamp_utc).TotalSeconds -ge $MinimumSnapshotSpacingSeconds) 'RUNTIME_SNAPSHOT_SPACING_INVALID'
    Require (($observations[2].file_timestamp_utc-$observations[1].file_timestamp_utc).TotalSeconds -ge $MinimumSnapshotSpacingSeconds) 'RUNTIME_SNAPSHOT_SPACING_INVALID'
    $stableDeadline=(Get-Date).ToUniversalTime().AddSeconds($StableSeconds)
    $stableStamp=$observations[-1].file_timestamp_utc
    $stableCycle=[int]$observations[-1].cycle_count
    $stableInitialCycle=$stableCycle
    $stableDeferred=[int]$observations[-1].deferred
    while((Get-Date).ToUniversalTime() -lt $stableDeadline) {
        $service=Service-Info $AgentName
        Require ($service.State -eq 'Running') 'AGENT_SERVICE_NOT_RUNNING'
        Require ([int]$service.ProcessId -eq $initialPid) 'AGENT_PID_CHANGED_DURING_STABILITY'
        $stableItem=Get-Item -LiteralPath $RuntimeFile -ErrorAction Stop
        Require ((((Get-Date).ToUniversalTime()-$stableItem.LastWriteTimeUtc).TotalSeconds -le 30)) 'RUNTIME_SUSTAINED_STATE_STALE'
        $stableSnapshot=Read-RuntimeSnapshot
        Require (Runtime-IsHealthy $stableSnapshot) 'RUNTIME_SUSTAINED_HEALTH_FAILED'
        if($stableItem.LastWriteTimeUtc -gt $stableStamp) {
            Require ([int]$stableSnapshot.runtime.cycle_count -gt $stableCycle) 'RUNTIME_CYCLE_NOT_ADVANCING'
            $stableStamp=$stableItem.LastWriteTimeUtc
            $stableCycle=[int]$stableSnapshot.runtime.cycle_count
        }
        Require ([int]$stableSnapshot.runtime.events_persisted_deferred -le ($stableDeferred + 1)) 'UNACKNOWLEDGED_OUTBOX_GROWTH'
        Start-Sleep -Seconds ([Math]::Min(5,[Math]::Max(1,$StableSeconds)))
    }
    $finalItem=Get-Item -LiteralPath $RuntimeFile
    Require ((((Get-Date).ToUniversalTime()-$finalItem.LastWriteTimeUtc).TotalSeconds -le 30)) 'RUNTIME_SUSTAINED_STATE_STALE'
    $final=Read-RuntimeSnapshot
    Require (Runtime-IsHealthy $final) 'RUNTIME_SUSTAINED_HEALTH_FAILED'
    $last=$observations[-1]
    Require ([int]$final.runtime.cycle_count -gt $stableInitialCycle) 'RUNTIME_CYCLE_NOT_ADVANCING'
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

function Verify-AgentProcess([string]$ExpectedBin,[string]$ExpectedReleaseRoot='',[datetime]$StartedUtc=[datetime]::MinValue,[int]$TimeoutMilliseconds=5000,[string]$ExpectedExecutable='') {
    if(-not $ExpectedExecutable) {
        $ExpectedExecutable=[string](Get-Variable -Name LegacyPython -ValueOnly -ErrorAction SilentlyContinue)
        if(-not $ExpectedExecutable){$ExpectedExecutable=[string](Get-Variable -Name Python -ValueOnly -ErrorAction SilentlyContinue)}
    }
    Require ([bool]$ExpectedExecutable) 'AGENT_EXPECTED_EXECUTABLE_MISSING'
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
        companion_degraded_acknowledged=[bool]($null -ne $AcknowledgeCompanionDegraded -and $AcknowledgeCompanionDegraded.IsPresent)
        companion_baseline=@($OtherServices | ForEach-Object {
            $entry=$Others[$_]
            [ordered]@{service=$_;state=$entry.State;listener_present=$entry.ListenerPresent;health_code=$entry.HealthCode}
        })
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
foreach($required in ($LegacyPython,$Manager,$Provenance,$Bootstrap,$Probe,$ReleaseZip,$RuntimeZip,$LocalToken)) {
    Require (Test-Path -LiteralPath $required -PathType Leaf) ('REQUIRED_FILE_MISSING:' + $required)
    Inspect-NoReparse $required
}
$agentBaseline=Capture-Service $AgentName
$baselineIdentity=Resolve-AgentBaselineIdentity $agentBaseline
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
Assert-CompanionBaseline $otherBaseline
Inspect-NoReparse $ProductRoot
Inspect-NoReparse $Releases
$runtimePackage=Read-PinnedRuntimePackage $RuntimeZip $ApprovedRuntimeZipSHA256
Require-Administrator
$PreflightRoot=Join-Path ([IO.Path]::GetTempPath()) ('CyberDefenderReleasePlan-' + [Guid]::NewGuid().ToString('N'))
$PreflightPython=Join-Path $PreflightRoot 'python.exe'
$planOnly=-not $Apply.IsPresent
try {
    New-ProtectedDirectory $PreflightRoot
    Expand-PinnedRuntimePackage $runtimePackage $PreflightRoot $PreflightRoot
    Verify-ExtractedRuntime $runtimePackage $PreflightRoot $PreflightRoot
    $preflightSignature=Get-AuthenticodeSignature -LiteralPath $PreflightPython
    Require ([string]$preflightSignature.Status -eq 'Valid') 'PINNED_RUNTIME_SIGNATURE_INVALID'
    Require ([string]$preflightSignature.SignerCertificate.Subject -like '*Python Software Foundation*') 'PINNED_RUNTIME_SIGNER_INVALID'
    Inspect-ProtectedPath $ProductRoot
    Inspect-ProtectedPath $LegacyPython
    if(Test-Path -LiteralPath $Releases -PathType Container) { Inspect-ProtectedPath $Releases }
    Inspect-ProtectedPath $PreflightRoot
    Inspect-ProtectedPath $PreflightPython
    if(Test-Path -LiteralPath $OriginFile -PathType Leaf) {
        $url=(Get-Content -LiteralPath $OriginFile -Raw -Encoding Ascii).Trim().TrimEnd('/')
        Require ($url -eq 'https://cyberdefender-staging.up.railway.app' -or $url -eq 'http://127.0.0.1:8785') 'UNAPPROVED_DISTRIBUTION_ORIGIN'
        if($url -ne 'http://127.0.0.1:8785') {
            Require (Test-Path -LiteralPath $RemoteToken -PathType Leaf) 'REMOTE_FLEET_TOKEN_MISSING'
            Inspect-NoReparse $RemoteToken
            Inspect-ProtectedPath (Split-Path $RemoteToken -Parent)
        }
    }
    Run-Checked $PreflightPython @('-I',$Manager,'verify','--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision)
    Run-Checked $PreflightPython @('-I',$Provenance,'--repo',$SourceRoot,'--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision)
    if($baselineIdentity.Kind -eq 'pinned') {
        Run-Checked $PreflightPython @('-I',$Manager,'verify','--zip',$BaselineReleaseZip,'--sha256',$ApprovedBaselineZipSHA256,'--commit',$ApprovedBaselineCommit)
        Run-Checked $PreflightPython @('-I',$Provenance,'--repo',$SourceRoot,'--zip',$BaselineReleaseZip,'--sha256',$ApprovedBaselineZipSHA256,'--commit',$ApprovedBaselineCommit)
        Verify-InstalledPinnedBaseline $BaselineReleaseZip $baselineIdentity.ReleaseRoot $ApprovedBaselineZipSHA256
        Verify-ExtractedRuntime $runtimePackage $baselineIdentity.RuntimeRoot $baselineIdentity.RuntimeRoot
    }
    Run-Checked $PreflightPython @('-I',$Bootstrap,'--recovery-plan-copy')
    Verify-Others $otherBaseline
    Write-Host 'PLAN_PASS: pinned release, Agent baseline and companion snapshots verified.' -ForegroundColor Green
    if($Apply) {
        Require ($HostAcknowledgement -eq 'AGENT_ONLY_AUTHORIZED') 'HOST_ACKNOWLEDGEMENT_REQUIRED'
        Require (-not (Test-Path -LiteralPath $NewRoot)) 'VERSION_ALREADY_STAGED_REFUSE_OVERWRITE'
        New-Item -ItemType Directory -Path $Releases -Force | Out-Null
        Inspect-NoReparse $Releases
        Inspect-ProtectedPath $Releases
        Run-Checked $PreflightPython @('-I',$Manager,'extract','--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision,'--dest',$NewRoot,'--bootstrap',$Bootstrap)
        Run-Checked $PreflightPython @('-I',$Provenance,'--repo',$SourceRoot,'--zip',$ReleaseZip,'--sha256',$ApprovedZipSHA256,'--commit',$Revision,'--release-root',$NewRoot)
        Inspect-NoReparse $NewRoot
        Inspect-ProtectedPath $NewRoot
        $newRuntime=Join-Path $NewRoot 'runtime'
        New-ProtectedDirectory $newRuntime
        Expand-PinnedRuntimePackage $runtimePackage $newRuntime $newRuntime
        Inspect-NoReparse $newRuntime
        Inspect-ProtectedPath $newRuntime
        Verify-ExtractedRuntime $runtimePackage $newRuntime $newRuntime
        $newPython=Join-Path $newRuntime 'python.exe'
        Inspect-ProtectedPath $newPython
        $pythonSignature=Get-AuthenticodeSignature -LiteralPath $newPython
        Require ([string]$pythonSignature.Status -eq 'Valid') 'PINNED_RUNTIME_SIGNATURE_INVALID'
        Require ([string]$pythonSignature.SignerCertificate.Subject -like '*Python Software Foundation*') 'PINNED_RUNTIME_SIGNER_INVALID'
        $newBootstrap=Join-Path $NewRoot 'agent_service_bootstrap.py'
        Run-Checked $newPython @('-I',$newBootstrap,'--dependency-probe')
        Run-Checked $newPython @('-I',$Probe,$NewRoot,'--runtime')
        Verify-Others $otherBaseline
    }
} finally {
    if(Test-Path -LiteralPath $PreflightRoot) { Remove-Item -LiteralPath $PreflightRoot -Recurse -Force -ErrorAction Stop }
    Require (-not (Test-Path -LiteralPath $PreflightRoot)) 'PRECHECK_RUNTIME_CLEANUP_FAILED'
}
if($planOnly) {
    Write-Host 'PLAN_ONLY: no release files or service settings changed.'
    exit 0
}

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
    $runtimeEvidence=Await-HealthyRuntime $startedAt 1200
    Verify-Others $otherBaseline
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
            $rollbackStartedAt=(Get-Date).ToUniversalTime()
            Start-Agent
            [void](Verify-AgentProcess $agentBaseline.PathName $baselineIdentity.ReleaseRoot $rollbackStartedAt 5000 $baselineIdentity.Executable)
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
    try { Verify-Others $otherBaseline } catch { $rollbackFailures+=('companions:' + $_.Exception.Message) }
    if($rollbackFailures.Count -eq 0) {
        Write-Host ('AGENT_RELEASE_FAIL_ROLLBACK_PASS: ' + $failure) -ForegroundColor Yellow
    } else {
        Write-Host ('AGENT_RELEASE_FAIL_ROLLBACK_INCOMPLETE: ' + $failure) -ForegroundColor Red
        Write-Host ('Rollback issues: ' + ($rollbackFailures -join ' | '))
    }
    Write-Host 'Candidate release preserved for forensic review; original app remains intact.'
    exit 1
}
