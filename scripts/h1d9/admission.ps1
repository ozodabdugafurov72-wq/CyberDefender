# Definition-only admission functions. No OS mutation and no test bypass.
function ConvertTo-H1D9RuntimeEvidence {
    param($Runtime)
    try {
        $a=$Runtime.health.process_sensor_authority
        $c=$Runtime.health.rust_process_canary
        $status=if($Runtime.runtime.status -cin @('HEALTHY','DEGRADED','UNAVAILABLE','STOPPED','SAFE_MODE')){$Runtime.runtime.status}else{'INVALID'}
        $source=if($a.authoritative_sensor -cin @('ProcessSensor','RustProcessSensor')){$a.authoritative_sensor}else{'NONE_OR_INVALID'}
        $mode=if($a.mode -cin @('PYTHON_ONLY','RUST_CANARY','RUST_SHADOW','RUST_PRIMARY_WITH_FALLBACK')){$a.mode}else{'INVALID'}
        $canaryStatus=if($c.status -cin @('HEALTHY','DEGRADED','UNAVAILABLE','DISABLED','ERROR','CLOSED')){$c.status}else{'INVALID'}
        return @{status=$status;authority=@{mode=$mode;authoritative_sensor=$source;compiled_primary_enabled=if($a.compiled_primary_enabled -is [bool]){$a.compiled_primary_enabled}else{$null}};
          canary=@{status=$canaryStatus;authoritative=if($c.authoritative -is [bool]){$c.authoritative}else{$null}}}
    } catch {return @{status='INVALID';authority=$null;canary=$null}}
}

function Assert-H1D9Identity {
    param($Context,$Authorization,[string]$PackageSha256)
    $protected='195d1d40f7e40d281fe8d46d33f4c4e13d44490ffa58edc6a1e2d634375b6732'
    if($Context.identity_hash -eq $protected){throw 'H1D9_PRODUCTION_HOST_DENIED'}
    if($Context.identity_hash -notmatch '^[a-f0-9]{64}$' -or $Context.uuid_valid -ne $true){throw 'H1D9_IDENTITY_UNAVAILABLE'}
    if($Context.vm_model -match 'Acer'){throw 'H1D9_PERSONAL_ACER_DENIED'}
    if($Context.vm_model -notmatch 'Virtual Machine|VMware|VirtualBox|QEMU|KVM|innotek'){
        if(-not $Authorization -or $Authorization.schema -ne 'cd.h1d9.authorization.v2' -or
           $Authorization.environment_type -ne 'UNIVERSITY_PHYSICAL_LAB' -or
           $Authorization.staff_authorized -isnot [bool] -or $Authorization.staff_authorized -ne $true -or
           $Authorization.no_unrelated_data -isnot [bool] -or $Authorization.no_unrelated_data -ne $true -or
           $Authorization.recovery_image_verified -isnot [bool] -or $Authorization.recovery_image_verified -ne $true -or
           $Authorization.staff_reference -notmatch '^[A-Za-z0-9_.:-]{3,80}$'){
            throw 'H1D9_DISPOSABLE_VM_NOT_ESTABLISHED'
        }
    }
    if($Context.admin -ne $true){throw 'H1D9_GUEST_ADMIN_REQUIRED'}
    if(-not $Authorization){throw 'H1D9_GUEST_AUTHORIZATION_REQUIRED'}
    if($Authorization.schema -notin @('cd.h1d9.authorization.v1','cd.h1d9.authorization.v2') -or
       $Authorization.guest_uuid_sha256 -cne $Context.identity_hash -or
       $Authorization.package_sha256 -cne $PackageSha256 -or
       $PackageSha256 -cnotmatch '^[a-f0-9]{64}$') {throw 'H1D9_GUEST_AUTHORIZATION_MISMATCH'}
    foreach($name in @('disposable','isolated_network','rollback_verified','operator_acknowledged','dependencies_ready')){
        if($Authorization.$name -isnot [bool] -or $Authorization.$name -ne $true){throw 'H1D9_ACKNOWLEDGEMENT_REQUIRED'}
    }
    if([string]::IsNullOrWhiteSpace($Authorization.clean_checkpoint) -or
       $Authorization.clean_checkpoint.Length -gt 200 -or
       $Authorization.lab_nonce -cnotmatch '^[a-f0-9]{32,64}$'){throw 'H1D9_CHECKPOINT_OR_LAB_NONCE_REQUIRED'}
    $expiry=[DateTimeOffset]::Parse($Authorization.expires_utc)
    if($expiry -le $Context.now -or $expiry -gt $Context.now.AddHours(24)){throw 'H1D9_AUTHORIZATION_EXPIRED_OR_TOO_LONG'}
    if($Context.package_root -ine 'C:\H1D9\package'){throw 'H1D9_TEST_ROOT_INVALID'}
    if($Context.os_build -lt 26100 -or $Context.os_64bit -ne $true){throw 'H1D9_GUEST_OS_UNSUPPORTED'}
    if($Context.total_ram -lt 8GB -or $Context.free_ram -lt 3GB -or $Context.free_disk -lt 20GB){throw 'H1D9_GUEST_RESOURCES_INSUFFICIENT'}
}

function Assert-H1D9NoReparse {
    param([string]$Path)
    $part=[IO.Path]::GetFullPath($Path)
    while($part){
        if((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'H1D9_REPARSE_PATH'}
        $part=Split-Path -Parent $part
    }
}

function Assert-H1D9Package {
    param([string]$Root,[string]$Archive,[string]$ExpectedSha256,$Authorization)
    if($ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'H1D9_PACKAGE_SHA_REQUIRED'}
    Assert-H1D9NoReparse $Root
    Assert-H1D9NoReparse $Archive
    if((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256){throw 'H1D9_ARCHIVE_SHA_MISMATCH'}
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip=[IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $entry=$zip.GetEntry('manifest.json')
        if(-not $entry -or $entry.Length -gt 2MB){throw 'H1D9_MANIFEST_INVALID'}
        $reader=New-Object IO.StreamReader($entry.Open())
        try {$raw=$reader.ReadToEnd()} finally {$reader.Dispose()}
        $local=Get-Content -LiteralPath (Join-Path $Root 'manifest.json') -Raw
        if($local -cne $raw){throw 'H1D9_MANIFEST_ARCHIVE_MISMATCH'}
        $metadata=$raw|ConvertFrom-Json
        if($metadata.schema -cne 'cd.h1d9.package.v1' -or $metadata.readiness -cne 'PREPARATION_ONLY' -or
           $metadata.package_id -cnotmatch '^H1D9-[a-f0-9]{24}$' -or
           $Authorization.package_id -cne $metadata.package_id -or
           $metadata.excluded_host_uuid_sha256 -cne '195d1d40f7e40d281fe8d46d33f4c4e13d44490ffa58edc6a1e2d634375b6732'){
            throw 'H1D9_PACKAGE_SCHEMA_OR_BINDING_INVALID'
        }
        if(@($metadata.files).Count -lt 1 -or @($metadata.files).Count -gt 2000){throw 'H1D9_INVENTORY_BOUND'}
        $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach($e in $zip.Entries){if(-not $seen.Add($e.FullName)){throw 'H1D9_DUPLICATE_ARCHIVE_ENTRY'}}
        $paths=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $source=Join-Path $Root 'payload'
        foreach($item in $metadata.files){
            $relative=[string]$item.path
            if($relative -notmatch '^[A-Za-z0-9_./-]+$' -or $relative.StartsWith('/') -or
               @($relative.Split('/')|Where-Object {$_ -in @('','..','.') -or $_.EndsWith('.')}).Count -ne 0 -or
               $item.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $item.bytes -lt 0 -or $item.bytes -gt 64MB -or
               -not $paths.Add($relative)){throw 'H1D9_MANIFEST_PATH_OR_ENTRY_INVALID'}
            $file=Join-Path $source $relative
            Assert-H1D9NoReparse $file
            $inside=$zip.GetEntry('payload/'+$relative)
            if(-not $inside -or $inside.Length -ne $item.bytes -or
               (Get-Item -LiteralPath $file).Length -ne $item.bytes -or
               (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item.sha256){throw 'H1D9_PAYLOAD_HASH_MISMATCH'}
            $stream=$inside.Open(); $sha=[Security.Cryptography.SHA256]::Create()
            try {$compressedHash=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}
            finally {$stream.Dispose();$sha.Dispose()}
            if($compressedHash -cne $item.sha256){throw 'H1D9_ARCHIVED_PAYLOAD_MISMATCH'}
        }
        $required=@('scripts/install_machine.ps1','scripts/service_recovery_policy.ps1','scripts/h1d9/guest.ps1',
          'scripts/h1d9/admission.ps1','agent/windows_service.py','control_plane/windows_service.py',
          'dashboard_owner/windows_service.py','requirements.txt','config/process_sensor_runtime.example.json',
          'native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe')
        foreach($name in $required){if(-not $paths.Contains($name)){throw 'H1D9_REQUIRED_FILE_MISSING'}}
        $actual=@(Get-ChildItem -LiteralPath $source -Recurse -Force -File)
        foreach($dir in Get-ChildItem -LiteralPath $source -Recurse -Force -Directory){Assert-H1D9NoReparse $dir.FullName}
        if($actual.Count -ne $paths.Count -or $zip.Entries.Count -ne ($paths.Count+2)){throw 'H1D9_UNMANIFESTED_FILES'}
        if(-not $seen.Contains('guest-authorization.example.json')){throw 'H1D9_TEMPLATE_MISSING'}
        return $metadata
    } finally {$zip.Dispose()}
}
