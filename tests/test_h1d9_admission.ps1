param([string]$FixtureRoot,[string]$Admission)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Import definition-only functions without changing execution policy. No guest phases.
. ([scriptblock]::Create([IO.File]::ReadAllText($Admission)))
$script:passed=0; $script:failed=0
function Case([string]$name,[scriptblock]$body){
    try {& $body; $script:passed++; Write-Output "PASS $name"}
    catch {$script:failed++; Write-Output "FAIL $name : $($_.Exception.Message)"}
}
function Denied([scriptblock]$body,[string]$code){
    $caught=$false
    try {& $body | Out-Null} catch {$caught=$true;if($_.Exception.Message -notlike "*$code*"){throw}}
    if(-not $caught){throw 'EXPECTED_DENIAL_NOT_RAISED'}
}
function Context {
    return @{identity_hash=('a'*64);uuid_valid=$true;vm_model='Microsoft Virtual Machine';admin=$true;
      now=[DateTimeOffset]::UtcNow;package_root='C:\H1D9\package';os_build=26100;os_64bit=$true;
      total_ram=8GB;free_ram=4GB;free_disk=40GB}
}
function Authorization {
    return @{schema='cd.h1d9.authorization.v1';guest_uuid_sha256=('a'*64);package_sha256=('b'*64);
      disposable=$true;isolated_network=$true;rollback_verified=$true;operator_acknowledged=$true;dependencies_ready=$true;
      clean_checkpoint='fixture-C0';lab_nonce=('c'*32);expires_utc=[DateTimeOffset]::UtcNow.AddHours(1).ToString('o')}
}
Case 'valid identity' {Assert-H1D9Identity (Context) (Authorization) ('b'*64)}
Case 'protected host overrides VM claim' {$c=Context;$c.identity_hash='195d1d40f7e40d281fe8d46d33f4c4e13d44490ffa58edc6a1e2d634375b6732';Denied {Assert-H1D9Identity $c (Authorization) ('b'*64)} 'PRODUCTION_HOST_DENIED'}
Case 'invalid UUID' {$c=Context;$c.uuid_valid=$false;Denied {Assert-H1D9Identity $c (Authorization) ('b'*64)} 'IDENTITY_UNAVAILABLE'}
Case 'physical model denied' {$c=Context;$c.vm_model='HP OMEN';Denied {Assert-H1D9Identity $c (Authorization) ('b'*64)} 'VM_NOT_ESTABLISHED'}
Case 'nonadmin denied' {$c=Context;$c.admin=$false;Denied {Assert-H1D9Identity $c (Authorization) ('b'*64)} 'ADMIN_REQUIRED'}
Case 'missing authorization' {Denied {Assert-H1D9Identity (Context) $null ('b'*64)} 'AUTHORIZATION_REQUIRED'}
Case 'wrong guest identity' {$a=Authorization;$a.guest_uuid_sha256=('d'*64);Denied {Assert-H1D9Identity (Context) $a ('b'*64)} 'AUTHORIZATION_MISMATCH'}
Case 'wrong authorization schema' {$a=Authorization;$a.schema='wrong';Denied {Assert-H1D9Identity (Context) $a ('b'*64)} 'AUTHORIZATION_MISMATCH'}
Case 'wrong authorized SHA' {$a=Authorization;$a.package_sha256=('d'*64);Denied {Assert-H1D9Identity (Context) $a ('b'*64)} 'AUTHORIZATION_MISMATCH'}
foreach($key in @('disposable','isolated_network','rollback_verified','operator_acknowledged','dependencies_ready')){
    Case "missing $key acknowledgement" {$a=Authorization;$a[$key]=$false;Denied {Assert-H1D9Identity (Context) $a ('b'*64)} 'ACKNOWLEDGEMENT_REQUIRED'}
}
Case 'string true is not acknowledgement' {$a=Authorization;$a.disposable='true';Denied {Assert-H1D9Identity (Context) $a ('b'*64)} 'ACKNOWLEDGEMENT_REQUIRED'}
Case 'missing checkpoint' {$a=Authorization;$a.clean_checkpoint=' ';Denied {Assert-H1D9Identity (Context) $a ('b'*64)} 'CHECKPOINT_OR_LAB_NONCE_REQUIRED'}
Case 'missing nonce' {$a=Authorization;$a.lab_nonce='';Denied {Assert-H1D9Identity (Context) $a ('b'*64)} 'CHECKPOINT_OR_LAB_NONCE_REQUIRED'}
Case 'expired authorization' {$a=Authorization;$a.expires_utc=[DateTimeOffset]::UtcNow.AddHours(-1).ToString('o');Denied {Assert-H1D9Identity (Context) $a ('b'*64)} 'AUTHORIZATION_EXPIRED'}
Case 'unbounded authorization' {$a=Authorization;$a.expires_utc=[DateTimeOffset]::UtcNow.AddDays(2).ToString('o');Denied {Assert-H1D9Identity (Context) $a ('b'*64)} 'AUTHORIZATION_EXPIRED_OR_TOO_LONG'}
Case 'source tree denied' {$c=Context;$c.package_root='C:\Users\HP\Desktop\CyberDefender';Denied {Assert-H1D9Identity $c (Authorization) ('b'*64)} 'TEST_ROOT_INVALID'}
Case 'old OS denied' {$c=Context;$c.os_build=19045;Denied {Assert-H1D9Identity $c (Authorization) ('b'*64)} 'OS_UNSUPPORTED'}
foreach($key in @('total_ram','free_ram','free_disk')){
    Case "insufficient $key" {$c=Context;$c[$key]=0;Denied {Assert-H1D9Identity $c (Authorization) ('b'*64)} 'RESOURCES_INSUFFICIENT'}
}
function UniversityAuthorization {
    $a=Authorization;$a.schema='cd.h1d9.authorization.v2';$a.environment_type='UNIVERSITY_PHYSICAL_LAB'
    $a.staff_authorized=$true;$a.no_unrelated_data=$true;$a.recovery_image_verified=$true;$a.staff_reference='staff-fixture';$a.warnings_reviewed=$true
    return $a
}
Case 'university physical explicit staff receipt' {$c=Context;$c.vm_model='University disposable workstation';Assert-H1D9Identity $c (UniversityAuthorization) ('b'*64)}
Case 'university missing staff denied' {$c=Context;$c.vm_model='University disposable workstation';$a=UniversityAuthorization;$a.staff_authorized=$false;Denied {Assert-H1D9Identity $c $a ('b'*64)} 'VM_NOT_ESTABLISHED'}
Case 'university string staff denied' {$c=Context;$c.vm_model='University disposable workstation';$a=UniversityAuthorization;$a.staff_authorized='true';Denied {Assert-H1D9Identity $c $a ('b'*64)} 'VM_NOT_ESTABLISHED'}
Case 'university wrong environment denied' {$c=Context;$c.vm_model='University disposable workstation';$a=UniversityAuthorization;$a.environment_type='VM';Denied {Assert-H1D9Identity $c $a ('b'*64)} 'VM_NOT_ESTABLISHED'}
Case 'personal Acer overrides staff receipt' {$c=Context;$c.vm_model='Acer laptop';Denied {Assert-H1D9Identity $c (UniversityAuthorization) ('b'*64)} 'PERSONAL_ACER_DENIED'}
Case 'production host overrides staff receipt' {$c=Context;$c.identity_hash='195d1d40f7e40d281fe8d46d33f4c4e13d44490ffa58edc6a1e2d634375b6732';Denied {Assert-H1D9Identity $c (UniversityAuthorization) ('b'*64)} 'PRODUCTION_HOST_DENIED'}
$cases=Get-Content -Raw (Join-Path $FixtureRoot 'cases.json')|ConvertFrom-Json
Case 'runtime projection rejects synthetic secret strings' {
    $r=@{runtime=@{status='H1D9_SYNTHETIC_SECRET'};health=@{process_sensor_authority=@{mode='H1D9_SYNTHETIC_SECRET';authoritative_sensor='H1D9_SYNTHETIC_SECRET';compiled_primary_enabled='H1D9_SYNTHETIC_SECRET'};rust_process_canary=@{status='H1D9_SYNTHETIC_SECRET';authoritative='H1D9_SYNTHETIC_SECRET'}}}
    $out=ConvertTo-H1D9RuntimeEvidence $r | ConvertTo-Json -Depth 6
    if($out -match 'H1D9_SYNTHETIC_SECRET'){throw 'SECRET_EXPOSED'}
}
Case 'missing snapshot is not healthy' {
    $r=ConvertTo-H1D9RuntimeEvidence $null
    if($r.status -ne 'INVALID'){throw 'MISSING_SNAPSHOT_TRUSTED'}
}
foreach($f in $cases){
    Case "package $($f.name)" {
        $root=Join-Path $FixtureRoot ($f.name+'/expanded')
        $archive=Join-Path $FixtureRoot ($f.name+'/package.zip')
        $a=@{package_id=$f.package_id}
        if($f.expected -eq 'PASS'){$null=Assert-H1D9Package $root $archive $f.sha256 $a}
        else {Denied {Assert-H1D9Package $root $archive $f.sha256 $a} $f.expected}
    }
}
Write-Output "RESULT passed=$script:passed failed=$script:failed"
if($script:failed){throw 'H1D9_FIXTURE_TEST_FAILURE'}
