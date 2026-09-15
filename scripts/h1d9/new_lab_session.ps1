param(
 [Parameter(Mandatory=$true)][string]$Archive,[Parameter(Mandatory=$true)][string]$PackageSha256,
 [Parameter(Mandatory=$true)][string]$TargetUuidHash,[Parameter(Mandatory=$true)][string]$Checkpoint,
 [Parameter(Mandatory=$true)][string]$StaffReference,
 [ValidateSet('VM','UNIVERSITY_PHYSICAL_LAB')][string]$EnvironmentType='VM',
 [switch]$StaffPermits,[switch]$RecoveryVerified,[switch]$NoUnrelatedData,[switch]$DependenciesReady,[switch]$NetworkIsolated,[switch]$WarningsReviewed,[switch]$Renew
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'admission.ps1')
. (Join-Path $PSScriptRoot 'lab_preflight.ps1')
$facts=Get-H1D9LabPreflight
if($facts.verdict -eq 'BLOCK' -or $facts.machine_uuid_sha256 -cne $TargetUuidHash){throw 'LAB_TARGET_REJECTED'}
if(-not $StaffPermits -or -not $RecoveryVerified -or -not $NoUnrelatedData -or -not $DependenciesReady -or -not $NetworkIsolated -or -not $WarningsReviewed){throw 'LAB_EXPLICIT_ACKNOWLEDGEMENTS_REQUIRED'}
$package=(Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$manifest=Get-Content -LiteralPath (Join-Path $package 'manifest.json') -Raw|ConvertFrom-Json
$auth=@{schema='cd.h1d9.authorization.v2';guest_uuid_sha256=$TargetUuidHash;package_id=$manifest.package_id;package_sha256=$PackageSha256;
 disposable=$true;isolated_network=$true;rollback_verified=$true;operator_acknowledged=$true;dependencies_ready=$true;
 clean_checkpoint=$Checkpoint;lab_nonce=[guid]::NewGuid().ToString('N');expires_utc=[DateTimeOffset]::UtcNow.AddHours(12).ToString('o');
 environment_type=$EnvironmentType;staff_authorized=$true;staff_reference=$StaffReference;no_unrelated_data=$true;recovery_image_verified=$true;warnings_reviewed=$true}
$context=@{identity_hash=$TargetUuidHash;uuid_valid=($facts.machine_uuid -match '^[0-9A-F-]{36}$');vm_model=$facts.model;admin=$facts.admin;now=[DateTimeOffset]::UtcNow;
 package_root=$package;os_build=$facts.build;os_64bit=[Environment]::Is64BitOperatingSystem;total_ram=$facts.total_ram;free_ram=$facts.free_ram;
 free_disk=(@($facts.disks|Where-Object DeviceID -eq 'C:')[0].FreeSpace)}
Assert-H1D9Identity $context $auth $PackageSha256
$null=Assert-H1D9Package $package $Archive $PackageSha256 $auth
$path='C:\H1D9\authorization.json'
if(Test-Path $path){
 Assert-H1D9NoReparse $path
 if(-not $Renew){throw 'LAB_AUTH_EXISTS; EXPLICIT_RENEW_REQUIRED'}
 $old=Get-Content -Raw $path|ConvertFrom-Json
 if($old.guest_uuid_sha256 -cne $TargetUuidHash -or $old.package_sha256 -cne $PackageSha256){throw 'LAB_RENEW_BINDING_REJECTED'}
 $auth.lab_nonce=$old.lab_nonce
} elseif($Renew){throw 'LAB_RENEW_MISSING_MARKER'}
$auth|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $path -Encoding Ascii
Write-Output 'LAB_SESSION_MARKER_CREATED; run Preflight next. No installation or fault executed.'
