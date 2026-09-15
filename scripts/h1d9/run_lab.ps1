param(
 [ValidateSet('Preflight','ConfirmC0','Install','C1Validate','ConfirmC1','EnableRustCanary','C2Validate','ConfirmC2','Crash','SCMStorm','NativeHang','CleanRestart','Resources','FixtureTests','StoreFault','PrepareReboot','PostReboot','PrepareSleep','PostSleep','PreparePowerLoss','PostPowerLoss','PrepareRollback','PrepareCheckpointRestore','ResumeCheckpoint','RollbackValidate','RecordOperatorCase','Report','Status')][string]$Phase='Status',
 [Parameter(Mandatory=$true)][string]$GuestAuthorization,
 [Parameter(Mandatory=$true)][string]$Archive,
 [Parameter(Mandatory=$true)][string]$PackageSha256,
 [Parameter(Mandatory=$true)][string]$Python,
 [ValidateSet('CyberDefenderAgent','CyberDefenderControlPlane','CyberDefenderOwnerUI')][string]$Service='CyberDefenderAgent',
 [string]$Checkpoint='', [string]$Receipt='',
 [string]$PreservedStateSha256='', [string]$ExportSha256='',
 [ValidateSet('truncate','corrupt','oversized','wrong-schema','wrong-service','delete-slot','delete-anchor')][string]$StoreVariant='truncate',
 [ValidateRange(2,600)][int]$Samples=60
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$gate=Join-Path $PSScriptRoot 'guest.ps1'
$binding=& $gate -Phase Admission -GuestAuthorization $GuestAuthorization -Archive $Archive -PackageSha256 $PackageSha256
if(-not $binding.admitted){throw 'LAB_ADMISSION_REQUIRED'}
$auth=Get-Content -Raw -LiteralPath $GuestAuthorization|ConvertFrom-Json
if($auth.schema -ne 'cd.h1d9.authorization.v2' -or $auth.staff_authorized -ne $true -or $auth.warnings_reviewed -ne $true){throw 'UNIVERSITY_LAB_AUTHORIZATION_REQUIRED'}
if(-not (Test-Path -LiteralPath $Python)){throw 'LAB_PYTHON_REQUIRED'}
& $Python -c 'import sys,struct; assert sys.version_info >= (3,13) and struct.calcsize("P")==8; import psutil,win32api,cryptography'
if($LASTEXITCODE -ne 0){throw 'LAB_DEPENDENCIES_NOT_READY'}
$root=Join-Path 'C:\H1D9\results' $binding.session
. (Join-Path $PSScriptRoot 'admission.ps1')
$ancestor=$root
while(-not (Test-Path -LiteralPath $ancestor)){$ancestor=Split-Path -Parent $ancestor}
Assert-H1D9NoReparse $ancestor
if(-not (Test-Path $root)){
 if($Phase -ne 'Preflight'){throw 'LAB_STATE_MISSING_RESTORE_EVIDENCE_OR_REVIEW'}
 New-Item -ItemType Directory -Path $root | Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $admin=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
 $acl.SetOwner($admin);$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $root -AclObject $acl
}
# Reuse actual protected-path validator, never permissive fixture validation.
& $Python -c 'import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); from agent.service_crash_store import protected_path; protected_path(Path(sys.argv[2]))' (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path $root
if($LASTEXITCODE -ne 0){throw 'LAB_EVIDENCE_ACL_REJECTED'}
$lock=$null
try {
 if(Test-Path (Join-Path $root 'orchestrator.lock')){Assert-H1D9NoReparse (Join-Path $root 'orchestrator.lock')}
 $lock=[IO.File]::Open((Join-Path $root 'orchestrator.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
 $argsList=@((Join-Path $PSScriptRoot 'lab_engine.py'),'--phase',$Phase,'--root',$root,'--authorization',$GuestAuthorization,'--archive',$Archive,'--sha',$PackageSha256,'--service',$Service,'--samples',[string]$Samples,'--variant',$StoreVariant)
 if($Checkpoint){$argsList+=@('--checkpoint',$Checkpoint)}
 if($Receipt){$argsList+=@('--receipt',$Receipt)}
 if($PreservedStateSha256){$argsList+=@('--preserved-state-sha',$PreservedStateSha256)}
 if($ExportSha256){$argsList+=@('--export-sha',$ExportSha256)}
 & $Python @argsList
 if($LASTEXITCODE -ne 0){throw 'LAB_PHASE_NOT_PASSED; SEE_SANITIZED_STATE_AND_REPORT'}
} finally {if($lock){$lock.Dispose()}}
