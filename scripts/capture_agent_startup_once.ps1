param(
  [Parameter(Mandatory=$true)][string]$SourceZip,
  [Parameter(Mandatory=$true)][string]$SourceSHA256,
  [Parameter(Mandatory=$true)][string]$Commit,
  [Parameter(Mandatory=$true)][string]$RuntimeZip,
  [Parameter(Mandatory=$true)][string]$RuntimeSHA256,
  [switch]$Worker,
  [string]$WorkRoot
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Require([bool]$Condition,[string]$Code){if(-not $Condition){throw $Code}}
function File-SHA([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
function Tree-Digest([string]$Root,[string[]]$Extra=@()){
  $rows=@()
  if(Test-Path -LiteralPath $Root -PathType Container){
    $base=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    foreach($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Force | Sort-Object FullName){
      $rows+=($file.FullName.Substring($base.Length)+'|'+$file.Length+'|'+(File-SHA $file.FullName))
    }
  }
  foreach($file in $Extra){if(Test-Path -LiteralPath $file -PathType Leaf){$rows+=('EXTRA|'+(Split-Path $file -Leaf)+'|'+(File-SHA $file))}}
  $bytes=[Text.Encoding]::UTF8.GetBytes(($rows -join "`n"))
  $sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
function Restrict-Path([string]$Path,[bool]$Directory){
  $args=@($Path,'/inheritance:r','/grant:r','*S-1-5-18:F','*S-1-5-32-544:F','/C')
  if($Directory){$args=@($Path,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','/T','/C')}
  & icacls.exe @args | Out-Null; Require ($LASTEXITCODE -eq 0) 'CAPTURE_ACL_FAILED'
}

$source=[IO.Path]::GetFullPath($SourceZip);$runtime=[IO.Path]::GetFullPath($RuntimeZip)
Require ((File-SHA $source) -eq $SourceSHA256.ToLowerInvariant()) 'CAPTURE_SOURCE_HASH_MISMATCH'
Require ((File-SHA $runtime) -eq $RuntimeSHA256.ToLowerInvariant()) 'CAPTURE_RUNTIME_HASH_MISMATCH'

if(-not $Worker){
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $principal=New-Object Security.Principal.WindowsPrincipal($identity)
  Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'CAPTURE_ADMIN_REQUIRED'
  $runRoot=Join-Path $env:WINDIR ('Temp\CyberDefenderStartupCapture-'+[guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $runRoot | Out-Null; Restrict-Path $runRoot $true
  $task='CyberDefenderStartupCapture-'+[guid]::NewGuid().ToString('N')
  $script=$MyInvocation.MyCommand.Path
  $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$script,'-SourceZip',$source,'-SourceSHA256',$SourceSHA256,'-Commit',$Commit,'-RuntimeZip',$runtime,'-RuntimeSHA256',$RuntimeSHA256,'-Worker','-WorkRoot',$runRoot)
  $dq=[char]34
  $quoted=($arguments | ForEach-Object {if($_ -match '[\s"]'){($dq+($_ -replace '"','\"')+$dq)}else{$_}}) -join ' '
  $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $quoted
  $principalSpec=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  try{
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principalSpec -Settings $settings | Out-Null
    $startedAt=Get-Date
    Start-ScheduledTask -TaskName $task
    $deadline=(Get-Date).AddMinutes(3)
    $observedStart=$false
    $sanitized=Join-Path $runRoot 'sanitized.json'
    do {
      Start-Sleep -Milliseconds 250
      $state=(Get-ScheduledTask -TaskName $task -ErrorAction Stop).State
      $taskInfo=Get-ScheduledTaskInfo -TaskName $task -ErrorAction Stop
      if($state -eq 'Running' -or $taskInfo.LastRunTime -ge $startedAt.AddSeconds(-1)){$observedStart=$true}
      if($observedStart -and $state -ne 'Running'){
        Require ([int]$taskInfo.LastTaskResult -eq 0) 'CAPTURE_SYSTEM_TASK_FAILED'
        break
      }
    } while((Get-Date) -lt $deadline)
    Require $observedStart 'CAPTURE_SYSTEM_TASK_NOT_STARTED'
    Require ($state -ne 'Running') 'CAPTURE_SYSTEM_TASK_TIMEOUT'
    Require ([int]$taskInfo.LastTaskResult -eq 0) 'CAPTURE_SYSTEM_TASK_FAILED'
    Require (Test-Path -LiteralPath $sanitized -PathType Leaf) 'CAPTURE_SANITIZED_RESULT_MISSING'
    Get-Content -LiteralPath $sanitized -Raw -Encoding UTF8
  } finally {
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
  }
  exit 0
}

Require ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') 'CAPTURE_SYSTEM_REQUIRED'
Require ([IO.Path]::GetFullPath($WorkRoot).StartsWith(([IO.Path]::GetFullPath((Join-Path $env:WINDIR 'Temp'))+'\'),[StringComparison]::OrdinalIgnoreCase)) 'CAPTURE_ROOT_REJECTED'
Restrict-Path $WorkRoot $true
$candidate=Join-Path $WorkRoot 'candidate';$clone=Join-Path $WorkRoot 'clone';$evidence=Join-Path $WorkRoot 'evidence'
New-Item -ItemType Directory -Path $candidate,$clone,$evidence | Out-Null; Restrict-Path $WorkRoot $true
$liveState=Join-Path $env:ProgramData 'CyberDefender\state';$liveKey=Join-Path $env:ProgramData 'CyberDefender\secrets\storage_key.b64'
$before=Tree-Digest $liveState @($liveKey)
$candidateExit=$null
try {
  Expand-Archive -LiteralPath $source -DestinationPath $candidate -Force
  $manifestPath=Join-Path $candidate 'PINNED_MANIFEST.json'
  Require (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'CAPTURE_SOURCE_MANIFEST_MISSING'
  $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
  Require ($manifest.schema -eq 'cyberdefender.pinned-review-source.v1') 'CAPTURE_SOURCE_MANIFEST_SCHEMA'
  Require ($manifest.commit -eq $Commit.ToLowerInvariant()) 'CAPTURE_SOURCE_COMMIT_MISMATCH'
  Expand-Archive -LiteralPath $runtime -DestinationPath (Join-Path $candidate 'runtime') -Force
  Copy-Item -LiteralPath $liveState -Destination (Join-Path $clone 'state') -Recurse -Force
  New-Item -ItemType Directory -Path (Join-Path $clone 'secrets') | Out-Null
  Copy-Item -LiteralPath $liveKey -Destination (Join-Path $clone 'secrets\storage_key.b64') -Force
  Restrict-Path $clone $true
  [void]@(Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction Stop)
  $env:CYBERDEFENDER_STATE_DIR=Join-Path $clone 'state'
  $env:CYBERDEFENDER_STORAGE_KEY_B64=(Get-Content -LiteralPath (Join-Path $clone 'secrets\storage_key.b64') -Raw -Encoding Ascii).Trim()
  $env:CYBERDEFENDER_ENDPOINT_ID='startup-capture-isolated'
  $env:CYBERDEFENDER_DISTRIBUTION_URL=''
  Remove-Item Env:CYBERDEFENDER_FLEET_TOKEN_FILE -ErrorAction SilentlyContinue
  $python=Join-Path $candidate 'runtime\python.exe';$worker=Join-Path $candidate 'scripts\agent_release\startup_capture_once.py'
  $result=Join-Path $evidence 'candidate.json';$trace=Join-Path $evidence 'traceback.txt'
  & $python -I $worker --source-root $candidate --result $result --trace $trace
  $candidateExit=$LASTEXITCODE
  $after=Tree-Digest $liveState @($liveKey)
  Require ($before -eq $after) 'CAPTURE_LIVE_STATE_CHANGED'
} finally {
  $env:CYBERDEFENDER_STORAGE_KEY_B64=''
  if(Test-Path -LiteralPath $clone){Remove-Item -LiteralPath $clone -Recurse -Force}
}
Require (-not (Test-Path -LiteralPath $clone)) 'CAPTURE_CLONE_DELETE_FAILED'
$candidateResult=Get-Content -LiteralPath $result -Raw -Encoding UTF8 | ConvertFrom-Json
$summary=[ordered]@{status=$candidateResult.status;exception_class=$candidateResult.exception_class;stage=$candidateResult.stage;gate_code=$candidateResult.gate_code;failing_component=$candidateResult.failing_component;runtime_status=$candidateResult.runtime_status;component_failures=$candidateResult.component_failures;candidate_exit=$candidateExit;live_hashes_match=$true;clone_exists_after=$false;trace_retained_system_only=$true}
$summary | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $WorkRoot 'sanitized.json') -Encoding utf8
Restrict-Path $WorkRoot $true
