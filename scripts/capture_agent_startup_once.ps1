param(
  [Parameter(Mandatory=$true)][string]$SourceZip,
  [Parameter(Mandatory=$true)][string]$SourceSHA256,
  [Parameter(Mandatory=$true)][string]$Commit,
  [Parameter(Mandatory=$true)][string]$RuntimeZip,
  [Parameter(Mandatory=$true)][string]$RuntimeSHA256,
  [Parameter(Mandatory=$true)][string]$LauncherSHA256,
  [Parameter(Mandatory=$true)][string]$HarnessWorker,
  [Parameter(Mandatory=$true)][string]$HarnessWorkerSHA256,
  [Parameter(Mandatory=$true)][string]$CloneWorker,
  [Parameter(Mandatory=$true)][string]$CloneWorkerSHA256,
  [int]$StageTimeoutSeconds=90,
  [switch]$Worker,
  [switch]$CoreWorker,
  [string]$WorkRoot
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Require([bool]$Condition,[string]$Code){if(-not $Condition){throw $Code}}
function File-SHA([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
function Restrict-Path([string]$Path,[bool]$Directory){
  $args=@($Path,'/inheritance:r','/grant:r','*S-1-5-18:F','*S-1-5-32-544:F','/C')
  if($Directory){$args=@($Path,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','/T','/C')}
  & icacls.exe @args | Out-Null; Require ($LASTEXITCODE -eq 0) 'CAPTURE_ACL_FAILED'
}
function Stage-Code-Valid([string]$Code){
  return $Code -match '^(worker_started|key_ready|clone_begin|clone_item:[0-9]+:[a-z0-9_]+:[0-9]+|clone_done|clone_ready|runtime_imported|gate_result|acl_cleanup|STAGE_TIMEOUT:[a-z0-9_]+|worker_finished:[A-Z0-9_]+)$'
}
function Write-CaptureStage([string]$Path,[string]$Code){
  Require (Stage-Code-Valid $Code) 'CAPTURE_STAGE_CODE_REJECTED'
  $line=(Get-Date).ToUniversalTime().ToString('o')+'|'+$Code+"`n"
  $bytes=[Text.Encoding]::ASCII.GetBytes($line)
  $stream=[IO.File]::Open($Path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Read-CaptureStages([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){return @()}
  $file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  Require ($file.Length -le 8192) 'CAPTURE_STAGE_FILE_OVERSIZED'
  $rows=@();$lines=@(Get-Content -LiteralPath $Path -Encoding Ascii -ErrorAction Stop | ForEach-Object {[string]$_})
  Require ($lines.Count -le 64) 'CAPTURE_STAGE_COUNT_EXCEEDED'
  foreach($line in $lines){
    $parts=$line.Split(@('|'),2);Require ($parts.Count -eq 2) 'CAPTURE_STAGE_FILE_INVALID'
    $stamp=[DateTimeOffset]::MinValue;Require ([DateTimeOffset]::TryParse($parts[0],[ref]$stamp)) 'CAPTURE_STAGE_FILE_INVALID';Require (Stage-Code-Valid $parts[1]) 'CAPTURE_STAGE_FILE_INVALID'
    $rows+=[pscustomobject]@{utc=[string]$stamp.UtcDateTime.ToString('o');code=[string]$parts[1]}
  }
  return $rows
}
function New-ClosedSummary([string]$RunRoot,[object[]]$Stages,[string]$TaskResult){
  $codes=@($Stages|ForEach-Object{[string]$_.code});$times=@($Stages|ForEach-Object{[string]$_.utc});$seconds=@()
  if($Stages.Count -gt 0){$zero=[DateTimeOffset]::Parse($Stages[0].utc);foreach($row in $Stages){$seconds+=([string][math]::Round(([DateTimeOffset]::Parse($row.utc)-$zero).TotalSeconds,3))}}
  $cloneResult=Join-Path $RunRoot 'evidence\clone-result.json';$files='0';$mb='0';$top=@()
  if(Test-Path -LiteralPath $cloneResult -PathType Leaf){
    $cloneJson=[string](Get-Content -LiteralPath $cloneResult -Raw -Encoding Ascii);Require ([Text.Encoding]::UTF8.GetByteCount($cloneJson) -le 16384) 'CAPTURE_CLONE_RESULT_OVERSIZED';$cloneData=$cloneJson|ConvertFrom-Json
    $files=[string]$cloneData.files;$mb=[string][math]::Round(([double]$cloneData.bytes/1MB),3)
    $top=@($cloneData.items|Sort-Object {[int64]$_.bytes} -Descending|Select-Object -First 5|ForEach-Object{[pscustomobject]@{name=[string]$_.relative_name;mb=[string][math]::Round(([double]$_.bytes/1MB),3)}})
  }
  $terminal='NONE';foreach($code in $codes){if($code -match '^worker_finished:'){$terminal=$code.Substring(16)};if($code -match '^STAGE_TIMEOUT:'){$terminal=$code}}
  $svc=Get-CimInstance Win32_Service -Filter "Name='CyberDefenderAgent'" -ErrorAction Stop;$tasks=@(Get-ScheduledTask -TaskName 'CyberDefenderStartupCapture-*' -ErrorAction SilentlyContinue).Count
  $summary=[ordered]@{run=[string](Split-Path $RunRoot -Leaf);last_stage=[string]$(if($codes.Count){$codes[-1]}else{'NONE'});stage_utc=@($times);stage_seconds=@($seconds);terminal_code=[string]$terminal;task_last_result=[string]$TaskResult;clone_files=[string]$files;clone_mb=[string]$mb;top_files=@($top);clone_exists=[string](Test-Path -LiteralPath (Join-Path $RunRoot 'clone'));tasks=[string]$tasks;agent_state=[string]$svc.State}
  $raw=$summary|ConvertTo-Json -Compress -Depth 4;Require ([Text.Encoding]::UTF8.GetByteCount($raw) -le 4096) 'CAPTURE_SUMMARY_BOUND_EXCEEDED';return $raw
}

$source=[IO.Path]::GetFullPath($SourceZip);$runtime=[IO.Path]::GetFullPath($RuntimeZip);$launcher=[IO.Path]::GetFullPath($MyInvocation.MyCommand.Path);$harness=[IO.Path]::GetFullPath($HarnessWorker);$cloneHelper=[IO.Path]::GetFullPath($CloneWorker)
Require ((File-SHA $source) -eq $SourceSHA256.ToLowerInvariant()) 'CAPTURE_SOURCE_HASH_MISMATCH';Require ((File-SHA $runtime) -eq $RuntimeSHA256.ToLowerInvariant()) 'CAPTURE_RUNTIME_HASH_MISMATCH';Require ((File-SHA $launcher) -eq $LauncherSHA256.ToLowerInvariant()) 'CAPTURE_LAUNCHER_HASH_MISMATCH';Require ((File-SHA $harness) -eq $HarnessWorkerSHA256.ToLowerInvariant()) 'CAPTURE_HARNESS_WORKER_HASH_MISMATCH';Require ((File-SHA $cloneHelper) -eq $CloneWorkerSHA256.ToLowerInvariant()) 'CAPTURE_CLONE_WORKER_HASH_MISMATCH';Require ($StageTimeoutSeconds -ge 15 -and $StageTimeoutSeconds -le 120) 'CAPTURE_STAGE_TIMEOUT_REJECTED'

if(-not $Worker){
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($identity);Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'CAPTURE_ADMIN_REQUIRED'
  $runRoot=Join-Path $env:WINDIR ('Temp\CyberDefenderStartupCapture-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $runRoot|Out-Null;Restrict-Path $runRoot $true
  $task='CyberDefenderStartupCapture-'+[guid]::NewGuid().ToString('N');$stageFile=Join-Path $runRoot 'worker-stages.log';$taskResultFile=Join-Path $runRoot 'capture-task-result.json'
  $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$launcher,'-SourceZip',$source,'-SourceSHA256',$SourceSHA256,'-Commit',$Commit,'-RuntimeZip',$runtime,'-RuntimeSHA256',$RuntimeSHA256,'-LauncherSHA256',$LauncherSHA256,'-HarnessWorker',$harness,'-HarnessWorkerSHA256',$HarnessWorkerSHA256,'-CloneWorker',$cloneHelper,'-CloneWorkerSHA256',$CloneWorkerSHA256,'-StageTimeoutSeconds',[string]$StageTimeoutSeconds,'-Worker','-WorkRoot',$runRoot)
  $dq=[char]34;$quoted=($arguments|ForEach-Object{if($_ -match '[\s"]'){($dq+($_ -replace '"','\"')+$dq)}else{$_}})-join ' '
  $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $quoted;$principalSpec=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  $state='Ready';$taskInfo=$null;$observedStart=$false;$timedOut=$false;$preStopStages=@();$registered=$false
  try{
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principalSpec -Settings $settings|Out-Null;$registered=$true;$startedAt=Get-Date;Start-ScheduledTask -TaskName $task;$deadline=(Get-Date).AddMinutes(4)
    do{Start-Sleep -Milliseconds 250;$state=(Get-ScheduledTask -TaskName $task -ErrorAction Stop).State;$taskInfo=Get-ScheduledTaskInfo -TaskName $task -ErrorAction Stop;if($state -eq 'Running' -or $taskInfo.LastRunTime -ge $startedAt.AddSeconds(-1)){$observedStart=$true};if($observedStart -and $state -ne 'Running'){break}}while((Get-Date) -lt $deadline)
    if($state -eq 'Running'){$preStopStages=@(Read-CaptureStages $stageFile);$timedOut=$true;Stop-ScheduledTask -TaskName $task -ErrorAction Stop;$stopDeadline=(Get-Date).AddSeconds(10);do{Start-Sleep -Milliseconds 250;$state=(Get-ScheduledTask -TaskName $task -ErrorAction Stop).State}while($state -eq 'Running' -and (Get-Date) -lt $stopDeadline);$taskInfo=Get-ScheduledTaskInfo -TaskName $task -ErrorAction Stop}
    $stages=@(Read-CaptureStages $stageFile);if($stages.Count -eq 0){$stages=$preStopStages}
    $detail=[ordered]@{status='CAPTURE_TASK_TERMINAL';last_task_result=[string]$taskInfo.LastTaskResult;observed_start=[string]$observedStart;timed_out=[string]$timedOut;last_stage=[string]$(if($stages.Count){$stages[-1].code}else{'NONE'});utc=(Get-Date).ToUniversalTime().ToString('o')};$detail|ConvertTo-Json -Compress|Set-Content -LiteralPath $taskResultFile -Encoding ascii;Restrict-Path $taskResultFile $false
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop;$registered=$false
    Write-Output (New-ClosedSummary $runRoot $stages ([string]$taskInfo.LastTaskResult));Require $observedStart 'CAPTURE_SYSTEM_TASK_NOT_STARTED';Require ($state -ne 'Running') 'CAPTURE_SYSTEM_TASK_TIMEOUT';Require ([int]$taskInfo.LastTaskResult -eq 0) 'CAPTURE_SYSTEM_TASK_FAILED'
    $sanitized=Join-Path $runRoot 'sanitized.json';Require (Test-Path -LiteralPath $sanitized -PathType Leaf) 'CAPTURE_SANITIZED_RESULT_MISSING';Write-Output ([string](Get-Content -LiteralPath $sanitized -Raw -Encoding Ascii))
  } finally {if($registered){Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue}}
  exit 0
}

Require ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') 'CAPTURE_SYSTEM_REQUIRED';Require ([IO.Path]::GetFullPath($WorkRoot).StartsWith(([IO.Path]::GetFullPath((Join-Path $env:WINDIR 'Temp'))+'\'),[StringComparison]::OrdinalIgnoreCase)) 'CAPTURE_ROOT_REJECTED'
$stageFile=Join-Path $WorkRoot 'worker-stages.log';$clone=Join-Path $WorkRoot 'clone'
if(-not $CoreWorker){
  if(-not (Test-Path -LiteralPath $stageFile)){New-Item -ItemType File -Path $stageFile|Out-Null};Write-CaptureStage $stageFile 'worker_started';Restrict-Path $WorkRoot $true;Restrict-Path $stageFile $false
  $stdout=Join-Path $WorkRoot 'core.stdout';$stderr=Join-Path $WorkRoot 'core.stderr';$args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$launcher,'-SourceZip',$source,'-SourceSHA256',$SourceSHA256,'-Commit',$Commit,'-RuntimeZip',$runtime,'-RuntimeSHA256',$RuntimeSHA256,'-LauncherSHA256',$LauncherSHA256,'-HarnessWorker',$harness,'-HarnessWorkerSHA256',$HarnessWorkerSHA256,'-CloneWorker',$cloneHelper,'-CloneWorkerSHA256',$CloneWorkerSHA256,'-StageTimeoutSeconds',[string]$StageTimeoutSeconds,'-Worker','-CoreWorker','-WorkRoot',$WorkRoot)
  $proc=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $args -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr;$workerTotalBudgetSeconds=210;$started=[DateTimeOffset]::UtcNow;$progressAt=$started;$last='worker_started';$timeout=$null
  while(-not $proc.HasExited){Start-Sleep -Milliseconds 250;$rows=@(Read-CaptureStages $stageFile);if($rows.Count -and $rows[-1].code -ne $last){$last=[string]$rows[-1].code;$progressAt=[DateTimeOffset]::UtcNow};if(([DateTimeOffset]::UtcNow-$progressAt).TotalSeconds -ge $StageTimeoutSeconds){$timeout='STAGE_TIMEOUT:'+$(if($last -match '^clone'){'clone'}elseif($last -match 'runtime|gate'){'runtime'}else{'setup'});break};if(([DateTimeOffset]::UtcNow-$started).TotalSeconds -ge $workerTotalBudgetSeconds){$timeout='STAGE_TIMEOUT:worker_total';break}}
  if($timeout){Write-CaptureStage $stageFile $timeout;& taskkill.exe /PID $proc.Id /T /F|Out-Null;$proc.WaitForExit()}else{$proc.WaitForExit()}
  $codes=@(Read-CaptureStages $stageFile|ForEach-Object{$_.code});if(-not ($codes -contains 'acl_cleanup')){if(Test-Path -LiteralPath $clone){Remove-Item -LiteralPath $clone -Recurse -Force};Write-CaptureStage $stageFile 'acl_cleanup'};if(-not ($codes|Where-Object{$_ -match '^worker_finished:'})){Write-CaptureStage $stageFile ('worker_finished:'+$(if($timeout){'STAGE_TIMEOUT'}elseif($proc.ExitCode -eq 0){'PASS'}else{'WORKER_FAILED'}))};if($timeout){exit 2};exit $proc.ExitCode
}

$candidate=Join-Path $WorkRoot 'candidate';$evidence=Join-Path $WorkRoot 'evidence';$liveState=Join-Path $env:ProgramData 'CyberDefender\state';$liveKey=Join-Path $env:ProgramData 'CyberDefender\secrets\storage_key.b64';$workerCode='WORKER_FAILED';$candidateExit=$null;$fixedError=$null
try{
  New-Item -ItemType Directory -Path $candidate,$clone,$evidence -Force|Out-Null;Restrict-Path $WorkRoot $true;Restrict-Path $stageFile $false;Require (Test-Path -LiteralPath $liveState -PathType Container) 'CAPTURE_LIVE_STATE_MISSING';Require (Test-Path -LiteralPath $liveKey -PathType Leaf) 'CAPTURE_LIVE_KEY_MISSING';Write-CaptureStage $stageFile 'key_ready';Write-CaptureStage $stageFile 'clone_begin'
  Expand-Archive -LiteralPath $source -DestinationPath $candidate -Force;$manifestPath=Join-Path $candidate 'PINNED_MANIFEST.json';Require (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'CAPTURE_SOURCE_MANIFEST_MISSING';$manifest=([string](Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8))|ConvertFrom-Json;Require ($manifest.schema -eq 'cyberdefender.pinned-review-source.v1') 'CAPTURE_SOURCE_MANIFEST_SCHEMA';Require ($manifest.commit -eq $Commit.ToLowerInvariant()) 'CAPTURE_SOURCE_COMMIT_MISMATCH';Expand-Archive -LiteralPath $runtime -DestinationPath (Join-Path $candidate 'runtime') -Force
  $python=Join-Path $candidate 'runtime\python.exe';$cloneResult=Join-Path $evidence 'clone-result.json';& $python -I $cloneHelper --live-state $liveState --live-key $liveKey --clone-root $clone --stage-file $stageFile --result $cloneResult --stage-timeout $StageTimeoutSeconds
  if($LASTEXITCODE -ne 0){$cloneFailure=([string](Get-Content -LiteralPath $cloneResult -Raw -Encoding Ascii)|ConvertFrom-Json).code;if($cloneFailure -match '^CLONE_TOO_LARGE'){$workerCode='CLONE_TOO_LARGE'}elseif($cloneFailure -match '^CLONE_FILE_LOCKED'){$workerCode='CLONE_FILE_LOCKED'}else{$workerCode='CLONE_FAILED'};throw $workerCode}
  $cloneData=([string](Get-Content -LiteralPath $cloneResult -Raw -Encoding Ascii))|ConvertFrom-Json;Require ($cloneData.status -eq 'CLONE_PASS' -and $cloneData.live_hashes_match) 'CAPTURE_CLONE_INVALID';Restrict-Path $clone $true;Write-CaptureStage $stageFile 'clone_ready';[void]@(Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction Stop)
  $env:CYBERDEFENDER_STATE_DIR=Join-Path $clone 'state';$env:CYBERDEFENDER_STORAGE_KEY_B64=([string](Get-Content -LiteralPath (Join-Path $clone 'secrets\storage_key.b64') -Raw -Encoding Ascii)).Trim();$env:CYBERDEFENDER_ENDPOINT_ID='startup-capture-isolated';$env:CYBERDEFENDER_DISTRIBUTION_URL='';Remove-Item Env:CYBERDEFENDER_FLEET_TOKEN_FILE -ErrorAction SilentlyContinue
  $result=Join-Path $evidence 'candidate.json';$trace=Join-Path $evidence 'traceback.txt';& $python -I $harness --source-root $candidate --result $result --trace $trace --stage-file $stageFile;$candidateExit=$LASTEXITCODE;Require (Test-Path -LiteralPath $result -PathType Leaf) 'CAPTURE_CANDIDATE_RESULT_MISSING'
  $verifyResult=Join-Path $evidence 'live-state-verify.json';& $python -I $cloneHelper --verify-only --expected-result $cloneResult --live-state $liveState --live-key $liveKey --clone-root $clone --stage-file $stageFile --result $verifyResult --stage-timeout $StageTimeoutSeconds;Require ($LASTEXITCODE -eq 0) 'CAPTURE_LIVE_STATE_CHANGED';$verify=([string](Get-Content -LiteralPath $verifyResult -Raw -Encoding Ascii))|ConvertFrom-Json;Require ($verify.status -eq 'VERIFY_PASS' -and $verify.live_hashes_match) 'CAPTURE_LIVE_STATE_CHANGED';$workerCode=$(if($candidateExit -eq 0){'PASS'}else{'CAPTURED_FAILURE'})
} catch {$fixedError=$workerCode} finally {$env:CYBERDEFENDER_STORAGE_KEY_B64='';if(Test-Path -LiteralPath $clone){Remove-Item -LiteralPath $clone -Recurse -Force};if(-not (Test-Path -LiteralPath $clone)){Write-CaptureStage $stageFile 'acl_cleanup'};Write-CaptureStage $stageFile ('worker_finished:'+$workerCode)}
Require (-not (Test-Path -LiteralPath $clone)) 'CAPTURE_CLONE_DELETE_FAILED';if($fixedError){throw $fixedError}
$candidateResult=([string](Get-Content -LiteralPath $result -Raw -Encoding Ascii))|ConvertFrom-Json;$summary=[ordered]@{status=[string]$candidateResult.status;exception_class=[string]$candidateResult.exception_class;stage=[string]$candidateResult.stage;gate_code=[string]$candidateResult.gate_code;failing_component=[string]$candidateResult.failing_component;runtime_status=[string]$candidateResult.runtime_status;component_failures=[string]$candidateResult.component_failures;candidate_exit=[string]$candidateExit;live_hashes_match='true';clone_exists_after='false';trace_retained_system_only='true'};$raw=$summary|ConvertTo-Json -Compress;Require ([Text.Encoding]::UTF8.GetByteCount($raw) -le 2048) 'CAPTURE_SANITIZED_BOUND_EXCEEDED';$raw|Set-Content -LiteralPath (Join-Path $WorkRoot 'sanitized.json') -Encoding ascii;Restrict-Path $WorkRoot $true;Restrict-Path $stageFile $false;Restrict-Path (Join-Path $WorkRoot 'sanitized.json') $false
