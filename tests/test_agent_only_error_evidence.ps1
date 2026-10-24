# Windows PowerShell 5.1 regression for bounded/sanitized child diagnostics.
$ErrorActionPreference = 'Stop'
$helper = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\agent_release\agent_only_error_evidence.ps1'
if(-not (Test-Path -LiteralPath $helper -PathType Leaf)) { $helper=Join-Path $PSScriptRoot 'agent_release\agent_only_error_evidence.ps1' }
. $helper

# Exercise the same bounded native child-process capture used by the wrapper.
$sandbox = Join-Path ([IO.Path]::GetTempPath()) ('agent-only-error-evidence-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $sandbox -Force | Out-Null
$child = Invoke-AgentOnlyBoundedChild -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') `
    -ArgumentList @('-NoProfile','-NonInteractive','-Command',"Write-Output 'child-out'; Write-Error ('PINNED_BASELINE_FILE_SET_MISMATCH password=do-not-store token=secret-value C:\\Secret\\token.txt ' + ('x' * 70000)); exit 7") `
    -MaximumChars 1024
$childOut = $child.Stdout
$secretText = $child.Stderr
$evidence = New-AgentOnlyEvidenceObject `
    -Status 'FAIL' `
    -Code 'INSTALLER_FAILED:1' `
    -ExitCode 1 `
    -Apply:$false `
    -ChildExitCode $child.ExitCode `
    -ChildStdout $childOut `
    -ChildStderr $secretText `
    -Artifacts @{commit='test';zip_sha256=('0' * 64);installer_sha256=('1' * 64)} `
    -CompanionsUnchanged:$true `
    -SpoolUnchanged:$true `
    -LiveMutationPerformed:$false

if ($evidence.failure_stage -ne 'child_installer') { throw 'FAILURE_STAGE_NOT_RECORDED' }
if ($evidence.child_exit_code -ne 7) { throw 'CHILD_EXIT_NOT_RECORDED' }
if ($evidence.child_error_code -ne 'PINNED_BASELINE_FILE_SET_MISMATCH') { throw 'CHILD_ERROR_CODE_NOT_EXTRACTED' }
if ($evidence.child_stderr.Length -gt 1024 + 11) { throw 'DIAGNOSTIC_NOT_BOUNDED' }
if ($evidence.child_stderr -match 'secret-value|do-not-store') { throw 'SECRET_NOT_REDACTED' }
if ((Sanitize-AgentOnlyDiagnosticText '"token":"secret-value" {"authorization":"Bearer abc"}') -match 'secret-value|Bearer abc') { throw 'QUOTED_SECRET_NOT_REDACTED' }
if ($evidence.child_stderr -notmatch '\[TRUNCATED\]') { throw 'TRUNCATION_MARKER_MISSING' }
if ($evidence.live_mutation_performed -ne $false) { throw 'MUTATION_MARKER_WRONG' }
$applyEvidence = New-AgentOnlyEvidenceObject -Status 'FAIL' -Code 'X' -ExitCode 1 -Apply:$true -ChildExitCode 1 -ChildStdout '' -ChildStderr '' -Artifacts @{} -LiveMutationPerformed:$true
if ($applyEvidence.live_mutation_performed -ne $true) { throw 'APPLY_MUTATION_MARKER_WRONG' }
if ($evidence.child_stderr -match 'C:\\Secret|C:\\ProgramData|token.txt') { throw 'PATH_NOT_REDACTED' }
if ($evidence.child_error_code -ne 'PINNED_BASELINE_FILE_SET_MISMATCH') { throw 'ERROR_CODE_PATH_LEAKED' }
if ($child.ExitCode -ne 7) { throw 'CHILD_EXIT_PROCESS_NOT_CAPTURED' }
if ($evidence.child_stdout -notmatch 'child-out') { throw 'CHILD_STDOUT_NOT_PRESERVED' }
$before=@{State='Stopped';ProcessId=0;StartMode='Auto';StartName='LocalSystem';PathName='agent.exe';ExitCode=0}
$after=@{State='Stopped';ProcessId=0;StartMode='Auto';StartName='LocalSystem';PathName='agent.exe';ExitCode=0}
if (-not (Assert-AgentOnlySnapshotUnchanged -Before $before -After $after)) { throw 'AGENT_READBACK_NOT_ACCEPTED' }
$after['State']='Running'
try { Assert-AgentOnlySnapshotUnchanged -Before $before -After $after; throw 'AGENT_READBACK_CHANGE_NOT_REJECTED' } catch { if($_.Exception.Message -notlike 'AGENT_CHANGED_DURING_PLAN:*'){ throw } }
Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
Write-Output 'AGENT_ONLY_ERROR_EVIDENCE_TEST=PASS'
