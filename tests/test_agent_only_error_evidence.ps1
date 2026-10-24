# Windows PowerShell 5.1 regression for bounded/sanitized child diagnostics.
$ErrorActionPreference = 'Stop'
$helper = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\agent_release\agent_only_error_evidence.ps1'
. $helper

# Exercise the same native child-process capture shape used by the wrapper.
$sandbox = Join-Path ([IO.Path]::GetTempPath()) ('agent-only-error-evidence-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $sandbox -Force | Out-Null
$stdoutPath = Join-Path $sandbox 'child.stdout.log'
$stderrPath = Join-Path $sandbox 'child.stderr.log'
$child = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') `
    -ArgumentList @('-NoProfile','-NonInteractive','-Command',"Write-Output 'child-out'; Write-Error 'PINNED_BASELINE_FILE_SET_MISMATCH password=do-not-store token=secret-value'; exit 7") `
    -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
$secretText = [IO.File]::ReadAllText($stderrPath) + ('x' * 70000)
$childOut = [IO.File]::ReadAllText($stdoutPath)
$evidence = New-AgentOnlyEvidenceObject `
    -Status 'FAIL' `
    -Code 'INSTALLER_FAILED:1' `
    -ExitCode 1 `
    -Apply:$false `
    -ChildExitCode 1 `
    -ChildStdout $childOut `
    -ChildStderr $secretText `
    -Artifacts @{commit='test';zip_sha256=('0' * 64);installer_sha256=('1' * 64)} `
    -CompanionsUnchanged:$true `
    -SpoolUnchanged:$true

if ($evidence.failure_stage -ne 'child_installer') { throw 'FAILURE_STAGE_NOT_RECORDED' }
if ($evidence.child_exit_code -ne 1) { throw 'CHILD_EXIT_NOT_RECORDED' }
if ($evidence.child_error_code -ne 'PINNED_BASELINE_FILE_SET_MISMATCH') { throw 'CHILD_ERROR_CODE_NOT_EXTRACTED' }
if ($evidence.child_stderr.Length -gt 65536 + 11) { throw 'DIAGNOSTIC_NOT_BOUNDED' }
if ($evidence.child_stderr -match 'secret-value|do-not-store') { throw 'SECRET_NOT_REDACTED' }
if ($evidence.child_stderr -notmatch '\[TRUNCATED\]') { throw 'TRUNCATION_MARKER_MISSING' }
if ($evidence.live_mutation_performed -ne $false) { throw 'MUTATION_MARKER_WRONG' }
if ($child.ExitCode -ne 7) { throw 'CHILD_EXIT_PROCESS_NOT_CAPTURED' }
if ($evidence.child_stdout -notmatch 'child-out') { throw 'CHILD_STDOUT_NOT_PRESERVED' }
Remove-Item -LiteralPath $sandbox -Recurse -Force -ErrorAction SilentlyContinue
Write-Output 'AGENT_ONLY_ERROR_EVIDENCE_TEST=PASS'
