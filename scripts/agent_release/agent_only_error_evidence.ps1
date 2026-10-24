# Shared, side-effect-free diagnostics helpers for the Agent-only deployment wrapper.
# These helpers preserve bounded, sanitized child output without storing secrets.

function Limit-AgentOnlyDiagnosticText {
    param([AllowNull()][string]$Text, [int]$MaximumChars = 65536)
    if ($null -eq $Text) { return '' }
    if ($Text.Length -le $MaximumChars) { return $Text }
    return $Text.Substring(0, $MaximumChars) + "`n[TRUNCATED]"
}

function Sanitize-AgentOnlyDiagnosticText {
    param([AllowNull()][string]$Text, [int]$MaximumChars = 65536)
    $value = Limit-AgentOnlyDiagnosticText -Text $Text -MaximumChars $MaximumChars
    # Keep error codes and paths useful, but never persist credential material.
    $value = $value -replace '(?im)(password|passwd|token|secret|apikey|api_key|authorization|bearer)\s*[:=]\s*[^\r\n\s]+', '$1=<REDACTED>'
    $value = $value -replace '(?im)(endpoint[_-]?id|storage[_-]?key|private[_-]?key)\s*[:=]\s*[^\r\n\s]+', '$1=<REDACTED>'
    return $value
}

function Get-AgentOnlyTextSha256 {
    param([AllowNull()][string]$Text)
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-AgentOnlyDiagnosticCode {
    param([AllowNull()][string]$Text)
    $patterns = @(
        '(?m)(PINNED_[A-Z0-9_]+)',
        '(?m)(AGENT_[A-Z0-9_]+)',
        '(?m)(RUNTIME_[A-Z0-9_]+)',
        '(?m)(ACL_[A-Z0-9_]+)',
        '(?m)(REQUIRED_FILE_MISSING:[^\r\n]+)',
        '(?m)(COMMAND_FAILED\s+exit=\d+)',
        '(?m)([A-Za-z_]+Error)'
    )
    foreach ($pattern in $patterns) {
        $match = [regex]::Match([string]$Text, $pattern)
        if ($match.Success) { return $match.Value.Trim() }
    }
    return $null
}

function New-AgentOnlyEvidenceObject {
    param(
        [Parameter(Mandatory=$true)][string]$Status,
        [Parameter(Mandatory=$true)][string]$Code,
        [Parameter(Mandatory=$true)][int]$ExitCode,
        [Parameter(Mandatory=$true)][bool]$Apply,
        [AllowNull()][Nullable[int]]$ChildExitCode,
        [AllowNull()][string]$ChildStdout,
        [AllowNull()][string]$ChildStderr,
        [Parameter(Mandatory=$true)][hashtable]$Artifacts,
        [AllowNull()][bool]$CompanionsUnchanged,
        [AllowNull()][bool]$SpoolUnchanged
    )
    $combined = ([string]$ChildStdout) + "`n" + ([string]$ChildStderr)
    $safeOut = Sanitize-AgentOnlyDiagnosticText $ChildStdout
    $safeErr = Sanitize-AgentOnlyDiagnosticText $ChildStderr
    return [ordered]@{
        schema = 'cyberdefender.agent-only-deploy-evidence.v2'
        captured_utc = (Get-Date).ToUniversalTime().ToString('o')
        status = $Status
        code = (Sanitize-AgentOnlyDiagnosticText $Code 4096)
        exit_code = $ExitCode
        apply = $Apply
        failure_stage = if ($null -ne $ChildExitCode -and $ChildExitCode -ne 0) { 'child_installer' } else { 'wrapper' }
        child_exit_code = $ChildExitCode
        child_error_code = Get-AgentOnlyDiagnosticCode $combined
        child_stdout = $safeOut
        child_stderr = $safeErr
        child_stdout_sha256 = Get-AgentOnlyTextSha256 $safeOut
        child_stderr_sha256 = Get-AgentOnlyTextSha256 $safeErr
        artifacts = $Artifacts
        companions_unchanged = $CompanionsUnchanged
        spool_unchanged = $SpoolUnchanged
        live_mutation_performed = $false
    }
}
