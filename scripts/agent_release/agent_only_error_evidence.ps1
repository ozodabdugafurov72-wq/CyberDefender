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
    # Keep error codes useful while redacting credential values and filesystem paths.
    $credentialPattern='(?im)(?<prefix>["'']?(?:password|passwd|token|secret|apikey|api_key|authorization|bearer|endpoint[_-]?id|storage[_-]?key|private[_-]?key)["'']?\s*[:=]\s*)(?:Bearer\s+)?(?:"[^"]*"|''[^'']*''|[^\s,;}]+)'
    $value = [regex]::Replace($value,$credentialPattern,{ param($m) $m.Groups['prefix'].Value + '<REDACTED>' })
    $value = $value -replace '(?i)(?:[A-Z]:\\|\\\\)[^\r\n\"<>|]*', '<PATH_REDACTED>'
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
        '(?m)(REQUIRED_FILE_MISSING)\b',
        '(?m)(COMMAND_FAILED\s+exit=\d+)',
        '(?m)([A-Za-z_]+Error)'
    )
    foreach ($pattern in $patterns) {
        $match = [regex]::Match([string]$Text, $pattern)
        if ($match.Success) { return $match.Value.Trim() }
    }
    return $null
}

function Invoke-AgentOnlyBoundedChild {
    param([Parameter(Mandatory=$true)][string]$FilePath,[Parameter(Mandatory=$true)][string[]]$ArgumentList,[int]$MaximumChars=65536)
    if(-not ('AgentOnly.BoundedCapture' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
namespace AgentOnly {
 public sealed class BoundedCaptureResult { public int ExitCode; public string Stdout; public string Stderr; }
 public static class BoundedCapture {
  static string Quote(string s) {
   if(s == null) return "\"\"";
   var b = new StringBuilder(); b.Append('"'); int slashes=0;
   foreach(char c in s) { if(c=='\\') { slashes++; continue; } if(c=='"') { b.Append(new string('\\',slashes*2+1)); b.Append('"'); slashes=0; continue; } if(slashes>0) { b.Append(new string('\\',slashes)); slashes=0; } b.Append(c); }
   if(slashes>0) b.Append(new string('\\',slashes*2)); b.Append('"'); return b.ToString();
  }
  public static BoundedCaptureResult Run(string fileName, string[] args, int maxChars) {
   var psi=new ProcessStartInfo(); psi.FileName=fileName; psi.Arguments=String.Join(" ", Array.ConvertAll(args, Quote)); psi.UseShellExecute=false; psi.CreateNoWindow=true; psi.RedirectStandardOutput=true; psi.RedirectStandardError=true;
   var p=new Process(); p.StartInfo=psi; var o=new StringBuilder(); var e=new StringBuilder(); bool ot=false, et=false; object gate=new object();
   p.OutputDataReceived += delegate(object sender, DataReceivedEventArgs a) { if(a.Data==null) return; lock(gate) { const int marker=11; int room=maxChars-o.Length; if(!ot && room>a.Data.Length+1) o.AppendLine(a.Data); else if(!ot) { int keep=Math.Max(0,maxChars-marker-o.Length); if(keep>0) o.Append(a.Data.Substring(0,Math.Min(a.Data.Length,keep))); o.Append("[TRUNCATED]"); ot=true; } } };
   p.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs a) { if(a.Data==null) return; lock(gate) { const int marker=11; int room=maxChars-e.Length; if(!et && room>a.Data.Length+1) e.AppendLine(a.Data); else if(!et) { int keep=Math.Max(0,maxChars-marker-e.Length); if(keep>0) e.Append(a.Data.Substring(0,Math.Min(a.Data.Length,keep))); e.Append("[TRUNCATED]"); et=true; } } };
   if(!p.Start()) throw new InvalidOperationException("CHILD_PROCESS_START_FAILED"); p.BeginOutputReadLine(); p.BeginErrorReadLine(); p.WaitForExit(); Thread.Sleep(100);
   var r=new BoundedCaptureResult(); r.ExitCode=p.ExitCode; r.Stdout=o.ToString(); r.Stderr=e.ToString(); p.Dispose(); return r;
  }
 }
}

'@
    }
    return [AgentOnly.BoundedCapture]::Run($FilePath,$ArgumentList,$MaximumChars)
}

function Assert-AgentOnlySnapshotUnchanged {
    param([Parameter(Mandatory=$true)][System.Collections.IDictionary]$Before,[Parameter(Mandatory=$true)][System.Collections.IDictionary]$After)
    foreach($field in 'State','ProcessId','StartMode','StartName','PathName','ExitCode') {
        if([string]$After[$field] -ne [string]$Before[$field]) { throw ('AGENT_CHANGED_DURING_PLAN:' + $field) }
    }
    return $true
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
        [AllowNull()][bool]$SpoolUnchanged,
        [AllowNull()][bool]$AgentUnchanged,
        [AllowNull()][object]$AgentBefore,
        [AllowNull()][object]$AgentAfter,
        [Parameter(Mandatory=$true)][bool]$LiveMutationPerformed
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
        agent_unchanged = $AgentUnchanged
        agent_before = $AgentBefore
        agent_after = $AgentAfter
        live_mutation_performed = $LiveMutationPerformed
    }
}
