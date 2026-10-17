# Hash-pinned Windows PowerShell 5.1 PLAN launcher. Run this script elevated.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InstallerPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedInstallerSHA256,
    [Parameter(Mandatory=$true)][string]$ReleaseZip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedZipSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ApprovedCommit,
    [Parameter(Mandatory=$true)][string]$RuntimeZip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedRuntimeZipSHA256,
    [Parameter(Mandatory=$true)][string]$ResultPath,
    [switch]$RecoverStoppedAgent,
    [switch]$AcknowledgeCompanionDegraded
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$result='PLAN_FAIL:WRAPPER_FAILURE'
$installerExit=1
$launcherExit=1
$stdoutPath=$ResultPath + '.stdout.log'
$stderrPath=$ResultPath + '.stderr.log'

function Require([bool]$Condition,[string]$Code) {
    if(-not $Condition){ throw $Code }
}

function Require-PinnedFile([string]$Path,[string]$Expected,[string]$Code) {
    Require (Test-Path -LiteralPath $Path -PathType Leaf) 'WRAPPER_INPUT_UNAVAILABLE'
    $entry=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Require (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'WRAPPER_INPUT_REPARSE'
    $actual=(Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash.ToLowerInvariant()
    Require ($actual -eq $Expected.ToLowerInvariant()) $Code
}

try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'ADMIN_REQUIRED'
    $resultDirectory=Split-Path -Parent ([IO.Path]::GetFullPath($ResultPath))
    Require (Test-Path -LiteralPath $resultDirectory -PathType Container) 'RESULT_DIRECTORY_UNAVAILABLE'
    Require-PinnedFile $InstallerPath $ApprovedInstallerSHA256 'INSTALLER_SHA256_MISMATCH'
    Require-PinnedFile $ReleaseZip $ApprovedZipSHA256 'RELEASE_ZIP_SHA256_MISMATCH'
    Require-PinnedFile $RuntimeZip $ApprovedRuntimeZipSHA256 'RUNTIME_ZIP_SHA256_MISMATCH'
    foreach($path in @($ResultPath,$stdoutPath,$stderrPath)) {
        Require (-not (Test-Path -LiteralPath $path)) 'RESULT_PATH_ALREADY_EXISTS'
    }
    $powershell="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    Require-PinnedFile $powershell (Get-FileHash -Algorithm SHA256 -LiteralPath $powershell).Hash 'POWERSHELL_IDENTITY_UNAVAILABLE'
    $arguments=@(
        '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$InstallerPath,
        '-ReleaseZip',$ReleaseZip,'-ApprovedZipSHA256',$ApprovedZipSHA256,
        '-ApprovedCommit',$ApprovedCommit,'-RuntimeZip',$RuntimeZip,
        '-ApprovedRuntimeZipSHA256',$ApprovedRuntimeZipSHA256
    )
    if($RecoverStoppedAgent.IsPresent){$arguments+='-RecoverStoppedAgent'}
    if($AcknowledgeCompanionDegraded.IsPresent){$arguments+='-AcknowledgeCompanionDegraded'}
    $process=Start-Process -FilePath $powershell -ArgumentList $arguments -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $installerExit=[int]$process.ExitCode
    $stdout=if(Test-Path -LiteralPath $stdoutPath){Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction Stop}else{''}
    $stderr=if(Test-Path -LiteralPath $stderrPath){Get-Content -LiteralPath $stderrPath -Raw -ErrorAction Stop}else{''}
    $combined=$stdout + "`n" + $stderr
    if($installerExit -eq 0 -and $stdout -match '(?m)^PLAN_PASS:' -and $stdout -match '(?m)^PLAN_ONLY:') {
        $result='PLAN_PASS'
        $launcherExit=0
    } else {
        $known=@(
            'ACL_GATE_UNAVAILABLE','ACL_VIOLATION','ADMIN_REQUIRED','AGENT_BASELINE_RUNTIME_UNHEALTHY',
            'AGENT_ORIGINAL_PATH_NOT_RECOGNIZED','AGENT_STATE_UNSUPPORTED','AGENT_STARTMODE_NOT_AUTO',
            'COMPANION_CONTROLPLANE_UNREACHABLE','COMPANION_OWNERUI_UNREACHABLE','COMPANION_LISTENER_QUERY_FAILED',
            'PINNED_RUNTIME_SIGNATURE_INVALID','PINNED_RUNTIME_SIGNER_INVALID','RECOVER_STOPPED_AGENT_ACK_REQUIRED',
            'REQUIRED_FILE_MISSING','RUNTIME_ZIP_SHA256_MISMATCH','UNAPPROVED_DISTRIBUTION_ORIGIN'
        )
        $code='INSTALLER_FAILED'
        foreach($candidate in $known){if($combined -match ('(?m)' + [regex]::Escape($candidate))){$code=$candidate;break}}
        $result='PLAN_FAIL:' + $code
    }
} catch {
    $code=[string]$_.Exception.Message
    if($code -notmatch '^[A-Z][A-Z0-9_]{2,63}$'){$code='WRAPPER_FAILURE'}
    $result='PLAN_FAIL:' + $code
} finally {
    $lines=@($result,('INSTALLER_EXIT=' + $installerExit))
    [IO.File]::WriteAllLines($ResultPath,$lines,(New-Object Text.UTF8Encoding($false)))
    Write-Host $result
}
exit $launcherExit
