[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InstallerPath,
    [Parameter(Mandatory=$true)][string]$ReleaseZip,
    [Parameter(Mandatory=$true)][string]$RuntimeZip,
    [Parameter(Mandatory=$true)][string]$BaselineReleaseZip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedInstallerSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedZipSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ApprovedCommit,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedRuntimeZipSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedBaselineZipSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ApprovedBaselineCommit,
    [string]$ResultPath='',
    [switch]$RecoverStoppedAgent,
    [switch]$AcknowledgeCompanionDegraded,
    [switch]$Apply,
    [ValidateSet('', 'AGENT_ONLY_AUTHORIZED')][string]$HostAcknowledgement=''
)

# This wrapper is deliberately pinned to one reviewed candidate.  It delegates
# installation and rollback to install_agent_release.ps1; it never changes SCM
# configuration itself and never passes a recovery-probe switch.
$PinnedCommit='bda8126b517a6c46c6078996c148d5d32164c4d0'
$PinnedZipSHA256='106398453f5c0d7d4056e58838c3c847b1d75b02473e199cb5511fe6cea7bd7d'
$PinnedRuntimeSHA256='7368ccfc91f605b3f3aa96de804a950d1797699021a5236b66a607e643878bb2'
$PinnedInstallerSHA256='6917043b433cc4eac884300ee301f230d54d436c4b4f500fcb9864c2b6a49d86'
$PinnedBaselineCommit='c5030219ba3a996013b8ab0dda48f60743e5c665'
$PinnedBaselineSHA256='6240488d506d1fb7ebac264fa0a1dbc7c05e1a74c65d5a2667fc98603af346bf'
$AgentName='CyberDefenderAgent'
$CompanionNames=@('CyberDefenderControlPlane','CyberDefenderOwnerUI')
$SpoolRoot=Join-Path $env:ProgramData 'CyberDefender\state\spool'
$ErrorActionPreference='Stop'

function Require([bool]$Condition,[string]$Code) { if(-not $Condition){ throw $Code } }

function Hash-File([string]$Path) {
    Require (Test-Path -LiteralPath $Path -PathType Leaf) 'PINNED_FILE_NOT_FOUND'
    $item=Get-Item -LiteralPath $Path -Force
    Require (-not [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'PINNED_FILE_REPARSE_POINT'
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Assert-Hash([string]$Path,[string]$Expected,[string]$Code) {
    Require ((Hash-File $Path) -eq $Expected.ToLowerInvariant()) $Code
}

function Service-Snapshot([string]$Name) {
    $s=Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction Stop
    Require ($null -ne $s) ('SERVICE_MISSING:' + $Name)
    return [ordered]@{Name=$s.Name;State=$s.State;ProcessId=[int]$s.ProcessId;StartMode=$s.StartMode;StartName=$s.StartName;PathName=$s.PathName;ExitCode=[int]$s.ExitCode}
}

function Snapshot-Digest([string]$Root) {
    Require (Test-Path -LiteralPath $Root -PathType Container) 'SPOOL_ROOT_UNREADABLE'
    $rows=@(Get-ChildItem -LiteralPath $Root -Recurse -Force -File -ErrorAction Stop | Sort-Object FullName | ForEach-Object {
        $rel=$_.FullName.Substring($Root.Length+1).Replace('\','/')
        $hash=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $rel + '|' + $_.Length + '|' + $hash
    })
    $text=[string]::Join("`n",$rows)
    $bytes=[Text.Encoding]::UTF8.GetBytes($text)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Assert-CompanionsUnchanged($Before) {
    foreach($name in $CompanionNames) {
        $after=Service-Snapshot $name
        $old=$Before[$name]
        foreach($field in 'State','ProcessId','StartMode','StartName','PathName','ExitCode') {
            Require ([string]$after[$field] -eq [string]$old[$field]) ('COMPANION_CHANGED:' + $name + ':' + $field)
        }
    }
}

function Write-Result([string]$Status,[string]$Code,[int]$ExitCode) {
    $line='AGENT_ONLY_DEPLOY status=' + $Status + ' code=' + $Code + ' apply=' + [bool]$Apply + ' exit=' + $ExitCode
    Write-Output $line
    if(-not [string]::IsNullOrWhiteSpace($ResultPath)) {
        $parent=Split-Path -Parent ([IO.Path]::GetFullPath($ResultPath))
        if(-not (Test-Path -LiteralPath $parent -PathType Container)){ [void](New-Item -ItemType Directory -Path $parent -Force) }
        [IO.File]::WriteAllText($ResultPath,$line,(New-Object Text.UTF8Encoding($false)))
    }
}

$exitCode=1
$status='FAIL'
$code='UNINITIALIZED'
$childOut=''
$childErr=''
$tmpRoot=Join-Path ([IO.Path]::GetTempPath()) ('CyberDefender-AgentOnly-' + [guid]::NewGuid().ToString('N'))
$companionBaseline=@{}
$spoolBefore=''

try {
    Require ($ApprovedCommit.ToLowerInvariant() -eq $PinnedCommit) 'CANDIDATE_COMMIT_PIN_MISMATCH'
    Require ($ApprovedZipSHA256.ToLowerInvariant() -eq $PinnedZipSHA256) 'CANDIDATE_ZIP_PIN_MISMATCH'
    Require ($ApprovedRuntimeZipSHA256.ToLowerInvariant() -eq $PinnedRuntimeSHA256) 'RUNTIME_ZIP_PIN_MISMATCH'
    Require ($ApprovedInstallerSHA256.ToLowerInvariant() -eq $PinnedInstallerSHA256) 'INSTALLER_PIN_MISMATCH'
    Require ($ApprovedBaselineCommit.ToLowerInvariant() -eq $PinnedBaselineCommit) 'BASELINE_COMMIT_PIN_MISMATCH'
    Require ($ApprovedBaselineZipSHA256.ToLowerInvariant() -eq $PinnedBaselineSHA256) 'BASELINE_ZIP_PIN_MISMATCH'
    Assert-Hash $InstallerPath $PinnedInstallerSHA256 'INSTALLER_SHA256_MISMATCH'
    Assert-Hash $ReleaseZip $PinnedZipSHA256 'CANDIDATE_ZIP_SHA256_MISMATCH'
    Assert-Hash $RuntimeZip $PinnedRuntimeSHA256 'RUNTIME_ZIP_SHA256_MISMATCH'
    Assert-Hash $BaselineReleaseZip $PinnedBaselineSHA256 'BASELINE_ZIP_SHA256_MISMATCH'
    Require ((Test-Path -LiteralPath $ResultPath -PathType Leaf) -eq $false) 'RESULT_PATH_EXISTS'

    $agentBefore=Service-Snapshot $AgentName
    foreach($name in $CompanionNames){ $companionBaseline[$name]=Service-Snapshot $name }
    $spoolBefore=Snapshot-Digest $SpoolRoot

    if($Apply.IsPresent){ Require ($HostAcknowledgement -eq 'AGENT_ONLY_AUTHORIZED') 'AGENT_ONLY_ACK_REQUIRED' }
    [void](New-Item -ItemType Directory -Path $tmpRoot -Force)
    $stdoutPath=Join-Path $tmpRoot 'installer.stdout.log'
    $stderrPath=Join-Path $tmpRoot 'installer.stderr.log'
    $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$InstallerPath,
        '-ReleaseZip',$ReleaseZip,'-ApprovedZipSHA256',$ApprovedZipSHA256,'-ApprovedCommit',$ApprovedCommit,
        '-RuntimeZip',$RuntimeZip,'-ApprovedRuntimeZipSHA256',$ApprovedRuntimeZipSHA256,
        '-BaselineReleaseZip',$BaselineReleaseZip,'-ApprovedBaselineZipSHA256',$ApprovedBaselineZipSHA256,
        '-ApprovedBaselineCommit',$ApprovedBaselineCommit)
    if($RecoverStoppedAgent.IsPresent){ $arguments += '-RecoverStoppedAgent' }
    if($AcknowledgeCompanionDegraded.IsPresent){ $arguments += '-AcknowledgeCompanionDegraded' }
    if($Apply.IsPresent){ $arguments += @('-HostAcknowledgement','AGENT_ONLY_AUTHORIZED','-Apply') }

    $p=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $childExit=[int]$p.ExitCode
    if(Test-Path -LiteralPath $stdoutPath){ $childOut=[IO.File]::ReadAllText($stdoutPath) }
    if(Test-Path -LiteralPath $stderrPath){ $childErr=[IO.File]::ReadAllText($stderrPath) }

    Assert-CompanionsUnchanged $companionBaseline
    Require ((Snapshot-Digest $SpoolRoot) -eq $spoolBefore) 'SPOOL_CHANGED'
    if($childExit -ne 0){ throw ('INSTALLER_FAILED:' + $childExit) }
    if($Apply.IsPresent){ Require ($childOut -match '(?m)^AGENT_RELEASE_PASS:') 'AGENT_RELEASE_PASS_MISSING' }
    else { Require ($childOut -match '(?m)^PLAN_PASS:') 'PLAN_PASS_MISSING' }
    $status='PASS'; $code=if($Apply.IsPresent){'APPLY_PASS'}else{'PLAN_PASS'}; $exitCode=0
} catch {
    $code=$_.Exception.Message
    if($code -like 'INSTALLER_FAILED:*' -or $code -like 'AGENT_RELEASE_PASS_MISSING') {
        # The reviewed installer owns the transactional rollback.  This wrapper
        # only performs read-back; it never invents a second rollback path.
        try { Assert-CompanionsUnchanged $companionBaseline; Require ((Snapshot-Digest $SpoolRoot) -eq $spoolBefore) 'POST_FAILURE_STATE_CHANGED' } catch { $code += '|ROLLBACK_READBACK:' + $_.Exception.Message }
    }
    $status='FAIL'; $exitCode=1
} finally {
    Write-Result $status $code $exitCode
    if(Test-Path -LiteralPath $tmpRoot){ Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
exit $exitCode
