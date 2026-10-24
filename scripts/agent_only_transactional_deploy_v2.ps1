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
    [string]$EvidenceRoot='C:\CD\EVIDENCE_PROTECTED',
    [switch]$RecoverStoppedAgent,
    [switch]$AcknowledgeCompanionDegraded,
    [switch]$Apply,
    [ValidateSet('', 'AGENT_ONLY_AUTHORIZED')][string]$HostAcknowledgement=''
)

# This wrapper is deliberately pinned to one reviewed candidate.  It delegates
# installation and rollback to install_agent_release.ps1; it never changes SCM
# configuration itself and never passes a recovery-probe switch.
$PinnedCommit='837e6a0b5336bb69888eef13a2e40a352ca6ad29'
$PinnedZipSHA256='51729553d6d533959e389c15c0b58d40306056e7e9b5e82abe5ac7b7ae29874a'
$PinnedRuntimeSHA256='7368ccfc91f605b3f3aa96de804a950d1797699021a5236b66a607e643878bb2'
$PinnedInstallerSHA256='0df0f26299a899da0099015f6e6c251a50ae4b560e2a8908db2463f75a59e0ef'
$PinnedBaselineCommit='c5030219ba3a996013b8ab0dda48f60743e5c665'
$PinnedBaselineSHA256='6240488d506d1fb7ebac264fa0a1dbc7c05e1a74c65d5a2667fc98603af346bf'
$AgentName='CyberDefenderAgent'
$CompanionNames=@('CyberDefenderControlPlane','CyberDefenderOwnerUI')
$SpoolRoot=Join-Path $env:ProgramData 'CyberDefender\state\spool'
$EvidenceHelper=Join-Path $PSScriptRoot 'agent_release\agent_only_error_evidence.ps1'
$EvidenceHelperSHA256='7a45859a11dcd9103ffcd7b6ac504c7db97bc4229d2450e2071cc057ac6b38ad'
$ErrorActionPreference='Stop'

function Require([bool]$Condition,[string]$Code) { if(-not $Condition){ throw $Code } }

Require (Test-Path -LiteralPath $EvidenceHelper -PathType Leaf) 'EVIDENCE_HELPER_MISSING'
Require ((Get-FileHash -LiteralPath $EvidenceHelper -Algorithm SHA256).Hash.ToLowerInvariant() -eq $EvidenceHelperSHA256) 'EVIDENCE_HELPER_HASH_MISMATCH'
. $EvidenceHelper

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

$exitCode=1
$status='FAIL'
$code='UNINITIALIZED'
$childOut=''
$childErr=''
$childExit=$null
$tmpRoot=Join-Path ([IO.Path]::GetTempPath()) ('CyberDefender-AgentOnly-' + [guid]::NewGuid().ToString('N'))
$companionBaseline=@{}
$spoolBefore=''
$companionsUnchanged=$false
$spoolUnchanged=$false
$agentAfter=$null
$agentUnchanged=$false
$CaptureLimit=65536

function Write-Result([string]$Status,[string]$Code,[int]$ExitCode) {
    $artifacts=@{
        candidate_commit=$PinnedCommit
        candidate_zip_sha256=$PinnedZipSHA256
        installer_sha256=$PinnedInstallerSHA256
        runtime_zip_sha256=$PinnedRuntimeSHA256
        baseline_commit=$PinnedBaselineCommit
        baseline_zip_sha256=$PinnedBaselineSHA256
        evidence_helper_sha256=$EvidenceHelperSHA256
    }
    $evidence=New-AgentOnlyEvidenceObject -Status $Status -Code $Code -ExitCode $ExitCode -Apply ([bool]$Apply) `
        -ChildExitCode $childExit -ChildStdout $childOut -ChildStderr $childErr -Artifacts $artifacts `
        -CompanionsUnchanged:$companionsUnchanged -SpoolUnchanged:$spoolUnchanged `
        -AgentUnchanged:$agentUnchanged -AgentBefore $agentBefore -AgentAfter $agentAfter `
        -LiveMutationPerformed ([bool]$Apply)
    if([string]::IsNullOrWhiteSpace($ResultPath)) {
        $ResultPath=Join-Path $EvidenceRoot ('agent-only-plan-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '.json')
    }
    $parent=Split-Path -Parent ([IO.Path]::GetFullPath($ResultPath))
    if(-not (Test-Path -LiteralPath $parent -PathType Container)){ [void](New-Item -ItemType Directory -Path $parent -Force) }
    $json=$evidence | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($ResultPath,$json,(New-Object Text.UTF8Encoding($false)))
    $line='AGENT_ONLY_DEPLOY status=' + $Status + ' code=' + $Code + ' apply=' + [bool]$Apply + ' exit=' + $ExitCode
    Write-Output $line
    Write-Output ('EVIDENCE=' + $ResultPath)
}

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
    $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$InstallerPath,
        '-ReleaseZip',$ReleaseZip,'-ApprovedZipSHA256',$ApprovedZipSHA256,'-ApprovedCommit',$ApprovedCommit,
        '-RuntimeZip',$RuntimeZip,'-ApprovedRuntimeZipSHA256',$ApprovedRuntimeZipSHA256,
        '-BaselineReleaseZip',$BaselineReleaseZip,'-ApprovedBaselineZipSHA256',$ApprovedBaselineZipSHA256,
        '-ApprovedBaselineCommit',$ApprovedBaselineCommit)
    if($RecoverStoppedAgent.IsPresent){ $arguments += '-RecoverStoppedAgent' }
    if($AcknowledgeCompanionDegraded.IsPresent){ $arguments += '-AcknowledgeCompanionDegraded' }
    if($Apply.IsPresent){ $arguments += @('-HostAcknowledgement','AGENT_ONLY_AUTHORIZED','-Apply') }

    $child=Invoke-AgentOnlyBoundedChild -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -MaximumChars $CaptureLimit
    $childExit=[int]$child.ExitCode
    $childOut=[string]$child.Stdout
    $childErr=[string]$child.Stderr

    Assert-CompanionsUnchanged $companionBaseline
    $companionsUnchanged=$true
    Require ((Snapshot-Digest $SpoolRoot) -eq $spoolBefore) 'SPOOL_CHANGED'
    $spoolUnchanged=$true
    $agentAfter=Service-Snapshot $AgentName
    if(-not $Apply.IsPresent){ Assert-AgentOnlySnapshotUnchanged -Before $agentBefore -After $agentAfter }
    $agentUnchanged=$true
    if($childExit -ne 0){ throw ('INSTALLER_FAILED:' + $childExit) }
    if($Apply.IsPresent){ Require ($childOut -match '(?m)^AGENT_RELEASE_PASS:') 'AGENT_RELEASE_PASS_MISSING' }
    else { Require ($childOut -match '(?m)^PLAN_PASS:') 'PLAN_PASS_MISSING' }
    $status='PASS'; $code=if($Apply.IsPresent){'APPLY_PASS'}else{'PLAN_PASS'}; $exitCode=0
} catch {
    $code=Sanitize-AgentOnlyDiagnosticText $_.Exception.Message 4096
    if($code -like 'INSTALLER_FAILED:*' -or $code -like 'AGENT_RELEASE_PASS_MISSING') {
        # The reviewed installer owns the transactional rollback.  This wrapper
        # only performs read-back; it never invents a second rollback path.
        try {
            Assert-CompanionsUnchanged $companionBaseline
            $companionsUnchanged=$true
            Require ((Snapshot-Digest $SpoolRoot) -eq $spoolBefore) 'POST_FAILURE_STATE_CHANGED'
            $spoolUnchanged=$true
        } catch { $code=Sanitize-AgentOnlyDiagnosticText ($code + '|ROLLBACK_READBACK:' + $_.Exception.Message) 4096 }
    }
    $status='FAIL'; $exitCode=1
} finally {
    try { Write-Result $status $code $exitCode }
    catch { Write-Output ('AGENT_ONLY_DEPLOY status=FAIL code=EVIDENCE_WRITE_FAILED apply=' + [bool]$Apply + ' exit=1'); $exitCode=1 }
    if(Test-Path -LiteralPath $tmpRoot){ Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
exit $exitCode


