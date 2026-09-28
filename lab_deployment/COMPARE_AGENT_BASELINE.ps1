param(
    [Parameter(Mandatory=$true)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$EvidenceA,
    [Parameter(Mandatory=$true)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$EvidenceB,
    [string]$CandidateSourceRoot = "",
    [string]$OutputPath = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Read-Evidence([string]$Path){ Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json }
$a=Read-Evidence $EvidenceA; $b=Read-Evidence $EvidenceB
$am=@{}; @($a.files)|ForEach-Object{$am[[string]$_.path]=[string]$_.sha256}; $bm=@{}; @($b.files)|ForEach-Object{$bm[[string]$_.path]=[string]$_.sha256}
$common=@($am.Keys|Where-Object{$bm.ContainsKey($_)}); $matches=@($common|Where-Object{$am[$_] -eq $bm[$_]}); $mismatches=@($common|Where-Object{$am[$_] -ne $bm[$_]})
$missingA=@($bm.Keys|Where-Object{-not $am.ContainsKey($_)}); $missingB=@($am.Keys|Where-Object{-not $bm.ContainsKey($_)})
$candidate='UNVERIFIED'
if(-not [string]::IsNullOrWhiteSpace($CandidateSourceRoot)){
    if(-not (Test-Path (Join-Path $CandidateSourceRoot '.git'))){$candidate='MISMATCH'} else {$candidate='CANDIDATE_ONLY'}
}
$result='NOT_PROVEN'
if($mismatches.Count -gt 0 -or $a.native_sensor.sha256 -ne $b.native_sensor.sha256 -or $a.runtime_version -ne $b.runtime_version){$result='MISMATCH'}
elseif($common.Count -gt 0 -and $missingA.Count -eq 0 -and $missingB.Count -eq 0 -and $candidate -eq 'CANDIDATE_ONLY'){$result='PROVEN'}
$out=[ordered]@{schema='cyberdefender.agent-baseline-comparison.v1';result=$result;evidence_a=$EvidenceA;evidence_b=$EvidenceB;candidate=$candidate;common_files=$common.Count;hash_matches=$matches.Count;hash_mismatches=$mismatches.Count;missing_from_a=$missingA;missing_from_b=$missingB;native_sensor_match=($a.native_sensor.sha256 -eq $b.native_sensor.sha256);runtime_version_match=($a.runtime_version -eq $b.runtime_version)}
if([string]::IsNullOrWhiteSpace($OutputPath)){$OutputPath=Join-Path (Get-Location) 'agent_baseline_comparison.json'}
$out|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Host $result
