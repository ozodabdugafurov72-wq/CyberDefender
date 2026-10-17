# Resumable deterministic Agent release build. Reads only committed Git objects.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Repository,
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)][string]$RuntimeZip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$RuntimeSHA256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$commitLower=$Commit.ToLowerInvariant()
$short=$commitLower.Substring(0,7)
$zipA=Join-Path $OutputDirectory ('CD_AGENT_PINNED_' + $short + '_A.zip')
$zipB=Join-Path $OutputDirectory ('CD_AGENT_PINNED_' + $short + '_B.zip')
$manifestPath=Join-Path $OutputDirectory ('CD_AGENT_BUILD_' + $short + '.json')

function Invoke-PythonJson([string[]]$Arguments) {
    $output=& $Python @Arguments
    if($LASTEXITCODE -ne 0){throw 'PYTHON_GATE_FAILED'}
    return (($output -join "`n") | ConvertFrom-Json -ErrorAction Stop)
}

foreach($path in @($Repository,$OutputDirectory)) {
    if(-not (Test-Path -LiteralPath $path -PathType Container)){throw 'BUILD_DIRECTORY_UNAVAILABLE'}
}
foreach($path in @($Python,$RuntimeZip)) {
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw 'BUILD_INPUT_UNAVAILABLE'}
}
if((git -C $Repository status --porcelain).Count -ne 0){throw 'SOURCE_TREE_DIRTY'}
if((git -C $Repository rev-parse HEAD).Trim() -ne $commitLower){throw 'SOURCE_HEAD_MISMATCH'}

$builder=Join-Path $Repository 'scripts\agent_release\build_pinned_release.py'
$provenance=Join-Path $Repository 'scripts\agent_release\verify_git_zip_provenance.py'
$releaseManager=Join-Path $Repository 'scripts\agent_release\release_manager.py'
$runtimeManager=Join-Path $Repository 'scripts\agent_release\runtime_manager.py'
foreach($target in @($zipA,$zipB)) {
    if(-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        [void](Invoke-PythonJson @($builder,'--repo',$Repository,'--commit',$commitLower,'--out',$target))
    }
}

$shaA=(Get-FileHash -Algorithm SHA256 -LiteralPath $zipA).Hash.ToLowerInvariant()
$shaB=(Get-FileHash -Algorithm SHA256 -LiteralPath $zipB).Hash.ToLowerInvariant()
if($shaA -ne $shaB){throw 'DETERMINISTIC_BUILD_MISMATCH'}
$provA=Invoke-PythonJson @($provenance,'--repo',$Repository,'--zip',$zipA,'--sha256',$shaA,'--commit',$commitLower)
$provB=Invoke-PythonJson @($provenance,'--repo',$Repository,'--zip',$zipB,'--sha256',$shaB,'--commit',$commitLower)
$source=Invoke-PythonJson @($releaseManager,'verify','--zip',$zipA,'--sha256',$shaA,'--commit',$commitLower)
$runtimeVerifyParent=Join-Path $OutputDirectory ('.runtime-verify-' + [Guid]::NewGuid().ToString('N'))
$runtimeRoot=Join-Path $runtimeVerifyParent 'runtime'
[void](New-Item -ItemType Directory -Path $runtimeVerifyParent -ErrorAction Stop)
try {
    $runtime=Invoke-PythonJson @($runtimeManager,'extract','--zip',$RuntimeZip,'--sha256',$RuntimeSHA256,'--dest',$runtimeRoot)
    $rootPrefix=[IO.Path]::GetFullPath($runtimeRoot).TrimEnd('\')+'\'
    $signedFiles=@((Join-Path $runtimeRoot 'python.exe')) + @(
        Get-ChildItem -LiteralPath $runtimeRoot -Filter *.dll -File -Recurse | Select-Object -ExpandProperty FullName
    )
    $signatures=@(foreach($file in $signedFiles) {
        $full=[IO.Path]::GetFullPath($file)
        if(-not $full.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)){throw 'RUNTIME_INVENTORY_ESCAPE'}
        $signature=Get-AuthenticodeSignature -LiteralPath $full
        [ordered]@{
            name=$full.Substring($rootPrefix.Length).Replace('\','/')
            status=$signature.Status.ToString()
        }
    })
    $valid=@($signatures | Where-Object status -eq 'Valid').Count
    $unsigned=@($signatures | Where-Object status -eq 'NotSigned').Count
    $other=$signatures.Count-$valid-$unsigned
    if($other -ne 0){throw 'RUNTIME_AUTHENTICODE_INVALID'}
} finally {
    if(Test-Path -LiteralPath $runtimeVerifyParent){Remove-Item -LiteralPath $runtimeVerifyParent -Recurse -Force}
}

$installer=Join-Path $Repository 'scripts\install_agent_release.ps1'
$wrapper=Join-Path $Repository 'scripts\agent_release\run_installer_plan.ps1'
$gitPath=(Get-Command git -ErrorAction Stop).Source
$result=[ordered]@{
    schema='cyberdefender.agent-build-gates.v2'
    status='BUILD_GATES_PASS'
    commit=$commitLower
    source_zip_a=$zipA
    source_zip_b=$zipB
    source_sha256=$shaA
    deterministic=$true
    source_files=[int]$source.files
    source_bytes=[int64]$source.bytes
    provenance_a=$provA.status
    provenance_b=$provB.status
    runtime_zip=$RuntimeZip
    runtime_sha256=$RuntimeSHA256.ToLowerInvariant()
    runtime_files=[int]$runtime.files
    runtime_bytes=[int64]$runtime.bytes
    authenticode_valid=$valid
    authenticode_unsigned=$unsigned
    authenticode_other=$other
    installer_sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash.ToLowerInvariant()
    wrapper_sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $wrapper).Hash.ToLowerInvariant()
    git_executable_sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $gitPath).Hash.ToLowerInvariant()
    services_untouched=$true
}
$temporary=$manifestPath+'.pending'
$json=$result | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($temporary,$json+"`n",(New-Object Text.UTF8Encoding($false)))
Move-Item -LiteralPath $temporary -Destination $manifestPath -Force
$json
