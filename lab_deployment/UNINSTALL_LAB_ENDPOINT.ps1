param([switch]$RemoveIdentityAndStorage)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Require-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent(); $p=New-Object Security.Principal.WindowsPrincipal($id)
    if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ throw 'Administrator rights required' }
}
Require-Administrator
if (Get-Service -Name 'CyberDefenderControlPlane' -ErrorAction SilentlyContinue) { throw 'Refusing: ControlPlane is present; this kit only removes Agent' }
if (Get-Service -Name 'CyberDefenderOwnerUI' -ErrorAction SilentlyContinue) { throw 'Refusing: OwnerUI is present; this kit only removes Agent' }
$service=Get-Service -Name 'CyberDefenderAgent' -ErrorAction SilentlyContinue
if($null -ne $service){
    if($service.Status -ne 'Stopped'){ Stop-Service -Name 'CyberDefenderAgent' -Force; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
    & sc.exe delete CyberDefenderAgent | Out-Null
    if($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060){ throw "Agent service removal failed: $LASTEXITCODE" }
}
$app=Join-Path $env:ProgramFiles 'CyberDefender\app'
if(Test-Path -LiteralPath $app){Remove-Item -LiteralPath $app -Recurse -Force}
Write-Host 'PASS: CyberDefenderAgent service and application runtime removed'
Write-Host 'PRESERVED: endpoint identity, storage key, fleet credential, state, logs, and CrashGuard evidence'
if($RemoveIdentityAndStorage){
    $base=Join-Path $env:ProgramData 'CyberDefender'
    foreach($path in @((Join-Path $base 'identity'),(Join-Path $base 'secrets'),(Join-Path $base 'state'))){if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force}}
    Write-Host 'PASS: explicit destructive identity/storage removal completed'
} else { Write-Host 'WAIT: identity/storage removal not requested' -ForegroundColor Yellow }
