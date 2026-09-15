param([switch]$RemoveState)
$ErrorActionPreference='Stop'
$id=[Security.Principal.WindowsIdentity]::GetCurrent(); $p=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator huquqi kerak.'}
$services=@('CyberDefenderAgent','CyberDefenderControlPlane','CyberDefenderOwnerUI')
foreach($name in $services){
  $svc=Get-Service -Name $name -ErrorAction SilentlyContinue
  if($null -ne $svc){
    if($svc.Status -ne 'Stopped'){try{Stop-Service -Name $name -Force -ErrorAction SilentlyContinue}catch{};try{(Get-Service $name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))}catch{}}
    & sc.exe delete $name | Out-Null
  }
}
Start-Sleep -Seconds 1
$AppParent=Join-Path $env:ProgramFiles 'CyberDefender'
if(Test-Path $AppParent){Remove-Item -Recurse -Force $AppParent}
if($RemoveState){$base=Join-Path $env:ProgramData 'CyberDefender'; if(Test-Path $base){Remove-Item -Recurse -Force $base}}
Write-Host "CyberDefender services removed. State preserved: $(-not $RemoveState)"
