$services=@("CyberDefenderAgent","CyberDefenderControlPlane","CyberDefenderOwnerUI")
foreach($name in $services){
  $svc=Get-Service -Name $name -ErrorAction SilentlyContinue
  if($null -eq $svc){Write-Host "$name : NOT_INSTALLED"}else{Write-Host "$name : $($svc.Status) | StartType=$($svc.StartType)"}
}
