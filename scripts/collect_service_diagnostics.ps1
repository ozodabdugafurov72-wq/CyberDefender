$base=Join-Path $env:ProgramData 'CyberDefender'
$services=@('CyberDefenderAgent','CyberDefenderControlPlane','CyberDefenderOwnerUI')
Write-Host '=== Service status ==='
foreach($name in $services){
  $svc=Get-Service -Name $name -ErrorAction SilentlyContinue
  if($null -eq $svc){Write-Host "$name : NOT_INSTALLED"}else{Write-Host "$name : $($svc.Status) | StartType=$($svc.StartType)"; sc.exe qc $name}
}
$evidence=Join-Path $env:ProgramData 'CyberDefenderCrashGuard\diagnostics'
foreach($name in $services){
  $log=Join-Path $evidence ($name+'.jsonl')
  if(Test-Path -LiteralPath $log){
    Get-Content -LiteralPath $log -Tail 120 | ForEach-Object {
      try {
        $entry=$_ | ConvertFrom-Json
        if($entry.schema -eq 'cd.service-diagnostic.v1' -and $entry.service -eq $name -and
           $entry.event -in @('READY','STARTING','RUNNING','STOPPED','FATAL','LATCHED','PROBE','UNAVAILABLE','HEALTHY','DEGRADED','STALLED','TELEMETRY_UNAVAILABLE','UNCLASSIFIED')) {
          [pscustomobject]@{Service=$name;Event=$entry.event}
        }
      } catch { Write-Output 'DIAGNOSTIC_RECORD_REJECTED' }
    }
  }
}
Write-Host '=== SCM events ==='
Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager';StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue |
  Where-Object {$_.Message -match 'CyberDefender'} |
  Select-Object -First 40 TimeCreated,Id,LevelDisplayName | Format-List
