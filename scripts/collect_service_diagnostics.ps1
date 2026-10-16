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
           $entry.event -in @('READY','STARTING','RUNNING','STOPPED','EXIT','FATAL','LATCHED','PROBE','UNAVAILABLE','HEALTHY','DEGRADED','STALLED','TELEMETRY_UNAVAILABLE','UNCLASSIFIED')) {
          $source=$null
          if($null -ne $entry.source){$source=('{0}:{1}:{2}' -f $entry.source.file,$entry.source.function,$entry.source.line)}
          [pscustomobject]@{
            Service=$name
            Event=$entry.event
            Utc=$entry.time
            ExitReason=$entry.exit_reason
            ExceptionCategory=$entry.exception_category
            ExceptionClass=$entry.exception_class
            Stage=$entry.stage
            GateCode=$entry.gate_code
            FailingComponent=$entry.failing_component
            Source=$source
          }
        }
      } catch { Write-Output 'DIAGNOSTIC_RECORD_REJECTED' }
    }
  }
}
Write-Host '=== SCM events ==='
Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager';StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue |
  Where-Object {$_.Message -match 'CyberDefender'} |
  Select-Object -First 40 TimeCreated,Id,LevelDisplayName | Format-List
