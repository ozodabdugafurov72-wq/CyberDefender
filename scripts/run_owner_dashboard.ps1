$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "runtime_env.ps1")
Set-Location $ProjectRoot
Write-Host "Owner dashboard: http://127.0.0.1:8775/owner"
& $VenvPython -m dashboard_owner.server
