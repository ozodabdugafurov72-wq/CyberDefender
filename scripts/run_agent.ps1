$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "runtime_env.ps1")
Set-Location $ProjectRoot
& $VenvPython -m agent.main
