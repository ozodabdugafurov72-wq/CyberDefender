$ErrorActionPreference="Stop"
. (Join-Path $PSScriptRoot "runtime_env.ps1")
$ControlDir=Join-Path $StateDir "control_plane"; New-Item -ItemType Directory -Force -Path $ControlDir | Out-Null
$FleetToken=Join-Path $SecretDir "fleet_token.txt"
if(-not(Test-Path $FleetToken)){
  $bytes=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
  [Convert]::ToBase64String($bytes)|Set-Content $FleetToken -Encoding ascii -NoNewline
}
$env:CYBERDEFENDER_DISTRIBUTION_DB=Join-Path $ControlDir "distribution.db"
$env:CYBERDEFENDER_FLEET_TOKEN_FILE=$FleetToken
Set-Location $ProjectRoot
& $VenvPython -m control_plane.distribution_server
