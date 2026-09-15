$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Base = Join-Path $env:LOCALAPPDATA "CyberDefender"
$StateDir = Join-Path $Base "state"
$SecretDir = Join-Path $Base "secrets"
$KeyFile = Join-Path $SecretDir "storage_key.b64"
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment topilmadi. Avval .\scripts\install.ps1 ni ishga tushiring."
}
if (-not (Test-Path $KeyFile)) {
    throw "Storage key topilmadi. Avval .\scripts\install.ps1 ni ishga tushiring."
}

$env:CYBERDEFENDER_ROOT = $ProjectRoot
$env:CYBERDEFENDER_STATE_DIR = $StateDir
$env:CYBERDEFENDER_STORAGE_KEY_B64 = (Get-Content -Raw $KeyFile).Trim()
# Ensure project packages are importable when scripts/tests are launched by file path.
if ([string]::IsNullOrWhiteSpace($env:PYTHONPATH)) {
    $env:PYTHONPATH = $ProjectRoot
} else {
    $paths = $env:PYTHONPATH -split [IO.Path]::PathSeparator
    if ($paths -notcontains $ProjectRoot) {
        $env:PYTHONPATH = $ProjectRoot + [IO.Path]::PathSeparator + $env:PYTHONPATH
    }
}

