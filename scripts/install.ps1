param(
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $ProjectRoot

if ($Python) {
    $PythonExe = $Python
    $PythonPrefix = @()
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonExe = "py"
    $PythonPrefix = @("-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonExe = "python"
    $PythonPrefix = @()
} else {
    throw "Python 3.13+ topilmadi. Avval Python o'rnating."
}

Write-Host "[1/5] Python tekshirilmoqda..."
& $PythonExe @PythonPrefix -c "import sys; assert sys.version_info >= (3,13), 'Python 3.13+ required'; print(sys.version)"

Write-Host "[2/5] Virtual environment yaratilmoqda..."
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    & $PythonExe @PythonPrefix -m venv .venv
}

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

Write-Host "[3/5] Dependencies o'rnatilmoqda..."
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r requirements.txt

Write-Host "[4/5] Runtime state va secret tayyorlanmoqda..."
$Base = Join-Path $env:LOCALAPPDATA "CyberDefender"
$StateDir = Join-Path $Base "state"
$SecretDir = Join-Path $Base "secrets"
$DataDir = Join-Path $StateDir "data"
$DataDb = Join-Path $DataDir "cyberdefender.db"
$KeyFile = Join-Path $SecretDir "storage_key.b64"
New-Item -ItemType Directory -Force -Path $StateDir, $SecretDir, $DataDir | Out-Null

if (-not (Test-Path $KeyFile)) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [Convert]::ToBase64String($bytes) | Set-Content -Path $KeyFile -Encoding ascii -NoNewline
}

try {
    & icacls.exe $SecretDir /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
} catch {
    Write-Warning "Secret ACL avtomatik cheklanmadi; papka ruxsatlarini qo'lda tekshiring."
}

Write-Host "[5/5] Smoke import tekshiruvi..."
& $VenvPython -c "import sqlite3; from agent.main import CyberDefenderRuntime; from agent.bus.event_bus import EventBus; from agent.data.sqlite_repository import SQLiteDataRepository; print('Runtime', CyberDefenderRuntime.VERSION, '| EventBus', EventBus.VERSION, '| SQLite', sqlite3.sqlite_version, '| DataRepo', SQLiteDataRepository.VERSION)"

Write-Host ""
Write-Host "CyberDefender o'rnatildi."
Write-Host "State: $StateDir"
Write-Host "Data:  $DataDb"
Write-Host "Key:   $KeyFile"
Write-Host "Agent: .\scripts\run_agent.ps1"
Write-Host "Owner: .\scripts\run_owner_dashboard.ps1"
Write-Host "Verify: .\scripts\verify.ps1"
