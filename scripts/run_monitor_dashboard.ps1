$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "runtime_env.ps1")
Set-Location $ProjectRoot
$Secure = Read-Host "Legacy monitor uchun yangi lokal admin parolini kiriting" -AsSecureString
$Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
try {
    $env:CYBERDEFENDER_DASHBOARD_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
    & $VenvPython .\dashboard\server.py
} finally {
    if ($Bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr) }
    Remove-Item Env:CYBERDEFENDER_DASHBOARD_PASSWORD -ErrorAction SilentlyContinue
}
