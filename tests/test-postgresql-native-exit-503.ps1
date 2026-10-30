#!/usr/bin/env pwsh
# Regression: failed Chocolatey native exit must be observable as LASTEXITCODE,
# NEVER prematurely short-circuit three attempts and strict signed-byte EDB.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = Get-Content (Join-Path $PSScriptRoot '..\scripts\install-postgresql.ps1') -Raw
$need = @(
  '$PSNativeCommandUseErrorActionPreference = $false',
  '$code = $LASTEXITCODE',
  '$maxAttempts = 3',
  'if ($successCodes -notcontains $code)',
  'if ($feedOutageCount -ne $maxAttempts)',
  'Get-FileHash -LiteralPath $installer -Algorithm SHA256',
  '$length -ne $pin.Bytes',
  'Chocolatey failed after $maxAttempts attempts, without verified V2'
)
foreach ($pattern in $need) {
  if (-not $source.Contains($pattern)) { throw "R08 native 503 regression missing guard: $pattern" }
}
$nativePref = $PSNativeCommandUseErrorActionPreference
try {
  $PSNativeCommandUseErrorActionPreference = $false
  # Actual child native command exits 1; ErrorActionPreference=Stop remains
  # active while $LASTEXITCODE is read as the explicit safe denial decision.
  & pwsh -NoLogo -NoProfile -NonInteractive -Command 'exit 1' 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 1) { throw "R08 native command exit code not observable" }
  if ($ErrorActionPreference -ne 'Stop') { throw "PowerShell safety preference weakened" }
} finally {
  $PSNativeCommandUseErrorActionPreference = $nativePref
}
Write-Host 'R08_NATIVE_503_EXIT_CAPTURE_AND_STRICT_3_ATTEMPT_EDB_SHA256_GUARDS_PASS'
