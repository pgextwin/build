[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Join-Path ([System.IO.Path]::GetTempPath()) ("pgextwin-package-metadata-" + [guid]::NewGuid().ToString("N"))
$dist = Join-Path $root "dist"
$stage = Join-Path $dist "demo_ext-v1.0-pg18-windows-x64"
$extract = Join-Path $root "extract"

try {
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $root "upstream") | Out-Null

    @"
demo_ext Windows binary package
===============================

Upstream repository: example/demo_ext
Upstream ref:        v1.0
Upstream commit:     1111111111111111111111111111111111111111
demo_ext version:    1.0
PostgreSQL major:    18
PostgreSQL tested:   18.6
Architecture:        Windows x64
Compiler:            MSVC
"@ | Set-Content -Path (Join-Path $stage "PACKAGE-INFO.txt") -Encoding utf8

    "payload" | Set-Content -Path (Join-Path $stage "demo.txt") -Encoding utf8
    $zipPath = Join-Path $dist "demo_ext-v1.0-pg18-windows-x64.zip"
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -CompressionLevel Optimal

    & (Join-Path $PSScriptRoot "..\scripts\finalize-package.ps1") -ExtensionName "demo_ext" -UpstreamDir (Join-Path $root "upstream") -UpstreamRepository "example/demo_ext" -UpstreamRef "v1.0" -UpstreamVersion "1.0" -PostgreSqlMajor 18 -PostgreSqlTestedVersion "18.6" -ChocolateyPackage "postgresql18" -ChocolateyPackageVersion "18.6.5" -PackagingRepository "pgextwin/demo_ext" -BuildRepository "pgextwin/build" -BuildCommit "3333333333333333333333333333333333333333" -ReusableWorkflow ".github/workflows/build-extension.yml" -BuildMode "normal" -WorkflowRunId 1234567890 -WorkflowRunAttempt 2 -WorkflowRunUrl "https://github.com/pgextwin/demo_ext/actions/runs/1234567890" -WorkflowEvent "pull_request" -WorkflowRef "refs/pull/42/merge" -DistDir $dist -PackagingCommit "2222222222222222222222222222222222222222" -UpstreamCommit "1111111111111111111111111111111111111111" -BuildCheckoutCommit "3333333333333333333333333333333333333333" -CompilerVersion "19.44.35221.0" -RunnerOs "Windows" -RunnerArchitecture "X64" -RunnerImageOs "win25" -RunnerImageVersion "20261001.1"

    $metadataPath = Join-Path $stage "PACKAGE-INFO.json"
    if (-not (Test-Path $metadataPath)) {
        throw "PACKAGE-INFO.json was not generated."
    }

    $metadata = Get-Content -Path $metadataPath -Raw | ConvertFrom-Json
    if ($metadata.schemaVersion -ne 1) { throw "Unexpected schemaVersion." }
    if ($metadata.buildMode -ne "normal") { throw "Unexpected buildMode." }
    if ($metadata.upstream.commit -ne "1111111111111111111111111111111111111111") { throw "Unexpected upstream commit." }
    if ($metadata.source.packagingCommit -ne "2222222222222222222222222222222222222222") { throw "Unexpected packaging commit." }
    if ($metadata.buildInfrastructure.commit -ne "3333333333333333333333333333333333333333") { throw "Unexpected build commit." }
    if ($metadata.workflowRun.attempt -ne 2) { throw "Unexpected run attempt." }
    if ($metadata.toolchain.compilerVersion -ne "19.44.35221.0") { throw "Unexpected compiler version." }

    $raw = Get-Content -Path $metadataPath -Raw
    foreach ($forbidden in @("attestationId", "attestationUrl", "sha256", "buildTimestamp", $root)) {
        if ($raw.Contains($forbidden)) {
            throw "Generated metadata contains forbidden value or field: $forbidden"
        }
    }

    python (Join-Path $PSScriptRoot "..\scripts\validate-package-metadata.py") --schema (Join-Path $PSScriptRoot "..\schema\package-info.schema.json") --file $metadataPath
    if ($LASTEXITCODE -ne 0) {
        throw "Generated metadata failed schema validation."
    }

    Expand-Archive -Path $zipPath -DestinationPath $extract -Force
    foreach ($required in @("PACKAGE-INFO.txt", "PACKAGE-INFO.json", "demo.txt")) {
        if (-not (Test-Path (Join-Path $extract $required))) {
            throw "Final ZIP is missing required file: $required"
        }
    }

    python (Join-Path $PSScriptRoot "..\scripts\validate-package-metadata.py") --schema (Join-Path $PSScriptRoot "..\schema\package-info.schema.json") --zip $zipPath
    if ($LASTEXITCODE -ne 0) {
        throw "Embedded metadata failed schema validation."
    }

    Write-Host "Package metadata finalizer tests passed."
}
finally {
    if (Test-Path $root) {
        Remove-Item -Path $root -Recurse -Force
    }
}
