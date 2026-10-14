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
    # The original fixture represents an MSVC-built native distribution.
    # Give it a DLL payload so compiler attribution remains applicable.
    New-Item -ItemType Directory -Force -Path (Join-Path $stage "lib") | Out-Null
    "mock-DLL" | Set-Content -Path (Join-Path $stage "lib/demo_ext.dll") -Encoding ascii
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


    # Issue #75: run the actual signer-pinned and current finalizer from local
    # fixture files. Only synthetic staged ZIPs; no GitHub CLI/network/token.
    $historicalFinalizer = Join-Path $PSScriptRoot "fixtures/issue-75-pre-g4/finalize-package.ps1"
    $currentFinalizer = Join-Path $PSScriptRoot "../scripts/finalize-package.ps1"
    $fixedBuildSha = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
    $fixedPackagingSha = "881efc3c170e89ee68fd336f2e224fbd462c1c10"
    $fixedUpstreamSha = "ccdbcce9de51f01e1138c270aeb9fe4e26c6e911"

    function Invoke-PreG4Finalizer {
        param(
            [Parameter(Mandatory = $true)][string]$CaseName,
            [Parameter(Mandatory = $true)][string]$ScriptPath,
            [bool]$HasDll = $false,
            [string]$EventName = "workflow_dispatch",
            [string]$RefName = "refs/heads/main",
            [string]$CheckoutSha = $fixedBuildSha
        )
        $caseRoot = Join-Path $root $CaseName
        $caseDist = Join-Path $caseRoot "dist"
        $caseStage = Join-Path $caseDist "demo_ext-v1.0-pg18-windows-x64"
        New-Item -ItemType Directory -Path $caseStage -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $caseRoot "upstream") -Force | Out-Null
        @"
demo_ext Windows binary package
===============================
Upstream repository: example/demo_ext
Upstream ref:        v1.0
Upstream commit:     $fixedUpstreamSha
demo_ext version:    1.0
PostgreSQL major:    18
PostgreSQL tested:   18.6
Architecture:        Windows x64
Compiler:            MSVC
"@ | Set-Content -Path (Join-Path $caseStage "PACKAGE-INFO.txt") -Encoding utf8
        "SELECT 1;" | Set-Content -Path (Join-Path $caseStage "demo_ext.sql") -Encoding utf8
        if ($HasDll) {
            New-Item -ItemType Directory -Path (Join-Path $caseStage "lib") -Force | Out-Null
            "synthetic native payload" | Set-Content -Path (Join-Path $caseStage "lib/demo_ext.dll") -Encoding ascii
        }
        $caseZip = Join-Path $caseDist "demo_ext-v1.0-pg18-windows-x64.zip"
        Compress-Archive -Path (Join-Path $caseStage "*") -DestinationPath $caseZip
        & $ScriptPath -ExtensionName "demo_ext" -UpstreamDir (Join-Path $caseRoot "upstream") -UpstreamRepository "example/demo_ext" -UpstreamRef "v1.0" -UpstreamVersion "1.0" -PostgreSqlMajor 18 -PostgreSqlTestedVersion "18.6" -ChocolateyPackage "postgresql18" -ChocolateyPackageVersion "18.6.5" -PackagingRepository "pgextwin/demo_ext" -BuildRepository "pgextwin/build" -BuildCommit $fixedBuildSha -ReusableWorkflow ".github/workflows/build-extension-attested.yml" -BuildMode "release-attested" -WorkflowRunId 987654321 -WorkflowRunAttempt 2 -WorkflowRunUrl "https://github.com/pgextwin/demo_ext/actions/runs/987654321" -WorkflowEvent $EventName -WorkflowRef $RefName -DistDir $caseDist -PackagingCommit $fixedPackagingSha -UpstreamCommit $fixedUpstreamSha -BuildCheckoutCommit $CheckoutSha -CompilerVersion "19.44.35221.0" -RunnerOs "Windows" -RunnerArchitecture "X64" -RunnerImageOs "win25" -RunnerImageVersion "20261001.1"
        $generated = Get-Content -Path (Join-Path $caseStage "PACKAGE-INFO.json") -Raw | ConvertFrom-Json
        $unpacked = Join-Path $caseRoot "unpacked"
        Expand-Archive -Path $caseZip -DestinationPath $unpacked
        $embedded = Get-Content -Path (Join-Path $unpacked "PACKAGE-INFO.json") -Raw | ConvertFrom-Json
        if (($generated | ConvertTo-Json -Depth 10 -Compress) -ne ($embedded | ConvertTo-Json -Depth 10 -Compress)) {
            throw "Embedded PACKAGE-INFO was not retained: $CaseName"
        }
        return $generated
    }

    foreach ($kind in @("sql", "native")) {
        $withDll = $kind -eq "native"
        $old = Invoke-PreG4Finalizer -CaseName "frozen-$kind" -ScriptPath $historicalFinalizer -HasDll $withDll
        $new = Invoke-PreG4Finalizer -CaseName "current-$kind" -ScriptPath $currentFinalizer -HasDll $withDll
        foreach ($value in @($old, $new)) {
            if ($value.buildMode -ne "release-attested" -or $value.postgresql.major -ne 18) { throw "PG or mode mismatch" }
            if ($value.upstream.commit -ne $fixedUpstreamSha -or $value.source.packagingCommit -ne $fixedPackagingSha) { throw "SHA mismatch" }
            if ($value.buildInfrastructure.commit -ne $fixedBuildSha) { throw "Signer job SHA mismatch" }
            if ($value.workflowRun.id -ne 987654321 -or $value.workflowRun.attempt -ne 2 -or $value.workflowRun.event -ne "workflow_dispatch" -or $value.workflowRun.ref -ne "refs/heads/main") { throw "Workflow provenance mismatch" }
        }
        if ($withDll) {
            if ($old.toolchain.compiler -ne "MSVC" -or $new.toolchain.compiler -ne "MSVC" -or $old.toolchain.compilerVersion -ne $new.toolchain.compilerVersion) { throw "Native compiler metadata differs" }
        }
        else {
            if ($old.toolchain.compiler -ne "MSVC" -or $new.toolchain.compiler -ne "not-applicable" -or $null -ne $new.toolchain.compilerVersion) { throw "SQL-only compiler boundary not detected" }
        }
    }

    # The historical finalizer DOES accept invalid attested origins. This
    # deliberately records non-equivalence; the current finalizer must deny.
    $null = Invoke-PreG4Finalizer -CaseName "old-wrong-event" -ScriptPath $historicalFinalizer -EventName "pull_request"
    $null = Invoke-PreG4Finalizer -CaseName "old-wrong-ref" -ScriptPath $historicalFinalizer -RefName "refs/heads/feature"
    foreach ($case in @(
        @{ Name = "new-wrong-event"; Event = "pull_request"; Ref = "refs/heads/main"; Checkout = $fixedBuildSha },
        @{ Name = "new-wrong-ref"; Event = "workflow_dispatch"; Ref = "refs/heads/feature"; Checkout = $fixedBuildSha },
        @{ Name = "new-wrong-checkout"; Event = "workflow_dispatch"; Ref = "refs/heads/main"; Checkout = ("f" * 40) },
        @{ Name = "old-wrong-checkout"; Event = "workflow_dispatch"; Ref = "refs/heads/main"; Checkout = ("f" * 40) }
    )) {
        $target = if ($case.Name.StartsWith("old")) { $historicalFinalizer } else { $currentFinalizer }
        $denied = $false
        try {
            $null = Invoke-PreG4Finalizer -CaseName $case.Name -ScriptPath $target -EventName $case.Event -RefName $case.Ref -CheckoutSha $case.Checkout
        }
        catch {
            $denied = $true
        }
        if (-not $denied) { throw "Untrusted attested provenance accepted: $($case.Name)" }
    }
    Write-Host "Issue #75 old/new immutable signer finalizer comparison passed (nonpublishable)."

    Write-Host "Package metadata finalizer tests passed."
}
finally {
    if (Test-Path $root) {
        Remove-Item -Path $root -Recurse -Force
    }
}
