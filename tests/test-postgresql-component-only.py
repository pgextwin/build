#!/usr/bin/env python3
"""Fail-closed offline regression against archived, successful five-major Chocolatey pilot."""
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
old = (ROOT / "scripts/install-postgresql.ps1").read_text(encoding="utf-8")
new = (ROOT / "scripts/install-postgresql-component-only.ps1").read_text(encoding="utf-8")
workflow = (ROOT / "tests/fixtures/historical-workflows/chocolatey-components-benchmark.yml").read_text(encoding="utf-8")
metadata = json.loads((ROOT / "metadata/postgresql.json").read_text(encoding="utf-8"))

# The proven previous PR #110 approach is mandatory and must not disappear.
assert '--ia "--enable-components server,commandlinetools --disable-components pgAdmin,stackbuilder --create_shortcuts 0 --install_runtimes 0"' in old
assert "--params \"/Password:postgres\"" in old
assert "$maxAttempts = 3" in old
assert [x["major"] for x in metadata["postgresql"]] == [14, 15, 16, 17, 18]
assert set(re.findall(r"major: (\d+), package: (postgresql\d+), version: '([^']+)'",workflow)) == {
    (str(row["major"]),row["chocolateyPackage"],row["chocolateyVersion"])
    for row in metadata["postgresql"]
}
assert "max-parallel: 5" in workflow and "fail-fast: false" in workflow
assert "github.event_name == 'pull_request'" in workflow
assert "permissions:\n  contents: read" in workflow
assert "persist-credentials: false" in workflow
assert "timeout-minutes: 30" in workflow
assert "repository: pgextwin/plpgsql_check" in workflow
assert "ref: c5b759074db6c8713f8aebed873eb6be8e64513d" in workflow
assert "ref: 0ac96adc13b34d071c4be8ba0ec4f73e6e7520f5" in workflow

line = next(x.strip() for x in new.splitlines() if x.strip().startswith("& choco install "))
assert line.count("--ia") == 1
assert '"--enable-components server,commandlinetools --disable-components pgAdmin,stackbuilder --create_shortcuts 0 --install_runtimes 0"' in line
assert '"--version=$ChocolateyVersion"' in line
assert '--params "/Password:postgres"' in line
assert '--override' not in line and '--force' not in line
assert all(v in new for v in (
    "$maxAttempts = 3",
    "$successCodes = @(0, 1641, 3010)",
    "if ($successCodes -notcontains $exit)",
    "throw \"Chocolatey PG$Major failed",
    "include\\server\\postgres.h",
    "lib\\postgres.lib",
    "bin\\postgres.exe",
    "bin\\initdb.exe",
    "share\\extension\\plpgsql.control",
    "GITHUB_STEP_SUMMARY",
    "PGEXTWIN_CHOCO_MINIMUM",
))
for item in (
    "Compile pinned plpgsql_check with real MSVC DLL and 48 exports",
    "CREATE EXTENSION and invalid-record-field regression against real PG",
    "Install DLL and extension SQL into real PostgreSQL",
    "CHOCOLATEY_COMPONENTS_REAL_BUILD_SQL_SMOKE=PASS",
):
    assert item in workflow, item
for forbidden in ("gh release", "gh workflow run", "contents: write", "id-token: write",
                  "attestations: write", "continue-on-error:", "|| true", "schedule:",
                  "workflow_dispatch:", "pull_request_target:"):
    assert forbidden not in workflow, forbidden
print("PASS: five PGs, proven Chocolatey exclusion, explicit server/CLI only, fail closed, real SQL, never publish")
