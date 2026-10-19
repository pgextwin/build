#!/usr/bin/env python3
"""Offline contract checks for fail-closed Chocolatey/EDB installation flags."""
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
script = (ROOT / "scripts/install-postgresql.ps1").read_text(encoding="utf-8")
meta = json.loads((ROOT / "metadata/postgresql.json").read_text(encoding="utf-8"))
assert {v["major"] for v in meta["postgresql"]} == {14, 15, 16, 17, 18}
for v in meta["postgresql"]:
    assert v["chocolateyPackage"] == f'postgresql{v["major"]}'
    assert re.fullmatch(r"\d+\.\d+\.\d+", v["chocolateyVersion"])
line = next(x.strip() for x in script.splitlines() if x.strip().startswith("& choco install "))
assert line.count("--ia") == 1
assert '--ia "--enable-components server,commandlinetools --disable-components pgAdmin,stackbuilder --create_shortcuts 0 --install_runtimes 0"' in line
assert '"--version=$ChocolateyVersion"' in line
assert '--params "/Password:postgres"' in line
assert "--override" not in line and "--force" not in line
assert "for ($attempt = 1; $attempt -le $maxAttempts; $attempt++)" in script
assert "$maxAttempts = 3" in script
assert "$successCodes = @(0, 1641, 3010)" in script
assert "if ($successCodes -notcontains $code)" in script
assert "throw \"Chocolatey failed after $maxAttempts attempts" in script
assert 'include\\server\\postgres.h' in script
assert 'lib\\postgres.lib' in script
assert 'bin\\postgres.exe' in script and 'bin\\initdb.exe' in script
assert 'bin\\psql.exe' in script and 'share\\extension\\plpgsql.control' in script
assert '"PGROOT=$pgRoot" >> $env:GITHUB_ENV' in script
assert '"$pgRoot\\bin" >> $env:GITHUB_PATH' in script
print("PASS: PG14-18 metadata, Chocolatey installer args, retry and fail-closed contract")
