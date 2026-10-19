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
line = next(x.strip() for x in script.splitlines() if "& choco install " in x)
assert line.count("--ia") == 1
assert '--ia "--enable-components server,commandlinetools --disable-components pgAdmin,stackbuilder --create_shortcuts 0 --install_runtimes 0"' in line
assert '"--version=$ChocolateyVersion"' in line
assert '--params "/Password:postgres"' in line
assert "--override" not in line and "--force" not in line
assert "for ($attempt = 1; $attempt -le $maxAttempts; $attempt++)" in script
assert "$maxAttempts = 3" in script
assert "$successCodes = @(0, 1641, 3010)" in script
assert "if ($successCodes -notcontains $code)" in script
assert "$feedOutageCount = 0" in script
assert "$feedOutageCount++" in script
assert "if ($feedOutageCount -ne $maxAttempts)" in script
assert "Chocolatey failed after $maxAttempts attempts, without verified V2 HTTP 502/503/504 in every attempt; EDB fallback DENY" in script
assert "502 \\(Bad Gateway\\)" in script
assert "503 \\(Service Unavailable\\)" in script
assert "504 \\(Gateway Timeout\\)" in script
assert "https://community.chocolatey.org/api/v2/" in script
assert script.index("if ($feedOutageCount -ne $maxAttempts)") < script.index("Start-Process -FilePath $installer")
# Chocolatey failure is not success: permit only five previously byte-verified
# EDB EXEs and fail closed on any discrepancy or unsafe installer exit.
receipt = json.loads((ROOT / "evidence/issue-75/edb-pg14-18-exe-byte-observations-20261017.json").read_text(encoding="utf-8"))
pins = receipt["sources"][0]["sourcePackages"]
assert len(pins) == 5 and receipt["verifiedInstallerCount"] == 5
for package in pins:
    major = package["package"].removeprefix("postgresql")
    assert major in {"14", "15", "16", "17", "18"}
    assert f"'{major}' = @{{" in script
    assert package["checksum64"] in script
    assert package["version"] in script
    assert package["url64"].removeprefix("https://get.enterprisedb.com/postgresql/") in script
    assert str(next(x["bytesRead"] for source in receipt["sources"] for x in source["downloadedInstallers"] if x["package"] == package["package"])) in script
assert "if (-not $edb.ContainsKey($majorKey)" in script
assert 'throw "Chocolatey failure; direct installer fallback DENY for unknown package/version"' in script
assert "Invoke-WebRequest -Uri $uri -OutFile $installer" in script
assert "Get-FileHash -LiteralPath $installer -Algorithm SHA256" in script
assert "if ($actual -cne $pin.Sha256)" in script
assert "if ($length -ne $pin.Bytes)" in script
assert "Start-Process -FilePath $installer" in script
assert "if ($successCodes -notcontains $process.ExitCode)" in script
assert script.index("if ($actual -cne $pin.Sha256)") < script.index("Start-Process -FilePath $installer")
assert "Remove-Item -LiteralPath $installer -Force" in script
assert 'include\\server\\postgres.h' in script
assert 'lib\\postgres.lib' in script
assert 'bin\\postgres.exe' in script and 'bin\\initdb.exe' in script
assert 'bin\\psql.exe' in script and 'share\\extension\\plpgsql.control' in script
assert '"PGROOT=$pgRoot" >> $env:GITHUB_ENV' in script
assert '"$pgRoot\\bin" >> $env:GITHUB_PATH' in script
print("PASS: PG14-18 metadata, Chocolatey installer args, retry and fail-closed contract")
