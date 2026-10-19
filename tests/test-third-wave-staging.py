#!/usr/bin/env python3
"""Static deny-by-default third-wave repository staging checks; not a Windows acceptance claim."""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "templates" / "third-wave"
SPECS = {
    "pgtap": ("theory/pgtap", "1.3.4", "968eb53a33114e83042b3bdb0c664b5b80cf8bdf"),
    "pg_variables": ("postgrespro/pg_variables", "1.2.1", "1d1bfe26a5e2eec6dda761565e1307d679b1072b"),
    "pg_store_plans": ("ossc-db/pg_store_plans", "1.10", "e802804d4d2763ad3b32fc8fcf9f218c61cc475f"),
}
from jsonschema import Draft202012Validator

schema = json.loads((ROOT / "schema" / "extension.schema.json").read_text())
contract_schema = json.loads((ROOT / "schema" / "test-contract.schema.json").read_text())
for name, (upstream, version, sha) in SPECS.items():
    path = STAGE / name
    manifest = json.loads((path / "config" / "extension.json").read_text())
    contract = json.loads((path / "config" / "test-contract.json").read_text())
    Draft202012Validator(schema).validate(manifest)
    Draft202012Validator(contract_schema).validate(contract)
    assert manifest["name"] == name
    assert manifest["upstream"]["repository"] == upstream
    assert manifest["upstream"]["version"] == version
    assert manifest["upstream"]["commit"] == sha
    assert re.fullmatch(r"[0-9a-f]{40}", sha)
    assert manifest["postgresql"]["majors"] == [14, 15, 16, 17, 18]
    assert contract["extension"] == name
    assert contract["functionalScenarios"]
    for hook in ("build", "install", "smoke-test", "package"):
        assert (path / "windows" / "ci" / (hook + ".ps1")).is_file()
    assert (path / "windows" / "ci" / "test-feature.sql").is_file()
    assert (path / "LICENSE").is_file()
    for safety in ("candidate-build.json", "release-promotion.json"):
        data = json.loads((path / "config" / safety).read_text())
        assert data["enabled"] is False, (name, safety)
    for workflow in ("windows.yml", "promote.yml", "update-watch.yml"):
        assert (path / ".github" / "workflows" / workflow).is_file()
    subprocess.run([sys.executable, str(ROOT / "scripts" / "validate-test-contract.py"),
                    "--schema", str(ROOT / "schema" / "test-contract.schema.json"),
                    "--contract", str(path / "config" / "test-contract.json"),
                    "--extension-config", str(path / "config" / "extension.json"),
                    "--repository-root", str(path)], check=True)
pg=STAGE / "pgtap" / "windows" / "ci"
assert "no DLL" in (pg / "build.ps1").read_text()
assert "not ok 2" in (pg / "smoke-test.ps1").read_text()
plans=STAGE / "pg_store_plans" / "windows" / "ci"
assert "shared_preload_libraries=pg_store_plans" in (plans / "smoke-test.ps1").read_text()
assert "pgextwin_plan_probe" in (plans / "test-feature.sql").read_text()
print("Third-wave PG14-18 static schema, smoke contracts and publication-deny staging passed.")
