#!/usr/bin/env python3
"""Offline fail-closed static and event gate regression for App 17 fleet."""
import ast
import importlib.util
import os
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
main_path = root / "scripts/issue311-coordinator-fleet-local-prepare.py"
helper_path = root / "scripts/issue311-coordinator-fleet-local-helper.py"
main = main_path.read_text(encoding="utf-8")
helper = helper_path.read_text(encoding="utf-8")
compile(main, str(main_path), "exec")
compile(helper, str(helper_path), "exec")
tree = ast.parse(main)
table = next(ast.literal_eval(x.value) for x in tree.body
             if isinstance(x, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "LOCAL_IDS" for t in x.targets))
assert len(table) == len(set(table)) == len(set(table.values())) == 17
assert "pg_store_plans" in table and "orafce" in table
assert all(x.startswith("r-20261030-r06coordlocal") for x in table.values())
assert "r-20261030-r06preparecoordfleet03" in main
assert "ThreadPoolExecutor(max_workers=4)" in main
assert "compare/" not in main
assert "commit.get(\"files\", [])" in main
assert "source_digest" in main and '"sourceZipSha256": source_digest' in main
assert "identity.revoke_401(token)" in main
assert "need(len(found) <= 1" in main
assert 'result["dispatchCount"] = 1' in main
assert '"durableCasVerified": False' in main
assert 'runtimeEnabled": False' in main
assert "publicationAuthorized" in main
assert "CHILDREN_17_ORIGINAL_ZIP_VERIFIED_CAS_PENDING" in main
assert 'm.verify_original_child_archive(token, child, r)' in main
assert 'm.check_source(r)' in main
assert "repos/pgextwin/orafce/" not in helper  # helper reads only selected REPO
assert "set(minted.get(\"permissions\", {})) <= {\"actions\", \"metadata\"}" in main
for disallowed in ("release create", "git push", "PUBLISH_ELIGIBLE", "repos/pgextwin/catalog/releases"):
    assert disallowed not in main
spec = importlib.util.spec_from_file_location("r06fleet", main_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert {"pgextwin/" + n for n in module.LOCAL_IDS} == module.identity.EXPECTED_REPOS
with patch.dict(os.environ, {
    "GITHUB_REPOSITORY": "pgextwin/build",
    "GITHUB_EVENT_NAME": "pull_request",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_WORKFLOW": module.LISTENER,
    "GITHUB_RUN_ATTEMPT": "1"}, clear=True):
    try:
        module.source_original()
    except ValueError as e:
        assert "R06_APP_FLEET_DENY" in str(e)
    else:
        raise AssertionError("untrusted PR accepted as real central source")
print("ISSUE311_APP_17_FLEET_NEGATIVE_POLICY_PASS")
