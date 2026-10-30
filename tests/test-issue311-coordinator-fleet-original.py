#!/usr/bin/env python3
"""Offline fail-closed static and event gate regression for App 17 fleet."""
import ast
import importlib.util
import os
import re
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
assert "global REQUEST_ID, REQUEST_PATH" in main
assert 'terminal["requestId"] = REQUEST_ID' in main
pattern=r"\.github/execution-requests/(r-20261030-r06prepare[a-z0-9-]{4,40})\.json"
assert re.fullmatch(pattern,".github/execution-requests/r-20261030-r06prepareautochain04.json")
for unsafe in [
 ".github/execution-requests/r-20261029-r06prepareold01.json",
 ".github/execution-requests/r-20261030-r06appcas17terminal001.json",
 ".github/execution-requests/../r-20261030-r06prepareother04.json",
 ".github/execution-requests/r-20261030-r06prepareautochain04.yml",
]:
    assert re.fullmatch(pattern,unsafe) is None
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

# R07-01 admitted child must be the actual original App workflow's five
# successful PG14–18 reusable Windows jobs and required summary (not a
# separate successful PR/main push). Old 16 App-only originals stay strict.
helper_spec = importlib.util.spec_from_file_location("r07_helper",helper_path)
helper_mod = importlib.util.module_from_spec(helper_spec)
helper_spec.loader.exec_module(helper_mod)
def record(mapping):
    return {"total_count":len(mapping),
            "jobs":[{"name":n,"status":"completed","conclusion":c}
                    for n,c in mapping.items()]}
base_jobs={
    "Original protected PREPARE ZIP verification (NO RELEASE)":"success",
    "Strict App identity and PREPARE source-kind denial tests":"skipped",
}
prefix="R07-01 authenticated App original Windows PG14-18 / "
r07_jobs={
    **base_jobs,
    prefix+"Resolve extension and PostgreSQL matrix":"success",
    **{prefix+f"PostgreSQL {n} / Windows x64":"success"
       for n in range(14,19)},
    "R07-01 Windows required summary":"success",
}
assert helper_mod.verify_original_child_jobs("pgextwin/orafce",record(r07_jobs)) is None
assert helper_mod.verify_original_child_jobs("pgextwin/pg_bigm",record(base_jobs)) is None
def reject_jobs(repo,mapping):
    try:
        helper_mod.verify_original_child_jobs(repo,record(mapping))
    except helper_mod.Denied:
        return
    raise AssertionError("R07 unverified Windows or old App child accepted")
reject_jobs("pgextwin/orafce",base_jobs)
reject_jobs("pgextwin/pg_bigm",r07_jobs)
for field in r07_jobs:
    bad=dict(r07_jobs)
    bad[field]="skipped" if field != "Strict App identity and PREPARE source-kind denial tests" else "success"
    reject_jobs("pgextwin/orafce",bad)
    bad=dict(r07_jobs)
    del bad[field]
    reject_jobs("pgextwin/orafce",bad)
reject_jobs("pgextwin/orafce",{**r07_jobs,"Unverified Windows PG19":"success"})
print("ISSUE311_R07_REAL_APP_CHILD_WINDOWS_STRICT_DENIAL_PASS")

# Original App job now has 5 real Windows package artifacts in addition to
# one receipt; reject extra/old/stale/foreign artifacts and mismatched digests.
def original_art(name, ident, runid=123, digest="a"*64):
    return {"name":name,"id":ident,"expired":False,
            "workflow_run":{"id":runid},"digest":"sha256:"+digest}
receipt=original_art(helper_mod.ARTIFACT,1)
orafce_packages=[
    original_art(f"orafce-pg{n}-windows-x64",n+10) for n in range(14,19)]
def arlist(rows):
    return {"total_count":len(rows),"artifacts":rows}
got, extras=helper_mod.verify_original_child_artifacts(
    "pgextwin/orafce",arlist([receipt,*orafce_packages]),123)
assert got == receipt and len(extras)==5
got,extras=helper_mod.verify_original_child_artifacts(
    "pgextwin/pg_bigm",arlist([receipt]),123)
assert got == receipt and extras=={}
def reject_art(repo,rows):
    try:
        helper_mod.verify_original_child_artifacts(repo,arlist(rows),123)
    except helper_mod.Denied:
        return
    raise AssertionError("untrusted R07 package artifact accepted")
reject_art("pgextwin/orafce",[receipt])
reject_art("pgextwin/pg_bigm",[receipt,*orafce_packages])
for artifact in [receipt,*orafce_packages]:
    reject_art("pgextwin/orafce",[a for a in [receipt,*orafce_packages] if a is not artifact])
reject_art("pgextwin/orafce",[receipt,*orafce_packages,orafce_packages[-1]])
reject_art("pgextwin/orafce",[receipt,*orafce_packages[:-1],original_art("orafce-pg19-windows-x64",19)])
for field, bad in (
    ("expired",True),("digest","sha256:"+"0"*63),
    ("workflow_run",{"id":124}),("id",0)):
    corrupt=dict(orafce_packages[0],**{field:bad})
    reject_art("pgextwin/orafce",[receipt,corrupt,*orafce_packages[1:]])

# R08 App-OIDC pilot extends (never replaces) the exact 9-job R07 original.
# A partial or forged signer/auditor may not be treated as successful 17-fleet.
r08_jobs={
    **r07_jobs,
    "R08 authenticated original App OIDC signing intent (NO PUBLISH)":"success",
    "R08 first independently verified real App OIDC Sigstore bytes (NO PUBLISH)":"success",
    "R08 SECOND independent original-byte OIDC Sigstore verification (NO PUBLISH)":"success",
    "R08 strict independent 2 Sigstore original-byte source agreement (PUBLISH_DENY)":"success",
}
assert helper_mod.verify_original_child_jobs("pgextwin/orafce", record(r08_jobs)) is None
reject_jobs("pgextwin/pg_bigm",r08_jobs)
for job in r08_jobs:
    if job not in r07_jobs:
        forged=dict(r08_jobs)
        forged.pop(job)
        reject_jobs("pgextwin/orafce",forged)
        forged=dict(r08_jobs)
        forged[job]="failure"
        reject_jobs("pgextwin/orafce",forged)
reject_jobs("pgextwin/orafce",{**r08_jobs,"forged extra auditor":"success"})
r08_artifacts=[
    original_art("issue311-r08-app-oidc-intent-nonpublishing",90),
    original_art("issue311-r08-signed-first-nonpublishing",91),
    original_art("issue311-r08-signed-second-nonpublishing",92),
    original_art("issue311-r08-app-oidc-dual-audit-nonpublishing",93),
]
r08_all=[receipt,*orafce_packages,*r08_artifacts]
got,extras=helper_mod.verify_original_child_artifacts(
    "pgextwin/orafce",arlist(r08_all),123,expected_r08=True)
assert got == receipt and len(extras) == 9
for artifact in r08_all:
    try:
        helper_mod.verify_original_child_artifacts(
            "pgextwin/orafce",arlist([r for r in r08_all if r is not artifact]),
            123,expected_r08=True)
    except helper_mod.Denied:
        pass
    else:
        raise AssertionError("R08 original audit artifact missing but accepted")
for repo, expected in (("pgextwin/orafce",False),("pgextwin/pg_bigm",True)):
    try:
        helper_mod.verify_original_child_artifacts(
            repo,arlist(r08_all),123,expected_r08=expected)
    except helper_mod.Denied:
        pass
    else:
        raise AssertionError("R08 signed artifacts laundered to wrong source-kind")
print("ISSUE311_R08_REAL_APP_OIDC_JOB_AND_FOUR_ARTIFACT_ADMISSION_NEGATIVE_PASS")
assert "SafeArchiveRedirect" in helper
assert "ISSUE311_R07_ORIGINAL_WINDOWS_ZIP_ACTUAL_SHA256" in helper_path.read_text()
print("ISSUE311_R07_REAL_WINDOWS_PACKAGE_ZIP_NEGATIVE_PASS")

# R08 genuine signed App original has real Windows PG14–18 and two separately
# verified Sigstore jobs within ONE local Run. Bounded GET only, orafce only.
assert 'original_child_max_polls = 240 if name == "orafce" else 70' in main
assert 'for _ in range(original_child_max_polls):' in main
assert 'time.sleep(10)' in main
assert main.count('m.api("POST", m.POST') == 1
assert main.count('result["dispatchCount"] = 1') == 1
assert 'max_workers=4' in main
print("ISSUE311_R08_SIGNED_ORAFCE_FINITE_CHILD_POLL_POLICY_PASS")
