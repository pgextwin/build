#!/usr/bin/env python3
"""Hostile completed automatic signed main/push contract: NO GitHub mutations.

All certificate fixtures below are synthetic and NOT Sigstore authentication.
Production callers must run real gh attestation verify and check live GET both
before and after ZIP/SPDX/Grype verification, then apply separate authorization.
"""
import copy
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("completed_publisher_guard",
    ROOT / "scripts/issue-75-publisher-preflight.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
REPO = "pgextwin/pg_ivm"
SHA = "a" * 40
RUN = 12345

def snapshot():
    run = {"id": RUN, "run_attempt": 1,
           "repository": {"full_name": REPO}, "head_sha": SHA,
           "head_branch": "main", "path": guard.PUSH_PATH,
           "event": "push", "status": "completed", "conclusion": "success"}
    jobs = {"jobs": [
        {"id": 100+i, "name": "Shared / "+name, "run_id": RUN,
         "run_attempt": 1, "head_sha": SHA, "status": "completed",
         "conclusion": "success"}
        for i,name in enumerate(guard.SIGNED_PUSH_JOBS)]}
    jobs["total_count"] = len(jobs["jobs"])
    artifacts = {"artifacts": [
        {"name": name, "id": 200+i, "size_in_bytes": 100,
         "expired": False, "workflow_run": {"id":RUN,"head_sha":SHA}}
        for i,name in enumerate(sorted(guard.SIGNED_PUSH_ARTIFACTS))]}
    artifacts["total_count"] = len(artifacts["artifacts"])
    return run,jobs,artifacts

def verify(run,jobs,artifacts, **kwargs):
    return guard.validate_completed_push_snapshot(
        run,jobs,artifacts,repo=kwargs.get("repo",REPO),
        sha=kwargs.get("sha",SHA),run_id=kwargs.get("run_id",RUN),
        attempt=kwargs.get("attempt",1))

class CompletedPushContract(unittest.TestCase):
    def test_original_protected_push_metadata_is_bound_but_not_authorized(self):
        result=verify(*snapshot())
        self.assertEqual(result[:4],(REPO,SHA,RUN,1))
        self.assertEqual(len(result[4]),4)
        self.assertEqual(len(result[5]),2)
        self.assertNotIn("publicationAuthorized",str(result))

    def test_no_rerun_off_main_or_manual_event(self):
        for key,bad in (("event","workflow_dispatch"),("event","schedule"),
                        ("path",guard.PROMOTE_PATH),("head_branch","candidate"),
                        ("head_sha","b"*40),("run_attempt",2),
                        ("status","in_progress"),("conclusion","failure"),
                        ("id",RUN+1),("repository",{"full_name":"pgextwin/orafce"})):
            with self.subTest(key=key,bad=bad):
                run,jobs,assets=snapshot();run[key]=bad
                with self.assertRaises(guard.Deny):
                    verify(run,jobs,assets)
        for bad in (0,2,"1",True):
            with self.subTest(attempt=bad),self.assertRaises(guard.Deny):
                verify(*snapshot(),attempt=bad)

    def test_missing_duplicate_failed_or_cross_run_signed_job(self):
        for variant in ("missing","duplicate","failed","skipped","attempt","id","sha"):
            with self.subTest(variant=variant):
                run,jobs,assets=snapshot()
                if variant=="missing":jobs["jobs"].pop()
                if variant=="duplicate": jobs["jobs"][1]["name"]=jobs["jobs"][0]["name"]
                if variant=="failed": jobs["jobs"][0]["conclusion"]="failure"
                if variant=="skipped":jobs["jobs"][1]["conclusion"]="skipped"
                if variant=="attempt":jobs["jobs"][1]["run_attempt"]=2
                if variant=="id":jobs["jobs"][1]["run_id"]=RUN+1
                if variant=="sha":jobs["jobs"][1]["head_sha"]="b"*40
                jobs["total_count"]=len(jobs["jobs"])
                with self.assertRaises(guard.Deny):verify(run,jobs,assets)

    def test_missing_duplicate_expired_cross_run_or_empty_audit(self):
        for variant in ("missing","duplicate","expired","empty","id","sha",
                        "unknown","partial"):
            with self.subTest(variant=variant):
                run,jobs,assets=snapshot()
                if variant=="missing":assets["artifacts"].pop()
                if variant=="duplicate":assets["artifacts"][1]["name"]=assets["artifacts"][0]["name"]
                if variant=="expired":assets["artifacts"][0]["expired"]=True
                if variant=="empty":assets["artifacts"][0]["size_in_bytes"]=0
                if variant=="id":assets["artifacts"][0]["workflow_run"]["id"]=RUN+1
                if variant=="sha":assets["artifacts"][0]["workflow_run"]["head_sha"]="b"*40
                if variant=="unknown":assets["artifacts"][0]["name"]="forged"
                if variant=="partial":assets["total_count"]+=1
                if variant!="partial": assets["total_count"]=len(assets["artifacts"])
                with self.assertRaises(guard.Deny):verify(run,jobs,assets)

    def test_run_job_artifact_snapshot_toctou_detectable(self):
        run,jobs,assets=snapshot()
        original=verify(run,jobs,assets)
        assets["artifacts"][0]["id"]+=1
        self.assertNotEqual(verify(run,jobs,assets),original)

    def test_signed_package_event_default_manual_and_push_is_explicit(self):
        pkg={"source":{"packagingRepository":REPO,"packagingCommit":SHA},
             "upstream":{"commit":"b"*40},
             "buildInfrastructure":{"repository":"pgextwin/build",
                 "workflow":guard.SIGNER_PATH,"commit":guard.SIGNER_SHA},
             "postgresql":{"major":18},
             "workflowRun":{"id":RUN,"attempt":1,
                 "url":f"https://github.com/{REPO}/actions/runs/{RUN}",
                 "event":"workflow_dispatch","ref":"refs/heads/main"}}
        args=dict(major=18,repo=REPO,packaging_sha=SHA,
                  upstream_sha="b"*40,run_id=RUN,attempt=1)
        guard.validate_pkg(pkg,**args)
        with self.assertRaises(guard.Deny):
            guard.validate_pkg(pkg,**args,event="push")
        pkg["workflowRun"]["event"]="push"
        guard.validate_pkg(pkg,**args,event="push")
        with self.assertRaises(guard.Deny):
            guard.validate_pkg(pkg,**{**args,"attempt":2},event="push")
        with self.assertRaises(guard.Deny):
            guard.validate_pkg(pkg,**args) # Manual mode remains isolated.

    def test_signature_context_push_never_confuses_manual_caller(self):
        # The existing manual Publisher tests check valid synthetic attestations.
        # Here even a valid-looking envelope must be denied for wrong caller.
        with self.assertRaises(guard.Deny):
            guard.verified_claims("[]",predicate=guard.PROVENANCE,repo=REPO,
                packaging_sha=SHA,run_id=RUN,attempt=1,zip_name="x.zip",
                zip_digest="c"*64,sbom={"spdxVersion":"SPDX-2.3"},
                event="push",config_path=guard.PROMOTE_PATH)
        with self.assertRaises(guard.Deny):
            guard.verified_claims("[]",predicate=guard.PROVENANCE,repo=REPO,
                packaging_sha=SHA,run_id=RUN,attempt=2,zip_name="x.zip",
                zip_digest="c"*64,sbom={"spdxVersion":"SPDX-2.3"},
                event="push",config_path=guard.PUSH_PATH)
        with self.assertRaises(guard.Deny):
            guard.verified_claims("[]",predicate=guard.PROVENANCE,repo=REPO,
                packaging_sha=SHA,run_id=RUN,attempt=1,zip_name="x.zip",
                zip_digest="c"*64,sbom={"spdxVersion":"SPDX-2.3"},
                event="schedule",config_path=guard.PUSH_PATH)

if __name__ == "__main__":
    unittest.main()
