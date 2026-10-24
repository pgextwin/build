#!/usr/bin/env python3
"""Hostile offline Publisher intake; no external network and NEVER publish."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "publisher_intake", ROOT / "scripts/publisher-candidate-intake.py")
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)
REPO = "pgextwin/pg_ivm"
SHA = "a"*40

def fleet():
    return {"schemaVersion":1, "releasePolicy":"manual-only",
            "entries":[{"repository": REPO, "mode":"BUILD",
                        "candidateEnabled":True, "releasePolicy":"manual-only"}]}

def evidence():
    run = {"id":1234, "run_attempt":1, "status":"completed",
           "conclusion":"success", "event":"push",
           "head_sha":SHA, "head_branch":"main",
           "path":".github/workflows/update-watch.yml",
           "repository":{"full_name":REPO}}
    jobs = {"total_count":4,"jobs":[{"name":name,"status":"completed",
                                    "conclusion":"success"} for name in mod.SIGNED_JOBS]}
    artifacts = {"total_count":2, "artifacts":[
        {"name":name, "size_in_bytes":100, "expired":False}
        for name in sorted(mod.SIGNED_ARTIFACTS)]}
    return {"branch":{"name":"main","protected":True,"commit":{"sha":SHA}},
            "runs":{"workflow_runs":[run]},
            "jobs":jobs,"artifacts":artifacts}

def examine(d, repo=REPO):
    return mod.examine(repo, d["branch"],d["runs"],
                       read_jobs=lambda rid:d["jobs"],
                       read_artifacts=lambda rid:d["artifacts"])

class IntakeTests(unittest.TestCase):
    def test_eligible_structural_candidate_is_explicitly_nonpublishing(self):
        r=examine(evidence())
        self.assertEqual(r["status"],"SIGNED_RUN_FOUND_REVERIFICATION_REQUIRED")
        self.assertEqual(r["candidateRunId"],1234)
        self.assertFalse(r["publicationAuthorized"])
        self.assertTrue(r["needsRealSigstoreReverification"])
        self.assertFalse(r["publisherTokenRequested"])

    def test_generic_windows_or_skipped_schedule_never_qualifies(self):
        for mutate in [
            lambda d:d["runs"]["workflow_runs"][0].update(event="schedule"),
            lambda d:d["runs"]["workflow_runs"][0].update(event="workflow_run"),
            lambda d:d["runs"]["workflow_runs"][0].update(path=".github/workflows/windows.yml"),
            lambda d:d["runs"]["workflow_runs"][0].update(head_sha="b"*40),
            lambda d:d["runs"]["workflow_runs"][0].update(head_branch="other"),
        ]:
            with self.subTest(mutate=str(mutate)):
                d=evidence();mutate(d)
                self.assertEqual(examine(d)["status"],
                                 "NO_ORIGINAL_SIGNED_PUSH_ON_CURRENT_MAIN")
        d=evidence();d["runs"]["workflow_runs"][0].update(status="completed",conclusion="skipped")
        self.assertEqual(examine(d)["status"],"ORIGINAL_PUSH_NOT_SUCCESSFULLY_ATTESTED")

    def test_original_run_identity_fail_closed(self):
        for changes in ({"run_attempt":2},{"id":True},{"status":"in_progress"},
                        {"conclusion":"failure"},
                        {"repository":{"full_name":"pgextwin/orafce"}}):
            d=evidence();d["runs"]["workflow_runs"][0].update(changes)
            self.assertEqual(examine(d)["status"],"ORIGINAL_PUSH_NOT_SUCCESSFULLY_ATTESTED")

    def test_protected_main_job_signing_and_artifact_fail_closed(self):
        d=evidence();d["branch"]["protected"]=False
        with self.assertRaises(mod.Denied):examine(d)
        d=evidence();d["jobs"]["jobs"][-1]["conclusion"]="skipped"
        self.assertEqual(examine(d)["status"],"SIGNED_JOB_CHAIN_INCOMPLETE")
        d=evidence();d["jobs"]["jobs"].append(deepcopy(d["jobs"]["jobs"][0]))
        d["jobs"]["total_count"]=5
        self.assertEqual(examine(d)["status"],"SIGNED_JOB_CHAIN_INCOMPLETE")
        d=evidence();d["artifacts"]["artifacts"][0]["expired"]=True
        self.assertEqual(examine(d)["status"],"SIGNED_AUDIT_ARTIFACTS_INCOMPLETE")
        d=evidence();d["artifacts"]["artifacts"][0]["size_in_bytes"]=0
        self.assertEqual(examine(d)["status"],"SIGNED_AUDIT_ARTIFACTS_INCOMPLETE")
        d=evidence();d["artifacts"]["artifacts"][0]["name"]="irrelevant"
        self.assertEqual(examine(d)["status"],"SIGNED_AUDIT_ARTIFACTS_INCOMPLETE")

    def test_partial_pages_denied_instead_of_fake_success(self):
        for part in ("runs","jobs","artifacts"):
            with self.subTest(part=part):
                d=evidence()
                if part=="runs":
                    d[part]["workflow_runs"]= [deepcopy(d[part]["workflow_runs"][0])]*51
                else:
                    d[part]["total_count"]=101
                with self.assertRaises(mod.Denied):
                    examine(d)

    def test_dynamic_fleet_and_fail_closed_api_error(self):
        base=evidence()
        def get(repo,suffix):
            if "branches/" in suffix:return deepcopy(base["branch"])
            if "workflows/" in suffix:return deepcopy(base["runs"])
            if "/jobs?" in suffix:return deepcopy(base["jobs"])
            if "/artifacts?" in suffix:return deepcopy(base["artifacts"])
            raise AssertionError(suffix)
        result=mod.scan(fleet(),get=get)
        self.assertEqual(result["repositoryCount"],1)
        self.assertEqual(result["counts"],{"SIGNED_RUN_FOUND_REVERIFICATION_REQUIRED":1})
        for key in ("publicationAuthorized","publishableReceipt","publisherWriteAuthorized",
                    "verifiedSignedReleaseArtifacts","genuineScheduleVerified"):
            self.assertFalse(result[key])
        future=deepcopy(fleet())
        future["entries"].append({**future["entries"][0],
                                  "repository":"pgextwin/future_extension"})
        result=mod.scan(future,get=lambda *_: (_ for _ in ()).throw(ConnectionError("API down")))
        self.assertEqual(result["repositoryCount"],2)
        self.assertEqual(result["counts"],{"INDETERMINATE":2})
        self.assertFalse(result["publicationAuthorized"])

    def test_fleet_rejects_duplicate_and_non_manual_scope(self):
        f=fleet();f["entries"].append(deepcopy(f["entries"][0]))
        with self.assertRaises(mod.Denied):
            mod.scan(f,get=lambda *_:None)
        f=fleet();f["entries"][0]["releasePolicy"]="automatic"
        with self.assertRaises(ValueError):
            mod.scan(f,get=lambda *_:None)

    def test_never_invokes_write_or_publisher_key(self):
        d=evidence()
        with patch("subprocess.run",side_effect=AssertionError("network called")):
            row=examine(d)
            self.assertFalse(row["publicationAuthorized"])
        # The authenticated client path whitelist is deliberately GET-only.
        with patch.dict(mod.os.environ,{"GH_TOKEN":"synthetic-only"}):
            with self.assertRaises(mod.Denied):
                mod.github(REPO,"releases")
            with self.assertRaises(mod.Denied):
                mod.github(REPO,"actions/runs/1/jobs?per_page=100/anything")

if __name__=="__main__":
    unittest.main()
