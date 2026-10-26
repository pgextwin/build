#!/usr/bin/env python3
"""Hostile fixtures: a central schedule is a distinct origin, never workflow_run."""
from copy import deepcopy
from datetime import date
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("central_binder",
    ROOT / "scripts" / "bind-central-native-audit.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

REPO = "pgextwin/pg_ivm"
PARENT, CENTRAL, HEAD, MERGE = ("a"*40, "b"*40, "c"*40, "d"*40)
SOURCE = "678c37861080aa221b859cefaca98725646dbf7c"
BRANCH = "auto-candidate/" + "f"*20
RUN, ART, CI, PR = 1001, 2001, 3001, 28
LIFE = {"schemaVersion": 1, "postgresql": [
    {"major": m, "eol": "2030-11-12"} for m in range(14, 19)]}


def fixture():
    ext = {"name": "pg_ivm", "postgresql": {"majors": list(range(14, 19))},
           "upstream": {"repository": "sraoss/pg_ivm", "ref": "v1.17",
                        "version": "1.17", "commit": SOURCE}}
    rows = []
    for major in range(14, 19):
        stem = mod.ident.asset_stem(ext, major)
        rows.append({"major": major, "status": "SUCCESS", "sourceSha": SOURCE,
                     "zipSha256": "0"*64, "zip": stem + ".zip",
                     "sbom": stem + ".spdx.json",
                     "grype": stem + ".vulnerabilities.json"})
    context = {
        "schemaVersion": 1,
        "status": "NATIVE_PR_CI_AUTHENTICATED_NOT_PUBLISHABLE",
        "repository": REPO, "candidatePr": PR, "candidateRunId": CI,
        "candidateHeadSha": HEAD, "packagingMergeSha": MERGE,
        "branch": BRANCH, "matrixResult": "success",
        "scheduleRecovery": True, "scheduleMainSha": PARENT,
        "candidateAuditVerified": False, "signedArtifactsVerified": False,
        "publishableReceipt": False, "publicationAuthorized": False,
    }
    receipt = {
        "schemaVersion": 1,
        "status": "CENTRAL_GENUINE_SCHEDULE_ORIGINAL_NATIVE_CI_BYTES_VERIFIED_NONPUBLISHING",
        "auditorRepository": "pgextwin/build", "auditorEvent": "schedule",
        "auditorSourceSha": CENTRAL, "targetRepository": REPO,
        "targetMainSha": PARENT, "native": context,
        "candidateAudit": {
            "schemaVersion": 1, "status": "VERIFIED",
            "originEvent": "pull_request", "matrixResult": "success",
            "extension": "pg_ivm", "runId": CI, "branchSha": HEAD,
            "branch": BRANCH, "majors": rows,
        },
        "signedArtifactsVerified": False, "publishableReceipt": False,
        "publicationAuthorized": False,
    }
    run = {
        "id": RUN, "event": "schedule", "status": "completed",
        "conclusion": "success", "head_branch": "main",
        "head_sha": CENTRAL, "run_attempt": 1,
        "path": ".github/workflows/fleet-upstream-watch.yml",
        "repository": {"full_name": "pgextwin/build"},
    }
    jobs = {"total_count": 2, "jobs": [
        {"id": 9001, "run_id": RUN, "name": "readonly-fleet",
         "status": "completed", "conclusion": "success"},
        {"id": 9002, "run_id": RUN,
         "name": mod.WORKFLOWS[run["path"]],
         "status": "completed", "conclusion": "success"},
    ]}
    artifacts = {"total_count": 1, "artifacts": [{
        "id": ART, "name": "registered-original-native-pr-audits",
        "size_in_bytes": 5000, "expired": False,
        "workflow_run": {"id": RUN, "head_sha": CENTRAL},
    }]}
    ci = {"id": CI, "head_sha": HEAD, "head_branch": BRANCH,
          "event": "pull_request", "name": "Windows CI/CD",
          "status": "completed", "conclusion": "success",
          "run_attempt": 2, "head_repository": {"full_name": REPO}}
    return receipt, run, jobs, artifacts, ci, ext


class CentralBinderTests(unittest.TestCase):
    def check(self, mutate=None):
        data = list(deepcopy(fixture()))
        if mutate:
            mutate(*data)
        receipt, run, jobs, artifacts, ci, ext = data
        return mod.join(receipt=receipt, schedule_run=run, jobs=jobs,
                        artifacts=artifacts, ci_run=ci, ext=ext,
                        lifecycle=deepcopy(LIFE), repository=REPO,
                        parent_main_sha=PARENT, today=date(2026, 10, 26))

    def test_real_schedule_and_original_bytes_only_allow_nonpublishing_witness(self):
        bound = self.check()
        self.assertEqual(bound["status"], "BOUND_NATIVE_CANDIDATE_AUDIT_NONPUBLISHING")
        self.assertEqual(bound["nativeAuditProvenance"], "CENTRAL_GENUINE_SCHEDULE")
        self.assertEqual(bound["nativeAuditRunId"], RUN)
        self.assertEqual(bound["nativeAuditArtifactId"], ART)
        self.assertEqual(bound["candidateCiRunId"], CI)
        self.assertEqual(bound["mainShaAtAudit"], PARENT)
        self.assertEqual(len(bound["sourcesAndZipDigests"]), 5)
        for key in ("signedArtifactsVerified", "publishableReceipt",
                    "publicationAuthorized"):
            self.assertIs(bound[key], False)

    def test_reject_fake_events_skipped_job_and_substituted_artifacts(self):
        attacks = [
            lambda r,s,j,a,c,e: s.update(event="workflow_dispatch"),
            lambda r,s,j,a,c,e: s.update(event="push"),
            lambda r,s,j,a,c,e: s.update(conclusion="failure"),
            lambda r,s,j,a,c,e: s.update(path=".github/workflows/evil.yml"),
            lambda r,s,j,a,c,e: s["repository"].update(full_name=REPO),
            lambda r,s,j,a,c,e: s.update(head_sha="e"*40),
            lambda r,s,j,a,c,e: j["jobs"][1].update(conclusion="skipped"),
            lambda r,s,j,a,c,e: j["jobs"][1].update(run_id=999),
            lambda r,s,j,a,c,e: j.update(total_count=3),
            lambda r,s,j,a,c,e: a["artifacts"][0].update(expired=True),
            lambda r,s,j,a,c,e: a["artifacts"][0].update(name="fake"),
            lambda r,s,j,a,c,e: a["artifacts"][0]["workflow_run"].update(id=999),
            lambda r,s,j,a,c,e: r.update(auditorEvent="workflow_dispatch"),
            lambda r,s,j,a,c,e: r.update(targetMainSha="e"*40),
            lambda r,s,j,a,c,e: r.update(publicationAuthorized=True),
            lambda r,s,j,a,c,e: r["native"].update(scheduleRecovery=False),
            lambda r,s,j,a,c,e: r["native"].update(candidateHeadSha="e"*40),
            lambda r,s,j,a,c,e: r["candidateAudit"].update(originEvent="workflow_dispatch"),
            lambda r,s,j,a,c,e: r["candidateAudit"]["majors"][0].update(sourceSha="e"*40),
            lambda r,s,j,a,c,e: r["candidateAudit"]["majors"][0].update(zipSha256="broken"),
            lambda r,s,j,a,c,e: r["candidateAudit"]["majors"].pop(),
            lambda r,s,j,a,c,e: c.update(event="workflow_dispatch"),
            lambda r,s,j,a,c,e: c.update(conclusion="failure"),
            lambda r,s,j,a,c,e: c.update(head_sha="e"*40),
        ]
        for i, attack in enumerate(attacks):
            with self.subTest(i=i), self.assertRaises(mod.Denied):
                self.check(attack)

    def test_dedicated_schedule_workflow_requires_its_own_job(self):
        def dedicated(r, s, j, a, c, e):
            s["path"] = ".github/workflows/recover-native-pr-fleet.yml"
            j["jobs"][1]["name"] = mod.WORKFLOWS[s["path"]]
        self.assertEqual(self.check(dedicated)["nativeAuditRunId"], RUN)
        def fake_dedicated(r, s, j, a, c, e):
            s["path"] = ".github/workflows/recover-native-pr-fleet.yml"
        with self.assertRaises(mod.Denied):
            self.check(fake_dedicated)


if __name__ == "__main__":
    unittest.main()
