#!/usr/bin/env python3
"""Offline Step 21 promotion denial matrix. No Release or API mutations."""
import importlib.util
from pathlib import Path
import copy
import unittest
import sys

p = Path(__file__).resolve().parents[1] / "scripts" / "promotion-gate.py"
spec = importlib.util.spec_from_file_location("promotion_gate", p)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

COMMIT = "a" * 40
MAIN = "b" * 40
HEAD = "c" * 40
IDENT = "d" * 20
TAG = "v2.10.14-windows.1"

def fixtures():
    policy = {"schemaVersion": 1, "allowedRepositories": [g.REPO], "releasePolicy": "manual-approval"}
    local = {"schemaVersion": 1, "enabled": True, "releasePolicy": "manual-approval"}
    ext = {"name": "plpgsql_check", "upstream": {"repository": "okbob/plpgsql_check",
           "ref": "v2.10.14", "version": "2.10.14", "commit": COMMIT},
           "postgresql": {"majors": [15, 16, 17, 18]}}
    lifecycle = {"schemaVersion": 1, "postgresql":
                 [{"major": m, "eol": "2099-11-12"} for m in [14,15,16,17,18,19]]}
    branch = "auto-candidate/" + IDENT
    candidate_pr = {"number": 123, "head": {"ref": branch, "sha": HEAD},
                    "body": "<!-- pgextwin-candidate:v1:" + IDENT + " -->",
                    "user": {"login": "github-actions[bot]"}}
    approval_pr = {"number": 124}
    candidate_run = {"id": 555, "status": "completed", "conclusion": "success",
                     "event": "workflow_dispatch", "head_branch": branch, "head_sha": HEAD}
    decision_run = {"id": 444, "status": "completed", "conclusion": "success",
                    "head_branch": "main"}
    decision = {"schemaVersion": 1, "status": "candidate", "branch": branch,
                "candidateId": IDENT, "extension": "plpgsql_check",
                "repository": "okbob/plpgsql_check", "releasePolicy": "manual-only",
                "updates": [{"major": None, "commit": COMMIT, "ref": "v2.10.14", "version": "2.10.14"}]}
    audit = {"schemaVersion": 1, "status": "VERIFIED", "matrixResult": "success",
             "extension": "plpgsql_check", "runId": 555, "branch": branch,
             "branchSha": HEAD, "majors": [
                 {"major": m, "status": "SUCCESS", "sourceSha": COMMIT,
                  "zipSha256": "f"*64, "zip": "x.zip", "sbom": "x.spdx.json",
                  "grype": "x.vulnerabilities.json"} for m in [15,16,17,18]]}
    approval = {"schemaVersion": 1, "status": "APPROVED", "candidatePr": 123,
                "candidateRunId": 555, "decisionRunId": 444, "candidateId": IDENT,
                "upstreamCommit": COMMIT, "releaseTag": TAG,
                "licenseReviewed": True, "windowsCompatibilityReviewed": True,
                "sourceChangesReviewed": True, "testContractReviewed": True,
                "requiredMajors": [15,16,17,18]}
    return [policy, local, ext, lifecycle, approval, decision, audit,
            candidate_pr, approval_pr, candidate_run, decision_run, MAIN, TAG]

class Promotion(unittest.TestCase):
    def test_matching_approved_candidate_is_allowed_offline(self):
        self.assertEqual(g.verify(*fixtures())["status"], "VERIFIED_APPROVED")

    def test_fail_closed_cases(self):
        changes = {
            "unapproved": (4, lambda x: x.update(status="PENDING")),
            "policy-off": (0, lambda x: x.update(allowedRepositories=[])),
            "local-off": (1, lambda x: x.update(enabled=False)),
            "wrong-upstream": (2, lambda x: x["upstream"].update(commit="e"*40)),
            "missing-major": (6, lambda x: x["majors"].pop()),
            "duplicate-major": (6, lambda x: x["majors"][3].update(major=17)),
            "bad-spdx": (6, lambda x: x["majors"][0].update(sbom="")),
            "no-verified-audit": (6, lambda x: x.update(status="FAILED")),
            "audit-wrong-run": (6, lambda x: x.update(runId=900)),
            "not-a-bot": (7, lambda x: x["user"].update(login="ordinary-user")),
            "not-owned": (7, lambda x: x.update(body="hi")),
            "candidate-ci-failed": (9, lambda x: x.update(conclusion="failure")),
            "watch-ci-failed": (10, lambda x: x.update(conclusion="failure")),
            "PG19-included": (2, lambda x: x["postgresql"]["majors"].append(19)),
            "decision-sha-changed": (5, lambda x: x["updates"][0].update(commit="c"*40)),
            "export-review-missing": (4, lambda x: x.update(sourceChangesReviewed=False)),
        }
        for name,(index,change) in changes.items():
            with self.subTest(name=name):
                f = fixtures()
                change(f[index])
                with self.assertRaises(g.Denied):
                    g.verify(*f)

    def test_existing_tag_cannot_match_different_manifest(self):
        f=fixtures()
        f[-1]="v2.10.13-windows.1"
        with self.assertRaises(g.Denied):
            g.verify(*f)


    def test_postgresql14_supported_with_matching_full_matrix(self):
        f = fixtures()
        f[2]["postgresql"]["majors"] = [14,15,16,17,18]
        sample = dict(f[6]["majors"][0])
        sample["major"] = 14
        f[6]["majors"].insert(0, sample)
        f[4]["requiredMajors"] = [14,15,16,17,18]
        self.assertEqual(g.verify(*f)["majors"], [14,15,16,17,18])

    def test_postgresql14_eol_excludes_major_without_failing_release(self):
        f = fixtures()
        f[2]["postgresql"]["majors"] = [14,15,16,17,18]
        f[3]["postgresql"][0]["eol"] = "2000-01-01"
        self.assertEqual(g.verify(*f)["majors"], [15,16,17,18])

if __name__ == "__main__":
    unittest.main()
