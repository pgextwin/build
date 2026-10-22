#!/usr/bin/env python3
"""Hostile fixture suite for native PR Windows CI authentication."""
import importlib.util
from copy import deepcopy
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "native", ROOT/"scripts"/"verify-native-pr-run.py")
native=importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
SHA="a"*40
MERGE="b"*40
BASE="c"*40
REPO="pgextwin/pg_ivm"
BRANCH="auto-candidate/"+"d"*20
PR=28
RUN=39760879597

def fixture():
    return dict(
        repo=REPO,
        run={"id":RUN,"name":"Windows CI/CD","event":"pull_request",
             "status":"completed","conclusion":"success",
             "head_repository":{"full_name":REPO},
             "head_sha":SHA,"head_branch":BRANCH,
             "pull_requests":[{"number":PR,
                                "head":{"ref":BRANCH,"sha":SHA,
                                        "repo":{"name":"pg_ivm"}},
                                "base":{"ref":"main","sha":BASE,
                                        "repo":{"name":"pg_ivm"}}}]},
        pr={"number":PR,"state":"open","merged":False,"draft":True,
            "body":"<!-- pgextwin-candidate:v1:"+"d"*20+" -->",
            "head":{"ref":BRANCH,"sha":SHA,"repo":{"full_name":REPO}},
            "base":{"ref":"main","sha":BASE,"repo":{"full_name":REPO}},
            "user":{"login":"github-actions[bot]"},
            "merge_commit_sha":MERGE},
        pr_files=[{"filename":"config/extension.json",
                   "status":"modified","sha":"e"*40}],
        merge_ref={"object":{"type":"commit","sha":MERGE}},
        main={"name":"main","protected":True,"commit":{"sha":BASE},
              "protection":{"required_status_checks":{"checks":[
                  {"context":"Windows required summary","app_id":15368}]}}},
        checks={"total_count":1,"check_runs":[
            {"name":"Windows required summary","head_sha":SHA,
             "app":{"id":15368},"status":"completed","conclusion":"success"}]}
    )

class NativeRunTests(unittest.TestCase):
    def test_pass_is_not_release_authorization(self):
        x=native.validate(**fixture())
        self.assertEqual(x["status"],"NATIVE_PR_CI_AUTHENTICATED_NOT_PUBLISHABLE")
        self.assertEqual(x["packagingMergeSha"],MERGE)
        self.assertEqual(x["candidateRunId"],RUN)
        for field in ("candidateAuditVerified","signedArtifactsVerified",
                      "publishableReceipt","publicationAuthorized"):
            self.assertIs(x[field],False)

    def test_forged_ci_and_pr_provenance_denied(self):
        mutations=[
            lambda x:x.update(repo="evil/pg_ivm"),
            lambda x:x["run"].update(event="workflow_dispatch"),
            lambda x:x["run"].update(status="queued"),
            lambda x:x["run"].update(conclusion="failure"),
            lambda x:x["run"].update(head_sha=MERGE),
            lambda x:x["run"].update(head_branch="main"),
            lambda x:x["run"].update(pull_requests=[]),
            lambda x:x["run"]["pull_requests"].append(
                deepcopy(x["run"]["pull_requests"][0])),
            lambda x:x["run"]["head_repository"].update(full_name="evil/repo"),
            lambda x:x["run"]["pull_requests"][0].update(number=999),
            lambda x:x["pr"].update(merged=True),
            lambda x:x["pr"].update(state="closed"),
            lambda x:x["pr"].update(merge_commit_sha=SHA),
            lambda x:x["pr"].update(body=""),
            lambda x:x["pr"].update(number=0),
            lambda x:x["pr"]["head"].update(sha=MERGE),
            lambda x:x["pr"]["head"].update(ref="untrusted"),
            lambda x:x["pr"]["base"].update(ref="release/bypass"),
            lambda x:x["pr"]["user"].update(login="attacker"),
            lambda x:x["pr_files"].append(
                {"filename":".github/workflows/promote.yml",
                 "sha":"f"*40,"status":"modified"}),
            lambda x:x["pr_files"][0].update(filename="config/approval.json"),
            lambda x:x["pr_files"][0].update(status="added"),
            lambda x:x["merge_ref"]["object"].update(sha=SHA),
            lambda x:x["merge_ref"]["object"].update(type="tag"),
            lambda x:x["main"].update(protected=False),
            lambda x:x["main"]["commit"].update(sha=MERGE),
            lambda x:x["main"]["protection"]["required_status_checks"].update(checks=[]),
            lambda x:x["main"]["protection"]["required_status_checks"]["checks"][0].update(app_id=999),
            lambda x:x["checks"].update(total_count=100),
            lambda x:x["checks"]["check_runs"][0].update(head_sha=MERGE),
            lambda x:x["checks"]["check_runs"][0].update(conclusion="action_required"),
            lambda x:x["checks"]["check_runs"][0].update(status="in_progress"),
            lambda x:x["checks"]["check_runs"][0]["app"].update(id=999),
            lambda x:x["checks"]["check_runs"].append(
                deepcopy(x["checks"]["check_runs"][0])),
        ]
        for i,mutate in enumerate(mutations):
            with self.subTest(i=i),self.assertRaises(native.Denied):
                values=fixture()
                mutate(values)
                native.validate(**values)

if __name__=="__main__":
    unittest.main()
