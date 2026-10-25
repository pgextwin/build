#!/usr/bin/env python3
"""Hostile nonpublishing tests for verified PR-CI-audit to main squash join."""
from copy import deepcopy
from datetime import date
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "postmerge", ROOT / "scripts" / "automatic-postmerge-audit-bridge.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
FLEET = json.loads((ROOT / "metadata/automation-fleet.json").read_text("utf-8"))
REPO = "pgextwin/pg_ivm"
BASE, MERGE, HEAD, BLOB = "a"*40, "b"*40, "c"*40, "d"*40
UPSTREAM = "678c37861080aa221b859cefaca98725646dbf7c"
BRANCH = "auto-candidate/"+"e"*20


def fixture():
    return dict(
        repository=REPO,
        today=date(2026, 10, 22),
        fleet=deepcopy(FLEET),
        manifest={"name": "pg_ivm", "postgresql": {"majors": list(range(14,19))},
                  "upstream": {"repository": "sraoss/pg_ivm",
                               "ref": "v1.17", "version": "1.17", "commit": UPSTREAM}},
        lifecycle={"schemaVersion":1,"postgresql":[
            {"major": m, "eol": "2030-11-12"} for m in range(14,19)]},
        event={"ref": "refs/heads/main", "repository": {"full_name": REPO},
               "sender": {"login": "ShutenOishi"},
               "before": BASE, "after": MERGE,
               "created": False, "deleted": False,
               "commits": [{"id": MERGE}]},
        commit={"sha": MERGE, "parents": [{"sha": BASE}],
                "files": [{"filename":"config/extension.json",
                           "status":"modified","sha":BLOB}]},
        pr={"number":28,"state":"closed","merged":True,"draft":False,
            "merge_commit_sha":MERGE,
            "head":{"ref":BRANCH,"sha":HEAD,"repo":{"full_name":REPO}},
            "base":{"ref":"main","repo":{"full_name":REPO}},
            "user":{"login":"github-actions[bot]"},
            "merged_by":{"login":"ShutenOishi"},
            "body":"<!-- pgextwin-candidate:v1:"+"e"*20+" -->"},
        pr_files=[{"filename":"config/extension.json","status":"modified","sha":BLOB}],
        branch={"name":"main","protected":True,"commit":{"sha":MERGE},
                "protection":{"required_status_checks":{"checks":[
                    {"context":"Windows required summary","app_id":15368}]}}},
        checks={"total_count":1,"check_runs":[
            {"id":701,"check_suite":{"id":700},"name":"Windows required summary","head_sha":HEAD,
             "details_url":"https://github.com/"+REPO+"/actions/runs/39769754052/job/701",
             "status":"completed","conclusion":"success","app":{"id":15368}}]},
        ci_run={"id":39769754052,"check_suite_id":700,"run_attempt":1,
                "path":".github/workflows/windows.yml","name":"Windows CI/CD",
                "head_repository":{"full_name":REPO},"head_sha":HEAD,
                "event":"pull_request","status":"completed","conclusion":"success"},
        bound={"status":"BOUND_NATIVE_CANDIDATE_AUDIT_NONPUBLISHING",
               "repository":REPO,"candidatePr":28,"candidateHeadSha":HEAD,
               "mainShaAtAudit":BASE,"candidateMergeSha":"f"*40,
               "candidateCiRunId":39769754052,"nativeAuditRunId":39771145795,
               "nativeAuditArtifactId":12422372611,
               "majors":list(range(14,19)),
               "sourcesAndZipDigests":[{"major":m,"sourceSha":UPSTREAM,
                                       "zipSha256":"0"*64} for m in range(14,19)],
               "signedArtifactsVerified":False,"publishableReceipt":False,
               "publicationAuthorized":False},
    )


class PostmergeCandidateTests(unittest.TestCase):
    def test_trusted_fixture_is_never_release_or_publisher_receipt(self):
        out=gate.verify(**fixture())
        self.assertEqual(out["status"],"MERGED_NATIVE_CANDIDATE_NONPUBLISHING")
        self.assertEqual(out["candidatePr"],28)
        self.assertEqual(out["releaseTagStem"],"v1.17")
        self.assertEqual(out["maintainedMajors"],[14,15,16,17,18])
        for f in ("publicationAuthorized","publishableReceipt",
                  "signedArtifactsVerified","automaticReleaseEnabled"):
            self.assertIs(out[f],False)
        self.assertNotIn("authorizationMode",out)
        self.assertNotIn("confirmRelease",out)
        self.assertNotIn("releaseTag",out)

    def test_native_check_suite_is_required_after_merge_with_same_head_dispatch(self):
        args=fixture();native=args["checks"]["check_runs"][0]
        dispatch=deepcopy(native);dispatch.update(id=702,check_suite={"id":699},
            details_url="https://github.com/"+REPO+"/actions/runs/999/job/702")
        args["checks"]["check_runs"].append(dispatch);args["checks"]["total_count"]=2
        out=gate.verify(**args)
        self.assertEqual(out["candidateCheckSuiteId"],700)
        self.assertEqual(out["candidateRequiredCheckRunId"],701)
        for mutate in (
            lambda a:a["ci_run"].update(event="workflow_dispatch"),
            lambda a:a["ci_run"].update(check_suite_id=699),
            lambda a:a["ci_run"].update(id=999),
            lambda a:a["checks"]["check_runs"][0].update(conclusion="failure"),
        ):
            x=deepcopy(args);mutate(x)
            with self.subTest(mutate=str(mutate)),self.assertRaises(gate.Denied):
                gate.verify(**x)

    def test_failure_cases_refuse_publication_and_candidate_merge(self):
        mutations=[
            lambda x: x["fleet"].update(releasePolicy="automatic"),
            lambda x: x["fleet"]["entries"].pop(),
            lambda x: x["fleet"]["entries"].append(deepcopy(x["fleet"]["entries"][0])),
            lambda x: x.update(repository="pgextwin/evil"),
            lambda x: x["event"].update(ref="refs/heads/foo"),
            lambda x: x["event"].update(created=True),
            lambda x: x["event"].update(deleted=True),
            lambda x: x["event"].update(after=HEAD),
            lambda x: x["event"].update(before=HEAD),
            lambda x: x["event"]["sender"].update(login="github-actions[bot]"),
            lambda x: x["event"]["sender"].update(login="OtherUser"),
            lambda x: x["event"].update(commits=[]),
            lambda x: x["event"].update(commits=[{"id":MERGE},{"id":MERGE}]),
            lambda x: x["commit"].update(sha=HEAD),
            lambda x: x["commit"].update(parents=[{"sha":HEAD}]),
            lambda x: x["commit"].update(parents=[{"sha":BASE},{"sha":HEAD}]),
            lambda x: x["commit"]["files"].append(deepcopy(x["commit"]["files"][0])),
            lambda x: x["commit"]["files"][0].update(filename=".github/workflows/promote.yml"),
            lambda x: x["commit"]["files"][0].update(sha=HEAD),
            lambda x: x["pr"].update(merged=False),
            lambda x: x["pr"].update(state="open"),
            lambda x: x["pr"].update(draft=True),
            lambda x: x["pr"].update(merge_commit_sha=HEAD),
            lambda x: x["pr"].update(number=0),
            lambda x: x["pr"]["user"].update(login="SomeUser"),
            lambda x: x["pr"]["merged_by"].update(login="OtherUser"),
            lambda x: x["pr"]["head"].update(ref="main"),
            lambda x: x["pr"]["head"].update(sha=MERGE),
            lambda x: x["pr"]["base"].update(ref="dev"),
            lambda x: x["pr"].update(body=""),
            lambda x: x["pr_files"].append(deepcopy(x["pr_files"][0])),
            lambda x: x["pr_files"][0].update(sha=HEAD),
            lambda x: x["branch"].update(protected=False),
            lambda x: x["branch"].update(name="test"),
            lambda x: x["branch"]["commit"].update(sha=HEAD),
            lambda x: x["branch"]["protection"]["required_status_checks"].update(checks=[]),
            lambda x: x["branch"]["protection"]["required_status_checks"]["checks"][0].update(app_id=999),
            lambda x: x["checks"].update(total_count=100),
            lambda x: x["checks"]["check_runs"][0].update(conclusion="action_required"),
            lambda x: x["checks"]["check_runs"][0].update(head_sha=MERGE),
            lambda x: x["checks"]["check_runs"][0]["app"].update(id=999),
            lambda x: x["checks"]["check_runs"].append(deepcopy(x["checks"]["check_runs"][0])),
            lambda x: x["checks"].update(total_count=2),
            lambda x: x["bound"].update(status="VERIFIED_MANUAL_DISPATCH"),
            lambda x: x["bound"].update(candidatePr=29),
            lambda x: x["bound"].update(candidateHeadSha=MERGE),
            lambda x: x["bound"].update(mainShaAtAudit=HEAD),
            lambda x: x["bound"].update(candidateCiRunId=0),
            lambda x: x["bound"].update(nativeAuditArtifactId=0),
            lambda x: x["bound"].update(publicationAuthorized=True),
            lambda x: x["bound"].update(publishableReceipt=True),
            lambda x: x["bound"]["sourcesAndZipDigests"].pop(),
            lambda x: x["bound"]["sourcesAndZipDigests"][0].update(sourceSha=HEAD),
            lambda x: x["bound"]["sourcesAndZipDigests"][0].update(zipSha256="0"*63),
            lambda x: x["manifest"]["upstream"].update(commit=HEAD),
            lambda x: x["manifest"]["upstream"].update(repository="evil/pg_ivm"),
            lambda x: x["lifecycle"].update(postgresql=[]),
        ]
        for i, change in enumerate(mutations):
            with self.subTest(index=i),self.assertRaises(gate.Denied):
                a=fixture()
                change(a)
                gate.verify(**a)


if __name__=="__main__":
    unittest.main()
