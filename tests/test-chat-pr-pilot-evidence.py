#!/usr/bin/env python3
"""Phase C nonpublishing plpgsql_check evidence collector allow/deny fixtures."""
import base64
from copy import deepcopy
import importlib.util
import json
import io
from unittest import mock
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pilot", ROOT / "scripts" / "chat-pr-pilot-evidence.py")
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)

REPO = pilot.PILOT
BASE = "a" * 40
AFTER = "b" * 40
HEAD = "c" * 40
CANDIDATE = "d" * 40
OPERATOR = "HumanOperator"
TAG = "v2.10.14-windows.3"
AUTH_PATH = ".github/release-authorizations/" + TAG + ".json"
B = "repos/" + REPO + "/"


def fixture():
    record = {
        "schemaVersion": 1, "type": "pgextwin-chat-authorized-release",
        "repository": REPO, "releaseTag": TAG, "packagingMainSha": BASE,
        "candidatePr": 12, "candidateHeadSha": CANDIDATE,
        "candidateRunId": 900, "decisionRunId": 901,
        "operatorLogin": OPERATOR, "confirmRelease": "PUBLISH",
    }
    source = json.dumps(record, sort_keys=True, separators=(",", ":"))
    sha = pilot.auth.git_blob_sha(source.encode("utf-8"))
    pr = {"number": 33, "merged": True, "state": "closed",
          "merge_commit_sha": AFTER,
          "base": {"ref": "main", "repo": {"full_name": REPO}},
          "head": {"ref": "auth-release/" + TAG, "sha": HEAD,
                   "repo": {"full_name": REPO}},
          "user": {"login": OPERATOR, "type": "User"},
          "merged_by": {"login": OPERATOR, "type": "User"}}
    objects = {
        B + "branches/main": {"protected": True, "commit": {"sha": AFTER}},
        B + "commits/" + AFTER: {
            "sha": AFTER, "parents": [{"sha": BASE}],
            "files": [{"filename": AUTH_PATH, "status": "added", "sha": sha}]},
        B + "commits/" + AFTER + "/pulls": [{"number": 33,
                                              "merge_commit_sha": AFTER}],
        B + "pulls/33": pr,
        B + "pulls/33/files?per_page=100": [
            {"filename": AUTH_PATH, "status": "added", "sha": sha}],
        B + "contents/" + AUTH_PATH + "?ref=" + AFTER: {
            "sha": sha, "encoding": "base64",
            "content": base64.b64encode(source.encode("utf-8")).decode("ascii")},
        B + "branches/main/protection": {
            "required_pull_request_reviews": {
                "required_approving_review_count": 0,
                "bypass_pull_request_allowances": {
                    "users": [], "teams": [], "apps": []}},
            "required_status_checks": {
                "strict": True, "checks": [{"context": "Windows summary", "app_id": 1234}]},
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False}},
        B + "commits/" + HEAD + "/check-runs?per_page=100": {
            "total_count": 1,
            "check_runs": [{"name": "Windows summary", "head_sha": HEAD,
                            "status": "completed", "conclusion": "success",
                            "app": {"id": 1234}}]},
        B + "pulls/12": {
            "merged": True, "user": {"login": "github-actions[bot]"},
            "head": {"sha": CANDIDATE, "ref": "auto-candidate/test"}},
        B + "actions/runs/900": {"id": 900, "run_attempt": 1,
                                  "repository": {"full_name": REPO},
                                  "head_branch": "auto-candidate/test",
                                  "event": "workflow_dispatch",
                                  "status": "completed", "conclusion": "success",
                                  "head_sha": CANDIDATE},
        B + "actions/runs/901": {"id": 901, "run_attempt": 1,
                                  "repository": {"full_name": REPO},
                                  "status": "completed", "conclusion": "success",
                                  "head_branch": "main"},
        B + "git/ref/tags/" + TAG: None,
        B + "releases/tags/" + TAG: None,
    }
    event = {"ref": "refs/heads/main", "before": BASE, "after": AFTER,
             "repository": {"full_name": REPO},
             "sender": {"login": OPERATOR, "type": "User"},
             "created": False, "deleted": False,
             "commits": [{"id": AFTER}]}
    runtime = dict(runtime_repo=REPO, runtime_ref="refs/heads/main",
                   runtime_sha=AFTER, runtime_actor=OPERATOR,
                   allowed_operators={OPERATOR})
    return objects, event, runtime


class FakeApi:
    def __init__(self, objects):
        self.objects = objects
        self.reads = []

    def get(self, path, *, allow_404=False):
        self.reads.append(path)
        if path not in self.objects:
            raise AssertionError("unexpected GitHub read " + path)
        if self.objects[path] is None and not allow_404:
            raise pilot.Blocked("unexpected missing trusted GitHub resource")
        return self.objects[path]


class PilotTests(unittest.TestCase):
    def inspect(self, obj, event, runtime):
        return pilot.inspect_pilot(FakeApi(obj), event, **runtime)

    def test_positive_inert_context_does_not_issue_receipt(self):
        obj, event, runtime = fixture()
        got = self.inspect(obj, event, runtime)
        self.assertEqual(got["status"], "DRY_RUN_CONTEXT_ONLY")
        self.assertFalse(got["publishingEnabled"])
        self.assertFalse(got["publishableReceipt"])
        self.assertEqual(got["authorizationCommit"], AFTER)
        self.assertEqual(got["requiredChecks"], ["Windows summary"])
        self.assertEqual(got["candidateArtifactsAndSignatures"], "NOT_YET_VERIFIED")
        self.assertNotIn("authorizationMode", got)
        self.assertNotIn("status", got.get("candidateArtifactsAndSignatures", ""))

    def test_invalid_actor_event_sha_branch_or_merge_denied(self):
        alterations = [
            lambda o,e,r:r.update(runtime_repo="pgextwin/wal2json"),
            lambda o,e,r:r.update(runtime_ref="refs/heads/dev"),
            lambda o,e,r:r.update(runtime_sha=BASE),
            lambda o,e,r:r.update(runtime_actor="github-actions[bot]"),
            lambda o,e,r:e["sender"].update(login="intruder"),
            lambda o,e,r:e["sender"].update(type="Bot"),
            lambda o,e,r:o[B+"pulls/33"]["user"].update(type="Bot"),
            lambda o,e,r:o[B+"pulls/33"]["merged_by"].update(type="Bot"),
            lambda o,e,r:e.update(before=HEAD),
            lambda o,e,r:o[B+"branches/main"]["commit"].update(sha=HEAD),
            lambda o,e,r:o[B+"commits/"+AFTER]["parents"][0].update(sha=HEAD),
            lambda o,e,r:o[B+"commits/"+AFTER]["files"].append(
                {"filename":".github/workflows/promote.yml","status":"modified"}),
            lambda o,e,r:o[B+"pulls/33"]["merged_by"].update(login="attacker"),
            lambda o,e,r:o[B+"commits/"+AFTER+"/pulls"].append(
                {"number":34, "merge_commit_sha":AFTER}),
        ]
        self.assert_denied(alterations)

    def test_ci_protection_and_bypass_denied(self):
        changes = [
            lambda o,e,r:o[B+"branches/main"].update(protected=False),
            lambda o,e,r:o[B+"branches/main/protection"]["enforce_admins"].update(enabled=False),
            lambda o,e,r:o[B+"branches/main/protection"]["required_pull_request_reviews"].update(required_approving_review_count=1),
            lambda o,e,r:o[B+"branches/main/protection"]["required_pull_request_reviews"]["bypass_pull_request_allowances"]["users"].append({"login":"admin"}),
            lambda o,e,r:o[B+"branches/main/protection"]["required_status_checks"].update(strict=False),
            lambda o,e,r:o[B+"branches/main/protection"]["required_status_checks"]["checks"][0].update(app_id=-1),
            lambda o,e,r:o[B+"commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0].update(head_sha=AFTER),
            lambda o,e,r:o[B+"commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0].update(conclusion="failure"),
            lambda o,e,r:o[B+"commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0].update(conclusion="skipped"),
            lambda o,e,r:o[B+"commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0].update(conclusion="cancelled"),
            lambda o,e,r:o[B+"commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0].update(conclusion="timed_out"),
            lambda o,e,r:o[B+"commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0].update(status="in_progress"),
            lambda o,e,r:o[B+"commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"].append(
                {"name":"Windows summary", "head_sha":HEAD, "status":"completed",
                 "conclusion":"failure", "app":{"id":1234}}),
            lambda o,e,r:o[B+"commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"].append(
                {"name":"Windows summary", "head_sha":HEAD, "status":"completed",
                 "conclusion":"success", "app":{"id":1234}}),
            lambda o,e,r:o[B+"commits/"+HEAD+"/check-runs?per_page=100"].update(total_count=101),
            lambda o,e,r:o[B+"branches/main/protection"]["allow_force_pushes"].update(enabled=True),
        ]
        self.assert_denied(changes)

    def test_forged_json_candidate_and_tag_replay_denied(self):
        changes = [
            lambda o,e,r:o[B+"contents/"+AUTH_PATH+"?ref="+AFTER].update(
                content=base64.b64encode(b'{"confirmRelease":"PUBLISH"}').decode()),
            lambda o,e,r:o[B+"contents/"+AUTH_PATH+"?ref="+AFTER].update(sha="f"*40),
            lambda o,e,r:o[B+"pulls/33/files?per_page=100"][0].update(sha="f"*40),
            lambda o,e,r:o[B+"pulls/12"]["head"].update(sha=HEAD),
            lambda o,e,r:o[B+"pulls/12"]["user"].update(login="attacker"),
            lambda o,e,r:o[B+"actions/runs/900"].update(id=999),
            lambda o,e,r:o[B+"actions/runs/900"].update(run_attempt=2),
            lambda o,e,r:o[B+"actions/runs/900"].update(run_attempt=None),
            lambda o,e,r:o[B+"actions/runs/900"].update(repository={"full_name":"pgextwin/evil"}),
            lambda o,e,r:o[B+"actions/runs/900"].update(head_branch="main"),
            lambda o,e,r:o[B+"actions/runs/901"].update(id=999),
            lambda o,e,r:o[B+"actions/runs/901"].update(run_attempt=2),
            lambda o,e,r:o[B+"actions/runs/901"].update(repository={}),
            lambda o,e,r:o[B+"actions/runs/900"].update(conclusion="failure"),
            lambda o,e,r:o[B+"actions/runs/900"].update(head_sha=HEAD),
            lambda o,e,r:o[B+"actions/runs/901"].update(conclusion="failure"),
            lambda o,e,r:o.update({B+"git/ref/tags/"+TAG: {"ref":"refs/tags/"+TAG}}),
            lambda o,e,r:o.update({B+"releases/tags/"+TAG: {"tag_name":TAG}}),
        ]
        self.assert_denied(changes)

    def test_github_rest_page_truncation_is_denied(self):
        # Even when the returned list contains just one apparent PR, a
        # server-provided next-page Link means uniqueness is not established.
        for link, denied in [
            ("", False),
            ('<https://api.github.com/repos/pgextwin/plpgsql_check/commits/a/pulls?page=2>; rel="next"', True),
            ('<https://api.github.com/repos/pgextwin/plpgsql_check/commits/a/pulls?page=2>; rel=next', True),
        ]:
            with self.subTest(link=link):
                response = io.BytesIO(b'[{"number":33}]')
                response.status = 200
                response.headers = {"Link": link}
                with mock.patch.object(pilot, "urlopen", return_value=response):
                    client = pilot.GitHubReadOnly("read-only-token")
                    if denied:
                        with self.assertRaises(pilot.Blocked):
                            client.get(B + "commits/" + AFTER + "/pulls")
                    else:
                        self.assertEqual(
                            client.get(B + "commits/" + AFTER + "/pulls"),
                            [{"number": 33}])

    def assert_denied(self, mutations):
        for i, mutation in enumerate(mutations):
            obj, event, runtime = fixture()
            mutation(obj, event, runtime)
            with self.subTest(index=i), self.assertRaises(
                (pilot.Blocked, pilot.auth.Denied)):
                self.inspect(obj, event, runtime)


if __name__ == "__main__":
    unittest.main()
