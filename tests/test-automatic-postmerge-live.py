#!/usr/bin/env python3
"""Deny-by-default actual protected-main candidate audit REST orchestration."""
import base64
import importlib.util
import json
import os
from pathlib import Path
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "live_postmerge", ROOT / "scripts" / "automatic-postmerge-live.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

REPO, BEFORE, AFTER, HEAD, BLOB = ("pgextwin/pg_ivm", "a"*40,
                                  "b"*40, "c"*40, "d"*40)
AUDIT_ID, CI_ID, PR = 39771145795, 39769754052, 28


def history(*, sha=BEFORE, n=1, conclusion="success"):
    return {"total_count": n, "workflow_runs": [
        {"id": AUDIT_ID+i, "name": mod.AUDIT_WORKFLOW,
         "path": ".github/workflows/update-watch.yml", "head_branch": "main",
         "head_sha": sha, "event": "workflow_run",
         "status": "completed", "conclusion": conclusion}
        for i in range(n)]}


def event():
    return {"ref": "refs/heads/main", "repository": {"full_name": REPO},
            "before": BEFORE, "after": AFTER, "created": False, "deleted": False,
            "sender": {"login": "ShutenOishi"}, "commits": [{"id": AFTER}]}


class ProtectedMainLiveTests(unittest.TestCase):
    def test_only_unambiguous_successful_native_audit_runs(self):
        self.assertEqual([r["id"] for r in mod.candidate_audit_runs(
            history(), parent_sha=BEFORE)], [AUDIT_ID])
        for broken in [
            history(n=0), history(n=100), history(sha=HEAD),
            history(conclusion="failure"),
            {"total_count": 2, "workflow_runs": history()["workflow_runs"]},
            {"total_count": 2, "workflow_runs": [
                history()["workflow_runs"][0], history()["workflow_runs"][0]]},
        ]:
            with self.subTest(history=broken), self.assertRaises(mod.Denied):
                mod.candidate_audit_runs(broken, parent_sha=BEFORE)

    def test_production_main_push_environment_is_required(self):
        with mock.patch.dict(os.environ, {
            "GITHUB_REPOSITORY": REPO,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_ACTOR": "ShutenOishi",
            "GH_TOKEN": "test-token",
            "GITHUB_SHA": AFTER,
        }, clear=True):
            with self.assertRaises(mod.Denied):
                mod.live(repository=REPO, event=event(), fleet={}, lifecycle={})
        with mock.patch.dict(os.environ, {
            "GITHUB_REPOSITORY": REPO,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_ACTOR": "github-actions[bot]",
            "GH_TOKEN": "test-token",
            "GITHUB_SHA": AFTER,
        }, clear=True):
            with self.assertRaises(mod.Denied):
                mod.live(repository=REPO, event=event(), fleet={}, lifecycle={})

    def test_fetches_exact_git_push_and_original_ci_archive_before_bridge(self):
        data = {
            "commits/" + AFTER: {"sha": AFTER, "parents": [{"sha": BEFORE}],
                                  "files": [{"filename": "config/extension.json",
                                             "sha": BLOB, "status": "modified"}]},
            "commits/" + AFTER + "/pulls?per_page=100": [{"number": PR}],
            "pulls/28": {"number": PR, "head": {"sha": HEAD}},
            "pulls/28/files?per_page=100": [{"filename": "config/extension.json",
                                              "status": "modified", "sha": BLOB}],
            "branches/main": {"name": "main", "protected": True,
                              "commit": {"sha": AFTER}},
            "commits/" + HEAD + "/check-runs?per_page=100": {
                "total_count": 1, "check_runs": []},
            "contents/config/extension.json?ref=" + AFTER: {
                "path": "config/extension.json", "sha": BLOB,
                "encoding": "base64",
                "content": base64.b64encode(
                    json.dumps({"name": "pg_ivm"}).encode()).decode()},
            "actions/runs?event=workflow_run&head_sha=" + BEFORE + "&per_page=100": history(),
            "actions/runs/" + str(CI_ID): {"id": CI_ID, "head_sha": HEAD,
                                            "repository": {"full_name": REPO}},
            "actions/runs/" + str(AUDIT_ID): {"id": AUDIT_ID, "head_sha": BEFORE,
                                               "repository": {"full_name": REPO}},
        }

        def fake_get(repo, path):
            self.assertEqual(repo, REPO)
            return data[path]

        context = {"candidatePr": PR, "candidateHeadSha": HEAD,
                   "candidateRunId": CI_ID}
        b = {"status": "BOUND_NATIVE_CANDIDATE_AUDIT_NONPUBLISHING"}
        safe = {"status": "MERGED_NATIVE_CANDIDATE_NONPUBLISHING",
                "publicationAuthorized": False, "publishableReceipt": False,
                "signedArtifactsVerified": False, "automaticReleaseEnabled": False}
        env = {"GITHUB_REPOSITORY": REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "push", "GITHUB_ACTOR": "ShutenOishi",
               "GITHUB_SHA": AFTER, "GH_TOKEN": "dummy-not-a-secret"}
        with (mock.patch.dict(os.environ, env, clear=True),
              mock.patch.object(mod, "get", side_effect=fake_get),
              mock.patch.object(mod, "audit_artifact",
                                return_value=({"id": 12422372611},
                                              context, {"status": "VERIFIED"})),
              mock.patch.object(mod.binder, "join", return_value=b) as bind,
              mock.patch.object(mod.bridge, "verify", return_value=safe) as verify):
            result = mod.live(repository=REPO, event=event(), fleet={}, lifecycle={})
            self.assertEqual(result["status"], "MERGED_NATIVE_CANDIDATE_NONPUBLISHING")
            self.assertFalse(result["publicationAuthorized"])
            self.assertEqual(bind.call_args.kwargs["current_main_sha"], BEFORE)
            self.assertEqual(bind.call_args.kwargs["ci_run"]["id"], CI_ID)
            self.assertEqual(bind.call_args.kwargs["audit_run"]["id"], AUDIT_ID)
            self.assertEqual(verify.call_args.kwargs["bound"], b)
            self.assertEqual(verify.call_args.kwargs["event"]["after"], AFTER)

    def test_duplicate_successful_bound_audits_denied(self):
        env = {"GITHUB_REPOSITORY": REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "push", "GITHUB_ACTOR": "ShutenOishi",
               "GITHUB_SHA": AFTER, "GH_TOKEN": "dummy-not-a-secret"}
        manifest = {"path": "config/extension.json", "sha": BLOB,
                    "encoding": "base64",
                    "content": base64.b64encode(b'{"name":"pg_ivm"}').decode()}
        def fake_get(repo, path):
            if path == "commits/" + AFTER:
                return {"files": [{"sha": BLOB}]}
            if path.endswith("/pulls?per_page=100"):
                return [{"number": 28}]
            if path == "pulls/28":
                return {"head": {"sha": HEAD}}
            if path == "contents/config/extension.json?ref=" + AFTER:
                return manifest
            if path.startswith("actions/runs?"):
                return history(n=2)
            if path.startswith("actions/runs/"):
                runid = int(path.split("/")[-1])
                return {"id": runid, "head_sha": HEAD if runid==CI_ID else BEFORE,
                        "repository": {"full_name": REPO}}
            return {}
        with (mock.patch.dict(os.environ, env, clear=True),
              mock.patch.object(mod, "get", side_effect=fake_get),
              mock.patch.object(mod, "audit_artifact",
                                return_value=({}, {"candidateRunId":CI_ID}, {})),
              mock.patch.object(mod.binder, "join", return_value={})):
            with self.assertRaises(mod.Denied):
                mod.live(repository=REPO, event=event(), fleet={}, lifecycle={})


if __name__ == "__main__":
    unittest.main()
