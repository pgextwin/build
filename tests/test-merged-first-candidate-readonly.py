#!/usr/bin/env python3
"""Fail-closed tests for the non-publishing bot candidate main/push observer."""
import base64
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("candidate_observer", ROOT / "scripts/chat-publication-readonly.py")
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
REPO = "pgextwin/pgtap"
HEAD = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40
DIGEST = "d" * 20
NAME = "auto-candidate/" + DIGEST

def fixture():
    intent = {"schemaVersion": 1, "kind": "FIRST_RELEASE_PINNED_SOURCE",
              "repository": REPO, "extension": "pgtap", "releasePolicy": "manual-only",
              "candidateId": DIGEST, "source": {"repository": "upstream", "ref": "v1",
              "version": "1", "commit": "e" * 40}}
    raw = json.dumps(intent).encode()
    blob = m.auth.git_blob_sha(raw)
    pr = {"number": 7, "merged": True, "state": "closed", "merge_commit_sha": MERGE,
          "user": {"login": "github-actions[bot]", "type": "Bot"}, "changed_files": 1,
          "head": {"sha": HEAD, "ref": NAME, "repo": {"full_name": REPO}},
          "base": {"ref": "main", "repo": {"full_name": REPO}}}
    data = {
        "branches/main": {"protected": True, "commit": {"sha": MERGE}},
        "commits/" + MERGE: {"sha": MERGE, "parents": [{"sha": BASE}, {"sha": HEAD}]},
        "commits/" + MERGE + "/pulls?per_page=100": [pr],
        "pulls/7": pr,
        "pulls/7/files?per_page=100": [{"filename": m.FIRST_INTENT, "sha": blob, "status": "added"}],
        "contents/" + m.FIRST_INTENT + "?ref=" + MERGE: {
            "type": "file", "path": m.FIRST_INTENT, "encoding": "base64",
            "content": base64.b64encode(raw).decode(), "size": len(raw), "sha": blob},
        "commits/" + HEAD + "/check-runs?per_page=100": {"check_runs": [{
            "name": "Windows required summary", "app": {"id": 15368},
            "head_sha": HEAD, "conclusion": "success"}]}
    }
    env = {"GITHUB_REPOSITORY": REPO, "GITHUB_SHA": MERGE,
           "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main"}
    event = {"ref": "refs/heads/main", "after": MERGE, "before": BASE,
             "created": False, "deleted": False}
    run = {"head_sha": MERGE, "head_branch": "main"}
    return env, event, data, run

class Reader:
    def __init__(self, data): self.data = data
    def get(self, key):
        m.Reader.allowed(key)
        return deepcopy(self.data[key])

class TestMergedCandidate(unittest.TestCase):
    def check(self, f):
        env, event, data, run = f
        return m.observe_merged_first_candidate(env, event, Reader(data), run, data["branches/main"])

    def test_success_is_nonpublishing(self):
        out = self.check(fixture())
        self.assertEqual(out["status"], "MERGED_FIRST_CANDIDATE_OBSERVED_PUBLICATION_DENIED")
        self.assertEqual((out["publication"], out["goB"], out["g4"], out["g5"]),
                         ("DENY", "NO_GO", "NO_GO", "NO_GO"))
        self.assertFalse(out["publicationAuthorized"])
        self.assertFalse(out["mutationsEnabled"])

    def test_spoofed_merge_pr_manifest_ci_and_branch_are_rejected(self):
        cases = [
            lambda e,v,d,r: d["branches/main"].update(protected=False),
            lambda e,v,d,r: d["commits/"+MERGE]["parents"][1].update(sha=BASE),
            lambda e,v,d,r: d["pulls/7"]["user"].update(type="User"),
            lambda e,v,d,r: d["pulls/7"]["head"]["repo"].update(full_name="attacker/fork"),
            lambda e,v,d,r: d["pulls/7"].update(merged=False),
            lambda e,v,d,r: d["pulls/7/files?per_page=100"][0].update(status="modified"),
            lambda e,v,d,r: d["commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0]["app"].update(id=1),
            lambda e,v,d,r: d["commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0].update(conclusion="failure"),
            lambda e,v,d,r: d["contents/"+m.FIRST_INTENT+"?ref="+MERGE].update(content="%%%"), 
            lambda e,v,d,r: v.update(after=BASE),
        ]
        for i, mutate in enumerate(cases):
            with self.subTest(i=i):
                f = fixture()
                mutate(*f)
                with self.assertRaises((m.Denied, ValueError, KeyError, TypeError)):
                    self.check(f)

    def test_exact_shared_readonly_update_wrapper_can_be_observed_without_publish(self):
        expected_blob = "2d64faa10025dd65adc005bd8f3be3bbadf60802"
        for name in ("pgtap", "pg_variables", "pg_store_plans"):
            env, event, data, run = fixture()
            repo = "pgextwin/" + name
            env["GITHUB_REPOSITORY"] = repo
            pr = data["pulls/7"]
            pr["user"] = {"login": "ShutenOishi", "type": "User"}
            pr["merged_by"] = {"login": "ShutenOishi", "type": "User"}
            pr["head"]["ref"] = "refactor/shared-operator-readonly-20261021"
            pr["head"]["repo"]["full_name"] = repo
            pr["base"]["repo"]["full_name"] = repo
            file = data["pulls/7/files?per_page=100"][0]
            file.update(filename=".github/workflows/update-watch.yml",
                        sha=expected_blob, status="modified")
            data["commits/" + MERGE]["files"] = [deepcopy(file)]
            run["actor"] = {"login": "ShutenOishi", "type": "User"}
            event["sender"] = {"login": "ShutenOishi", "type": "User"}
            output = m.observe_merged_nonpublishing_pin(
                env, event, Reader(data), run, data["branches/main"])
            self.assertEqual(output["status"],
                             "MERGED_NONPUBLISHING_WORKFLOW_PIN_OBSERVED")
            self.assertEqual(output["publication"], "DENY")
            self.assertEqual((output["goB"], output["g4"], output["g5"]),
                             ("NO_GO",) * 3)
            self.assertFalse(output["publicationAuthorized"])
            for mutate in (
                lambda f,d: f.update(sha="0" * 40),
                lambda f,d: f.update(filename=".github/workflows/promote.yml"),
                lambda f,d: f.update(status="added"),
                lambda f,d: d["commits/" + MERGE]["files"].append(deepcopy(f)),
                lambda f,d: d["commits/" + HEAD + "/check-runs?per_page=100"]["check_runs"][0].update(conclusion="failure"),
                lambda f,d: d["branches/main"].update(protected=False),
            ):
                bad = deepcopy(data)
                changed = bad["pulls/7/files?per_page=100"][0]
                mutate(changed, bad)
                with self.subTest(repo=repo, mutation=str(mutate)), self.assertRaises((m.Denied, ValueError, KeyError, TypeError)):
                    m.observe_merged_nonpublishing_pin(
                        env, event, Reader(bad), run, bad["branches/main"])

    def test_human_workflow_pin_merge_stays_nonpublishing(self):
        env, event, data, run = fixture()
        pr = data["pulls/7"]
        pr["user"] = {"login": "ShutenOishi", "type": "User"}
        pr["merged_by"] = {"login": "ShutenOishi", "type": "User"}
        pr["head"]["ref"] = "fix/wave3-postmerge-pin-20261021"
        file = data["pulls/7/files?per_page=100"][0]
        file.update(filename=".github/workflows/windows.yml", status="modified")
        data["commits/"+MERGE]["files"] = [deepcopy(file)]
        run["actor"] = {"login": "ShutenOishi", "type": "User"}
        event["sender"] = {"login": "ShutenOishi", "type": "User"}
        output = m.observe_merged_nonpublishing_pin(env, event, Reader(data), run, data["branches/main"])
        self.assertEqual(output["status"], "MERGED_NONPUBLISHING_WORKFLOW_PIN_OBSERVED")
        self.assertEqual((output["publication"], output["goB"], output["g4"], output["g5"]),
                         ("DENY", "NO_GO", "NO_GO", "NO_GO"))
        self.assertFalse(output["publicationAuthorized"])
        for change in (
            lambda: data["branches/main"].update(protected=False),
            lambda: data["commits/"+MERGE]["parents"][1].update(sha=BASE),
            lambda: pr["user"].update(login="attacker"),
            lambda: file.update(filename=".github/release-authorizations/v1-windows.1.json"),
            lambda: data["commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0].update(conclusion="failure"),
        ):
            env, event, data, run = fixture()
            pr = data["pulls/7"]
            pr["user"] = {"login": "ShutenOishi", "type": "User"}
            pr["merged_by"] = {"login": "ShutenOishi", "type": "User"}
            pr["head"]["ref"] = "fix/wave3-postmerge-pin-20261021"
            file = data["pulls/7/files?per_page=100"][0]
            file.update(filename=".github/workflows/windows.yml", status="modified")
            data["commits/"+MERGE]["files"] = [deepcopy(file)]
            run["actor"] = {"login": "ShutenOishi", "type": "User"}
            event["sender"] = {"login": "ShutenOishi", "type": "User"}
            change()
            with self.assertRaises((m.Denied, ValueError, KeyError, TypeError)):
                m.observe_merged_nonpublishing_pin(env, event, Reader(data), run, data["branches/main"])

if __name__ == "__main__":
    unittest.main()
