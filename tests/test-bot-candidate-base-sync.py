#!/usr/bin/env python3
"""Fail-closed original-bot candidate base-sync repair tests (offline)."""
import copy
import importlib.util
import json
import os
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("candidate_update", ROOT / "scripts/candidate-update.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

REPO = "pgextwin/hypopg"
MAIN_SHA, ORIGINAL, HUMAN, NEW = ("a"*40, "b"*40, "c"*40, "d"*40)
BLOB = "e"*40
BRANCH = "auto-candidate/5860b6258e7d21085f38"
MARKER = "<!-- pgextwin-candidate:v1:5860b6258e7d21085f38 -->"
PATH = "config/extension.json"
PROPOSAL = {"schemaVersion": 1, "name": "hypopg", "upstream": {
    "repository": "HypoPG/hypopg", "ref": "1.4.4", "version": "1.4.4",
    "commit": "4e564ebbd46e1ab365ad0d05ca4a2f19cf316ba7"}}
RECORD = {"candidateId": "5860b6258e7d21085f38", "branch": BRANCH}
ENV = {"GITHUB_EVENT_NAME": "schedule", "GITHUB_RUN_ATTEMPT": "1",
       "GITHUB_REF": "refs/heads/main", "GITHUB_REPOSITORY": REPO,
       "GITHUB_SHA": MAIN_SHA, "GH_TOKEN": "fixture-token"}
LIST = [{"number": 41, "body": MARKER, "state": "OPEN", "isDraft": True,
         "headRefOid": HUMAN, "headRefName": BRANCH, "baseRefName": "main"}]
PR = {"number": 41, "state": "open", "draft": True, "merged": False,
      "body": MARKER, "user": {"login": "github-actions[bot]", "type": "Bot"},
      "head": {"sha": HUMAN, "ref": BRANCH, "repo": {"full_name": REPO}},
      "base": {"sha": MAIN_SHA, "ref": "main", "repo": {"full_name": REPO}}}
RUN = {"id": 40250481553, "event": "pull_request", "head_sha": HUMAN,
       "head_branch": BRANCH, "path": ".github/workflows/windows.yml",
       "status": "completed", "conclusion": "success", "run_attempt": 1,
       "repository": {"full_name": REPO}}


class BotRepairTests(TestCase):
    def run_case(self, *, change=None, good=False):
        env, listing, pr, run = copy.deepcopy(ENV), copy.deepcopy(LIST), copy.deepcopy(PR), copy.deepcopy(RUN)
        responses = {
            ("gh", "api", "repos/" + REPO + "/branches/main"):
                json.dumps({"protected": True, "commit": {"sha": MAIN_SHA}}),
            ("gh", "pr", "list", "--repo", REPO, "--head", BRANCH,
             "--state", "all", "--limit", "100", "--json",
             "number,body,state,headRefOid,headRefName,baseRefName,isDraft"): json.dumps(listing),
            ("gh", "api", "repos/" + REPO + "/pulls/41"): json.dumps(pr),
            ("gh", "api", "repos/" + REPO +
             "/actions/runs?event=pull_request&head_sha=" + HUMAN +
             "&per_page=100"): json.dumps({"workflow_runs": [run]}),
            ("git", "rev-parse", "refs/remotes/origin/" + BRANCH): HUMAN,
            ("git", "rev-list", "--parents", "-n", "1", HUMAN):
                HUMAN + " " + ORIGINAL + " " + MAIN_SHA,
            ("git", "log", "-1", "--format=%an", ORIGINAL): "github-actions[bot]",
            ("git", "log", "-1", "--format=%ae", ORIGINAL):
                "41898282+github-actions[bot]@users.noreply.github.com",
            ("git", "log", "-1", "--format=%B", ORIGINAL): "original bot\n" + MARKER,
            ("git", "diff", "--name-only", MAIN_SHA, HUMAN): PATH,
            ("git", "rev-parse", ORIGINAL + ":" + PATH): BLOB,
            ("git", "rev-parse", HUMAN + ":" + PATH): BLOB,
            ("git", "show", HUMAN + ":" + PATH): json.dumps(PROPOSAL),
            ("git", "diff", "--name-only", HUMAN, NEW): "",
        }
        if change:
            change(env, listing, pr, run, responses)
            responses[("gh", "pr", "list", "--repo", REPO, "--head", BRANCH,
                       "--state", "all", "--limit", "100", "--json",
                       "number,body,state,headRefOid,headRefName,baseRefName,isDraft")] = json.dumps(listing)
            responses[("gh", "api", "repos/" + REPO + "/pulls/41")] = json.dumps(pr)
            responses[("gh", "api", "repos/" + REPO +
                       "/actions/runs?event=pull_request&head_sha=" + HUMAN +
                       "&per_page=100")] = json.dumps({"workflow_runs": [run]})
        calls = []
        def execute(*args):
            calls.append(args)
            if args == ("git", "rev-parse", "HEAD"):
                return NEW if any(x[:2] == ("git", "commit") for x in calls) else MAIN_SHA
            if args in responses:
                return responses[args]
            if args[0] == "git" and args[1] in {"checkout", "config", "commit", "push"}:
                return ""
            raise AssertionError("unexpected command " + repr(args))
        with patch.dict(os.environ, env, clear=True), patch.object(c, "execute", execute):
            task = lambda: c.repair_exact_bot_candidate_base_sync(
                RECORD, REPO, PATH, PROPOSAL, MARKER, BRANCH)
            if good:
                task()
                self.assertEqual(sum(x[:2] == ("git", "commit") for x in calls), 1)
                self.assertEqual(sum(x[:2] == ("git", "push") for x in calls), 1)
                self.assertFalse(any(x[:3] == ("gh", "workflow", "run") for x in calls))
                self.assertFalse(any("force" in " ".join(x) for x in calls))
            else:
                with self.assertRaises((c.WatchError, ValueError, KeyError, TypeError)):
                    task()
                self.assertFalse(any(x[:2] == ("git", "commit") for x in calls))
                self.assertFalse(any(x[:2] == ("git", "push") for x in calls))

    def test_exact_bot_origin_human_sync_can_only_be_repaired_by_real_bot_commit(self):
        self.run_case(good=True)

    def test_all_provenance_mismatches_fail_before_any_write(self):
        cases = [
            lambda e,l,p,r,d: e.update(GITHUB_EVENT_NAME="workflow_dispatch"),
            lambda e,l,p,r,d: e.update(GITHUB_RUN_ATTEMPT="2"),
            lambda e,l,p,r,d: e.update(GITHUB_SHA="f"*40),
            lambda e,l,p,r,d: p["user"].update(login="human"),
            lambda e,l,p,r,d: p.update(draft=False),
            lambda e,l,p,r,d: p["base"].update(sha="f"*40),
            lambda e,l,p,r,d: l[0].update(headRefOid="f"*40),
            lambda e,l,p,r,d: d.update({("git", "rev-list", "--parents", "-n", "1", HUMAN):
                                           HUMAN + " " + ORIGINAL + " " + "f"*40}),
            lambda e,l,p,r,d: d.update({("git", "log", "-1", "--format=%an", ORIGINAL): "human"}),
            lambda e,l,p,r,d: d.update({("git", "log", "-1", "--format=%B", ORIGINAL): "no marker"}),
            lambda e,l,p,r,d: d.update({("git", "diff", "--name-only", MAIN_SHA, HUMAN):
                                           PATH + "\n.github/workflows/windows.yml"}),
            lambda e,l,p,r,d: d.update({("git", "rev-parse", HUMAN + ":" + PATH): "f"*40}),
            lambda e,l,p,r,d: d.update({("git", "show", HUMAN + ":" + PATH): '{"upstream":"forged"}'}),
            lambda e,l,p,r,d: r.update(event="workflow_dispatch"),
            lambda e,l,p,r,d: r.update(conclusion="failure"),
            lambda e,l,p,r,d: r.update(run_attempt=2),
        ]
        for i, modify in enumerate(cases):
            with self.subTest(case=i):
                self.run_case(change=modify)


if __name__ == "__main__":
    main()
