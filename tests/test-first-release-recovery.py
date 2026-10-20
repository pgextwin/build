#!/usr/bin/env python3
"""Adversarial Wave3 first-Release candidate recovery tests; offline, no GitHub writes."""
from copy import deepcopy
import importlib.util
import os
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
sp = importlib.util.spec_from_file_location("candidate_recovery", ROOT / "scripts/candidate-update.py")
c = importlib.util.module_from_spec(sp)
sp.loader.exec_module(c)
OLD, MAIN, NEW = "a"*40, "b"*40, "c"*40
REPO = "pgextwin/pgtap"
BRANCH = "auto-candidate/d2988a25e59025d4764a"
ID = "d2988a25e59025d4764a"
MARKER = "<!-- pgextwin-candidate:v1:" + ID + " -->"
SOURCE = {"repository": "theory/pgtap", "ref": "v1.3.4",
          "version": "1.3.4", "commit": "d"*40}
DOCUMENT = {"schemaVersion": 1, "kind": "FIRST_RELEASE_PINNED_SOURCE",
            "repository": REPO, "extension": "pgtap", "releasePolicy": "manual-only",
            "candidateId": ID, "source": SOURCE}
RECORD = {"status": "candidate", "firstRelease": True, "extension": "pgtap",
          "branch": BRANCH, "candidateId": ID}
ENV = {"GITHUB_REPOSITORY": REPO, "GITHUB_REF": "refs/heads/main",
       "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_ACTOR": "ShutenOishi",
       "GITHUB_TRIGGERING_ACTOR": "ShutenOishi", "GITHUB_RUN_ATTEMPT": "1",
       "GITHUB_SHA": MAIN, "GH_TOKEN": "testing-never-real"}
PR = {"number": 7, "body": MARKER, "state": "OPEN", "isDraft": True,
      "url": "https://github.com/pgextwin/pgtap/pull/7",
      "author": {"login": "github-actions[bot]"}, "headRefOid": OLD,
      "headRefName": BRANCH, "baseRefName": "main"}
FAILED = {"databaseId": 39437592613, "event": "workflow_dispatch",
          "status": "completed", "conclusion": "failure", "headSha": OLD}


def command_responses():
    return {
       ("gh","api","repos/"+REPO+"/branches/main"):
         '{"protected":true,"commit":{"sha":"'+MAIN+'"}}',
       ("git","rev-parse","HEAD"): MAIN,
       ("git","rev-parse","refs/remotes/origin/"+BRANCH): OLD,
       ("git","log","-1","--format=%an",OLD): "github-actions[bot]",
       ("git","diff","--name-only",MAIN,NEW): c.FIRST_FILE,
       ("git","show","HEAD:"+c.FIRST_FILE): __import__("json").dumps(DOCUMENT)
    }


class TestFirstReleaseRecovery(TestCase):
    def run_case(self, *, change=None, responses=None, good=False):
        record, pr, run, env = deepcopy(RECORD), deepcopy(PR), deepcopy(FAILED), deepcopy(ENV)
        data = command_responses()
        if change:
            change(record, pr, run, env)
        if responses:
            data.update(responses)
        calls = []
        def execute(*args):
            calls.append(args)
            if args == ("git", "rev-parse", "HEAD") and calls.count(args) > 1:
                return NEW
            if args in data:
                return data[args]
            if args[0] == "git" and args[1] in {"checkout", "config", "merge", "push"}:
                return ""
            if args[:3] == ("gh", "workflow", "run"):
                return ""
            raise AssertionError("unexpected external command: " + repr(args))
        # Two git rev-parse HEAD outputs: operator main before merge, new candidate afterward.
        with patch.dict(os.environ, env, clear=True), patch.object(c, "execute", execute):
            job = lambda: c.recover_failed_first_release(
                record, REPO, c.FIRST_FILE, DOCUMENT, MARKER,
                OLD + "\trefs/heads/" + BRANCH, [pr], [run])
            if good:
                job()
                self.assertEqual(sum(x[:2] == ("git", "push") for x in calls), 1)
                self.assertEqual(sum(x[:3] == ("gh", "workflow", "run") for x in calls), 1)
                self.assertTrue(any(x[:2] == ("git", "merge") and "--no-ff" in x for x in calls))
                self.assertTrue(any(x[:2] == ("git", "push") and
                                    x[-1] == "HEAD:refs/heads/" + BRANCH for x in calls))
                self.assertFalse(any("force" in " ".join(x) or "--no-verify" in x
                                     for x in calls))
                self.assertLess(next(i for i,x in enumerate(calls) if x[:2] == ("git","push")),
                                next(i for i,x in enumerate(calls) if x[:3] == ("gh","workflow","run")))
            else:
                with self.assertRaises((c.WatchError, ValueError, KeyError, TypeError)):
                    job()
                self.assertFalse(any(x[:2] == ("git", "push") for x in calls))
                self.assertFalse(any(x[:3] == ("gh", "workflow", "run") for x in calls))

    def test_legitimate_exact_failed_candidate_fresh_human_update(self):
        self.run_case(good=True)

    def test_forged_update_retry_and_old_head_denied(self):
        changes = [
          lambda r,p,u,e: e.update(GITHUB_ACTOR="github-actions[bot]"),
          lambda r,p,u,e: e.update(GITHUB_TRIGGERING_ACTOR="attacker"),
          lambda r,p,u,e: e.update(GITHUB_RUN_ATTEMPT="2"),
          lambda r,p,u,e: e.update(GITHUB_EVENT_NAME="push"),
          lambda r,p,u,e: e.update(GITHUB_SHA="notsha"),
          lambda r,p,u,e: r.update(firstRelease=False),
          lambda r,p,u,e: p.update(isDraft=False),
          lambda r,p,u,e: p["author"].update(login="attacker"),
          lambda r,p,u,e: p.update(headRefOid="e"*40),
          lambda r,p,u,e: p.update(state="CLOSED"),
          lambda r,p,u,e: p.update(headRefName="auto-candidate/other"),
          lambda r,p,u,e: p.update(baseRefName="wrong"),
          lambda r,p,u,e: p.update(body="no marker"),
          lambda r,p,u,e: u.update(status="in_progress"),
          lambda r,p,u,e: u.update(conclusion="success"),
          lambda r,p,u,e: u.update(conclusion="cancelled"),
          lambda r,p,u,e: u.update(headSha="e"*40),
          lambda r,p,u,e: u.update(event="pull_request"),
          lambda r,p,u,e: u.update(databaseId=0),
        ]
        for i, modify in enumerate(changes):
            with self.subTest(i=i):
                self.run_case(change=modify)

    def test_protected_main_and_immutable_diff_and_bot_commit_fail_closed(self):
        failures = [
          {("gh","api","repos/"+REPO+"/branches/main"):
             '{"protected":false,"commit":{"sha":"'+MAIN+'"}}'},
          {("gh","api","repos/"+REPO+"/branches/main"):
             '{"protected":true,"commit":{"sha":"'+OLD+'"}}'},
          {("git","rev-parse","HEAD"): "f"*40},
          {("git","rev-parse","refs/remotes/origin/"+BRANCH): "f"*40},
          {("git","log","-1","--format=%an",OLD): "unknown"},
          {("git","diff","--name-only",MAIN,NEW): "config/extension.json"},
          {("git","diff","--name-only",MAIN,NEW): c.FIRST_FILE+"\n.github/workflows/windows.yml"},
          {("git","show","HEAD:"+c.FIRST_FILE): '{"kind":"forged"}'},
        ]
        for i, responses in enumerate(failures):
            with self.subTest(i=i):
                self.run_case(responses=responses)


if __name__ == "__main__":
    main()
