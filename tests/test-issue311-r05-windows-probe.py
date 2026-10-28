#!/usr/bin/env python3
"""R05 original Windows runner evidence/negative terminal fail-closed fixtures."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("r05_win", "scripts/issue311-r05-windows-probe.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def receipt(repo):
    return {
        "requestId":m.REQUEST_ID, "repo":repo, "runnerOS":"Windows",
        "remoteVerified":True, "mainSha":m.TARGETS[repo],
        "publishAuthorized":False,
        "result":"FAILED" if repo==m.NEGATIVE_REPO else "SUCCESS",
        **({"failureClass":"CONTROLLED_AFTER_VERIFIED_GET"} if repo==m.NEGATIVE_REPO else {})
    }


class Tests(unittest.TestCase):
    def setUp(self):
        self.receipts={repo:receipt(repo) for repo in m.TARGETS}
        self.jobs=[
            {"name":"WINDOWS GET "+repo,"status":"completed",
             "conclusion":"failure" if repo==m.NEGATIVE_REPO else "success"}
            for repo in m.TARGETS
        ]

    def test_original_git_blob_not_windows_worktree_bytes(self):
        from unittest.mock import patch
        raw=b'{"sample":"original"}\n'
        self.assertNotEqual(raw,raw.replace(b"\n",b"\r\n"))
        with patch.dict("os.environ", {"GITHUB_SHA":"a"*40}):
            with patch.object(m.subprocess,"check_output",
                              side_effect=["a"*40+"\n",raw]) as command:
                self.assertEqual(m.original_request_bytes(),raw)
        self.assertEqual(command.call_args_list[1].args[0],
                         ["git","show","HEAD:"+m.REQUEST_PATH.as_posix()])
        self.assertNotIn("REQUEST_PATH.read_bytes()",Path(
            "scripts/issue311-r05-windows-probe.py").read_text())

    def test_expected_failure_never_upgraded_to_success(self):
        outcome=m.evaluate(self.jobs,self.receipts,"success")
        self.assertEqual(outcome["terminal"],"FAILED")
        self.assertTrue(outcome["controlledNegativeProved"])
        self.assertEqual(len(outcome["perTarget"]),2)

    def test_unexpected_failure_and_skip_not_controlled(self):
        for state in ("skipped","cancelled","success",None):
            jobs=[dict(x) for x in self.jobs]
            jobs[-1]["conclusion"]=state
            self.assertFalse(m.evaluate(jobs,self.receipts,"success")["controlledNegativeProved"])
        self.assertFalse(m.evaluate(self.jobs,self.receipts,"failure")["controlledNegativeProved"])

    def test_original_receipts_missing_or_fake_denied(self):
        for repo in m.TARGETS:
            entries=dict(self.receipts)
            del entries[repo]
            with self.assertRaises(ValueError):
                m.evaluate(self.jobs,entries,"success")
        for key,wrong in (("remoteVerified",False),("runnerOS","Linux"),
                          ("mainSha","0"*40),("publishAuthorized",True)):
            entries={repo:dict(x) for repo,x in self.receipts.items()}
            entries[m.NEGATIVE_REPO][key]=wrong
            with self.assertRaises(ValueError):
                m.evaluate(self.jobs,entries,"success")
        jobs=self.jobs+self.jobs[:1]
        with self.assertRaises(ValueError):
            m.evaluate(jobs,self.receipts,"success")

    def test_request_and_workflow_no_credential_expansion(self):
        path=Path(".github/execution-requests/"+m.REQUEST_ID+".json")
        obj=json.loads(path.read_text())
        self.assertEqual(obj["mode"],"AUDIT_ONLY")
        self.assertEqual({t["repo"]:t["mainSha"] for t in obj["targets"]},m.TARGETS)
        self.assertFalse(obj["approval"]["publicReleaseAuthorized"])
        self.assertFalse(obj["approval"]["publicationGrants"])
        self.assertFalse(obj["allowFutureUpdates"])
        y=Path(".github/workflows/issue311-r05-windows-negative.yml").read_text()
        for forbidden in ("contents: write","id-token: write","workflow_dispatch",
                          "repository_dispatch","schedule:","pull_request_target",
                          "secrets: inherit", "gh workflow run", "release:"):
            self.assertNotIn(forbidden,y)
        for marker in ("runs-on: windows-latest","max-parallel: 2","if: always()",
                       "persist-credentials: false","actions: read"):
            self.assertIn(marker,y)
        self.assertIn("paths:",y)

if __name__=="__main__":
    unittest.main()
