#!/usr/bin/env python3
"""Issue311 R05 17 original Windows child completion events, ZIP terminal hostile tests."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
import unittest

spec=importlib.util.spec_from_file_location("win17",Path("scripts/issue311-r05-windows-17.py"))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


class Tests(unittest.TestCase):
    def child(self,repo):
        return {"requestId":p.REQUEST,"repo":repo,"runnerOS":"Windows",
                "completionEvent":"WINDOWS_ORIGINAL_REMOTE_GET",
                "remoteProtected":True,"stateGitBlobSha":p.R04_BLOB,
                "targetMainSha":p.TARGETS[repo],"result":"SUCCESS",
                "publicationAuthorized":False}

    def jobs(self):
        return [{"name":"WINDOWS STATE GET "+repo,"status":"completed",
                 "conclusion":"success"} for repo in p.TARGETS]

    def receipts(self):
        return {repo:self.child(repo) for repo in p.TARGETS}

    def test_proven_original_r04_stopped_run_and_recovery_blob(self):
        state={"phase":"RECOVERED_ANOTHER_RUN","revision":2,"requestSha256":p.R04_INPUT_SHA,
               "sourceRunId":40789724530,"resumedByRunId":40789923987,
               "completedStages":["READONLY_PROTECTED_MAIN_BOUND"],
               "lease":{"generation":2,"scope":"READONLY"},
               "publisherAuthorized":False,"writeOutcomeUnknown":False}
        raw=json.dumps(state,sort_keys=True).encode()
        sha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        payload={"encoding":"base64","sha":sha,"content":base64.b64encode(raw).decode()}
        with patch.object(p,"R04_BLOB",sha):
            self.assertEqual(p.verify_immutable_state(payload)["revision"],2)
            for change in ({"phase":"PUBLISH"},{"revision":1},
                           {"sourceRunId":42},{"resumedByRunId":42},
                           {"publisherAuthorized":True},
                           {"completedStages":[]},
                           {"lease":{"generation":1,"scope":"READONLY"}},
                           {"writeOutcomeUnknown":True}):
                forged=dict(state,**change)
                data=json.dumps(forged,sort_keys=True).encode()
                with self.subTest(change=change),self.assertRaises(ValueError):
                    p.verify_immutable_state(dict(payload,content=base64.b64encode(data).decode()))
        with self.assertRaises(ValueError):
            p.verify_immutable_state(payload)

    def test_all_17_original_windows_jobs_and_receipts(self):
        self.assertEqual(len(p.TARGETS),17)
        good=p.evaluate(self.jobs(),self.receipts(),"success")
        self.assertEqual(good["terminal"],"NO_UPDATE")
        self.assertEqual(len(good["perTarget"]),17)
        self.assertFalse(good["publicReleaseAuthorized"])

    def test_missing_skipped_timeout_failed_duplicate_child_and_receipt_end_failed(self):
        good=self.jobs()
        receipts=self.receipts()
        for name in ("failure","cancelled","skipped","timed_out","incomplete"):
            jobs=[dict(x) for x in good]
            if name=="incomplete":
                jobs[-1]["status"]="in_progress"
            else:
                jobs[-1]["conclusion"]=name
            self.assertEqual(p.evaluate(jobs,receipts,"success")["terminal"],"FAILED")
        self.assertEqual(p.evaluate(good,receipts,"failure")["terminal"],"FAILED")
        with self.assertRaises(ValueError):
            p.evaluate(good[:-1],receipts,"success")
        with self.assertRaises(ValueError):
            p.evaluate(good,dict(list(receipts.items())[:-1]),"success")
        with self.assertRaises(ValueError):
            p.evaluate(good+[dict(good[0])],receipts,"success")
        with self.assertRaises(ValueError):
            p.evaluate(good+[{"name":"WINDOWS STATE GET pgextwin/evil",
                             "status":"completed","conclusion":"success"}],receipts,"success")

    def test_forged_protected_repo_event_scope_replay_denied(self):
        for field,value in (("requestId","r-forged"),("runnerOS","Linux"),
                            ("completionEvent","FAKE_WEBHOOK"),("result","SUCCESS_FAKE"),
                            ("remoteProtected",False),("stateGitBlobSha","a"*40),
                            ("publicationAuthorized",True),("targetMainSha","b"*40)):
            altered=self.receipts()
            repo="pgextwin/orafce"
            altered[repo]=dict(altered[repo],**{field:value})
            with self.subTest(field=field),self.assertRaises(ValueError):
                p.evaluate(self.jobs(),altered,"success")

    def test_real_git_registry_blob_survives_windows_checkout_crlf(self):
        # Pure bytes test also runs inside the no-.git policy projection fixture.
        # Runtime obtains those canonical bytes using git show, not checkout bytes.
        raw=Path("metadata/automation-fleet.json").read_bytes()
        self.assertIn("HEAD:metadata/automation-fleet.json",
                      Path(p.__file__).read_text())
        self.assertEqual(len(p.verify_immutable_registry_bytes(raw)["entries"]),17)
        with self.assertRaises(ValueError):
            p.verify_immutable_registry_bytes(raw.replace(b"\n",b"\r\n"))
        with self.assertRaises(ValueError):
            p.verify_immutable_registry_bytes(raw.replace(b"pgextwin/pg_bigm",
                                                         b"pgextwin/pg_fake"))

    def test_one_shot_17_window_scope_and_missing_event_terminal(self):
        y=Path(".github/workflows/issue311-r05-windows-17.yml").read_text()
        self.assertIn(p.REQUEST+".json",y)
        self.assertEqual(y.count("          - {name:"),17)
        self.assertIn("runs-on: windows-latest",y)
        self.assertIn("if: always()",y)
        self.assertIn("max-parallel: 4",y)
        self.assertIn("actions: read",y)
        self.assertIn("persist-credentials: false",y)
        self.assertIn("if-no-files-found: error",y)
        self.assertGreaterEqual(y.count("python -m pip install --disable-pip-version-check 'jsonschema>=4,<5'"),2)
        for bad in ("contents: write","id-token: write","workflow_dispatch:",
                    "repository_dispatch:","schedule:","secrets: inherit",
                    "gh workflow run","release:"):
            self.assertNotIn(bad,y)


if __name__=="__main__":
    unittest.main()
