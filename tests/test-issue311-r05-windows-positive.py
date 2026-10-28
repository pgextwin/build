#!/usr/bin/env python3
"""R05 positive Windows original state transport: hostile fixtures, no tokens."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
import unittest

spec=importlib.util.spec_from_file_location(
    "issue311_winpositive",Path("scripts/issue311-r05-windows-positive.py"))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


class Tests(unittest.TestCase):
    def child(self,repo):
        return {"requestId":p.REQUEST,"repo":repo,"runnerOS":"Windows",
                "remoteProtected":True,"stateGitBlobSha":p.R04_BLOB,
                "targetMainSha":p.TARGETS[repo],"result":"SUCCESS",
                "publicationAuthorized":False}

    def jobs(self):
        return [{"name":"WINDOWS STATE GET "+repo,"status":"completed",
                 "conclusion":"success"} for repo in p.TARGETS]

    def test_real_r04_state_byte_identity_and_denial(self):
        state={"phase":"RECOVERED","revision":2,"requestSha256":p.R04_INPUT_SHA,
               "lease":{"generation":2,"scope":"READONLY"},
               "publisherAuthorized":False,"writeOutcomeUnknown":False}
        raw=json.dumps(state,sort_keys=True).encode()
        sha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        payload={"encoding":"base64","sha":sha,"content":base64.b64encode(raw).decode()}
        with patch.object(p,"R04_BLOB",sha):
            self.assertEqual(p.verify_immutable_state(payload)["revision"],2)
            for change in ({"phase":"PUBLISH"}, {"revision":1}, {"publisherAuthorized":True},
                           {"lease":{"generation":1,"scope":"READONLY"}},
                           {"writeOutcomeUnknown":True}):
                changed=dict(state,**change)
                data=json.dumps(changed,sort_keys=True).encode()
                invalid=dict(payload,content=base64.b64encode(data).decode())
                with self.assertRaises(ValueError):
                    p.verify_immutable_state(invalid)
        with self.assertRaises(ValueError):
            p.verify_immutable_state(payload)

    def test_two_windows_positive_or_failed_and_missing_terminal(self):
        receipts={repo:self.child(repo) for repo in p.TARGETS}
        result=p.evaluate(self.jobs(),receipts,"success")
        self.assertEqual(result["terminal"],"NO_UPDATE")
        self.assertFalse(result["publicReleaseAuthorized"])
        bad=self.jobs()
        bad[-1]["conclusion"]="failure"
        self.assertEqual(p.evaluate(bad,receipts,"success")["terminal"],"FAILED")
        self.assertEqual(p.evaluate(self.jobs(),receipts,"failure")["terminal"],"FAILED")
        with self.assertRaises(ValueError):
            p.evaluate(self.jobs(),{next(iter(receipts)):next(iter(receipts.values()))},"success")
        for key,value in (("remoteProtected",False),("runnerOS","Linux"),
                          ("publicationAuthorized",True),("stateGitBlobSha","a"*40)):
            changed={repo:dict(v) for repo,v in receipts.items()}
            changed["pgextwin/orafce"][key]=value
            with self.assertRaises(ValueError):
                p.evaluate(self.jobs(),changed,"success")

    def test_scope_and_one_shot_nonpublishing_workflow(self):
        self.assertEqual(len(p.TARGETS),2)
        self.assertEqual(p.BASE_MAIN,"b41a0781d20d30cb69049641ddd56595a1b4e258")
        workflow=Path(".github/workflows/issue311-r05-windows-positive.yml").read_text()
        self.assertEqual(p.REQUEST, "r-20261029-r05winpositive02")
        self.assertIn("r-20261029-r05winpositive02.json", workflow)
        self.assertIn("python -m pip install --disable-pip-version-check 'jsonschema>=4,<5>'", workflow)
        self.assertGreaterEqual(workflow.count("python -m pip install --disable-pip-version-check 'jsonschema>=4,<5>'"),2)
        for required in ("runs-on: windows-latest","if: always()","max-parallel: 2",
                         "actions: read","persist-credentials: false","paths:"):
            self.assertIn(required,workflow)
        for bad in ("contents: write","id-token: write","workflow_dispatch:",
                    "repository_dispatch:", "schedule:", "secrets: inherit",
                    "gh workflow run","release:"):
            self.assertNotIn(bad,workflow)


if __name__=="__main__":
    unittest.main()
