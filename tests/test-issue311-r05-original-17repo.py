#!/usr/bin/env python3
"""R05 read-only 17-target static and hostile terminal contract tests."""
import importlib.util,json
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location("agg","scripts/issue311-r05-aggregate.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def test_registered_17_and_no_new_authority(self):
        req=json.loads(Path(".github/execution-requests/r-20261029-r05readonly17b.json").read_text())
        fleet=json.loads(Path("metadata/automation-fleet.json").read_text())
        self.assertEqual(set(x["repo"] for x in req["targets"]),m.REPOS)
        self.assertEqual(set(x["repository"] for x in fleet["entries"]),m.REPOS)
        self.assertEqual(req["mode"],"AUDIT_ONLY")
        self.assertFalse(req["approval"]["publicReleaseAuthorized"])
        self.assertFalse(req["approval"]["publicationGrants"])
        y=Path(".github/workflows/issue311-r05-original-17repo.yml").read_text()
        for forbidden in ("contents: write","id-token: write","workflow_dispatch","repository_dispatch","schedule:","pull_request_target"):
            self.assertNotIn(forbidden,y)
        for t in req["targets"]:
            self.assertIn("repo: "+t["repo"],y)
            self.assertIn("expected_sha: "+t["mainSha"],y)
        self.assertIn("fail-fast: false",y)
        self.assertIn("if: always()",y)

    def test_failed_missing_skipped_incomplete_and_duplicate_are_not_success(self):
        jobs=[{"name":"GET "+x,"status":"completed","conclusion":"success"} for x in m.REPOS]
        self.assertTrue(all(x=="success" for x in m.evaluate_jobs(jobs).values()))
        for status in ("failure","skipped","cancelled",None):
            altered=[dict(j) for j in jobs]
            altered[0]["conclusion"]=status
            self.assertNotEqual(set(m.evaluate_jobs(altered).values()),{"success"})
        self.assertIn("missing",m.evaluate_jobs(jobs[:1]).values())
        with self.assertRaises(ValueError):
            m.evaluate_jobs(jobs+jobs[:1])
        with self.assertRaises(ValueError):
            m.evaluate_jobs(jobs+[{"name":"GET pgextwin/fake","status":"completed","conclusion":"success"}])
        altered=[dict(j) for j in jobs]
        altered[0]["status"]="in_progress"
        self.assertIn("incomplete",m.evaluate_jobs(altered).values())

if __name__=="__main__": unittest.main()
