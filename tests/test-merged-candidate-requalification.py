#!/usr/bin/env python3
"""Adversarial offline contract for four merged candidates: NO PUBLISH."""
from __future__ import annotations
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location("merged_candidate_requalification",
 ROOT/"scripts/verify-merged-candidate-requalification.py")
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
REPO="pgextwin/orafce"
HEAD="6331bed1f4e367f6c6ad9944476e878c7eb6f448"
MERGE="9f09147b86703efd09e1ae1d5b23bd6c92c6b9b2"
MAIN="dedba985a6b06ff2840047264a2ef9841298a956"
RID=39782466959;SUITE=107817063865;CHECK=119840790156

def fixture():
    ext={"schemaVersion":1,"name":"orafce",
         "upstream":{"repository":"orafce/orafce","ref":"VERSION_4_17_1",
                     "version":"4.17.1","commit":"542aed2e0297898cc9844fede3c4452f894b37ed"},
         "windows":{"architecture":"x64"}}
    data=(json.dumps(ext,sort_keys=True)+"\n").encode()
    blob=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
    doc={"path":"config/extension.json","encoding":"base64",
         "content":base64.b64encode(data).decode(),"sha":blob}
    branch="auto-candidate/5196a8c370e942c69eaa"
    pr={"number":8,"state":"closed","merged":True,"draft":False,
        "merged_at":"2026-10-22T14:34:25Z","merge_commit_sha":MERGE,
        "user":{"login":"github-actions[bot]"},
        "head":{"sha":HEAD,"ref":branch,"repo":{"full_name":REPO}},
        "base":{"ref":"main","repo":{"full_name":REPO}},
        "body":"<!-- pgextwin-candidate:v1:5196a8c370e942c69eaa -->"}
    check={"id":CHECK,"name":"Windows required summary",
        "status":"completed","conclusion":"success","head_sha":HEAD,
        "check_suite":{"id":SUITE},"app":{"id":15368},
        "details_url":f"https://github.com/{REPO}/actions/runs/{RID}/job/{CHECK}"}
    return {
        "entry":{"repository":REPO,"candidateHead":HEAD,"mergeSha":MERGE,
                 "pr":8,"nativeRun":RID,"manifestBlob":blob},
        "current":{"name":"main","protected":True,"commit":{"sha":MAIN},
                   "protection":{"required_status_checks":{"checks":[
                       {"context":"Windows required summary","app_id":15368}]}}},
        "pr":pr,
        "changed":[{"filename":"config/extension.json","status":"modified","sha":blob}],
        "associated":[{"number":8,"head":{"sha":HEAD}}],
        "compare":{"status":"ahead","ahead_by":20,
                   "merge_base_commit":{"sha":MERGE}},
        "candidate_contents":deepcopy(doc),"main_contents":deepcopy(doc),
        "native_run":{"id":RID,"event":"pull_request",
             "name":"Windows CI/CD","path":".github/workflows/windows.yml",
             "status":"completed","conclusion":"success","run_attempt":1,
             "head_sha":HEAD,"head_branch":branch,
             "head_repository":{"full_name":REPO},"check_suite_id":SUITE},
        "checks":{"total_count":1,"check_runs":[check]}
    }

class Requalification(unittest.TestCase):
    def test_provenance_is_only_nonpublishing(self):
        x=m.validate_merged(**fixture())
        self.assertEqual(x["status"],m.SOURCE_KIND)
        self.assertEqual(x["originalNativeWindowsRun"],RID)
        self.assertEqual(x["requiredCheckRun"],CHECK)
        for forbidden in ("publicationAuthorized","publisherSourceKindAuthorized",
                          "originalNativeZipBytesRehashed"):
            self.assertIs(x[forbidden],False)
        self.assertIsNone(x["newOIDCSigningRun"])

    def test_all_forged_or_replayed_merged_identity_denied(self):
        mutations=[
            lambda a:a["pr"].update(merged=False,state="open"),
            lambda a:a["pr"].update(draft=True),
            lambda a:a["pr"].update(user={"login":"attacker"}),
            lambda a:a["pr"].update(merge_commit_sha="a"*40),
            lambda a:a["pr"].update(body="forged bot PR"),
            lambda a:a["pr"]["head"].update(sha="a"*40),
            lambda a:a["pr"]["head"].update(ref="manual-release"),
            lambda a:a["pr"]["base"].update(ref="other"),
            lambda a:a["changed"].append({"filename":"scripts/evil.py"}),
            lambda a:a["changed"][0].update(sha="b"*40),
            lambda a:a["associated"].append(deepcopy(a["associated"][0])),
            lambda a:a["associated"][0].update(number=99),
            lambda a:a["compare"].update(status="diverged"),
            lambda a:a["compare"].update(merge_base_commit={"sha":"a"*40}),
            lambda a:a["main_contents"].update(sha="a"*40),
            lambda a:a["candidate_contents"].update(content="###"),
            lambda a:a["current"].update(protected=False),
            lambda a:a["current"]["protection"]["required_status_checks"].update(checks=[]),
            lambda a:a["native_run"].update(event="workflow_dispatch"),
            lambda a:a["native_run"].update(run_attempt=2),
            lambda a:a["native_run"].update(head_sha="a"*40),
            lambda a:a["checks"]["check_runs"][0].update(conclusion="failure"),
            lambda a:a["checks"]["check_runs"][0].update(app={"id":999}),
            lambda a:a["checks"]["check_runs"][0].update(check_suite={"id":222}),
            lambda a:a["entry"].update(nativeRun=RID+1),
        ]
        for mutate in mutations:
            with self.subTest(mutate=str(mutate)):
                x=fixture();mutate(x)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    m.validate_merged(**x)

    def test_schedule_requires_current_main_real_run_complete_fleet(self):
        now=datetime(2026,10,27,7,15,tzinfo=timezone.utc)
        scan={"schemaVersion":1,"scope":"STABLE_UPSTREAM_GET_ONLY",
             "publication":"DENY","candidatePrCreated":False,
             "indeterminate":0,"fleetSize":1,
             "generatedAt":"2026-10-27T07:03:39Z",
             "extensions":[{"repository":REPO,"mainSha":MAIN,
                            "status":"up-to-date","updates":[]}]}
        fleet={"entries":[{"repository":REPO}]}
        main={"protected":True,"commit":{"sha":"a"*40}}
        run={"id":40464759125,"event":"schedule",
             "path":m.WATCH,"head_branch":"main","run_attempt":1,
             "head_sha":"a"*40,"repository":{"full_name":"pgextwin/build"},
             "status":"in_progress","conclusion":None,
             "created_at":"2026-10-27T07:03:02Z"}
        def good():
            return m.validate_schedule(run,main,scan,fleet,40464759125,now)
        self.assertEqual(good()[REPO]["mainSha"],MAIN)
        for field,val in [
            ("event","workflow_dispatch"),("event","push"),
            ("path",".github/workflows/other.yml"),
            ("run_attempt",2),("head_sha","b"*40),
            ("status","queued"),("conclusion","failure")]:
            old=run[field];run[field]=val
            with self.subTest(field=field,val=val),self.assertRaises(m.Denied):
                good()
            run[field]=old
        scan["indeterminate"]=1
        with self.assertRaises(m.Denied):good()
        scan["indeterminate"]=0
        scan["generatedAt"]="2026-10-26T00:00:00Z"
        with self.assertRaises(m.Denied):good()

    def test_registry_is_pinned_to_current_observed_bounded_four(self):
        data=json.loads((ROOT/"metadata/merged-candidate-requalification.json").read_text("utf-8"))
        self.assertEqual(data["publication"],"DENY")
        self.assertEqual(len(data["entries"]),4)
        self.assertEqual({x["repository"] for x in data["entries"]},
            {"pgextwin/orafce","pgextwin/pg_ivm",
             "pgextwin/plpgsql_check","pgextwin/pg_hint_plan"})
        self.assertEqual(len({x["candidateHead"] for x in data["entries"]}),4)

if __name__=="__main__":
    unittest.main()
