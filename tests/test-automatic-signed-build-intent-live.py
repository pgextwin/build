#!/usr/bin/env python3
"""Deny stale/forged original schedule artifacts before any future Signer."""
from copy import deepcopy
from datetime import date
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
live=load("live_signing_intent","scripts/automatic-signed-build-intent-live.py")
fixture_mod=load("signing_fixture","tests/test-automatic-signed-build-intent.py")
SOURCE=fixture_mod.SOURCE
MAIN=fixture_mod.MAIN
BRANCH=fixture_mod.BRANCH
RUN=615
ART=917
RUN_AT="2026-10-21T09:00:00Z"
def encoded(path,value):
    raw=json.dumps(value).encode()
    blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    return {"path":path,"encoding":"base64","sha":blob,
            "content":base64.encodebytes(raw).decode()}

def setup():
    base=fixture_mod.fixture()
    repo="pgextwin/orafce"
    event={"ref":"refs/heads/main","repository":{"full_name":repo},
           "created":False,"deleted":False,"after":MAIN}
    pr=deepcopy(base["pr"])
    pr["created_at"]="2026-10-20T00:00:00Z"
    pr["merged_at"]="2026-10-22T10:00:00Z"
    run={"id":RUN,"name":live.NAME,"path":live.WORKFLOW,"event":"schedule",
         "status":"completed","conclusion":"success","head_branch":"main",
         "head_sha":"a"*40,"created_at":RUN_AT}
    artifact={"id":ART,"name":"candidate-decision","expired":False,
              "size_in_bytes":1234,"workflow_run":{"id":RUN,"head_sha":"a"*40}}
    data={
        "branches/main":{"commit":{"sha":MAIN}},
        "pulls/8":pr,
        "contents/config/extension.json?ref="+MAIN:
            encoded("config/extension.json",base["manifest"]),
        "contents/config/candidate-build.json?ref="+MAIN:
            encoded("config/candidate-build.json",base["local_candidate_policy"]),
        "actions/runs?per_page=100":{"total_count":1,"workflow_runs":[run]},
        "actions/runs/615/artifacts?per_page=100":{
            "total_count":1,"artifacts":[artifact]},
    }
    def api(r,path):
        if r!=repo or path not in data:
            raise AssertionError((r,path))
        return deepcopy(data[path])
    def download(r,n):
        if r!=repo or n!=RUN:
            raise AssertionError((r,n))
        return deepcopy(base["decision"])
    return base,event,data,api,download

class SignedIntentLiveTests(unittest.TestCase):
    def execute(self,mutate=None):
        base,event,data,api,download=setup()
        if mutate:
            mutate(base,event,data)
        return live.bind(repository="pgextwin/orafce",event=event,
            witness=base["witness"],fleet=base["fleet"],
            central_policy=base["central_policy"],lifecycle=base["lifecycle"],
            api=api,download=download,today=date(2026,10,22))

    def test_valid_schedule_original_is_still_nonpublishing(self):
        result=self.execute()
        self.assertEqual(result["status"],
            "ELIGIBLE_FOR_FURTHER_SIGNED_BUILD_AUDIT_NONPUBLISHING")
        self.assertEqual(result["originalDecisionRunId"],RUN)
        self.assertEqual(result["originalDecisionArtifactId"],ART)
        for key in ("publicationAuthorized","publishableReceipt",
                    "signedArtifactsVerified","automaticReleaseEnabled"):
            self.assertIs(result[key],False)

    def test_reject_wrong_live_run_pr_artifact_manifest_or_policy(self):
        cases=[
            lambda b,e,d:e.update(after="f"*40),
            lambda b,e,d:e.update(ref="refs/heads/candidate"),
            lambda b,e,d:e.update(created=True),
            lambda b,e,d:d["branches/main"]["commit"].update(sha="f"*40),
            lambda b,e,d:d["pulls/8"].update(merged_at=None),
            lambda b,e,d:d["pulls/8"].update(merged=False),
            lambda b,e,d:d["pulls/8"]["user"].update(login="attacker"),
            lambda b,e,d:d["actions/runs?per_page=100"].update(total_count=0),
            lambda b,e,d:d["actions/runs?per_page=100"]["workflow_runs"][0].update(event="workflow_dispatch"),
            lambda b,e,d:d["actions/runs?per_page=100"]["workflow_runs"][0].update(conclusion="failure"),
            lambda b,e,d:d["actions/runs?per_page=100"]["workflow_runs"][0].update(path="bad.yml"),
            lambda b,e,d:d["actions/runs?per_page=100"]["workflow_runs"][0].update(head_branch="bad"),
            lambda b,e,d:d["actions/runs?per_page=100"]["workflow_runs"][0].update(created_at="2026-11-01T00:00:00Z"),
            lambda b,e,d:d["actions/runs/615/artifacts?per_page=100"].update(total_count=2),
            lambda b,e,d:d["actions/runs/615/artifacts?per_page=100"]["artifacts"][0].update(expired=True),
            lambda b,e,d:d["actions/runs/615/artifacts?per_page=100"]["artifacts"][0].update(id=0),
            lambda b,e,d:d["actions/runs/615/artifacts?per_page=100"]["artifacts"][0]["workflow_run"].update(id=999),
            lambda b,e,d:d["actions/runs/615/artifacts?per_page=100"]["artifacts"][0]["workflow_run"].update(head_sha="b"*40),
            lambda b,e,d:d["contents/config/extension.json?ref="+MAIN].update(content="%%%bad%%%"),
            lambda b,e,d:d["contents/config/extension.json?ref="+MAIN].update(sha="e"*40),
            lambda b,e,d:d["contents/config/candidate-build.json?ref="+MAIN].update(path="config/evil.json"),
            lambda b,e,d:b["witness"].update(candidateBranch="auto-candidate/forged"),
            lambda b,e,d:b["witness"].update(publicationAuthorized=True),
            lambda b,e,d:b["central_policy"].update(releasePolicy="automatic"),
        ]
        for i,case in enumerate(cases):
            with self.subTest(case=i),self.assertRaises((live.Denied,live.intent.Denied,ValueError)):
                self.execute(case)

    def test_a_large_historical_run_count_does_not_block_recent_verified_origins(self):
        self.assertEqual(self.execute(lambda b,e,d:d["actions/runs?per_page=100"].update(total_count=500))["originalDecisionRunId"],RUN)

    def test_fail_closed_on_incomplete_schedule_inventory(self):
        for n in (-1,0,"invalid"):
            with self.subTest(n=n):
                with self.assertRaises(live.Denied):
                    self.execute(lambda b,e,d: d["actions/runs?per_page=100"].update(total_count=n))

    def test_reject_duplicate_json_keys_and_nonallowlisted_endpoints(self):
        with self.assertRaises(live.Denied):
            live.parse_json('{"status":"candidate","status":"release"}')
        with self.assertRaises(live.Denied):
            live.github("pgextwin/orafce","releases")
        with self.assertRaises(live.Denied):
            live.github("pgextwin/../../bad","actions/runs?per_page=100")

if __name__=="__main__":
    unittest.main()
