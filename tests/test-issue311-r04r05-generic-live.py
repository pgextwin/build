#!/usr/bin/env python3
"""R04/R05 genuine generic App linkage + hostile independent watcher fixtures."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
def load(name,p):
    spec=importlib.util.spec_from_file_location(name,ROOT/p)
    lib=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lib)
    return lib

live=load("live","scripts/issue311-r04r05-generic-live.py")
watch=load("watch","scripts/issue311-r05-finite-watchdog.py")
SHA="a"*40
REQ=live.REQUEST

def sample_source():
    return {"id":10,"workflow_id":18,"head_sha":SHA,"head_branch":"main",
            "run_attempt":1,"path":live.SOURCE_PATH,"event":"push",
            "actor":{"login":"ShutenOishi"},"name":live.SOURCE_NAME,
            "status":"completed","conclusion":"success"}

class Evidence(unittest.TestCase):
    def test_real_completion_rejects_forged_event(self):
        event={"action":"completed","repository":{"full_name":"pgextwin/build"},
               "workflow_run":sample_source()}
        declaration={"requestId":REQ,"mode":"AUDIT_ONLY","rawSha256":"b"*64,
                     "targets":(live.TARGET,)}
        request={"requestId":REQ,"targets":[{"repo":live.TARGET,"mainSha":"c"*40}],
                 "source":{"centralMainSha":"d"*40},
                 "approval":{"publicReleaseAuthorized":False,"publicationGrants":[]}}
        with mock.patch.object(live.bridge,"get_json",return_value=sample_source()), \
             mock.patch.object(live,"contents_original",return_value=b"original"), \
             mock.patch.object(live,"read_request",return_value=(request,declaration)):
            original,data,dec=live.authenticated_completed_source(event)
            self.assertEqual(original["id"],10)
            for key,wrong in (("event","workflow_dispatch"),
                              ("path","other.yml"),("conclusion","failure"),
                              ("run_attempt",2),("head_branch","malicious")):
                e=json.loads(json.dumps(event))
                e["workflow_run"][key]=wrong
                with self.subTest(key=key),self.assertRaises(ValueError):
                    live.authenticated_completed_source(e)

    def test_bounded_watcher_decides_event_missing_only_if_full_listing(self):
        state=live.lifecycle.new(REQ,"b"*64,SHA,[live.TARGET],"2026-10-29T01:30:00Z")
        state=live.lifecycle.bind_source(state,0,"source",run_id=10,attempt=1,head_sha=SHA)
        original=sample_source()
        with mock.patch.object(watch.bridge,"get_json",return_value=original), \
             mock.patch.object(watch,"listed",return_value=[]):
            self.assertEqual(watch.snapshot(SHA,state),(True,"MISSING_VERIFIED",0))
        with mock.patch.object(watch.bridge,"get_json",return_value=original), \
             mock.patch.object(watch,"listed",return_value=[{"event":"workflow_run","head_sha":SHA}]):
            self.assertEqual(watch.snapshot(SHA,state),(True,"UNKNOWN",1))
        evil=dict(original,actor={"login":"someoneelse"})
        with mock.patch.object(watch.bridge,"get_json",return_value=evil), \
             mock.patch.object(watch,"listed",return_value=[]):
            with self.assertRaises(ValueError):watch.snapshot(SHA,state)
        with mock.patch.object(watch.bridge,"get_json",return_value={
             "total_count":101,"workflow_runs":[{"head_sha":SHA}]}):
            with self.assertRaises(ValueError):watch.listed(watch.BRIDGE_WORKFLOW,SHA)

    def test_namespaces_and_workflows_are_nonpublishing(self):
        paths=[
           ".github/workflows/issue311-r04r05-source.yml",
           ".github/workflows/issue311-r04r05-bridge.yml",
           ".github/workflows/issue311-r05-finite-watchdog.yml",
        ]
        src=[Path(p).read_text() for p in paths]
        for content in src:
            for illegal in ("workflow_dispatch:", "schedule:", "repository_dispatch:",
                            "id-token: write", "contents: write", "pull_request_target:",
                            "PUBLISH_ELIGIBLE"):
                self.assertNotIn(illegal,content)
            self.assertIn("issue311-state-writer",content)
        self.assertIn("workflow_run:",src[1])
        self.assertIn("push:",src[0])
        self.assertIn("push:",src[2])
        self.assertIn("timeout-minutes: 12",src[2])
        self.assertEqual(watch.MAX_POLL*watch.POLL_SECONDS,600)
        self.assertEqual(live.writer.APP_ID,5517840)
        self.assertEqual(live.writer.INSTALLATION_ID,176347451)

if __name__=="__main__":unittest.main()
