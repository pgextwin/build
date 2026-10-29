#!/usr/bin/env python3
"""Exact-17 controlled no-listener source contract, no GitHub/secret access."""
import importlib.util
import json
import os
from pathlib import Path
from unittest import TestCase, main, mock

ROOT=Path(__file__).resolve().parents[1]

class EventGap17Tests(TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch.dict(os.environ,{"ISSUE311_PROOF_CASE":"missing-event-17"}):
            spec=importlib.util.spec_from_file_location(
                "issue311_eventgap17",ROOT/"scripts/issue311-r04r05-generic-live.py")
            cls.mod=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.mod)

    def request(self):
        m=self.mod
        targets=[{"repo":repo,"mainSha":"a"*40}
                 for repo in sorted(m.bridge.win17.TARGETS)]
        return {
            "requestId":m.REQUEST,"mode":"AUDIT_ONLY",
            "targets":targets,"approval":{"publicReleaseAuthorized":False,
                                           "publicationGrants":[]},
            "allowFutureUpdates":False,
            "limits":{"maxWallClockMinutes":7,"maxOperations":25},
            "source":{"centralMainSha":"b"*40},
        }

    def evaluate(self,data,decl=None):
        m=self.mod
        if decl is None:
            decl={"requestId":m.REQUEST,"mode":"AUDIT_ONLY",
                  "targets":tuple(t["repo"] for t in data["targets"])}
        with mock.patch.object(m.contract,"validate_declaration",return_value=decl):
            return m.read_request(json.dumps(data).encode(),"c"*40)

    def test_exact17_audit_only_matches_source_kind_and_scope(self):
        m=self.mod
        self.assertEqual(m._CASE,"missing-event-17")
        self.assertEqual(len(m.bridge.win17.TARGETS),17)
        data,_=self.evaluate(self.request())
        self.assertEqual(len(data["targets"]),17)

    def test_skipped_original_child_case_is_fixed_to_same_17_and_new_id(self):
        with mock.patch.dict(os.environ,{"ISSUE311_PROOF_CASE":"skipped-17"}):
            spec=importlib.util.spec_from_file_location(
                "issue311_skip17",ROOT/"scripts/issue311-r04r05-generic-live.py")
            m=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        self.assertEqual(m._CASE,"skipped-17")
        self.assertEqual(m.REQUEST,"r-20261029-r05skip17c01")
        self.assertEqual(m.SOURCE_PATH,".github/workflows/issue311-r05-skip17-source.yml")
        self.assertEqual(len(m.bridge.win17.TARGETS),17)

    def test_controlled_ambiguous_ack_case_exact_request_only(self):
        with mock.patch.dict(os.environ,{"ISSUE311_PROOF_CASE":"ambiguous-write-17"}):
            spec=importlib.util.spec_from_file_location(
                "issue311_ambiguous17",ROOT/"scripts/issue311-r04r05-generic-live.py")
            m=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        self.assertEqual(m._CASE,"ambiguous-write-17")
        self.assertEqual(m.REQUEST,"r-20261029-r05ambiguous17d01")
        self.assertEqual(m.SOURCE_PATH,".github/workflows/issue311-r04-ambiguous17-source.yml")
        self.assertEqual(len(m.bridge.win17.TARGETS),17)

    def test_real_timed_out_child_identity_and_source_zip_requirements(self):
        with mock.patch.dict(os.environ,{"ISSUE311_PROOF_CASE":"timed-out-17"}):
            spec=importlib.util.spec_from_file_location(
                "issue311_timeout17",ROOT/"scripts/issue311-r04r05-generic-live.py")
            m=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        self.assertEqual(m.REQUEST,"r-20261029-r05timeout17e01")
        self.assertEqual(m.SOURCE_PATH,".github/workflows/issue311-r05-timeout17-source.yml")
        self.assertEqual(len(m.bridge.win17.TARGETS),17)
        source=(ROOT/".github/workflows/issue311-r05-timeout17-source.yml").read_text()
        self.assertIn("timeout-minutes: 1",source)
        self.assertIn("sleep 125",source)
        self.assertNotIn("workflow_dispatch:",source)

        sid=123
        targets=[{"repo":repo,"mainSha":"a"*40} for repo in sorted(m.bridge.win17.TARGETS)]
        data={"targets":targets}
        original={"id":sid,"head_sha":"c"*40}
        source_job={"run_id":sid,"name":"Actual 17 protected-main GETs and state-only App CAS",
                    "conclusion":"success"}
        timed_job={"run_id":sid,
                   "name":"Deliberately timed-out original child (must never count as successful 17)",
                   "conclusion":"failure","started_at":"2026-10-29T12:00:00Z",
                   "completed_at":"2026-10-29T12:01:00Z"}
        jobs={"total_count":2,"jobs":[source_job,timed_job]}
        arts={"total_count":1,"artifacts":[{"name":m.SOURCE_ZIP,"expired":False,
               "workflow_run":{"id":sid}}]}
        receipt={"result":"SUCCESS","requestId":m.REQUEST,"sourceSha":original["head_sha"],
                 "sourceRunId":sid,"runAttempt":1,"originalRequestSha256":"d"*64,
                 "targetMainSha":targets[0]["mainSha"],
                 "perTarget":{t["repo"]:t["mainSha"] for t in targets},
                 "remoteProtected":True,"publisherAuthorized":False,"revision":1}
        def verify(actual_jobs):
            def get_json(path):
                if path.endswith("/jobs?per_page=100"):
                    return actual_jobs
                if path.endswith("/artifacts?per_page=100"):
                    return arts
                raise AssertionError("unexpected GitHub API")
            with (mock.patch.object(m.bridge,"get_json",side_effect=get_json),
                  mock.patch.object(m.bridge,"original_zip",return_value=(receipt,"e"*64))):
                return m.verify_source_zip(original,{"rawSha256":"d"*64},data)
        self.assertEqual(verify(jobs),"e"*64)
        for short_elapsed in (0,12,30):
            bad=dict(jobs,jobs=[source_job,dict(timed_job,
                completed_at=f"2026-10-29T12:00:{short_elapsed:02d}Z")])
            with self.subTest(seconds=short_elapsed),self.assertRaises(ValueError):
                verify(bad)
        with self.assertRaises(ValueError):
            verify(dict(jobs,jobs=[source_job,dict(timed_job,conclusion="success")]))
        with self.assertRaises(ValueError):
            verify(dict(jobs,jobs=[source_job,dict(timed_job,name="foreign job")]))

    def test_controlled_post_auth_http_fault_case_remains_no_publication(self):
        with mock.patch.dict(os.environ,{"ISSUE311_PROOF_CASE":"http-fault-17"}):
            spec=importlib.util.spec_from_file_location(
                "issue311_httpfault17",ROOT/"scripts/issue311-r04r05-generic-live.py")
            m=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        self.assertEqual(m.REQUEST,"r-20261029-r05httpfault17f01")
        self.assertEqual(m.SOURCE_PATH,".github/workflows/issue311-r05-httpfault17-source.yml")
        self.assertEqual(len(m.bridge.win17.TARGETS),17)
        watcher=(ROOT/"scripts/issue311-r05-finite-watchdog.py").read_text()
        self.assertIn('m.verify_source_zip(original,{"rawSha256":state["requestSha256"]},data)',watcher)
        self.assertIn('CONTROLLED_POST_AUTH_REST_FAULT_INJECTION',watcher)
        for name in ("source","watchdog"):
            yml=(ROOT/f".github/workflows/issue311-r05-httpfault17-{name}.yml").read_text()
            self.assertIn("ISSUE311_PROOF_CASE: http-fault-17",yml)
            self.assertNotIn("workflow_dispatch:",yml)
            self.assertNotIn("contents: write",yml)

    def test_not_16_not_foreign_not_publish_not_unbounded(self):
        m=self.mod
        variations=[]
        candidate=self.request()
        candidate["targets"]=candidate["targets"][:-1]
        variations.append(candidate)
        candidate=self.request()
        candidate["targets"][0]["repo"]="attacker/other"
        variations.append(candidate)
        candidate=self.request()
        candidate["approval"]["publicReleaseAuthorized"]=True
        variations.append(candidate)
        candidate=self.request()
        candidate["approval"]["publicationGrants"]=[{"repo":"pgextwin/orafce"}]
        variations.append(candidate)
        candidate=self.request()
        candidate["limits"]["maxWallClockMinutes"]=999
        variations.append(candidate)
        candidate=self.request()
        candidate["limits"]["maxOperations"]=2000
        variations.append(candidate)
        for candidate in variations:
            with self.subTest(candidate=candidate),self.assertRaises(ValueError):
                self.evaluate(candidate)

if __name__=="__main__":main()
