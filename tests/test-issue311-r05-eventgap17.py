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
