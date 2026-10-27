#!/usr/bin/env python3
"""Fail-closed regression suite for the separate scheduled merged-bot signing intent."""
from __future__ import annotations
import importlib.util
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "scheduled_merged_intent", ROOT / "scripts/verify-merged-schedule-signing-intent.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
REPO = "pgextwin/orafce"
SHA = "dedba985a6b06ff2840047264a2ef9841298a956"
BRANCH = {"name":"main","protected":True,"commit":{"sha":SHA},
          "protection":{"required_status_checks":{"checks":[
              {"context":"Windows required summary","app_id":15368}]}}}
RUN = {"id":40490000001,"event":"schedule","run_attempt":1,
       "path":".github/workflows/update-watch.yml","head_branch":"main",
       "head_sha":SHA,"repository":{"full_name":REPO},
       "status":"in_progress","conclusion":None}

def call(run=None, branch=None, **overrides):
    kw = dict(repo=REPO,sha=SHA,run_id=RUN["id"],attempt=1,
              event="schedule",ref="refs/heads/main")
    kw.update(overrides)
    return mod.verify_local_runtime(RUN if run is None else run,
                                    BRANCH if branch is None else branch,**kw)

class ScheduleIdentityTests(TestCase):
    def test_valid_shape_is_only_a_runtime_prerequisite(self):
        self.assertIsNone(call())

    def test_synthetic_and_replayed_events_denied(self):
        for value in ("workflow_dispatch","push","workflow_run","pull_request"):
            with self.subTest(event=value),self.assertRaises(mod.Denied):
                call(event=value)
        with self.assertRaises(mod.Denied):
            call(attempt=2)
        with self.assertRaises(mod.Denied):
            call(ref="refs/heads/auto-candidate/abcdefabcdefabcdefab")

    def test_wrong_or_unprotected_branch_denied(self):
        for branch in [dict(BRANCH,protected=False),
                       dict(BRANCH,commit={"sha":"0"*40}),
                       dict(BRANCH,protection={"required_status_checks":{"checks":[]}}),
                       dict(BRANCH,protection={"required_status_checks":{"checks":[
                           {"context":"Windows required summary","app_id":0}]}})]:
            with self.subTest(branch=branch),self.assertRaises(mod.Denied):
                call(branch=branch)

    def test_wrong_run_head_source_attempt_status_denied(self):
        cases = [
            {"event":"push"}, {"run_attempt":2}, {"head_sha":"0"*40},
            {"head_branch":"candidate"}, {"path":".github/workflows/windows.yml"},
            {"repository":{"full_name":"pgextwin/hypopg"}}, {"id":4},
            {"status":"queued"}, {"conclusion":"failure"}]
        for change in cases:
            with self.subTest(change=change),self.assertRaises(mod.Denied):
                call(run=dict(RUN,**change))
        with self.assertRaises(mod.Denied):
            call(repo="pgextwin/not_on_explicit_four_list")

    def test_no_false_authority_from_live_proof(self):
        original = {"status":mod.origin.SOURCE_KIND,"verifiedOriginalNativeCi":True,
                    "publicationAuthorized":False,"publisherSourceKindAuthorized":False,
                    "requiredCheckRun":123,"manifestBlob":"a"*40,
                    "upstream":{"repository":"upstream/orafce"}}
        registry = {"entries":[{"repository":REPO,"pr":8,"candidateHead":"a"*40,
                                "mergeSha":"b"*40,"nativeRun":1234}]}
        scan = {"schemaVersion":1}
        fleet = {"entries":[]}
        central = {"commit":{"sha":"c"*40}}
        scan_run = {"id":12345}
        with patch.object(mod.origin,"validate_schedule",return_value={
                REPO:{"status":"up-to-date","mainSha":SHA}}),\
             patch.object(mod.origin,"github",return_value={}),\
             patch.object(mod.origin,"validate_merged",return_value=original):
            got = mod.bound_intent(repo=REPO,current=BRANCH,central=central,
                scan_run=scan_run,scan=scan,fleet=fleet,registry=registry,
                local_run=RUN,now=None)
            self.assertFalse(got["publicationAuthorized"])
            self.assertFalse(got["publisherSourceKindAuthorized"])
            self.assertFalse(got["signedArtifactsVerified"])
            self.assertIsNone(got["newOIDCSigningRun"])
            self.assertEqual(got["independentSigstoreAudits"],0)

            for attack in [{"publicationAuthorized":True},
                           {"publisherSourceKindAuthorized":True},
                           {"verifiedOriginalNativeCi":False},
                           {"status":"UNSIGNED_MANUAL"}]:
                with self.subTest(attack=attack),\
                     patch.object(mod.origin,"validate_merged",
                                  return_value=dict(original,**attack)),\
                     self.assertRaises(mod.Denied):
                    mod.bound_intent(repo=REPO,current=BRANCH,central=central,
                        scan_run=scan_run,scan=scan,fleet=fleet,registry=registry,
                        local_run=RUN,now=None)
        with patch.object(mod.origin,"validate_schedule",return_value={
                REPO:{"status":"update-available","mainSha":SHA}}),\
             self.assertRaises(mod.Denied):
            mod.bound_intent(repo=REPO,current=BRANCH,central=central,
                scan_run=scan_run,scan=scan,fleet=fleet,registry=registry,
                local_run=RUN,now=None)

if __name__ == "__main__":
    main()
