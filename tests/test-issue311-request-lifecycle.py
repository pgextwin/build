#!/usr/bin/env python3
"""Hostile R04/R05 general request lifecycle; no App token, no publication."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lifecycle",ROOT/"scripts"/"issue311-request-lifecycle.py")
life = importlib.util.module_from_spec(spec)
spec.loader.exec_module(life)
R="r-20261029-finitewatch001"
A="a"*64
SHA="b"*40
T=["pgextwin/orafce","pgextwin/pg_ivm"]
EXP="2026-10-29T01:30:00Z"


class LifecycleTests(unittest.TestCase):
    def fresh(self):
        return life.new(R,A,SHA,T,EXP,max_events=4)

    def bound(self):
        return life.bind_source(self.fresh(),0,"source-1",run_id=42,attempt=1,head_sha=SHA)

    def test_generic_request_and_duplicate_event(self):
        s=self.bound()
        self.assertEqual(s["revision"],1)
        self.assertEqual(life.bind_source(s,0,"source-1",run_id=42,attempt=1,head_sha=SHA),s)
        with self.assertRaises(life.Denied):
            life.bind_source(s,1,"source-1",run_id=99,attempt=1,head_sha=SHA)
        with self.assertRaises(life.Denied):
            life.bind_source(s,0,"source-2",run_id=44,attempt=1,head_sha=SHA)
        with self.assertRaises(life.Denied):
            life.bind_source(s,1,"source-2",run_id=43,attempt=1,head_sha=SHA)

    def test_original_event_terminal_and_no_update_guard(self):
        s=self.bound()
        good={t:"SUCCESS" for t in T}
        result=life.record_completion(s,1,"join",run_id=90,attempt=1,
                source_id=42,outcome="NO_UPDATE",target_outcomes=good,original_zip_sha=A)
        self.assertEqual(result["terminal"],"NO_UPDATE")
        self.assertEqual(result["eventTransport"],"workflow_run.completed")
        self.assertFalse(result["publisherAuthorized"])
        with self.assertRaises(life.Denied):
            life.event_deadline(result,2,"late",now=EXP,source_completed=True,
                    original_source_sha=SHA,completion_lookup="MISSING_VERIFIED")
        with self.assertRaises(life.Denied):
            life.record_completion(s,1,"bad",run_id=91,attempt=1,
                    source_id=42,outcome="NO_UPDATE",
                    target_outcomes={T[0]:"SUCCESS",T[1]:"FAILED"},original_zip_sha=A)

    def test_deadline_missing_and_unknown_fail_closed(self):
        s=self.bound()
        with self.assertRaises(life.Denied):
            life.event_deadline(s,1,"early",now="2026-10-29T01:29:59Z",
                    source_completed=True,original_source_sha=SHA,
                    completion_lookup="MISSING_VERIFIED")
        with self.assertRaises(life.Denied):
            life.event_deadline(s,1,"not-missing",now=EXP,
                    source_completed=True,original_source_sha=SHA,
                    completion_lookup="DELIVERED")
        failed=life.event_deadline(s,1,"expire",now=EXP,source_completed=True,
                    original_source_sha=SHA,completion_lookup="MISSING_VERIFIED")
        self.assertEqual(failed["terminal"],"FAILED")
        self.assertEqual(set(failed["targets"].values()),{"FAILED"})
        for original,lookup in ((False,"MISSING_VERIFIED"),(None,"UNKNOWN"),(True,"UNKNOWN")):
            quarantine=life.event_deadline(s,1,"uncertain",now=EXP,
                  source_completed=original,original_source_sha=SHA,completion_lookup=lookup)
            self.assertEqual(quarantine["terminal"],"QUARANTINED")
            self.assertFalse(quarantine["publisherAuthorized"])

    def test_immutability_poison_and_exhaustion(self):
        s=self.bound()
        for patch in ({"publisherAuthorized":True},{"writeOutcomeUnknown":True},
                      {"scope":"PUBLISH"},{"revision":True},
                      {"targets":{T[0]:"SUCCESS"}},
                      {"eventTransport":"PUBLISH"}):
            bad=dict(s,**patch)
            if "eventTransport" in patch:
                continue
            with self.subTest(patch=patch),self.assertRaises(life.Denied):
                life.validate(bad)
        with self.assertRaises(life.Denied):
            life.new(R,A,SHA,[T[0],T[0]],EXP)
        with self.assertRaises(life.Denied):
            life.new(R,A,SHA,T,EXP,max_events=0)
        with self.assertRaises(life.Denied):
            life.event_deadline(s,1,"bad",now=EXP,source_completed=True,
                original_source_sha="c"*40,completion_lookup="MISSING_VERIFIED")
        self.assertEqual(s["terminal"],None)
        self.assertEqual(s["revision"],1)

if __name__=="__main__":
    unittest.main()
