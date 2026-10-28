#!/usr/bin/env python3
"""Issue 311 R04 pure CAS/state denial fixtures (NO RELEASE, NO WRITE)."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("issue311_state", ROOT / "scripts" / "issue311-state-core.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)
REPO = "pgextwin/orafce"
REQ = "r-20261029-aaaaaaaa"
H = "a" * 64
RECEIPT = "b" * 64


def event(key, stage="AUTHENTICATE", outcome="STEP_OK", repo=REPO, input_digest=H):
    return {"key":key, "repo":repo, "stage":stage, "outcome":outcome,
            "inputSha256":input_digest, "receiptSha256":RECEIPT,
            "runId":123, "runAttempt":1, "reason":"original immutable read-only evidence"}


class StateTests(unittest.TestCase):
    def new(self, targets=None, max_attempts=2, max_operations=20):
        return lib.create_state(REQ,H, targets or [REPO], max_attempts=max_attempts,
                                max_operations=max_operations)

    def test_success_path_requires_all_seven_bounded_stages(self):
        s = self.new()
        for stage in lib.STAGES:
            s = lib.advance(s,s["revision"],event("event-"+stage,stage))
        self.assertTrue(s["terminal"])
        self.assertEqual(s["targets"][REPO]["outcome"],"SUCCESS")
        self.assertFalse(lib.summarize(s)["publisherAuthorized"])
        self.assertFalse(lib.summarize(s)["persistenceAccepted"])
        with self.assertRaises(lib.Conflict):
            lib.advance(s,s["revision"],event("extra","DOWNSTREAM"))

    def test_idempotent_exact_replay_and_stale_cas_conflict(self):
        original = self.new()
        ev = event("first")
        updated = lib.advance(original,0,ev)
        self.assertEqual(original["revision"],0)
        self.assertEqual(updated["revision"],1)
        self.assertEqual(lib.advance(updated,0,ev),updated)
        altered = dict(ev,reason="tampered event replay")
        with self.assertRaises(lib.Conflict):
            lib.advance(updated,1,altered)
        with self.assertRaises(lib.Conflict):
            lib.advance(updated,0,event("second","SCAN"))
        with self.assertRaises(lib.Conflict):
            lib.advance(updated,1,event("skip","CANDIDATE"))

    def test_retries_are_finite_and_input_fixed(self):
        s = self.new()
        s = lib.advance(s,0,event("retry1",outcome="RETRYABLE"))
        self.assertEqual(s["targets"][REPO]["stage"],"AUTHENTICATE")
        with self.assertRaises(lib.Conflict):
            lib.advance(s,1,event("changed",outcome="RETRYABLE",input_digest="c"*64))
        s = lib.advance(s,1,event("retry2",outcome="RETRYABLE"))
        self.assertTrue(s["terminal"])
        self.assertEqual(s["targets"][REPO]["outcome"],"FAILED")

    def test_ambiguous_write_is_quarantined_without_retry(self):
        s = lib.advance(self.new(),0,event("unknown",outcome="WRITE_OUTCOME_UNKNOWN"))
        self.assertTrue(s["terminal"])
        self.assertEqual(s["targets"][REPO]["outcome"],"QUARANTINED")
        with self.assertRaises(lib.Conflict):
            lib.advance(s,1,event("blind-write-retry"))

    def test_two_targets_partial_no_update_and_failure(self):
        repo2="pgextwin/pg_ivm"
        s = self.new([REPO,repo2])
        s = lib.advance(s,0,event("no-update",outcome="NO_UPDATE"))
        self.assertFalse(s["terminal"])
        s = lib.advance(s,1,event("blocked",outcome="BLOCKED_APPROVAL",repo=repo2))
        self.assertTrue(s["terminal"])
        self.assertEqual(lib.summarize(s)["outcomes"],
                         {REPO:"NO_UPDATE",repo2:"BLOCKED_APPROVAL"})

    def test_bad_original_and_scope_are_denied(self):
        tests = [
            lambda v:v.update(key=""),
            lambda v:v.update(repo="pgextwin/evil"),
            lambda v:v.update(stage="PUBLISH"),
            lambda v:v.update(outcome="FORCE_PUBLISH"),
            lambda v:v.update(runId=0),
            lambda v:v.update(runId=True),
            lambda v:v.update(runAttempt=0),
            lambda v:v.update(inputSha256="short"),
            lambda v:v.update(receiptSha256="short"),
            lambda v:v.update(reason=""),
            lambda v:v.update(fakePublisher=True),
        ]
        for n,mutate in enumerate(tests):
            s = self.new()
            e = event("test-"+str(n))
            mutate(e)
            with self.subTest(index=n),self.assertRaises(lib.Conflict):
                lib.advance(s,0,e)

    def test_operation_budget_and_initial_state(self):
        with self.assertRaises(lib.Conflict):
            self.new([REPO,REPO])
        with self.assertRaises(lib.Conflict):
            lib.create_state(REQ,"bad",[REPO])
        s = self.new(max_operations=1)
        s = lib.advance(s,0,event("e1"))
        with self.assertRaises(lib.Conflict):
            lib.advance(s,1,event("e2",stage="SCAN"))


if __name__=="__main__":
    unittest.main()
