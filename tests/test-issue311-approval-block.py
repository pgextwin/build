#!/usr/bin/env python3
"""Deterministic OFFLINE approval transition/CAS proof; no real approval claim."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
store = load("approval_store", "scripts/issue311-lifecycle-store.py")
fixtures = load("approval_store_fixtures", "tests/test-issue311-lifecycle-store.py")
life = store.lifecycle
TARGETS = sorted("pgextwin/" + n for n in (
    "pg_bigm", "pg_cron", "pg_hint_plan", "pgaudit", "set_user", "pg_repack",
    "pg_ivm", "pg_qualstats", "plpgsql_check", "orafce", "hypopg", "wal2json",
    "pg_partman", "pg_stat_monitor", "pgtap", "pg_variables", "pg_store_plans"))

def bound():
    initial = life.new("r-20261031-approvalfixture01", "a" * 64, "b" * 40,
                       TARGETS, "2026-10-31T04:00:00Z")
    return life.bind_source(initial, 0, "source", run_id=42, attempt=1, head_sha="b" * 40)

def evidence(state):
    return {**{k: copy.deepcopy(state[k]) for k in
               ("requestId", "requestSha256", "sourceHeadSha", "sourceRun", "targetScope")},
            "policyPath": "metadata/approval-policy.json", "policyBlobSha": "c" * 40,
            "policyMode": "PREPARE", "requiredApprovals": 1, "observedApprovals": 0,
            "observedAt": "2026-10-31T03:00:00Z",
            "lookup": "AUTHENTICATED_HUMAN_APPROVAL_MISSING", "lookupReceiptSha256": "d" * 64,
            "reasonCode": "HUMAN_PREPARE_APPROVAL_MISSING", "lastSuccessfulStage": "SOURCE_BOUND",
            "resumeAt": "RECHECK_ORIGINAL_APPROVAL_WITH_NEW_AUTHORIZATION"}

class CountedBackend(fixtures.Backend):
    def __init__(self):
        super().__init__()
        self.puts = 0
    def __call__(self, method, endpoint, body):
        self.puts += int(method == "PUT")
        return super().__call__(method, endpoint, body)

class ApprovalTests(unittest.TestCase):
    def test_17_terminal_reason_commitment_and_idempotency(self):
        s = bound(); e = evidence(s)
        out = life.record_approval_block(s, 1, "approval", evidence=e)
        self.assertEqual(set(out["targets"].values()), {"BLOCKED_APPROVAL"})
        self.assertEqual(len(out["targets"]), 17)
        self.assertEqual(out["terminal"], "BLOCKED_APPROVAL")
        self.assertEqual(out["revision"], 2)
        self.assertFalse(out["publisherAuthorized"])
        self.assertIsNone(out["completionRun"])
        self.assertEqual(s["terminal"], None)
        self.assertEqual(life.record_approval_block(out, 1, "approval", evidence=e), out)
        changed = dict(e, lookupReceiptSha256="e" * 64)
        with self.assertRaises(life.Denied):
            life.record_approval_block(out, 2, "approval", evidence=changed)
        # The reason/resume/evidence bytes, not only a status, bind the State event.
        digest = hashlib.sha256(json.dumps(dict(op="approval_block", evidence=e),
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(out["events"]["approval"], digest)

    def test_reject_cross_request_policy_missing_and_expired_observations(self):
        s = bound(); e = evidence(s)
        patches = [
            {"requestId": "r-20261031-otherrequest01"}, {"requestSha256": "f" * 64},
            {"sourceHeadSha": "f" * 40}, {"sourceRun": {"id": 99, "attempt": 1}},
            {"targetScope": TARGETS[:-1]}, {"targetScope": TARGETS[::-1]},
            {"policyBlobSha": None}, {"policyPath": "../../policy.json"},
            {"policyMode": "PUBLISH"}, {"policyMode": "AUDIT_ONLY"},
            {"lookup": "PUBLISH_DENY"}, {"lookup": "UNKNOWN"},
            {"lookupReceiptSha256": None}, {"requiredApprovals": True},
            {"observedApprovals": 1}, {"observedApprovals": -1},
            {"observedAt": s["expiresAt"]}, {"reasonCode": "PUBLISH_DENY"},
            {"lastSuccessfulStage": "CHILDREN_COMPLETED"}, {"resumeAt": "RETRY_PUBLISH"},
            {"publicationAuthorized": True}]
        for patch in patches:
            with self.subTest(patch=patch), self.assertRaises(life.Denied):
                life.record_approval_block(s, 1, "approval", evidence=dict(e, **patch))
        for key in e:
            bad = dict(e); del bad[key]
            with self.subTest(missing=key), self.assertRaises(life.Denied):
                life.record_approval_block(s, 1, "approval", evidence=bad)

    def test_never_reopen_success_failure_or_approval_terminal(self):
        s = bound(); e = evidence(s)
        for terminal in ("NO_UPDATE", "FAILED", "QUARANTINED"):
            ended = life.record_completion(s, 1, "done", run_id=99, attempt=1,
                    source_id=42, outcome=terminal,
                    target_outcomes={t: "SUCCESS" if terminal == "NO_UPDATE" else terminal
                                     for t in TARGETS}, original_zip_sha="a" * 64)
            with self.subTest(terminal=terminal), self.assertRaises(life.Denied):
                life.record_approval_block(ended, 2, "approval", evidence=e)
        blocked = life.record_approval_block(s, 1, "approval", evidence=e)
        with self.assertRaises(life.Denied):
            life.record_completion(blocked, 2, "approved-later", run_id=99, attempt=1,
                    source_id=42, outcome="NO_UPDATE", target_outcomes={t: "SUCCESS" for t in TARGETS},
                    original_zip_sha="a" * 64)
        with self.assertRaises(store.Denied):
            store.require_transition(blocked, dict(blocked, terminal=None, revision=3))

    def test_source_and_partial_success_not_overwritten(self):
        s = bound(); e = evidence(s)
        for bad in (dict(s, sourceRun=None), dict(s, sourceRun={"id": 42, "attempt": 2}),
                    dict(s, targets=dict(s["targets"], **{TARGETS[0]: "SUCCESS"}))):
            with self.assertRaises(life.Denied):
                life.record_approval_block(bad, 1, "approval", evidence=e)

    def test_original_cas_adapter_one_put_ack_loss_and_conflict_offline(self):
        # Actual production CAS adapter; IN-MEMORY transport, never real HTTP/App.
        for ack_loss in (False, True):
            backend = CountedBackend(); cas = store.CAS(backend)
            s = bound()
            initial = life.new(s["requestId"], s["requestSha256"], s["sourceHeadSha"],
                               TARGETS, s["expiresAt"])
            cas.write(initial); sha, original = cas.read(s["requestId"])
            cas.write(s, previous=original, expected_blob=sha)
            sha, original = cas.read(s["requestId"])
            out = life.record_approval_block(original, 1, "approval", evidence=evidence(original))
            backend.drop = ack_loss; backend.store_before_drop = True
            before = backend.puts
            result = cas.write(out, previous=original, expected_blob=sha)
            self.assertEqual(backend.puts - before, 1)
            self.assertEqual(result, "RECONCILED_BY_ORIGINAL_GET" if ack_loss else "ORIGINAL_GET_VERIFIED")
            blob, actual = cas.read(s["requestId"])
            self.assertEqual(actual, out)
            self.assertEqual(blob, store.blob_hash(store.canonical(out)))
            # A different stale writer cannot convert the blocked original to success.
            competing = life.record_completion(original, 1, "competitor", run_id=99, attempt=1,
                source_id=42, outcome="NO_UPDATE", target_outcomes={t: "SUCCESS" for t in TARGETS},
                original_zip_sha="e" * 64)
            before = backend.puts
            with self.assertRaises(store.UnknownWrite):
                cas.write(competing, previous=original, expected_blob=sha)
            self.assertEqual(backend.puts - before, 1)
            self.assertEqual(cas.read(s["requestId"])[1], out)

    def test_plan_has_exact_pending_scope_and_no_unbounded_wait(self):
        plan = json.loads((ROOT / "metadata/issue311-remaining-work-v22.json").read_text())
        self.assertEqual(plan["pendingCheckboxes"], ["R09-02", "R09", "R10-02", "R10",
                                                   "R11-01", "R11-02", "R11", "R12-02", "R12"])
        self.assertEqual(plan["acceptedCount"], 85)
        self.assertEqual(plan["targetScope"], TARGETS)
        self.assertFalse(plan["publicationAuthorized"])
        self.assertEqual(len({w["id"] for w in plan["workPackages"]}), 7)
        for work in plan["workPackages"]:
            self.assertTrue(work["inputs"] and work["procedure"] and work["passWhen"]
                            and work["failWhen"] and work["nextAction"])
            self.assertFalse(work["accepted"])
            self.assertIn(work["classification"], ("IMPLEMENT", "VERIFY_EXISTING", "EXTERNAL_GATE"))

def main():
    receipt = None
    if "--receipt" in sys.argv:
        index = sys.argv.index("--receipt"); receipt = Path(sys.argv[index + 1])
        del sys.argv[index:index + 2]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ApprovalTests))
    if not result.wasSuccessful(): return 1
    if receipt:
        paths = ["scripts/issue311-request-lifecycle.py", "scripts/issue311-lifecycle-store.py",
                 "tests/test-issue311-approval-block.py", "metadata/issue311-remaining-work-v22.json",
                 "docs/issue311-remaining-work-v22.md"]
        data = {"schemaVersion": 1, "scope": "OFFLINE_CONTROLLED_APPROVAL_TRANSITION_AND_CAS",
                "realHumanApprovalObserved": False, "realAppCasPerformed": False,
                "r10_02Accepted": False, "publicationAuthorized": False,
                "runId": os.environ.get("GITHUB_RUN_ID"), "headSha": os.environ.get("GITHUB_SHA"),
                "testsPassed": result.testsRun, "targetCount": 17,
                "files": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}}
        raw = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if receipt.exists():
            if receipt.read_bytes() != raw: raise ValueError("independent fixture receipt mismatch")
        else: receipt.write_bytes(raw)
        print("OFFLINE_APPROVAL_BOUNDARY_SHA256", hashlib.sha256(raw).hexdigest())
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
