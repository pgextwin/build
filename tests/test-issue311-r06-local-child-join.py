#!/usr/bin/env python3
"""R06-05-02-02 negative policy tests. Fixtures do NOT represent real GitHub Runs."""
import copy
from datetime import datetime, timezone, timedelta
import importlib.util
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "issue311_r06_join", root / "scripts/issue311-r06-local-child-join.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

CENTRAL = {
    "requestId": "r-20261029-r06prepare17pin03",
    "sourceRunId": 40852118886,
    "sourceRunAttempt": 1,
    "sourceHeadSha": "49575a2d11a591fbf456c0c4d790cd0346ef2fe7",
    "sourceArtifactId": 12886559374,
    "sourceZipSha256": "b81a14c98b7fcc403970b7bde40028799a99938bef595a8ea1400154b35e5262",
    "created_at": "2026-10-29T09:00:00Z",
    "sourceEvent": "push", "publicationAuthorized": False,
    "targetMainSha": {f"pgextwin/ext{i}": f"{i + 1:040x}" for i in range(17)},
}


def child(i):
    repo = f"pgextwin/ext{i}"
    reqid = f"r-20261029-r06localext{i:02d}test"
    head = f"{i + 100:040x}"
    parent = CENTRAL["targetMainSha"][repo]
    req = {
        "schemaVersion": 1, "kind": "pgextwin-local-prepare",
        "mode": "PREPARE", "requestId": reqid,
        "centralRequestId": CENTRAL["requestId"],
        "sourceRunId": CENTRAL["sourceRunId"], "sourceHeadSha": CENTRAL["sourceHeadSha"],
        "sourceArtifactId": CENTRAL["sourceArtifactId"],
        "sourceZipSha256": CENTRAL["sourceZipSha256"],
        "targetMainSha": parent, "publicReleaseAuthorized": False,
        "expiresAt": "2026-10-29T11:00:00Z",
    }
    run = {"id": 2000+i, "run_attempt": 1, "repository": repo,
           "path": mod.LOCAL_WORKFLOW, "event": "push", "head_branch": "main",
           "actor": "ShutenOishi", "status": "completed", "conclusion": "success",
           "head_sha": head, "protectedMain": True,
           "created_at": "2026-10-29T10:00:00Z"}
    receipt = {"schemaVersion": 1, "requestId": reqid, "result": "NO_UPDATE",
               "sourceKind": mod.SOURCE_KIND,
               "originalSourceRunId": CENTRAL["sourceRunId"],
               "originalSourceHeadSha": CENTRAL["sourceHeadSha"],
               "originalSourceArtifactId": CENTRAL["sourceArtifactId"],
               "originalOuterZipSha256Verified": CENTRAL["sourceZipSha256"],
               "localRunId": run["id"], "localRunAttempt": 1,
               "localProtectedRequestParentMainSha": parent,
               "localProtectedHeadSha": head,
               "candidateAdmissionAuthorized": False,
               "publisherSourceKindAuthorized": False,
               "publicationAuthorized": False, "genuineSchedule": False}
    return {"repo": repo, "request": req, "run": run, "parentSha": parent,
            "receipt": receipt, "publisherAuthorized": False, "publicationRequested": False,
            "originalJobConclusion": "success", "completionEventDelivered": True}


def abnormal(c, conclusion):
    c = copy.deepcopy(c)
    c["run"]["conclusion"] = conclusion
    c["receipt"] = None
    c["originalJobConclusion"] = conclusion
    c["watchdog"] = {
        "sourceRunId": c["run"]["id"], "sourceRunAttempt": 1,
        "centralRunId": CENTRAL["sourceRunId"],
        "centralRequestId": CENTRAL["requestId"],
        "localRequestId": c["request"]["requestId"],
        "status": mod.ABNORMAL[conclusion], "terminal": "QUARANTINED",
        "originalGetVerified": True, "durableAppCasReadbackVerified": True,
        "noReexecute": True, "publisherAuthorized": False,
        "watchdogRunId": 80000+c["run"]["id"],
        "observedAt": "2026-10-29T10:20:00Z",
    }
    return c


class JoinPolicyOnly(unittest.TestCase):
    def setUp(self):
        self.items = [child(i) for i in range(17)]

    def denied(self, update):
        copies = copy.deepcopy(self.items)
        update(copies)
        with self.assertRaises(mod.Denied):
            mod.validate_17_original_children(CENTRAL, copies)

    def test_happy_fixture_is_policy_only_not_genuine_run_or_cas(self):
        out = mod.validate_17_original_children(CENTRAL, self.items)
        self.assertEqual(out["targetCount"], 17)
        self.assertEqual(out["proofScope"], "POLICY_BOUNDARY_ONLY_NOT_LIVE_CAS")
        self.assertEqual(out["result"], "NO_UPDATE")

    def test_genuine_conclusion_classes_require_witness(self):
        for conclusion in mod.ABNORMAL:
            with self.subTest(conclusion=conclusion):
                copies = copy.deepcopy(self.items)
                copies[0] = abnormal(copies[0], conclusion)
                self.assertEqual(mod.validate_17_original_children(CENTRAL, copies)["result"], "QUARANTINED")
                copies[0]["watchdog"]["durableAppCasReadbackVerified"] = False
                with self.assertRaises(mod.Denied):
                    mod.validate_17_original_children(CENTRAL, copies)

    def test_real_actions_job_skipped_with_workflow_success_is_not_normal(self):
        xs = copy.deepcopy(self.items)
        xs[0] = abnormal(xs[0], "skipped")
        xs[0]["run"]["conclusion"] = "success"
        xs[0]["completionEventDelivered"] = False
        self.assertEqual(mod.validate_17_original_children(CENTRAL, xs)["result"],
                         "QUARANTINED")
        xs[0]["watchdog"]["durableAppCasReadbackVerified"] = False
        with self.assertRaises(mod.Denied):
            mod.validate_17_original_children(CENTRAL, xs)

    def test_real_actions_failed_workflow_requires_authenticated_timeout_step(self):
        xs = copy.deepcopy(self.items)
        xs[0] = abnormal(xs[0], "timed_out")
        xs[0]["run"]["conclusion"] = "failure"
        xs[0]["originalJobConclusion"] = "failure"
        with self.assertRaises(mod.Denied):
            mod.validate_17_original_children(CENTRAL, xs)
        xs[0]["originalTimeoutStepVerified"] = True
        self.assertEqual(mod.validate_17_original_children(CENTRAL, xs)["result"],
                         "QUARANTINED")
        xs[0]["watchdog"]["originalGetVerified"] = False
        with self.assertRaises(mod.Denied):
            mod.validate_17_original_children(CENTRAL, xs)

    def test_wrong_central_cycle_is_never_reused(self):
        self.denied(lambda xs: xs[0]["request"].update(sourceRunId=40864238327))
        self.denied(lambda xs: xs[0]["request"].update(centralRequestId="foreign"))
        self.denied(lambda xs: xs[0]["request"].update(sourceZipSha256="f"*64))
        self.denied(lambda xs: xs[0]["request"].update(targetMainSha="b"*40))
        self.denied(lambda xs: xs[0].update(parentSha="b"*40))

    def test_source_kind_and_replay_fail_closed(self):
        self.denied(lambda xs: xs[0]["receipt"].update(sourceKind="FAKE_SCHEDULE"))
        self.denied(lambda xs: xs[0]["receipt"].update(publisherSourceKindAuthorized=True))
        self.denied(lambda xs: xs[0]["receipt"].update(originalSourceRunId=99999))
        self.denied(lambda xs: xs[0]["run"].update(run_attempt=2))
        self.denied(lambda xs: xs[0]["run"].update(event="schedule"))
        self.denied(lambda xs: xs[0]["run"].update(protectedMain=False))
        self.denied(lambda xs: xs[0]["request"].update(publicReleaseAuthorized=True))

    def test_missing_duplicate_and_faked_failed_children_deny(self):
        self.denied(lambda xs: xs.pop())
        self.denied(lambda xs: xs.__setitem__(0, copy.deepcopy(xs[1])))
        self.denied(lambda xs: xs[0]["run"].update(conclusion="failure"))
        self.denied(lambda xs: xs[0].update(watchdog={"terminal": "QUARANTINED"}))
        self.denied(lambda xs: xs[0]["run"].update(created_at="2026-10-29T11:00:01Z"))

    def test_missing_completion_event_requires_bounded_durable_original(self):
        cases = copy.deepcopy(self.items)
        cases[0]["completionEventDelivered"] = False
        with self.assertRaises(mod.Denied):
            mod.validate_17_original_children(CENTRAL, cases)
        cases[0]["watchdog"] = {
            "sourceRunId": cases[0]["run"]["id"], "sourceRunAttempt": 1,
            "centralRunId": CENTRAL["sourceRunId"],
            "centralRequestId": CENTRAL["requestId"],
            "localRequestId": cases[0]["request"]["requestId"],
            "status": "MISSING_EVENT", "terminal": "QUARANTINED",
            "originalGetVerified": True, "durableAppCasReadbackVerified": True,
            "noReexecute": True, "publisherAuthorized": False,
            "watchdogRunId": 11111,
            "observedAt": "2026-10-29T11:01:00Z",
        }
        self.assertEqual(mod.validate_17_original_children(CENTRAL, cases)["result"],
                         "QUARANTINED")
        cases[0]["watchdog"]["observedAt"] = "2026-10-29T10:01:00Z"
        with self.assertRaises(mod.Denied):
            mod.validate_17_original_children(CENTRAL, cases)

    def test_missing_event_cannot_be_claimed_from_absent_watchdog(self):
        self.denied(lambda xs: xs[0].update(receipt=None))
        self.denied(lambda xs: xs[0].update(originalJobConclusion="skipped"))
        self.denied(lambda xs: xs[0]["run"].update(conclusion="skipped"))


if __name__ == "__main__":
    unittest.main()
