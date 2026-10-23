#!/usr/bin/env python3
"""Regression/hostile fixtures for nonpublishing ChatGPT hourly fleet triage."""
from __future__ import annotations
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("task_queue", ROOT / "scripts" / "chat-task-queue.py")
queue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(queue)
POLICY = json.loads((ROOT / "metadata" / "automation-fleet.json").read_text("utf-8"))


def snapshot():
    return {
        "schemaVersion": 1, "policyRelease": "manual-only",
        "extensions": [
            {
                "repository": entry["repository"],
                "extension": entry["repository"].split("/")[1],
                "mode": entry["mode"],
                "errors": [], "watchResult": "SUCCESS",
                "lastCandidateStatus": "NOT_RUN",
                "candidatePrUrl": None, "detectedCandidate": None
            }
            for entry in POLICY["entries"]
        ]
    }


def target(status, name="orafce"):
    return next(x for x in status["extensions"]
                if x["repository"] == "pgextwin/" + name)


class HourlyQueueTests(unittest.TestCase):
    def test_all_seventeen_idle_no_publication(self):
        result = queue.plan(POLICY, snapshot())
        self.assertEqual(result["fleetSize"], 17)
        self.assertEqual(result["pending"], 0)
        self.assertEqual(result["actions"], [])
        self.assertIs(result["releaseAuthorized"], False)
        self.assertIs(result["formalReleasePermitted"], False)

    def test_candidate_triage_never_confuses_ci_with_release(self):
        state = snapshot()
        target(state)["detectedCandidate"] = {"url": "https://github.com/pgextwin/orafce/issues/7"}
        target(state, "pg_hint_plan")["candidatePrUrl"] = (
            "https://github.com/pgextwin/pg_hint_plan/pull/19")
        result = queue.plan(POLICY, state)
        self.assertEqual({x["repository"]: x["action"] for x in result["actions"]},
                         {"pgextwin/orafce": "VERIFY_UPSTREAM",
                          "pgextwin/pg_hint_plan": "REVIEW_CANDIDATE"})
        self.assertIs(result["formalReleasePermitted"], False)
        self.assertTrue(all(x["action"] in {"VERIFY_UPSTREAM", "REVIEW_CANDIDATE", "INVESTIGATE_CI", "INVESTIGATE_EVIDENCE"} for x in result["actions"]))
        self.assertFalse(any("releaseTag" in x or "confirmRelease" in x for x in result["actions"]))

    def test_old_issue_with_successful_watch_still_requires_fresh_upstream_sha(self):
        state = snapshot()
        row = target(state)
        row["detectedCandidate"] = {
            "url": "https://github.com/pgextwin/orafce/issues/7",
            "mayBeStale": False,
        }
        row["watchResult"] = "SUCCESS"
        result = queue.plan(POLICY, state)
        self.assertEqual(result["pending"], 1)
        self.assertEqual(result["actions"][0]["action"], "VERIFY_UPSTREAM")
        self.assertIs(result["formalReleasePermitted"], False)
        self.assertFalse(any(x["action"] == "PREPARE_CANDIDATE"
                             for x in result["actions"]))

    def test_failed_ci_or_incomplete_observation_must_not_pass(self):
        state = snapshot()
        target(state)["lastCandidateStatus"] = "FAILED_OR_UNVERIFIED"
        target(state)["candidatePrUrl"] = "https://github.com/pgextwin/orafce/pull/8"
        target(state, "pgtap")["errors"] = ["permission denied"]
        target(state, "pg_hint_plan")["watchResult"] = "FAILED"
        target(state, "pg_variables")["lastCandidateStatus"] = "RUNNING"
        actions = {x["repository"]: x["action"] for x in queue.plan(POLICY, state)["actions"]}
        self.assertEqual(actions, {
            "pgextwin/orafce": "INVESTIGATE_CI",
            "pgextwin/pgtap": "INVESTIGATE_EVIDENCE",
            "pgextwin/pg_hint_plan": "INVESTIGATE_EVIDENCE",
        })

    def test_native_pull_request_ci_success_is_review_only_not_release(self):
        state = snapshot()
        item = target(state, "pgtap")
        item["candidatePrUrl"] = "https://github.com/pgextwin/pgtap/pull/78"
        item["lastCandidateStatus"] = "NATIVE_CI_SUCCESS_UNVERIFIED"
        result = queue.plan(POLICY, state)
        self.assertEqual(result["pending"], 1)
        self.assertEqual(result["actions"][0]["action"], "REVIEW_CANDIDATE")
        self.assertIs(result["releaseAuthorized"], False)
        self.assertIs(result["formalReleasePermitted"], False)
        item["lastCandidateStatus"] = "DISPATCH_CI_SUCCESS_UNVERIFIED"
        self.assertEqual(queue.plan(POLICY, state)["actions"][0]["action"],
                         "REVIEW_CANDIDATE")
        item["lastCandidateStatus"] = "STALE_HEAD_CI"
        self.assertEqual(queue.plan(POLICY, state)["actions"][0]["action"],
                         "INVESTIGATE_CI")
        item["candidatePrUrl"] = None
        for ci in ("NATIVE_CI_SUCCESS_UNVERIFIED", "DISPATCH_CI_SUCCESS_UNVERIFIED", "STALE_HEAD_CI"):
            item["lastCandidateStatus"] = ci
            with self.assertRaises(queue.Denied):
                queue.plan(POLICY, state)

    def test_candidate_not_prepared_if_watch_or_fleet_gate_unproven(self):
        state = snapshot()
        row = target(state)
        row["detectedCandidate"] = {"title": "upstream"}
        row["watchResult"] = "UNKNOWN"
        self.assertEqual(queue.plan(POLICY, state)["actions"][0]["action"],
                         "INVESTIGATE_EVIDENCE")
        row["watchResult"] = "SUCCESS"
        row["mode"] = "OFF"
        with self.assertRaises(queue.Denied):
            queue.plan(POLICY, state)

    def test_snapshot_fail_closed_adversarial(self):
        mutations = [
            lambda x: x.update(policyRelease="automatic"),
            lambda x: x.update(schemaVersion=True),
            lambda x: x["extensions"].pop(),
            lambda x: x["extensions"].append(deepcopy(x["extensions"][-1])),
            lambda x: target(x).update(repository="pgextwin/evil"),
            lambda x: target(x).update(candidatePrUrl="https://evil.example/pull/1"),
            lambda x: target(x).update(candidatePrUrl="https://githubXcom/pgextwin/orafce/pull/8"),
            lambda x: target(x).update(candidatePrUrl="https://github.com/pgextwin/other/pull/8"),
            lambda x: target(x).update(candidatePrUrl="https://github.com/pgextwin/orafce/pull/0"),
            lambda x: target(x).update(lastCandidateStatus="success"),
            lambda x: target(x).update(watchResult="APPROVED"),
            lambda x: target(x).update(errors=""),
            lambda x: target(x).update(extension="another"),
        ]
        for index, change in enumerate(mutations):
            with self.subTest(case=index), self.assertRaises(queue.Denied):
                state = snapshot()
                change(state)
                queue.plan(POLICY, state)

    def test_policy_expansion_and_auto_release_denied(self):
        variations = [
            lambda x: x.update(releasePolicy="automatic"),
            lambda x: x["entries"].pop(),
            lambda x: x["entries"].append(deepcopy(x["entries"][0])),
            lambda x: x["entries"][0].update(releasePolicy="automatic"),
            lambda x: x["entries"][0].update(repository="someone/unknown"),
        ]
        for index, mutate in enumerate(variations):
            with self.subTest(case=index), self.assertRaises(queue.Denied):
                policy = deepcopy(POLICY)
                mutate(policy)
                queue.plan(policy, snapshot())


if __name__ == "__main__":
    unittest.main()
