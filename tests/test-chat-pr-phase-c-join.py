#!/usr/bin/env python3
"""Issue #75 Phase C: inert, cross-module candidate + PR evidence binding tests.

All records are synthetic. No network, Actions entrypoint, tag or Release write.
This does NOT establish actual artifact signatures or grant publication rights.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate_case = load("phase_c_gate_fixture", "tests/test-fleet-promotion-gate.py")
approval_case = load("phase_c_auth_fixture", "tests/test-chat-pr-authorization.py")
approval = load("phase_c_auth", "scripts/chat-pr-authorization.py")
receipt_check = load("phase_c_receipt", "scripts/release-authorization.py")


def paired_fixtures():
    candidate = gate_case.fixture("plpgsql_check")
    candidate["authorization_mode"] = "chat-pr-authorization"
    candidate["policy"]["releasePolicy"] = "chat-pr-authorization"
    candidate["local"]["releasePolicy"] = "chat-pr-authorization"
    auth = approval_case.fixture()
    candidate["main_sha"] = approval_case.AFTER
    candidate["tag"] = auth["request"]["releaseTag"]
    auth["request"]["candidatePr"] = candidate["pr"]["number"]
    auth["request"]["candidateHeadSha"] = candidate["pr"]["head"]["sha"]
    auth["request"]["candidateRunId"] = candidate["run"]["id"]
    auth["request"]["decisionRunId"] = candidate["watch_run"]["id"]
    return candidate, auth


def verify_pair(candidate, context):
    # These two independently invoked synthetic validators must agree on exact IDs.
    candidate_receipt = gate_case.gate.verify(**candidate)
    merged_pr_context = approval_case.verify_fixture(context)
    return approval.bind_verified_receipt(candidate_receipt, merged_pr_context)


class PhaseCJoinTests(unittest.TestCase):
    def test_exact_shared_gate_and_pr_context_join_is_inert(self):
        candidate, context = paired_fixtures()
        merged = verify_pair(candidate, context)
        self.assertEqual(merged["authorizationMode"], "chat-pr-authorization")
        self.assertEqual(merged["status"], "VERIFIED_CHAT_PR_AUTHORIZATION")
        self.assertEqual(merged["candidateHeadSha"], candidate["pr"]["head"]["sha"])
        self.assertEqual(merged["candidateRunId"], candidate["run"]["id"])
        self.assertEqual(merged["decisionRunId"], candidate["watch_run"]["id"])
        self.assertEqual(merged["authorizationCommit"], approval_case.AFTER)
        self.assertEqual(merged["authorizationBaseSha"], approval_case.BASE)
        self.assertEqual(
            receipt_check.auth.validate_receipt(
                merged, repository=candidate["repo"],
                commit=approval_case.AFTER, actor=candidate["actor"], event="push"),
            "push")
        # Critically, none of these pure validators creates a public Release.
        self.assertNotIn("publishableReceipt", merged)

    def test_cross_validator_identity_mismatch_denied(self):
        changes = [
            lambda c,a: a["request"].update(candidatePr=123),
            lambda c,a: a["request"].update(candidateHeadSha="0" * 40),
            lambda c,a: a["request"].update(candidateRunId=124),
            lambda c,a: a["request"].update(decisionRunId=125),
            lambda c,a: a["request"].update(releaseTag="v2.10.14-windows.5"),
            lambda c,a: a["request"].update(repository="pgextwin/wal2json"),
            lambda c,a: a["request"].update(operatorLogin="DifferentUser"),
            lambda c,a: a["event"].update(after="0" * 40),
            lambda c,a: a["event"].update(before="0" * 40),
            lambda c,a: c.update(main_sha="0" * 40),
            lambda c,a: c.update(actor="DifferentUser"),
        ]
        for idx, change in enumerate(changes):
            candidate, context = paired_fixtures()
            change(candidate, context)
            with self.subTest(index=idx), self.assertRaises(
                (gate_case.gate.Denied, approval.Denied)):
                verify_pair(candidate, context)

    def test_unverified_candidate_decision_audit_and_matrix_denied(self):
        mutations = [
            lambda c: c["run"].update(conclusion="skipped"),
            lambda c: c["run"].update(conclusion="cancelled"),
            lambda c: c["run"].update(head_sha="0" * 40),
            lambda c: c["watch_run"].update(conclusion="failure"),
            lambda c: c["decision"].update(status="unknown"),
            lambda c: c["decision"]["updates"][0].update(commit="0" * 40),
            lambda c: c["audit"].update(matrixResult="skipped"),
            lambda c: c["audit"]["majors"].pop(),
            lambda c: c["audit"]["majors"][0].update(sourceSha="0" * 40),
            lambda c: c["audit"]["majors"][0].update(zipSha256="invalid"),
            lambda c: c["pr_files"].append({"filename":".github/workflows/promote.yml"}),
            lambda c: c["local"].update(releasePolicy="manual-dispatch"),
            lambda c: c["policy"].update(releasePolicy="manual-dispatch"),
        ]
        for idx, mutation in enumerate(mutations):
            candidate, context = paired_fixtures()
            mutation(candidate)
            with self.subTest(index=idx), self.assertRaises(
                (gate_case.gate.Denied, gate_case.gate.ident.Denied, approval.Denied)):
                verify_pair(candidate, context)

    def test_typed_context_does_not_cross_into_dispatch_mode(self):
        candidate, context = paired_fixtures()
        merged = verify_pair(candidate, context)
        for bad_event in ("workflow_dispatch", "schedule", "pull_request"):
            with self.subTest(event=bad_event), self.assertRaises(receipt_check.auth.Denied):
                receipt_check.auth.validate_receipt(
                    merged, repository=candidate["repo"],
                    commit=approval_case.AFTER, actor=candidate["actor"],
                    event=bad_event)
        forged = deepcopy(merged)
        forged["authorizationBaseSha"] = "0" * 40
        with self.assertRaises(receipt_check.auth.Denied):
            receipt_check.auth.validate_receipt(
                forged, repository=candidate["repo"],
                commit=approval_case.AFTER, actor=candidate["actor"], event="push")


if __name__ == "__main__":
    unittest.main()
