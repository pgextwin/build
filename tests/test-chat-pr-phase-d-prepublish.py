#!/usr/bin/env python3
"""Issue #75 Phase D synthetic, nonpublishing TOCTOU/adversarial fixtures."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


phase_d = load("phase_d_gate_test", "scripts/chat-pr-phase-d-prepublish.py")
prior = load("phase_c_join_test", "tests/test-chat-pr-phase-c-join.py")
publisher = load("phase_d_publisher_test", "scripts/release-authorization.py")
SHA = prior.approval_case.AFTER
OPERATOR = "HumanOperator"


def snapshot():
    candidate, auth_context = prior.paired_fixtures()
    candidate_result = prior.gate_case.gate.verify(**candidate)
    approval = prior.approval_case.verify_fixture(auth_context)
    required = phase_d.classic_module.REQUIRED_CONTEXTS
    classic = {
        "schemaVersion": 1,
        "status": "VERIFIED_CLASSIC_COMPOSITE_READ_ONLY",
        "repository": "pgextwin/plpgsql_check",
        "branch": "main",
        "mainSha": SHA,
        "requiredChecks": sorted(required),
        "requiredChecksAppId": 15368,
        "strict": True,
        "pullRequestRequired": True,
        "requiredApprovals": 0,
        "adminEnforced": True,
        "actorBypass": False,
        "forcePushAllowed": False,
        "deletionAllowed": False,
        "bypassEvidence": "GRAPHQL_ZERO_FOR_REST_OMISSION",
        "pushEvidence": "GRAPHQL_UNRESTRICTED_FOR_REST_OMISSION",
        "independentEffectiveRefZero": True,
        "independentPushUnrestricted": True,
        "snapshotCount": 2,
        "publishableReceipt": False,
    }
    return {
        "mainSha": SHA,
        "tagRef": "ABSENT",
        "release": "ABSENT",
        "candidateReceipt": candidate_result,
        "approval": approval,
        "classicComposite": classic,
        "artifactSignatures": "NOT_INDEPENDENTLY_VERIFIED",
    }


class FakeReader:
    def __init__(self, first, second=None):
        self.snapshots = [deepcopy(first), deepcopy(first if second is None else second)]
        self.calls = 0

    def capture(self):
        if self.calls >= 2:
            raise AssertionError("unplanned extra evidence reads")
        data = self.snapshots[self.calls]
        self.calls += 1
        return deepcopy(data)


class PhaseDTests(unittest.TestCase):
    def verify(self, first=None, second=None):
        reader = FakeReader(snapshot() if first is None else first, second)
        result = phase_d.verify_inert_prepublication_recheck(
            reader, expected_main_sha=SHA, expected_operator=OPERATOR)
        self.assertEqual(reader.calls, 2)
        return result

    def test_two_independent_context_rounds_remain_nonpublishing(self):
        record = self.verify()
        self.assertEqual(record["status"], "DRY_RUN_PHASE_D_RECHECK_ONLY")
        self.assertEqual(record["mainSha"], SHA)
        self.assertEqual(record["snapshotCount"], 2)
        self.assertTrue(record["freshClassicCompositeEachRound"])
        self.assertTrue(record["tagAndReleaseAbsentEachRound"])
        self.assertIs(record["publishingEnabled"], False)
        self.assertIs(record["publishableReceipt"], False)
        self.assertIs(record["signedArtifactsVerified"], False)
        self.assertEqual(record["candidateArtifactsAndSignatures"],
                         "NOT_INDEPENDENTLY_VERIFIED")
        with self.assertRaises(publisher.Denied):
            publisher.validate_receipt(
                record, repository="pgextwin/plpgsql_check", commit=SHA,
                actor=OPERATOR, event="push")

    def test_modified_first_round_denied(self):
        changes = [
            lambda s: s.update(mainSha="b" * 40),
            lambda s: s.update(tagRef="UNKNOWN"),
            lambda s: s.update(tagRef="PRESENT"),
            lambda s: s.update(release="PRESENT"),
            lambda s: s.update(release=None),
            lambda s: s.update(artifactSignatures="VERIFIED"),
            lambda s: s.update(extra="adversarial"),
            lambda s: s.pop("approval"),
            lambda s: s["approval"].update(event="workflow_dispatch"),
            lambda s: s["approval"].update(operator="attacker"),
            lambda s: s["approval"].update(authorizationCommit="b" * 40),
            lambda s: s["approval"].update(candidatePr=333),
            lambda s: s["candidateReceipt"].update(candidateRunId=33),
            lambda s: s["candidateReceipt"].update(decisionRunId=33),
            lambda s: s["candidateReceipt"].update(candidateHeadSha="f" * 40),
            lambda s: s["candidateReceipt"].update(status="VERIFIED_MANUAL_DISPATCH"),
            lambda s: s["candidateReceipt"].update(operator="intruder"),
            lambda s: s["classicComposite"].update(mainSha="b" * 40),
            lambda s: s["classicComposite"].update(status="DENY"),
            lambda s: s["classicComposite"].update(snapshotCount=1),
            lambda s: s["classicComposite"].update(snapshotCount=True),
            lambda s: s["classicComposite"].update(requiredChecks=[]),
            lambda s: s["classicComposite"].update(requiredChecksAppId=-1),
            lambda s: s["classicComposite"].update(strict=False),
            lambda s: s["classicComposite"].update(requiredApprovals=1),
            lambda s: s["classicComposite"].update(adminEnforced=False),
            lambda s: s["classicComposite"].update(actorBypass=True),
            lambda s: s["classicComposite"].update(forcePushAllowed=True),
            lambda s: s["classicComposite"].update(deletionAllowed=True),
            lambda s: s["classicComposite"].update(independentEffectiveRefZero=False),
            lambda s: s["classicComposite"].update(independentPushUnrestricted=False),
            lambda s: s["classicComposite"].update(bypassEvidence="REST_UNKNOWN"),
            lambda s: s["classicComposite"].update(pushEvidence="REST_UNKNOWN"),
            lambda s: s["classicComposite"].update(publishableReceipt=True),
        ]
        for idx, alter in enumerate(changes):
            record = snapshot()
            alter(record)
            with self.subTest(mutation=idx), self.assertRaises(phase_d.PhaseDDenied):
                self.verify(record)

    def test_fresh_second_read_detects_main_and_candidate_toctou(self):
        changes = [
            lambda s: s.update(mainSha="b" * 40),
            lambda s: s.update(tagRef="PRESENT"),
            lambda s: s.update(release="PRESENT"),
            lambda s: s["approval"].update(authorizationCommit="f" * 40),
            lambda s: s["candidateReceipt"].update(candidatePr=99),
            lambda s: s["candidateReceipt"].update(candidateRunId=71),
            lambda s: s["candidateReceipt"].update(decisionRunId=71),
            lambda s: s["candidateReceipt"].update(sources=[{"commit": "c" * 40}]),
            lambda s: s["classicComposite"].update(mainSha="b" * 40),
            lambda s: s["classicComposite"].update(strict=False),
            lambda s: s["classicComposite"].update(bypassEvidence="REST_EXPLICIT_EMPTY"),
            lambda s: s["classicComposite"].update(pushEvidence="REST_EXPLICIT_UNRESTRICTED"),
            lambda s: s["classicComposite"].update(extra="changed-effective-rule"),
        ]
        for idx, alter in enumerate(changes):
            first = snapshot()
            changed = deepcopy(first)
            alter(changed)
            with self.subTest(race=idx), self.assertRaises(phase_d.PhaseDDenied):
                self.verify(first, changed)

    def test_invalid_runtime_sha_operator_and_missing_reader_denied(self):
        for sha, operator in (
            ("short", OPERATOR),
            (SHA, "github-actions[bot]"),
            (SHA, "Fakebot"),
            (SHA, ""),
        ):
            with self.subTest(sha=sha, operator=operator):
                with self.assertRaises(phase_d.PhaseDDenied):
                    phase_d.verify_inert_prepublication_recheck(
                        FakeReader(snapshot()), expected_main_sha=sha,
                        expected_operator=operator)
        with self.assertRaises(phase_d.PhaseDDenied):
            phase_d.verify_inert_prepublication_recheck(
                object(), expected_main_sha=SHA, expected_operator=OPERATOR)

    def test_no_publishing_functions_exposed(self):
        code = (ROOT / "scripts/chat-pr-phase-d-prepublish.py").read_text()
        self.assertNotIn("workflow_dispatch", code)
        self.assertNotIn("gh release create", code)
        self.assertNotIn("def publish(", code)
        self.assertNotIn("requests.post(", code)
        self.assertNotIn("urlopen(", code)
        self.assertNotIn("subprocess", code)


if __name__ == "__main__":
    unittest.main()
