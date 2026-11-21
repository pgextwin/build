#!/usr/bin/env python3
"""Hostile NONPUBLISHING tests for the final shared signed Publisher handoff."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, location):
    spec = importlib.util.spec_from_file_location(name, ROOT / location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


handoff = load("signed_publisher_handoff", "scripts/automatic-publisher-handoff.py")
tag_fixtures = load("signed_publisher_tag_fixtures",
                    "tests/test-automatic-release-tag-plan.py")
FLEET = tag_fixtures.pub.FLEET
REPO = tag_fixtures.REPO
SHA = tag_fixtures.SHA
RUN = tag_fixtures.RUN


def fixture():
    first, bridge, unused_manifest = tag_fixtures.fixture()
    tag = tag_fixtures.run_plan()
    opinion = {
        "schemaVersion": 1,
        "status": "INDEPENDENT_SIGNED_RECHECK_MATCH_NONPUBLISHING",
        "repository": REPO,
        "mainMergeSha": SHA,
        "runId": RUN,
        "runAttempt": 1,
        "maintainedMajors": first["maintainedMajors"],
        "assetByteDigestsMatch": True,
        "signedCandidateReverifiedBySeparateJob": True,
        "publishableReceipt": False,
        "publicationAuthorized": False,
        "automaticReleaseEnabled": False,
        "publisherWriteEnabled": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
    }
    return dict(
        first=first, second=deepcopy(first), bridge=bridge,
        opinion=opinion, tag=tag, fleet=deepcopy(FLEET),
        repository=REPO, main_sha=SHA, run_id=RUN, attempt=1,
        event="push", ref="refs/heads/main")


class PublisherHandoffTests(unittest.TestCase):
    def test_positive_is_structured_evidence_only(self):
        result = handoff.handoff(**fixture())
        self.assertEqual(result["status"],
                         "SIGNED_PUBLISHER_HANDOFF_EVIDENCE_ONLY")
        self.assertEqual(result["runId"], RUN)
        self.assertEqual(result["tagProposal"], "v18.1-windows.1")
        self.assertTrue(result["independentSigstoreSecondOpinion"])
        self.assertIn("INDEPENDENT_PUBLISHER_AUTHORIZATION_NOT_ESTABLISHED",
                      result["policyBlockers"])
        for flag in ("publishableReceipt", "publicationAuthorized",
                     "automaticReleaseEnabled", "publisherWriteEnabled"):
            self.assertIs(result[flag], False)
        for gate in ("goB", "g4", "g5"):
            self.assertEqual(result[gate], "NO_GO")
        for forbidden in ("token", "confirmRelease", "operator",
                          "authorizationMode", "releaseId"):
            self.assertNotIn(forbidden, result)

    def test_opted_in_pg19_can_cross_bridge_and_independent_handoff(self):
        values = fixture()
        audit = values["first"]
        audit["maintainedMajors"].append(19)
        for name in ("zip", "spdx", "grype"):
            audit[name + "Sha256ByMajor"]["19"] = "1" * 64
        audit["grypePolicyByMajor"]["19"] = deepcopy(audit["grypePolicyByMajor"]["18"])
        values["second"] = deepcopy(audit)
        values["opinion"]["maintainedMajors"] = audit["maintainedMajors"][:]
        values["tag"]["releaseTagProposal"] = "v19.1-windows.1"
        bridge = tag_fixtures.pub.bridge
        inputs = tag_fixtures.pub.fixture()
        inputs.update(audit=audit, repo=REPO)
        with patch.object(bridge.identity, "PG19_ADMISSION_OPT_IN", frozenset()):
            with self.assertRaisesRegex(bridge.Denied, "SHA256 matrices"):
                bridge.bridge(**inputs)
        values["bridge"] = deepcopy(bridge.bridge(**inputs))
        with patch.object(handoff.identity, "PG19_ADMISSION_OPT_IN", frozenset()):
            with self.assertRaisesRegex(handoff.Denied, "malformed PostgreSQL major matrix"):
                handoff.handoff(**values)
        result = handoff.handoff(**values)
        self.assertEqual(result["maintainedMajors"], list(range(14, 20)))
        self.assertIs(result["publicationAuthorized"], False)
        values["bridge"]["zipSha256ByMajor"]["19"] = "0" * 64
        with self.assertRaisesRegex(handoff.Denied, "signed zip differs"):
            handoff.handoff(**values)

    def test_reject_tampered_or_incomplete_independent_proof(self):
        attacks = [
            lambda x: x["second"]["zipSha256ByMajor"].update({"14": "f"*64}),
            lambda x: x["second"].update(status="VERIFIED"),
            lambda x: x["first"].update(cryptographicVerification="MOCK"),
            lambda x: x["first"].update(signedArtifactsVerified=False),
            lambda x: x["first"].update(automaticReleaseEnabled=True),
            lambda x: x["first"].update(runAttempt=True),
            lambda x: x["first"].update(maintainedMajors=[14,14,15,16,17,18]),
            lambda x: x["first"]["spdxSha256ByMajor"].pop("15"),
            lambda x: x["first"]["grypeSha256ByMajor"].update({"19": "a"*64}),
            lambda x: x["first"]["grypePolicyByMajor"]["14"].update(
                status="BLOCKING_FINDINGS",blockingFindingCount=1),
            lambda x: x["opinion"].update(status="RECHECK_IN_PROGRESS"),
            lambda x: x["opinion"].update(assetByteDigestsMatch=False),
            lambda x: x["opinion"].update(signedCandidateReverifiedBySeparateJob=False),
            lambda x: x["opinion"].update(runId=RUN+1),
            lambda x: x["opinion"].update(publisherWriteEnabled=True),
            lambda x: x["opinion"].update(g4="GO"),
            lambda x: x.update(attempt=2),
            lambda x: x.update(event="workflow_dispatch"),
            lambda x: x.update(ref="refs/heads/release"),
        ]
        self.deny(attacks)

    def test_reject_forged_publisher_or_tag_proposal(self):
        attacks = [
            lambda x: x["bridge"].update(status="PUBLISH_ALLOW"),
            lambda x: x["bridge"].update(mainMergeSha="b"*40),
            lambda x: x["bridge"].update(runAttempt=2),
            lambda x: x["bridge"].update(publisherWriteEnabled=True),
            lambda x: x["bridge"].update(goB="GO"),
            lambda x: x["bridge"]["policyBlockers"].clear(),
            lambda x: x["bridge"]["policyBlockers"].append("SILENT_BYPASS"),
            lambda x: x["bridge"]["zipSha256ByMajor"].update({"14":"b"*64}),
            lambda x: x["tag"].update(status="TAG_ALREADY_RESERVED"),
            lambda x: x["tag"].update(repository="pgextwin/evil"),
            lambda x: x["tag"].update(releaseTagProposal="../bad"),
            lambda x: x["tag"].update(releaseSequence=2),
            lambda x: x["tag"].update(publisherWriteEnabled=True),
            lambda x: x["tag"].update(publicationAuthorized=True),
            lambda x: x["tag"].update(requiresIndependentLiveRecheckAndAtomicTagReservation=False),
            lambda x: x["fleet"].update(releasePolicy="automatic"),
            lambda x: x["fleet"]["entries"].append(deepcopy(x["fleet"]["entries"][0])),
            lambda x: x.update(repository="pgextwin/evil"),
        ]
        self.deny(attacks)

    def test_dynamic_roster_preserves_unknown_repository_deny(self):
        value = fixture()
        # An absent member is still rejected; the old fixed-count rejection
        # was intentionally replaced by exact protected roster membership.
        value["fleet"]["entries"].pop()
        self.assertIsInstance(handoff.handoff(**value), dict)
        value["repository"] = "pgextwin/evil"
        with self.assertRaises(handoff.Denied):
            handoff.handoff(**value)

    def deny(self, attacks):
        for i, mutate in enumerate(attacks):
            with self.subTest(case=i), self.assertRaises(handoff.Denied):
                value=fixture()
                mutate(value)
                handoff.handoff(**value)

    def test_no_network_write_or_release_privilege_in_shared_intake(self):
        script = (ROOT/"scripts/automatic-publisher-handoff.py").read_text("utf-8")
        workflow = (ROOT/".github/workflows/verify-signed-candidate-readonly.yml").read_text("utf-8")
        self.assertNotIn("subprocess", script)
        self.assertNotIn("urllib", script)
        self.assertNotIn("requests", script)
        self.assertNotIn("GH_TOKEN", script)
        self.assertNotIn("github.token", script)
        self.assertIn("automatic-publisher-handoff.py",workflow)
        self.assertIn("publisher_second_opinion:",workflow)
        region = workflow.split("  publisher_second_opinion:",1)[1]
        for text in ("contents: write", "id-token: write",
                     "gh release create", "gh release upload", "confirm_release"):
            self.assertNotIn(text, region)
        self.assertIn("original-signed-audit", region)
        self.assertIn("automatic-release-tag-proposal-nonpublishing.json", region)
        self.assertIn("automatic-publisher-handoff-evidence-only", region)


if __name__ == "__main__":
    unittest.main()
