#!/usr/bin/env python3
"""Explicit trusted-Chat identity does not assert a nonexistent merge App."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

from publication_policy_fixtures import manual_policy

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load("explicit_merge_policy", "scripts/unattended-policy.py")
issuer = load("explicit_merge_issuer", "scripts/automatic-publisher-receipt-issuer.py")
bridge = load("explicit_merge_bridge", "scripts/automatic-postmerge-audit-bridge.py")
bridge_fixtures = load("explicit_merge_bridge_fixtures", "tests/test-automatic-postmerge-audit-bridge.py")


def automatic():
    fleet = manual_policy("automation-fleet.json")
    central = manual_policy("release-promotion.json")
    unattended = policy.with_explicit_merge_identities(manual_policy("unattended-publication.json"))
    boundary = manual_policy("publisher-write-boundary.json")
    fleet["releasePolicy"] = issuer.MODE
    for row in fleet["entries"]:
        row["releasePolicy"] = issuer.MODE
    central["releasePolicy"] = issuer.MODE
    unattended["mode"] = "UNATTENDED"
    unattended["controls"] = {name: True for name in unattended["controls"]}
    boundary.update(mode="ENFORCE", publisherAppId=issuer.APP,
                    publisherInstallationId=issuer.INSTALLATION)
    return fleet, central, unattended, boundary


class ExplicitMergeIdentities(unittest.TestCase):
    def test_conversion_preserves_mode_and_all_automation_switches(self):
        original = manual_policy("unattended-publication.json")
        before = deepcopy(original)
        converted = policy.with_explicit_merge_identities(original)
        self.assertEqual(original, before)
        self.assertEqual(converted["schemaVersion"], 2)
        self.assertEqual(converted["mode"], "OBSERVE")
        self.assertEqual(converted["defaultAction"], "DENY")
        for key, value in original["controls"].items():
            if key != "requireDedicatedMergeApp":
                self.assertIs(converted["controls"][key], value)
        self.assertNotIn("requireDedicatedMergeApp", converted["controls"])
        self.assertIs(converted["controls"]["requireTrustedCandidateMergeIdentity"], True)
        self.assertIs(converted["controls"]["requireDedicatedCatalogMergeApp"], True)
        self.assertEqual(policy.with_explicit_merge_identities(converted), converted)
        result = policy.evaluate(converted, manual_policy("automation-fleet.json"))
        self.assertEqual(result["status"], "OBSERVE_ONLY")
        self.assertIs(result["automaticPublicationAuthorized"], False)
        original["controls"]["requireDedicatedMergeApp"] = False
        with self.assertRaises(policy.PolicyDenied):
            policy.with_explicit_merge_identities(original)

    def test_static_automatic_bundle_keeps_all_runtime_authority_false(self):
        objects = automatic()
        decision = issuer.deployment_policy(*objects)
        self.assertIs(decision["staticPublisherReady"], True)
        self.assertIs(decision["publicationAuthorized"], False)
        self.assertIs(decision["publishableReceipt"], False)
        self.assertEqual(policy.evaluate(objects[2], objects[0])["status"],
                         "POLICY_READY_RUNTIME_EVIDENCE_REQUIRED")

    def test_policy_and_live_gate_share_one_existing_actor_source(self):
        identity = automatic()[2]["candidateMergeIdentity"]
        self.assertEqual(identity, {"mode": "authenticated-connected-chat",
            "actors": sorted(bridge.ALLOWED_ACTORS),
            "requireSamePushAndMergeActor": True})
        self.assertEqual(Path(bridge.candidate_identity.__file__).resolve(),
                         Path(policy.candidate_identity.__file__).resolve())
        args = bridge_fixtures.fixture()
        self.assertEqual(bridge.verify(**args)["status"],
                         "MERGED_NATIVE_CANDIDATE_NONPUBLISHING")
        for actor in ("github-actions[bot]", "pgextwin-publisher[bot]", "other-operator"):
            bad = deepcopy(args)
            bad["event"]["sender"]["login"] = actor
            bad["pr"]["merged_by"]["login"] = actor
            with self.subTest(actor=actor), self.assertRaises(bridge.Denied):
                bridge.verify(**bad)
        args["pr"]["merged_by"]["login"] = "other-operator"
        with self.assertRaises(bridge.Denied):
            bridge.verify(**args)

    def test_forged_identity_or_app_claim_never_passes_static_gate(self):
        changes = (
            lambda p: p["candidateMergeIdentity"].update(mode="github-app"),
            lambda p: p["candidateMergeIdentity"].update(mode="unattended-bot"),
            lambda p: p["candidateMergeIdentity"].update(actors=[]),
            lambda p: p["candidateMergeIdentity"].update(actors=["other-operator"]),
            lambda p: p["candidateMergeIdentity"].update(actors=["github-actions[bot]"]),
            lambda p: p["candidateMergeIdentity"]["actors"].append("other-operator"),
            lambda p: p["candidateMergeIdentity"]["actors"].append("ShutenOishi"),
            lambda p: p["candidateMergeIdentity"].update(actors="ShutenOishi"),
            lambda p: p["candidateMergeIdentity"].update(requireSamePushAndMergeActor=False),
            lambda p: p["candidateMergeIdentity"].update(requireSamePushAndMergeActor=1),
            lambda p: p["candidateMergeIdentity"].update(performedViaApp=True),
            lambda p: p.pop("candidateMergeIdentity"),
            lambda p: p.update(schemaVersion=True),
            lambda p: p.update(schemaVersion=3),
            lambda p: p.update(schemaVersion=1),
        )
        for number, change in enumerate(changes):
            fleet, central, unattended, boundary = automatic()
            change(unattended)
            with self.subTest(case=number), self.assertRaises(issuer.Denied):
                issuer.deployment_policy(fleet, central, unattended, boundary)

    def test_every_positive_control_remains_mandatory(self):
        for key in automatic()[2]["controls"]:
            for mutation in ("false", "missing", "nonboolean"):
                fleet, central, unattended, boundary = automatic()
                if mutation == "missing":
                    del unattended["controls"][key]
                else:
                    unattended["controls"][key] = False if mutation == "false" else 1
                with self.subTest(key=key, mutation=mutation), self.assertRaises(issuer.Denied):
                    issuer.deployment_policy(fleet, central, unattended, boundary)
        fleet, central, unattended, boundary = automatic()
        unattended["controls"]["requireDedicatedMergeApp"] = True
        with self.assertRaises(issuer.Denied):
            issuer.deployment_policy(fleet, central, unattended, boundary)


if __name__ == "__main__":
    unittest.main()
