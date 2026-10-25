#!/usr/bin/env python3
"""Actual checked-out deployment policy, separate from historical fixtures."""
import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("actual_deployment_policy",ROOT/"scripts/automatic-publisher-receipt-issuer.py")
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)

class PolicyTests(unittest.TestCase):
    def test_actual_policy_is_complete_but_never_release_authority(self):
        objects=[gate.fleet_policy.read(ROOT/"metadata"/name) for name in (
            "automation-fleet.json","release-promotion.json",
            "unattended-publication.json","publisher-write-boundary.json")]
        result=gate.deployment_policy(*objects)
        self.assertEqual(len(result["registeredRepositories"]),len(objects[0]["entries"]))
        self.assertIs(result["publicationAuthorized"],False)
        self.assertIs(result["publishableReceipt"],False)
        self.assertEqual(result["staticPublisherReady"],objects[0]["releasePolicy"]==gate.MODE)

    def test_legacy_manual_downstream_cannot_grant_automatic_release(self):
        downstream=gate.fleet_policy.read(ROOT/"metadata/manual-release-downstream.json")
        self.assertEqual(downstream["mode"],"POST_MANUAL_RELEASE_ONLY")
        self.assertIs(downstream["automaticFormalRelease"],False)
        self.assertIs(downstream["automaticCatalogMerge"],False)

if __name__=="__main__":unittest.main()
