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

    def test_actual_downstream_declaration_matches_but_never_grants_authority(self):
        spec=importlib.util.spec_from_file_location("actual_catalog_declaration",ROOT/"scripts/catalog-downstream-policy.py")
        contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)
        data=gate.fleet_policy.read(ROOT/"metadata/manual-release-downstream.json")
        fleet=gate.fleet_policy.read(ROOT/"metadata/automation-fleet.json")
        central=gate.fleet_policy.read(ROOT/"metadata/release-promotion.json")
        result=contract.validate(data,fleet,central)
        for key in ("publicationAuthorized","publishableReceipt","catalogWriteAuthorized"):
            self.assertIs(result[key],False)

if __name__=="__main__":unittest.main()
