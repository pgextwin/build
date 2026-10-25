#!/usr/bin/env python3
"""Offline downstream transition: declarations never authorize any write."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest
from publication_policy_fixtures import manual_policy

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tested_catalog_contract", ROOT / "scripts/catalog-downstream-policy.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Downstream(unittest.TestCase):
    def setUp(self):
        self.fleet = manual_policy("automation-fleet.json")
        self.central = manual_policy("release-promotion.json")
        self.downstream = manual_policy("manual-release-downstream.json")

    def automatic(self):
        f, c = deepcopy(self.fleet), deepcopy(self.central)
        f["releasePolicy"] = c["releasePolicy"] = m.fleet_policy.AUTOMATIC
        for row in f["entries"]:
            row["releasePolicy"] = m.fleet_policy.AUTOMATIC
        return f, c

    def test_historical_disabled_declaration_remains_manual(self):
        result = m.validate(self.downstream, self.fleet, self.central)
        self.assertIs(result["catalogMergeDeclared"], False)
        self.assertFalse(self.downstream["automaticFormalRelease"])
        self.assertEqual(self.downstream["allowedExtensions"], ["plpgsql_check"])

    def test_manual_catalog_optin_requires_exact_registered_fleet_and_never_formal_authority(self):
        future = deepcopy(self.downstream)
        future.update(enabled=True, automaticCatalogMerge=True)
        with self.assertRaises(ValueError):
            m.validate(future, self.fleet, self.central)
        future["allowedExtensions"] = sorted(r.split("/")[1] for r in m.fleet_policy.members(self.fleet))
        result = m.validate(future, self.fleet, self.central)
        self.assertIs(result["catalogMergeDeclared"], True)
        self.assertIs(result["publicationAuthorized"], False)
        self.assertFalse(future["automaticFormalRelease"])
        for field, value in (("automaticFormalRelease", True), ("mode", "UNATTENDED"),
                             ("enabled", False), ("allowedExtensions", ["evil"]),
                             ("requiredCatalogWorkflow", "unsafe.yml")):
            bad = deepcopy(future); bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.validate(bad, self.fleet, self.central)

    def test_automatic_tuple_and_every_safety_flag_are_required_but_not_authority(self):
        fleet, central = self.automatic()
        future = m.automatic_template(self.downstream, fleet, central)
        result = m.validate(future, fleet, central)
        for key in ("publicationAuthorized", "publishableReceipt", "catalogWriteAuthorized"):
            self.assertIs(result[key], False)
        mutations = [(k, False) for k in m.SAFE_FLAGS | {"automaticFormalRelease", "enabled", "automaticCatalogMerge"}]
        mutations += [("schemaVersion", True), ("mode", "POST_MANUAL_RELEASE_ONLY"),
                      ("releasePolicy", "manual-dispatch"), ("allowedExtensions", ["plpgsql_check"]),
                      ("allowedExtensions", future["allowedExtensions"] * 2)]
        for key, value in mutations:
            bad = deepcopy(future); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.validate(bad, fleet, central)
        with self.assertRaises(ValueError):
            m.validate(self.downstream, fleet, central)
        with self.assertRaises(ValueError):
            m.validate(future, self.fleet, self.central)

if __name__ == "__main__":
    unittest.main()
