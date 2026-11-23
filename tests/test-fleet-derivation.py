#!/usr/bin/env python3
"""Compare fleet-derived allowlists with the current canonical metadata."""
import importlib.util
import json
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
METADATA = ROOT / "metadata"
FLEET = "automation-fleet.json"
spec = importlib.util.spec_from_file_location("publication_policy", ROOT / "scripts" / "publication-policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def read(path):
    return json.loads(path.read_text("utf-8"))


class FleetDerivationTests(unittest.TestCase):
    def test_release_promotion_order(self):
        expected = read(METADATA / "release-promotion.json")["allowedRepositories"]
        self.assertEqual(policy.derive_release_promotion_repositories(ROOT), expected)

    def test_owner_source_field_not_yet_landed_fails_closed(self):
        # The ownerSource field addition to the live ledger is sequenced after
        # every pinned fleet-control validator tolerates it; until then the
        # derivation must refuse rather than guess membership.
        with self.assertRaisesRegex(policy.Denied, "missing ownerSource"):
            policy.derive_owner_source_repositories(ROOT)

    def test_owner_source_membership_with_field(self):
        expected = read(METADATA / "owner-source-publication.json")["allowedRepositories"]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            copytree(METADATA, root / "metadata")
            path = root / "metadata" / FLEET
            registry = read(path)
            for entry in registry["entries"]:
                entry["ownerSource"] = entry["repository"] in expected
            path.write_text(json.dumps(registry), "utf-8")
            actual = policy.derive_owner_source_repositories(root)
            self.assertEqual(len(actual), 23)
            self.assertEqual(set(actual), set(expected))
            fleet_order = [entry["repository"] for entry in registry["entries"]
                           if entry["ownerSource"]]
            self.assertEqual(actual, fleet_order)
            for entry in policy.load_fleet_registry(root)["entries"]:
                with self.subTest(repository=entry["repository"]):
                    self.assertIs(type(entry["ownerSource"]), bool)

    def test_manual_release_extension_order(self):
        expected = read(METADATA / "manual-release-downstream.json")["allowedExtensions"]
        self.assertEqual(policy.derive_manual_release_extensions(ROOT), expected)

    def test_owner_source_must_be_an_explicit_boolean(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            copytree(METADATA, root / "metadata")
            path = root / "metadata" / FLEET
            registry = read(path)
            allowed = read(METADATA / "owner-source-publication.json")["allowedRepositories"]
            for entry in registry["entries"]:
                entry["ownerSource"] = entry["repository"] in allowed
            del registry["entries"][-1]["ownerSource"]
            path.write_text(json.dumps(registry), "utf-8")
            with self.assertRaisesRegex(policy.Denied, "missing ownerSource"):
                policy.derive_owner_source_repositories(root)
            registry["entries"][-1]["ownerSource"] = 1
            path.write_text(json.dumps(registry), "utf-8")
            with self.assertRaisesRegex(policy.Denied, "invalid ownerSource"):
                policy.derive_owner_source_repositories(root)

    def test_strict_parser_rejects_duplicate_keys(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "metadata"
            metadata.mkdir()
            original = (METADATA / FLEET).read_text("utf-8")
            (metadata / FLEET).write_text('{"schemaVersion": 1,' + original[1:], "utf-8")
            with self.assertRaisesRegex(policy.Denied, "duplicate policy JSON key"):
                policy.load_fleet_registry(root)


if __name__ == "__main__":
    unittest.main()
