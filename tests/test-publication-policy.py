#!/usr/bin/env python3
"""Offline checks for the canonical policy bytes and legacy local shapes."""
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "publication_policy", ROOT / "scripts" / "publication-policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

CANDIDATE = "candidate-build.json"
RELEASE = "release-promotion.json"
OWNER = "owner-source-publication.json"
REPO = "pgextwin/orafce"
NO_OWNER_SOURCE = {"pgextwin/pg_repack", "pgextwin/pg_store_plans", "pgextwin/pg_variables", "pgextwin/pgtap"}


class PublicationPolicyTests(unittest.TestCase):
    def test_candidate_matches_legacy_git_blob(self):
        data = (ROOT / "metadata" / CANDIDATE).read_bytes()
        blob = f"blob {len(data)}\0".encode("ascii") + data
        self.assertEqual(hashlib.sha1(blob).hexdigest(), "6e0026edb31d76ddf26e92df489e3f7bfc11b2fb")
        self.assertEqual(policy.load_candidate_policy(ROOT), {
            "schemaVersion": 1, "enabled": True, "releasePolicy": "manual-only", "workflow": "windows.yml",
        })

    def test_current_projections_match_legacy_local_values(self):
        fleet = json.loads((ROOT / "metadata" / "automation-fleet.json").read_text("utf-8"))
        repositories = {entry["repository"] for entry in fleet["entries"]}
        self.assertEqual(len(repositories), 26)
        self.assertTrue(NO_OWNER_SOURCE <= repositories)
        self.assertEqual(len(repositories - NO_OWNER_SOURCE), 22)
        release = {"schemaVersion": 1, "enabled": True, "releasePolicy": "automatic-signed-schedule"}
        owner = {**release, "sourceKind": "OWNER_ISSUE_COMMENT_MAIN_SIGNING"}
        for repo in sorted(repositories):
            with self.subTest(repository=repo):
                actual_release = policy.release_promotion_policy(ROOT, repo)
                self.assertEqual(actual_release, release)
                self.assertIs(actual_release["enabled"], True)
                enabled = repo not in NO_OWNER_SOURCE
                actual_owner = policy.owner_source_policy(ROOT, repo)
                self.assertEqual(actual_owner, {**owner, "enabled": enabled})
                self.assertIs(actual_owner["enabled"], enabled)
        self.assertEqual(policy.release_promotion_policy(ROOT, "pgextwin/unregistered"), {
            **release, "enabled": False,
        })

    def test_projections_use_the_central_release_mode(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "metadata"
            metadata.mkdir()
            (metadata / OWNER).write_bytes((ROOT / "metadata" / OWNER).read_bytes())
            release = {"schemaVersion": 1, "allowedRepositories": [REPO], "releasePolicy": "manual-dispatch"}
            (metadata / RELEASE).write_text(json.dumps(release), "utf-8")
            self.assertEqual(policy.release_promotion_policy(root, REPO)["releasePolicy"], "manual-dispatch")
            self.assertEqual(policy.owner_source_policy(root, REPO)["releasePolicy"], "manual-dispatch")

    def test_rejects_malformed_central_policies(self):
        cases = {
            CANDIDATE: ({"schemaVersion": True}, {"enabled": 1}, {"enabled": False},
                        {"releasePolicy": "automatic-signed-schedule"}, {"workflow": "other.yml"},
                        {"unknown": True}),
            RELEASE: ({"releasePolicy": "unknown"}, {"allowedRepositories": REPO},
                      {"allowedRepositories": [REPO, 1]}, {"allowedRepositories": [REPO, REPO]}),
            OWNER: ({"ownerId": True}, {"ownerLogin": 1}, {"sourceKind": "PUSH"},
                    {"mode": "DENY"}, {"allowedRepositories": ["other/orafce"]}),
        }
        readers = {
            CANDIDATE: policy.load_candidate_policy,
            RELEASE: lambda root: policy.release_promotion_policy(root, REPO),
            OWNER: lambda root: policy.owner_source_policy(root, REPO),
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "metadata"
            metadata.mkdir()
            for filename in cases:
                (metadata / filename).write_bytes((ROOT / "metadata" / filename).read_bytes())
            for filename, edits in cases.items():
                path = metadata / filename
                original = path.read_text("utf-8")
                baseline = json.loads(original)
                malformed = ['{"schemaVersion": 1,' + original[1:], "[]", "{"]
                malformed.extend(json.dumps({**baseline, **edit}) for edit in edits)
                for data in malformed:
                    with self.subTest(filename=filename, data=data), self.assertRaises(policy.Denied):
                        path.write_text(data, "utf-8")
                        readers[filename](root)
                path.write_text(original, "utf-8")
            (metadata / RELEASE).unlink()
            with self.assertRaises(policy.Denied):
                policy.owner_source_policy(root, REPO)


if __name__ == "__main__":
    unittest.main()
