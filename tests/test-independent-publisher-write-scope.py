#!/usr/bin/env python3
"""Hostile offline tests for the inert Publisher WRITE authority boundary.

All minted-token examples are synthetic: no GitHub App auth, POST, or Release.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from publication_policy_fixtures import manual_policy
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "write_scope", ROOT / "scripts/independent-publisher-write-scope.py")
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)
NOW = datetime(2026, 10, 24, 6, tzinfo=timezone.utc)
REPO = "pgextwin/plpgsql_check"
REPO_ID = 123456

def fixture():
    policy = manual_policy("publisher-write-boundary.json")
    policy.update(mode="ENFORCE", publisherAppId=543210,
                  publisherInstallationId=678900)
    return {
        "policy": policy,
        "fleet": manual_policy("automation-fleet.json"),
        "repository": REPO, "observed_at": NOW,
        "trusted_issuer_app_id": 543210,
        "trusted_issuer_installation_id": 678900,
        "issuance": {
            "token": "synthetic-not-usable-publisher-token",
            "expires_at": (NOW + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
            "permissions": {"contents": "write", "metadata": "read"},
            "repository_selection": "selected"
        },
        "live_repositories": {"total_count": 1, "repositories": [
            {"id": REPO_ID, "full_name": REPO}]},
        "blob": {"sha": "d" * 40}, "expected_blob_sha": "d" * 40
    }

class WriteScopeTests(unittest.TestCase):
    def test_manual_fixture_deny_is_common_to_registered_fleet(self):
        args = fixture()
        args["policy"] = manual_policy("publisher-write-boundary.json")
        for row in args["fleet"]["entries"]:
            with self.subTest(repo=row["repository"]):
                a = dict(args, repository=row["repository"], issuance=None,
                         live_repositories=None, trusted_issuer_app_id=None,
                         trusted_issuer_installation_id=None)
                result = scope.evaluate(**a)
                self.assertEqual(result["status"], "PUBLISH_DENY")
                self.assertFalse(result["publisherWriteAuthorized"])
                self.assertFalse(result["publicationAuthorized"])

    def test_valid_synthetic_identity_is_still_nonpublishing(self):
        evidence = scope.evaluate(**fixture())
        self.assertEqual(evidence["status"], "SCOPED_APP_WRITE_EVIDENCE_ONLY")
        self.assertEqual(evidence["scopedRepositoryCount"], 1)
        self.assertFalse(evidence["publisherWriteAuthorized"])
        self.assertFalse(evidence["publicationAuthorized"])
        for forbidden in ("token", "publishableReceipt", "authorizationMode"):
            self.assertNotIn(forbidden, evidence)

    def test_forged_principal_permissions_scope_replay_and_fleet_denied(self):
        mutations = [
            lambda x: x["policy"].update(publisherAppId=15368),
            lambda x: x["policy"].update(publisherAppId=None),
            lambda x: x.update(trusted_issuer_app_id=15368),
            lambda x: x.update(trusted_issuer_installation_id=1),
            lambda x: x.update(trusted_issuer_app_id=True),
            lambda x: x["issuance"].update(permissions={"contents": "read"}),
            lambda x: x["issuance"].update(permissions={"contents": "write", "actions": "write"}),
            lambda x: x["issuance"].update(repository_selection="all"),
            lambda x: x["blob"].update(sha="a" * 40),
            lambda x: x.update(blob=None),
            lambda x: x.update(expected_blob_sha="a" * 40),
            lambda x: x.update(expected_blob_sha=None),
            lambda x: x["issuance"].update(expires_at=(NOW-timedelta(seconds=1)).isoformat().replace("+00:00", "Z")),
            lambda x: x["issuance"].update(expires_at=(NOW+timedelta(hours=3)).isoformat().replace("+00:00", "Z")),
            lambda x: x["issuance"].update(token=""),
            lambda x: x["live_repositories"].update(total_count=2),
            lambda x: x["live_repositories"].update(repositories=[]),
            lambda x: x["live_repositories"]["repositories"][0].update(full_name="pgextwin/orafce"),
            lambda x: x["live_repositories"]["repositories"].append(
                {"id": 2, "full_name": "pgextwin/orafce"}),
            lambda x: x["live_repositories"]["repositories"][0].update(full_name=None),
            lambda x: x.update(repository="pgextwin/orafce"),
            lambda x: x.update(repository="pgextwin/evil"),
            lambda x: x["fleet"].update(entries=[]),
            lambda x: x["fleet"]["entries"].append({"repository": []}),
            lambda x: x["fleet"]["entries"].append(deepcopy(x["fleet"]["entries"][0])),
            lambda x: x["fleet"].update(releasePolicy="automatic"),
            lambda x: x["policy"].update(mode="OBSERVE"),
            lambda x: x["policy"].update(signerAppId=543210),
            lambda x: x["policy"].update(unexpected=True),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(scope.Denied):
                args = fixture()
                mutation(args)
                scope.evaluate(**args)

    def test_fleet_can_grow_or_shrink_without_expanding_token(self):
        args = fixture()
        future = deepcopy(args["fleet"]["entries"][0])
        future["repository"] = "pgextwin/future_extension"
        args["fleet"]["entries"].append(future)
        self.assertEqual(scope.evaluate(**args)["scopedRepositoryCount"], 1)
        args["fleet"]["entries"] = [
            row for row in args["fleet"]["entries"] if row["repository"] == REPO]
        self.assertEqual(scope.evaluate(**args)["scopedRepositoryCount"], 1)
        args["fleet"]["entries"] = [future]
        with self.assertRaises(scope.Denied):
            scope.evaluate(**args)

    def test_no_shell_network_or_release_writes(self):
        with patch("subprocess.run", side_effect=AssertionError("NO PROCESS")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("NO NETWORK")):
            self.assertFalse(scope.evaluate(**fixture())["publicationAuthorized"])

if __name__ == "__main__":
    unittest.main()
