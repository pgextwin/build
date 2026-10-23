#!/usr/bin/env python3
"""Adversarial central signed-candidate to manual-only Publisher policy bridge."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "signed_publisher_policy_bridge", ROOT / "scripts" / "automatic-publisher-bridge.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
FLEET = json.loads((ROOT / "metadata" / "automation-fleet.json").read_text("utf-8"))
CENTRAL = json.loads((ROOT / "metadata" / "release-promotion.json").read_text("utf-8"))
UNATTENDED = json.loads((ROOT / "metadata" / "unattended-publication.json").read_text("utf-8"))
REPO = "pgextwin/pg_ivm"
SHA = "a" * 40
RUN_ID = 456789
ATTEMPT = 1


def fixture():
    return {
        "audit": {
            "schemaVersion": 1,
            "status": "VERIFIED_SIGNED_CANDIDATE_NONPUBLISHING",
            "cryptographicVerification": "REAL_GH_ATTESTATION_VERIFY",
            "repository": REPO, "mainMergeSha": SHA,
            "runId": RUN_ID, "runAttempt": ATTEMPT,
            "signedArtifactsVerified": True,
            "publishableReceipt": False,
            "publicationAuthorized": False,
            "automaticReleaseEnabled": False,
            "maintainedMajors": [14, 15, 16, 17, 18],
            "zipSha256ByMajor": {str(i): f"{i:064x}" for i in range(14, 19)}
        },
        "repo": REPO, "sha": SHA, "run_id": RUN_ID, "attempt": ATTEMPT,
        "event": "push", "ref": "refs/heads/main",
        "fleet": deepcopy(FLEET), "central": deepcopy(CENTRAL),
        "local": {"schemaVersion": 1, "enabled": True, "releasePolicy": "manual-dispatch"},
        "unattended": deepcopy(UNATTENDED)
    }


class NonpublishingPublisherBridgeTests(unittest.TestCase):
    def test_all_real_current_policies_only_deny_publish(self):
        result = bridge.bridge(**fixture())
        self.assertEqual(result["status"], "PUBLISH_DENY")
        self.assertEqual(result["verifiedAuditStatus"],
                         "VERIFIED_SIGNED_CANDIDATE_NONPUBLISHING")
        self.assertEqual(result["policyBlockers"][0], "CENTRAL_MANUAL_DISPATCH")
        self.assertEqual(result["policyBlockers"][-1],
                         "INDEPENDENT_PUBLISHER_AUTHORIZATION_NOT_ESTABLISHED")
        for key in ("publishableReceipt", "publicationAuthorized",
                    "automaticReleaseEnabled", "publisherWriteEnabled"):
            self.assertIs(result[key], False)
        for key in ("goB", "g4", "g5"):
            self.assertEqual(result[key], "NO_GO")
        for key in ("authorizationMode", "releaseTag", "operator",
                    "token", "receipt", "confirmRelease"):
            self.assertNotIn(key, result)

    def test_17_repo_roster_parity_current(self):
        for row in FLEET["entries"]:
            inputs = fixture()
            inputs["repo"] = row["repository"]
            inputs["audit"]["repository"] = row["repository"]
            self.assertEqual(bridge.bridge(**inputs)["status"], "PUBLISH_DENY")

    def test_forged_audit_and_runtime_identity_rejected(self):
        mutations = [
            lambda a: a.update(event="workflow_dispatch"),
            lambda a: a.update(ref="refs/heads/evil"),
            lambda a: a.update(repo="pgextwin/other"),
            lambda a: a.update(sha="b" * 40),
            lambda a: a.update(run_id=RUN_ID + 1),
            lambda a: a.update(attempt=2),
            lambda a: a.update(attempt=True),
            lambda a: a["audit"].update(schemaVersion=True),
            lambda a: a["audit"].update(status="VERIFIED_MANUAL_DISPATCH"),
            lambda a: a["audit"].update(cryptographicVerification="NOT_PERFORMED"),
            lambda a: a["audit"].update(repository="pgextwin/pgtap"),
            lambda a: a["audit"].update(mainMergeSha="b" * 40),
            lambda a: a["audit"].update(runId=RUN_ID + 1),
            lambda a: a["audit"].update(runAttempt=2),
            lambda a: a["audit"].update(signedArtifactsVerified=False),
            lambda a: a["audit"].update(publishableReceipt=True),
            lambda a: a["audit"].update(publicationAuthorized=True),
            lambda a: a["audit"].update(automaticReleaseEnabled=True),
            lambda a: a["audit"].update(maintainedMajors=[14, 15, 16, 17]),
            lambda a: a["audit"].update(maintainedMajors=[14, 14, 15, 16, 17, 18]),
            lambda a: a["audit"]["zipSha256ByMajor"].pop("14"),
            lambda a: a["audit"]["zipSha256ByMajor"].update({"19": "a" * 64}),
            lambda a: a["audit"]["zipSha256ByMajor"].update({"14": "NOT_SHA"}),
            lambda a: a["fleet"].update(releasePolicy="automatic"),
            lambda a: a["fleet"]["entries"].pop(),
            lambda a: a["fleet"]["entries"][0].update(releasePolicy="automatic"),
            lambda a: a["fleet"]["entries"][0].update(mode="PUBLISH"),
            lambda a: a["central"].update(releasePolicy="auto-signed"),
            lambda a: a["central"]["allowedRepositories"].pop(),
            lambda a: a["central"]["allowedRepositories"].append("pgextwin/evil"),
            lambda a: a["local"].update(releasePolicy="auto-signed"),
            lambda a: a["local"].update(enabled=False),
            lambda a: a["unattended"].update(mode="UNATTENDED"),
            lambda a: a["unattended"].update(defaultAction="ALLOW"),
            lambda a: a["unattended"]["controls"].update(automaticFormalRelease=True),
        ]
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                args = fixture()
                change(args)
                with self.assertRaises(bridge.Denied):
                    bridge.bridge(**args)

    def test_no_token_or_write_capability_in_boundary(self):
        source = (ROOT / "scripts" / "automatic-publisher-bridge.py").read_text("utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("urllib", source)
        self.assertNotIn("import requests", source)
        self.assertNotIn("GH_TOKEN", source)
        self.assertNotIn("github.token", source)
        self.assertNotIn("create_release", source)
        self.assertNotIn("draft_release", source)


if __name__ == "__main__":
    unittest.main()
