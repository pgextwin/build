#!/usr/bin/env python3
"""Nonpublishing regression contract for the shared four-extension promotion."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHARED = (ROOT / ".github/workflows/promote-verified-release.yml").read_text(encoding="utf-8")


class SharedPromotion(unittest.TestCase):
    def test_shared_job_labels_match_pinned_publisher_runtime_snapshot(self):
        preflight = (ROOT / "scripts/issue-75-publisher-preflight.py").read_text(
            encoding="utf-8")
        for symbol, label in (
            ("AUTHORIZE", "Verify manual operator confirmation and immutable candidate evidence"),
            ("BUILD", "Fresh attested Windows maintained PG14–18 build from validated main"),
            ("PUBLISH", "Verify signatures and SHA; create-only formal publication"),
        ):
            self.assertIn(symbol + ' = "' + label + '"', preflight)
            self.assertIn("name: " + label, SHARED)
        for label in (
            "Dispatch signed Release Catalog PR generation with short-lived App token",
            "Flag post-release Catalog dispatch as blocked (not falsely successful)",
        ):
            self.assertIn('"' + label + '"', preflight)
            self.assertIn("name: " + label, SHARED)
        self.assertIn("guard.validate_snapshot(",
                      (ROOT / "scripts/fleet-publish-release.py").read_text())

    def test_legacy_thirteen_central_source_matches_proven_release_body(self):
        # Exact old production job body; no deployed caller pin changes.
        legacy = (ROOT / "tests/fixtures/issue-75-legacy-promotion-normalized.txt").read_text()
        shared = (ROOT / ".github/workflows/promote-legacy-verified-release.yml").read_text()
        self.assertIn("  workflow_call:", shared)
        self.assertNotIn("  workflow_dispatch:", shared)
        self.assertIn("group: ${{ github.event.repository.name }}-human-release-promotion", shared)
        self.assertEqual(shared.count("ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977"), 2)
        self.assertEqual(
            shared.split("jobs:\\n", 1)[1].replace(
                "${{ github.event.repository.name }}", "__EXTENSION__"),
            legacy.split("jobs:\\n", 1)[1])
        self.assertNotIn("pgextwin/*", shared)
        self.assertNotIn("secrets: inherit", shared)

    def test_manual_gate_is_not_bypassed(self):
        self.assertIn("workflow_call:", SHARED)
        self.assertNotIn("  workflow_dispatch:", SHARED)
        for field in ("candidate_pr", "candidate_run_id", "decision_run_id",
                      "release_tag", "confirm_release"):
            self.assertIn(field + ":", SHARED)
        self.assertIn("github.ref == 'refs/heads/main'", SHARED)
        self.assertIn("fleet-promotion-gate.py", SHARED)
        self.assertIn("--confirm-release", SHARED)
        self.assertIn("--local-policy config/release-promotion.json", SHARED)
        self.assertIn("--lifecycle .pgextwin-build/metadata/postgresql.json", SHARED)
        self.assertIn("needs: [authorize, release_build]", SHARED)

    def test_provenance_and_create_only_publisher_preserved(self):
        self.assertIn("build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d", SHARED)
        self.assertIn("ref: dd4d35186edccfbf39b40d86cecb28380cf210da", SHARED)
        self.assertIn("fleet-publish-release.py", SHARED)
        # Both authorizer and publisher must use the same immutable future code.
        self.assertEqual(SHARED.count("ref: dd4d35186edccfbf39b40d86cecb28380cf210da"), 2)
        self.assertIn("promotion-recovery.json", SHARED)
        self.assertIn("promotion-receipt.json", SHARED)
        self.assertIn("attestations: write", SHARED)
        self.assertIn("attestations: read", SHARED)
        self.assertNotIn("--clobber", SHARED)
        self.assertNotIn("gh release delete", SHARED)
        self.assertNotIn("pull_request_target:", SHARED)
        self.assertNotIn("secrets: inherit", SHARED)
        self.assertNotIn("runs-on: self-hosted", SHARED)

    def test_exact_seventeen_fleet_identity_list_is_not_publish_permission(self):
        import json
        from pathlib import Path

        names = ("pg_bigm", "pg_cron", "pg_hint_plan", "pgaudit",
                 "set_user", "pg_repack", "pg_ivm", "pg_qualstats",
                 "plpgsql_check", "orafce", "hypopg", "wal2json",
                 "pg_partman", "pg_stat_monitor", "pgtap",
                 "pg_variables", "pg_store_plans")
        expected = {"pgextwin/" + n for n in names}
        match = re.search(r'(?m)^\s*(pgextwin/[a-z0-9_|/]+)\)\s*;;$', SHARED)
        self.assertIsNotNone(match, "exact, closed case statement required")
        observed = match.group(1).split("|")
        self.assertEqual(set(observed), expected)
        self.assertEqual(len(observed), len(expected))
        self.assertIn("DENY unknown promotion caller", SHARED)
        self.assertIn("github.event.repository.name }}-pg*-windows-x64", SHARED)

        policy = json.loads((ROOT / "metadata/release-promotion.json").read_text())
        self.assertEqual(policy["schemaVersion"], 1)
        self.assertEqual(policy["releasePolicy"], "manual-dispatch")
        self.assertEqual(len(policy["allowedRepositories"]), 14)
        self.assertEqual(set(policy["allowedRepositories"]),
                         expected - {"pgextwin/pgtap", "pgextwin/pg_variables",
                                     "pgextwin/pg_store_plans"})
        self.assertIn("--local-policy config/release-promotion.json", SHARED)
        self.assertIn("--confirm-release", SHARED)
        self.assertIn("needs: [authorize, release_build]", SHARED)

    def test_negative_guard_can_never_be_wildcard_or_runtime_approval(self):
        self.assertNotIn("pgextwin/*", SHARED)
        self.assertNotIn("secrets: inherit", SHARED)
        self.assertNotIn("releasePolicy: automatic", SHARED)
        self.assertNotIn("  workflow_dispatch:", SHARED)
        self.assertIn("if: github.ref == 'refs/heads/main'", SHARED)
        self.assertIn("fleet-promotion-gate.py", SHARED)
        self.assertIn("build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d", SHARED)


    def test_signed_catalog_sync_is_postpublish_only(self):
        self.assertIn("uses: actions/create-github-app-token@", SHARED)
        self.assertIn("sync-verified-release.yml", SHARED)
        self.assertIn("permission-actions: write", SHARED)
        self.assertIn("repositories: catalog", SHARED)
        self.assertIn("needs: publish", SHARED)
        self.assertIn("CATALOG_SYNC=BLOCKED_APP_CONFIGURATION", SHARED)
        self.assertIn("vars.PGEXTWIN_CATALOG_DISPATCH_ENABLED == 'true' && vars.PGEXTWIN_CATALOG_APP_CLIENT_ID != ''", SHARED)
        self.assertIn("vars.PGEXTWIN_CATALOG_DISPATCH_ENABLED != 'true' || vars.PGEXTWIN_CATALOG_APP_CLIENT_ID == ''", SHARED)
        self.assertNotIn("if: ${{ vars.PGEXTWIN_CATALOG_APP_CLIENT_ID != '' }}", SHARED)
        self.assertIn("permission-actions: write", SHARED)
        self.assertNotIn("permission-contents: write", SHARED)
        self.assertNotIn("permission-pull-requests: write", SHARED)
        self.assertIn("Requires separately authorized PGEXTWIN_CATALOG_DISPATCH_ENABLED=true", SHARED)
        self.assertNotIn("PGEXTWIN_CATALOG_APP_PRIVATE_KEY", SHARED)
        for action in re.findall(r"(?m)^\s*(?:- )?uses:\s+([^\s#]+)", SHARED):
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")


    def test_legacy_thirteen_source_parity_snapshot_is_not_a_publish_grant(self):
        import json

        inventory = json.loads(
            (ROOT / "metadata/promotion-legacy-parity-20261021.json")
            .read_text(encoding="utf-8")
        )
        legacy = (ROOT / "tests/fixtures/issue-75-legacy-promotion-normalized.txt"
                  ).read_text(encoding="utf-8")
        thirteen = {
            "pg_bigm", "pg_cron", "pg_hint_plan", "pgaudit", "set_user",
            "pg_repack", "pg_ivm", "pg_qualstats", "orafce", "hypopg",
            "wal2json", "pg_partman", "pg_stat_monitor",
        }
        four = {"plpgsql_check", "pgtap", "pg_variables", "pg_store_plans"}
        self.assertEqual(inventory["schemaVersion"], 1)
        self.assertEqual(inventory["classification"],
                         "READ_ONLY_SOURCE_PARITY_INVENTORY_NOT_LIVE_RELEASE_ATTESTATION")
        self.assertEqual(inventory["deploymentMode"], "NO_CONSUMER_CALLER_REPIN")
        self.assertEqual(inventory["runtimeSignerWriterPublisherAcceptance"],
                         "NOT_PROVEN")
        self.assertEqual(inventory["wave3Publication"], "DENY")
        self.assertEqual(inventory["releaseAdmission"],
                         "UNCHANGED_ORIGINAL_14_ONLY")
        self.assertIs(inventory["publishableReceipt"], False)
        self.assertEqual(inventory["workflowPath"], ".github/workflows/promote.yml")
        self.assertEqual(inventory["legacyReferenceRepository"], "pgextwin/pg_bigm")
        self.assertEqual(len(inventory["legacy"]), 13)
        self.assertEqual(len(inventory["shared"]), 4)
        self.assertEqual(
            {x["repository"] for x in inventory["legacy"]},
            {"pgextwin/" + n for n in thirteen},
        )
        self.assertEqual(
            {x["repository"] for x in inventory["shared"]},
            {"pgextwin/" + n for n in four},
        )
        blobs = inventory["legacy"] + inventory["shared"]
        self.assertEqual(len({x["workflowBlobSha"] for x in blobs}), 17)
        for record in blobs:
            self.assertRegex(record["workflowBlobSha"], r"^[0-9a-f]{40}$")
        pins = {x["repository"]: x["sharedWorkflowPin"]
                for x in inventory["shared"]}
        self.assertEqual(
            pins["pgextwin/plpgsql_check"],
            "5425225ea858f8c0165421902c3e66c6c9205f60",
        )
        for n in ("pgtap", "pg_variables", "pg_store_plans"):
            self.assertEqual(pins["pgextwin/" + n],
                             "acd6eb28be6d750e89b626fa4ccd4403e1265cd6")

        self.assertEqual(legacy.count("__EXTENSION__"), 2)
        self.assertNotIn("pg_bigm", legacy)
        required = (
            "  workflow_dispatch:", "candidate_pr:", "candidate_run_id:",
            "decision_run_id:", "release_tag:", "confirm_release:",
            "github.ref == 'refs/heads/main'", "fleet-promotion-gate.py",
            "--confirm-release", "--local-policy config/release-promotion.json",
            "needs: [authorize, release_build]", "fleet-publish-release.py",
            "promotion-receipt.json", "promotion-recovery.json",
            "id-token: write", "attestations: write", "attestations: read",
            "build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d",
            "persist-credentials: false",
        )
        for marker in required:
            with self.subTest(required=marker):
                self.assertIn(marker, legacy)
        for forbidden in ("  schedule:", "pull_request_target:", "secrets: inherit",
                          "gh release delete", "--clobber", "cancel-in-progress: true"):
            self.assertNotIn(forbidden, legacy)
        self.assertEqual(
            legacy.count("ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977"), 2
        )
        self.assertEqual(
            inventory["legacyGatePublisherCommit"],
            "455f0ccc667697f600700a6e64bcfd6c57b6a977",
        )
        self.assertEqual(
            inventory["legacySignerCommit"],
            "5756b3c5136a8bf4db710016cfe97555f0a71c6d",
        )
        self.assertEqual(
            inventory["sharedPublisherCandidateCommit"],
            "dd4d35186edccfbf39b40d86cecb28380cf210da",
        )
        for n in thirteen:
            with self.subTest(legacy=n):
                restored = legacy.replace("__EXTENSION__", n)
                self.assertIn("group: " + n + "-human-release-promotion", restored)
                self.assertIn("pattern: " + n + "-pg*-windows-x64", restored)
                self.assertEqual(restored.replace(n, "__EXTENSION__"), legacy)

        # Two different immutable publisher-source commits are *not* accepted
        # as interchangeable merely because manual gates look alike.
        self.assertNotEqual(inventory["legacyGatePublisherCommit"],
                            inventory["sharedPublisherCandidateCommit"])
        self.assertIn("fleet-promotion-gate.py", SHARED)
        self.assertIn("fleet-publish-release.py", SHARED)
        self.assertIn("--confirm-release", SHARED)
        self.assertIn("needs: [authorize, release_build]", SHARED)
        policy = json.loads((ROOT / "metadata/release-promotion.json").read_text())
        self.assertEqual(set(policy["allowedRepositories"]),
                         {"pgextwin/" + n for n in thirteen | {"plpgsql_check"}})

    def test_legacy_parity_fixture_hostile_removal_would_be_detected(self):
        legacy = (ROOT / "tests/fixtures/issue-75-legacy-promotion-normalized.txt"
                  ).read_text(encoding="utf-8")
        must = (
            "--confirm-release",
            "--local-policy config/release-promotion.json",
            "build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d",
            "fleet-publish-release.py",
            "needs: [authorize, release_build]",
        )
        for marker in must:
            with self.subTest(marker=marker):
                hostile = legacy.replace(marker, "REPLACED_UNTRUSTED", 1)
                self.assertNotIn(marker, hostile)
                self.assertFalse(all(x in hostile for x in must))



    def test_two_deployed_shared_pins_are_one_byte_identical_inert_blob(self):
        import hashlib
        import json

        ledger = json.loads((ROOT / "metadata/promotion-legacy-parity-20261021.json")
                            .read_text(encoding="utf-8"))
        record = ledger["sharedHistoricalSource"]
        raw = (ROOT / "tests/fixtures/issue-75-historical-shared-promotion.txt").read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + bytes([0]) + raw).hexdigest()
        self.assertEqual(blob, "1a87339fdf93d093aea0c976d7627ce9d8860eb1")
        self.assertEqual(record["verifiedSameWorkflowBlobSha"], blob)
        self.assertEqual(record["plpgsqlCheckPin"],
                         "5425225ea858f8c0165421902c3e66c6c9205f60")
        self.assertEqual(record["wave3Pin"],
                         "acd6eb28be6d750e89b626fa4ccd4403e1265cd6")
        self.assertNotEqual(record["plpgsqlCheckPin"], record["wave3Pin"])
        self.assertIs(record["identicalBytesAreNotExecutionIdentity"], True)
        self.assertIs(record["deployedCallerPinsChanged"], False)
        self.assertIs(record["newSharedRuntimeAccepted"], False)
        self.assertIs(record["noSignedProductionSignerAttestationAccepted"], True)
        self.assertEqual(record["runtimeGate"], "BLOCKED")
        self.assertEqual(record["wave3PUBLISH"], "DENY")
        self.assertEqual(record["legacyPublisherSourcePin"],
                         "455f0ccc667697f600700a6e64bcfd6c57b6a977")
        self.assertEqual(record["futureSharedGatePublisherSourcePin"],
                         "dd4d35186edccfbf39b40d86cecb28380cf210da")
        self.assertNotEqual(record["legacyPublisherSourcePin"],
                            record["futureSharedGatePublisherSourcePin"])
        self.assertEqual(record["classification"],
                         "TWO_PIN_REFS_SAME_IMMUTABLE_GIT_BLOB_NOT_RUNTIME_AUTHORIZATION")

        historical = raw.decode("utf-8")
        self.assertIn("workflow_call:", historical)
        self.assertIn("fleet-promotion-gate.py", historical)
        self.assertIn("fleet-publish-release.py", historical)
        self.assertIn("if: github.ref == 'refs/heads/main'", historical)
        self.assertIn("--confirm-release", historical)
        self.assertIn("needs: [authorize, release_build]", historical)
        self.assertIn("build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d", historical)
        self.assertEqual(
            historical.count("ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977"), 2
        )
        self.assertNotIn("releasePolicy: automatic", historical)
        self.assertNotIn("secrets: inherit", historical)
        self.assertNotIn("pull_request_target:", historical)
        self.assertNotIn("--clobber", historical)

        # Historical catalog trigger used mere client-ID presence. The proposed
        # shared source now has a *separate* opt-in. The older behavior must
        # not be treated as production-equivalent or silently reinstated.
        self.assertIn("vars.PGEXTWIN_CATALOG_APP_CLIENT_ID != ''", historical)
        self.assertNotIn("PGEXTWIN_CATALOG_DISPATCH_ENABLED", historical)
        self.assertIn("vars.PGEXTWIN_CATALOG_DISPATCH_ENABLED == 'true'", SHARED)
        self.assertIs(record["catalogDispatchExplicitOptInInFutureSharedSource"], True)
        self.assertIs(record["historicalCatalogDispatchAppIdentityAccepted"], False)

        # Exact historical shared identity list is only four. The current
        # central source expanded to 17 but actual 14-only publisher
        # authorization and three disabled local Wave3 policies remain.
        for n in ("plpgsql_check", "pgtap", "pg_variables", "pg_store_plans"):
            self.assertIn("pgextwin/" + n, historical)
        self.assertNotIn("pgextwin/pg_bigm|pgextwin/pg_cron", historical)
        self.assertIn("pgextwin/pg_bigm|pgextwin/pg_cron", SHARED)
        self.assertEqual(ledger["releaseAdmission"], "UNCHANGED_ORIGINAL_14_ONLY")
        self.assertIs(ledger["publishableReceipt"], False)

    def test_historical_shared_shadow_cannot_grant_publication(self):
        import json
        ledger = json.loads((ROOT / "metadata/promotion-legacy-parity-20261021.json")
                            .read_text(encoding="utf-8"))
        hist = ledger["sharedHistoricalSource"]
        for field in ("deployedCallerPinsChanged", "newSharedRuntimeAccepted",
                      "historicalCatalogDispatchAppIdentityAccepted"):
            with self.subTest(field=field):
                self.assertIs(hist[field], False)
        self.assertEqual(ledger["runtimeSignerWriterPublisherAcceptance"],
                         "NOT_PROVEN")
        self.assertEqual(ledger["deploymentMode"], "NO_CONSUMER_CALLER_REPIN")
        self.assertEqual(hist["runtimeGate"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
