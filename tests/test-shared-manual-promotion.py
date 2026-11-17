#!/usr/bin/env python3
"""Nonpublishing regression contract for the shared four-extension promotion."""
from pathlib import Path
import re
import unittest

from publication_policy_fixtures import manual_policy
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

    def test_legacy_prewrite_guard_preserves_live_scope_and_order(self):
        shared = (ROOT / ".github/workflows/promote-legacy-verified-release.yml").read_text()
        self.assertIn("  workflow_call:", shared)
        self.assertNotIn("  workflow_dispatch:", shared)
        self.assertIn("group: shared-legacy-${{ github.event.repository.name }}-human-release-promotion", shared)
        # Never reuse the caller's inherited concurrency group in a nested workflow.
        self.assertNotIn("group: ${{ github.event.repository.name }}-human-release-promotion\\n", shared)
        self.assertEqual(shared.count("ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977"), 2)
        # The read-only risk guard must precede the legacy Publisher step.
        first = shared.index("      # An independently pinned, READ-ONLY risk check")
        last = shared.index(
            "      - name: Verify signed binaries and publish only the fresh exact Release ID",
            first)
        inserted = shared[first:last]
        self.assertIn("ref: ${{ job.workflow_sha }}", inserted)
        self.assertIn("scripts/formal-publisher-grype-preflight.py", inserted)
        self.assertIn("--lifecycle .pgextwin-build/metadata/postgresql.json", inserted)
        self.assertIn("--dist dist", inserted)
        self.assertNotIn("continue-on-error:", inserted)
        self.assertNotIn("GH_TOKEN", inserted)
        self.assertNotIn("contents: write", inserted)
        self.assertEqual(inserted.count("- name: Deny blocked or untrustworthy Grype"), 1)
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
        self.assertIn("fleet-publish-release.py", SHARED)
        # Gate and Publisher helpers follow this reusable workflow's immutable
        # commit. This avoids stale transitive pins after a protected repair.
        authorize=SHARED.split("  authorize:\n",1)[1].split("  release_build:\n",1)[0]
        publish=SHARED.split("  publish:\n",1)[1].split("  catalog_sync:\n",1)[0]
        self.assertIn("ref: ${{ job.workflow_sha }}",authorize)
        self.assertIn("ref: ${{ job.workflow_sha }}",publish)
        self.assertEqual(SHARED.count("ref: ${{ job.workflow_sha }}"),2)
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

        policy = manual_policy("release-promotion.json")
        self.assertEqual(policy["schemaVersion"], 1)
        self.assertEqual(policy["releasePolicy"], "manual-dispatch")
        self.assertEqual(len(policy["allowedRepositories"]), 17)
        self.assertEqual(set(policy["allowedRepositories"]),
                         expected)
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
        # The retained ledger is evidence, never a current admission or repin.
        self.assertEqual(ledger["classification"],
                         "READ_ONLY_SOURCE_PARITY_INVENTORY_NOT_LIVE_RELEASE_ATTESTATION")
        self.assertEqual(ledger["wave3Publication"], "DENY")
        self.assertEqual(ledger["releaseAdmission"], "UNCHANGED_ORIGINAL_14_ONLY")
        self.assertIs(ledger["publishableReceipt"], False)
        self.assertIs(hist["identicalBytesAreNotExecutionIdentity"], True)
        self.assertIs(hist["noSignedProductionSignerAttestationAccepted"], True)
        self.assertEqual(hist["wave3PUBLISH"], "DENY")

    def test_both_shared_release_backends_keep_one_explicit_operator_contract(self):
        # Runtime authorization equivalence is NOT inferred: these two backends
        # intentionally pin different gate/Publisher implementations.
        legacy = (ROOT / ".github/workflows/promote-legacy-verified-release.yml").read_text(
            encoding="utf-8")
        for source in (legacy, SHARED):
            self.assertIn("  workflow_call:", source)
            self.assertNotIn("  workflow_dispatch:", source)
            self.assertEqual(source.count("required: true"), 5)
            for field in ("candidate_pr", "candidate_run_id", "decision_run_id",
                          "release_tag", "confirm_release"):
                self.assertIn(field + ":", source)
                self.assertIn("${{ inputs." + field + " }}", source)
            for required in (
                "github.ref == 'refs/heads/main'",
                "fleet-promotion-gate.py",
                "--confirm-release",
                "--local-policy config/release-promotion.json",
                "needs: [authorize, release_build]",
                "build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d",
                "fleet-publish-release.py",
                "promotion-receipt.json",
                "promotion-recovery.json",
                "attestations: write",
                "attestations: read",
                "cancel-in-progress: false",
                "persist-credentials: false",
            ):
                with self.subTest(runtime="legacy" if source is legacy else "verified",
                                  guard=required):
                    self.assertIn(required, source)
            for forbidden in ("  schedule:", "pull_request_target:",
                              "secrets: inherit", "gh release delete",
                              "--clobber", "cancel-in-progress: true"):
                self.assertNotIn(forbidden, source)
        self.assertEqual(
            legacy.count("ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977"), 2)
        self.assertEqual(SHARED.count("ref: ${{ job.workflow_sha }}"),2)
        self.assertNotIn(
            "ref: dd4d35186edccfbf39b40d86cecb28380cf210da", legacy)
        self.assertNotIn(
            "ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977", SHARED)

if __name__ == "__main__":
    unittest.main()

