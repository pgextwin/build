#!/usr/bin/env python3
"""Nonpublishing regression contract for the shared four-extension promotion."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHARED = (ROOT / ".github/workflows/promote-verified-release.yml").read_text(encoding="utf-8")


class SharedPromotion(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
