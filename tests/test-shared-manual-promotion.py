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
        self.assertIn("ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977", SHARED)
        self.assertIn("fleet-publish-release.py", SHARED)
        self.assertIn("promotion-recovery.json", SHARED)
        self.assertIn("promotion-receipt.json", SHARED)
        self.assertIn("attestations: write", SHARED)
        self.assertIn("attestations: read", SHARED)
        self.assertNotIn("--clobber", SHARED)
        self.assertNotIn("gh release delete", SHARED)
        self.assertNotIn("pull_request_target:", SHARED)
        self.assertNotIn("secrets: inherit", SHARED)
        self.assertNotIn("runs-on: self-hosted", SHARED)

    def test_only_the_four_intended_packaging_repositories_can_call(self):
        for name in ("plpgsql_check", "pgtap", "pg_variables", "pg_store_plans"):
            self.assertIn("pgextwin/" + name, SHARED)
        self.assertIn("DENY unknown promotion caller", SHARED)
        self.assertIn("github.event.repository.name }}-pg*-windows-x64", SHARED)

    def test_signed_catalog_sync_is_postpublish_only(self):
        self.assertIn("uses: actions/create-github-app-token@", SHARED)
        self.assertIn("sync-verified-release.yml", SHARED)
        self.assertIn("permission-actions: write", SHARED)
        self.assertIn("repositories: catalog", SHARED)
        self.assertIn("needs: publish", SHARED)
        self.assertIn("CATALOG_SYNC=BLOCKED_APP_CONFIGURATION", SHARED)
        self.assertNotIn("PGEXTWIN_CATALOG_APP_PRIVATE_KEY", SHARED)
        for action in re.findall(r"(?m)^\s*(?:- )?uses:\s+([^\s#]+)", SHARED):
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
