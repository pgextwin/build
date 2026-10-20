#!/usr/bin/env python3
"""Keep old one-shot proofs out of the active Workflow inventory.

Their historical execution records, frozen source commits and hostile fixtures
remain available; this file does not certify a new Release or actual Signature.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows"


class RetiredWorkflows(unittest.TestCase):
    def test_completed_nonpublishing_one_shots_have_no_live_triggers(self):
        for name in ("issue-75-historical-certificate-readonly.yml",
                     "pg_variables-edb-feature-smoke.yml",
                     "chocolatey-components-benchmark.yml",
                     "issue-75-wave3-actions-readonly.yml",
                     "issue-75-principal-boundaries.yml"):
            with self.subTest(name=name):
                self.assertFalse((WF / name).exists())

    def test_operational_build_provenance_promotion_and_validation_remain(self):
        for name in ("validate.yml", "build-extension.yml",
                     "build-extension-attested.yml", "verify-candidate.yml",
                     "candidate-update.yml", "promote-verified-release.yml",
                     "fleet-status.yml", "edb-installer-503-canary.yml"):
            with self.subTest(name=name):
                self.assertTrue((WF / name).is_file())

    def test_historical_wave3_observer_is_inert_and_still_tested(self):
        self.assertTrue((ROOT / "tests/fixtures/historical-workflows/issue-75-wave3-actions-readonly.yml").is_file())
        self.assertTrue((ROOT / "tests/test-issue-75-wave3-actions-readonly.py").is_file())

    def test_principal_boundary_probe_still_preserved_offline(self):
        self.assertTrue((ROOT / "tests/fixtures/historical-workflows/issue-75-principal-boundaries.yml").is_file())
        self.assertTrue((ROOT / "tests/test-issue-75-principal-boundaries.py").is_file())
        self.assertTrue((ROOT / "scripts/issue-75-principal-boundaries.py").is_file())


    def test_retired_pr_specific_experiments_not_in_required_actions(self):
        live = (WF / "validate.yml").read_text(encoding="utf-8")
        fixture = (ROOT / "tests/fixtures/historical-workflows/validate-issue75-pr-oneoffs.yml").read_text(encoding="utf-8")
        dead = (
            "issue75_reader_probe", "issue75_sandbox_probe",
            "issue75_public_byte_probe", "issue75_choco_script_probe",
            "issue75_wheel_lock_probe", "issue75_secondary_chocolatey_readonly",
            "issue75_kb_inert", "issue75_msu_original",
            "existing_signed_release_readonly",
        )
        for job in dead:
            with self.subTest(job=job):
                self.assertNotIn("\n  " + job + ":", live)
                self.assertIn("\n  " + job + ":", fixture)
        self.assertIn("  resolver:\n", live)
        self.assertIn("python tests/test-fleet-promotion-gate.py", live)
        self.assertIn("python tests/test-publish-release.py", live)
        self.assertIn("python tests/test-issue-75-private-principal-runtime.py", live)
        self.assertNotIn("pull_request_target:", live)

    def test_unused_vm_experiments_are_not_executable(self):
        # These five reports never held publication authority; Git history and
        # the original evidence/docs remain, but runtime experiments are retired.
        stems = (
            "issue-75-private-runtime-readiness",
            "issue-75-work-gui-readiness",
            "issue-75-private-runtime-options",
            "issue-75-external-writer-preboot",
            "issue-75-windows-host-assessment",
        )
        live = (WF / "validate.yml").read_text(encoding="utf-8")
        for stem in stems:
            with self.subTest(stem=stem):
                self.assertFalse((ROOT / "scripts" / (stem + ".py")).exists())
                self.assertFalse((ROOT / "tests" / ("test-" + stem + ".py")).exists())
                self.assertNotIn(stem + ".py", live)
        # No release trust elevation and none of the active admission tests
        # disappear as a side effect of cleanup.
        for path in ("tests/test-issue-75-private-principal-runtime.py",
                     "tests/test-issue-75-real-principal-acceptance.py",
                     "tests/test-issue-75-main-publisher-guard.py",
                     "tests/test-fleet-promotion-policy.py",
                     "scripts/fleet-promotion-gate.py",
                     "scripts/fleet-publish-release.py"):
            self.assertTrue((ROOT / path).is_file())
        self.assertIn("python tests/test-fleet-promotion-gate.py", live)
        self.assertIn("python tests/test-issue-75-real-principal-acceptance.py", live)

    def test_obsolete_vendor_kb_msu_auxiliary_experiments_retired(self):
        # Keep genuine present-day installer and signatory checks, not obsolete
        # Windows 7 / historical vendor package probes in every protected PR.
        stems = (
            "issue-75-choco-secondary-readonly",
            "issue-75-kb-conditional-inert",
            "issue-75-msu-original-bytes",
        )
        live = (WF / "validate.yml").read_text(encoding="utf-8")
        for stem in stems:
            with self.subTest(stem=stem):
                self.assertFalse((ROOT / "scripts" / (stem + ".py")).exists())
                self.assertFalse((ROOT / "tests" / ("test-" + stem + ".py")).exists())
                self.assertNotIn(stem + ".py", live)
        for path in ("docs/issue-75-chocolatey-secondary-closure.md",
                     "docs/issue-75-kb-conditional-inert.md",
                     "docs/issue-75-msu-original-bytes.md",
                     "scripts/install-postgresql.ps1",
                     "tests/test-postgresql-minimal-install.py",
                     "tests/test-postgresql-component-only.py"):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())
        self.assertIn("python tests/test-issue-75-private-principal-runtime.py", live)
        self.assertIn("python tests/test-fleet-promotion-policy.py", live)
        self.assertIn("python tests/test-publish-release.py", live)

    def test_historic_certificate_and_install_tests_preserved(self):
        for path in ("tests/test-issue-75-historical-certificate-readonly.py",
                     "scripts/issue-75-historical-certificate-readonly.py",
                     "tests/test-postgresql-component-only.py",
                     "scripts/install-postgresql-component-only.ps1"):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())


if __name__ == "__main__":
    unittest.main()
