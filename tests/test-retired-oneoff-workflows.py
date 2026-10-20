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

    def test_unreferenced_legacy_release_entrypoint_is_inert(self):
        # Only the shared manual promotion route may own the current
        # signer/publisher flow. The old standalone release workflow can no
        # longer be called in a new live release but its safety proof remains.
        self.assertFalse((WF / "release-extension.yml").exists())
        self.assertTrue((ROOT / "tests/fixtures/historical-workflows/release-extension.yml").is_file())
        self.assertTrue((WF / "promote-verified-release.yml").is_file())
        active = (WF / "promote-verified-release.yml").read_text(encoding="utf-8")
        for phrase in ("fleet-promotion-gate.py", "fleet-publish-release.py",
                       "build-extension-attested.yml", "candidate_run_id"):
            self.assertIn(phrase, active)
        self.assertNotIn("gh release edit", active)
        self.assertNotIn("release-extension.yml", active)

    def test_old_single_extension_publishers_only_exist_as_inert_fixtures(self):
        # Two deprecated plpgsql-only scripts are not referenced by any
        # present-day extension promotion workflow; do not restore them to
        # executable shared build scripts. Preserve historic hostile tests.
        for file in ("promotion-gate.py", "publish-release.py"):
            with self.subTest(file=file):
                self.assertFalse((ROOT / "scripts" / file).exists())
                self.assertTrue((ROOT / "tests/fixtures/historical-scripts" / file).is_file())
        live = (WF / "validate.yml").read_text(encoding="utf-8")
        for test in ("test-promotion-gate.py", "test-publish-release.py",
                     "test-fleet-promotion-gate.py", "test-fleet-publish-release.py"):
            self.assertIn("python tests/" + test, live)
        active = (WF / "promote-verified-release.yml").read_text(encoding="utf-8")
        self.assertIn("fleet-promotion-gate.py", active)
        self.assertIn("fleet-publish-release.py", active)
        for code in ("fleet-promotion-gate.py", "fleet-publish-release.py",
                     "fleet-release-identity.py", "issue-75-publisher-preflight.py",
                     "release-authorization.py"):
            self.assertTrue((ROOT / "scripts" / code).is_file())

    def test_historical_credential_and_host_probes_only_as_inert_fixtures(self):
        # Historically pin-scoped read-only probes have no current executable
        # Workflow consumer. Keep original witness bytes and hostile checks.
        names = ("issue-75-signer-sandbox-probe.py",
                 "issue-75-windows-host-readonly.ps1")
        for name in names:
            with self.subTest(name=name):
                self.assertFalse((ROOT / "scripts" / name).exists())
                self.assertTrue((ROOT / "tests/fixtures/historical-scripts" / name).is_file())
        for required in ("scripts/issue-75-private-signer-verify.py",
                         "scripts/issue-75-private-writer-app-probe.py",
                         "scripts/issue-75-real-principal-acceptance.py",
                         "tests/test-issue-75-signer-hardening.py",
                         "tests/test-issue-75-private-principal-runtime.py"):
            self.assertTrue((ROOT / required).is_file())
        active = (WF / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("python tests/test-issue-75-signer-hardening.py", active)
        self.assertIn("python tests/test-issue-75-private-principal-runtime.py", active)

    def test_historical_wave3_runtime_probe_is_offline_only(self):
        self.assertFalse((ROOT / "scripts/issue-75-wave3-actions-readonly.py").exists())
        self.assertTrue((ROOT / "tests/fixtures/historical-scripts/issue-75-wave3-actions-readonly.py").is_file())
        self.assertTrue((ROOT / "tests/fixtures/historical-workflows/issue-75-wave3-actions-readonly.yml").is_file())
        self.assertTrue((ROOT / "tests/test-issue-75-wave3-actions-readonly.py").is_file())
        live = (WF / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("python tests/test-issue-75-wave3-actions-readonly.py", live)
        self.assertIn("python tests/test-issue-75-private-principal-runtime.py", live)
        self.assertIn("python tests/test-fleet-promotion-gate.py", live)
        self.assertIn("python tests/test-fleet-publish-release.py", live)

    def test_unsigned_external_byte_observer_is_offline_only(self):
        # Prior double-GET evidence and hostile byte/hash tests remain exact,
        # but their one-shot dependency fetcher is not a live executable path.
        self.assertFalse((ROOT / "scripts/issue-75-external-byte-probe.py").exists())
        self.assertTrue((ROOT / "tests/fixtures/historical-scripts/issue-75-external-byte-probe.py").is_file())
        self.assertTrue((ROOT / "tests/test-issue-75-external-byte-probe.py").is_file())
        self.assertTrue((ROOT / "tests/fixtures/historical-workflows/validate-issue75-pr-oneoffs.yml").is_file())
        active = (WF / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("python tests/test-issue-75-external-byte-probe.py", active)
        self.assertNotIn("python scripts/issue-75-external-byte-probe.py", active)
        self.assertIn("python tests/test-fleet-publish-release.py", active)
        self.assertIn("python tests/test-issue-75-signer-hardening.py", active)

    def test_historical_ebd_and_wheel_experiments_are_offline_only(self):
        for name in ("issue-75-choco-edb-nonexec.py",
                     "issue-75-wheel-lock-candidate.py"):
            with self.subTest(name=name):
                self.assertFalse((ROOT / "scripts" / name).exists())
                self.assertTrue((ROOT / "tests/fixtures/historical-scripts" / name).is_file())
        self.assertTrue((ROOT / "tests/test-issue-75-edb-wheel-lock.py").is_file())
        live = (WF / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("python tests/test-issue-75-edb-wheel-lock.py", live)
        self.assertNotIn("python scripts/issue-75-choco-edb-nonexec.py", live)
        self.assertNotIn("python scripts/issue-75-wheel-lock-candidate.py", live)
        self.assertIn("python tests/test-postgresql-component-only.py", live)
        self.assertIn("python tests/test-fleet-publish-release.py", live)
        self.assertIn("python tests/test-issue-75-signer-hardening.py", live)

    def test_completed_historical_certificate_observer_is_offline_only(self):
        self.assertFalse((ROOT / "scripts/issue-75-historical-certificate-readonly.py").exists())
        self.assertTrue((ROOT / "tests/fixtures/historical-scripts/issue-75-historical-certificate-readonly.py").is_file())
        self.assertTrue((ROOT / "tests/test-issue-75-historical-certificate-readonly.py").is_file())
        self.assertTrue((ROOT / "tests/fixtures/historical-workflows/issue-75-historical-certificate-readonly.yml").is_file())
        validate = (WF / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("python tests/test-issue-75-historical-certificate-readonly.py", validate)
        self.assertIn("python tests/test-fleet-publish-release.py", validate)
        self.assertIn("python tests/test-issue-75-signer-hardening.py", validate)
        for name in ("promote-verified-release.yml",
                     "build-extension-attested.yml", "candidate-update.yml",
                     "verify-candidate.yml", "edb-installer-503-canary.yml"):
            self.assertTrue((WF / name).is_file())

    def test_historic_certificate_and_install_tests_preserved(self):
        for path in ("tests/test-issue-75-historical-certificate-readonly.py",
                     "tests/fixtures/historical-scripts/issue-75-historical-certificate-readonly.py",
                     "tests/test-postgresql-component-only.py",
                     "scripts/install-postgresql-component-only.ps1"):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())


if __name__ == "__main__":
    unittest.main()
