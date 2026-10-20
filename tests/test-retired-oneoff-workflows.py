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
                     "chocolatey-components-benchmark.yml"):
            with self.subTest(name=name):
                self.assertFalse((WF / name).exists())

    def test_operational_build_provenance_promotion_and_validation_remain(self):
        for name in ("validate.yml", "build-extension.yml",
                     "build-extension-attested.yml", "verify-candidate.yml",
                     "candidate-update.yml", "promote-verified-release.yml",
                     "fleet-status.yml", "edb-installer-503-canary.yml"):
            with self.subTest(name=name):
                self.assertTrue((WF / name).is_file())

    def test_historic_certificate_and_install_tests_preserved(self):
        for path in ("tests/test-issue-75-historical-certificate-readonly.py",
                     "scripts/issue-75-historical-certificate-readonly.py",
                     "tests/test-postgresql-component-only.py",
                     "scripts/install-postgresql-component-only.ps1"):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())


if __name__ == "__main__":
    unittest.main()
