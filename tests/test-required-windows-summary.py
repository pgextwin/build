#!/usr/bin/env python3
"""Test the exact stable aggregate check used by Windows CI, without Release."""
import importlib.util
from pathlib import Path
import os
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "summary", ROOT / "scripts" / "required_windows_summary.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class WindowsSummaryTests(unittest.TestCase):
    def test_success_only(self):
        self.assertTrue(module.verified_matrix_result("success"))
        for value in ("failure", "cancelled", "skipped", "", "Success",
                      "success ", True, 1, None):
            with self.subTest(value=value):
                self.assertFalse(module.verified_matrix_result(value))

    def test_real_exit_status_allow_and_deny(self):
        path = ROOT / "scripts" / "required_windows_summary.py"
        for value, expected in (("success", 0), ("failure", 2),
                                ("cancelled", 2), ("skipped", 2), ("", 2)):
            env = dict(os.environ, WINDOWS_MATRIX_RESULT=value)
            res = subprocess.run([sys.executable, str(path)], env=env,
                                 capture_output=True, text=True)
            with self.subTest(result=value):
                self.assertEqual(res.returncode, expected)

    def test_build_validation_runs_summary_tests_once(self):
        contents = (ROOT / ".github" / "workflows" / "validate.yml").read_text()
        self.assertEqual(
            contents.splitlines().count(
                "        run: python tests/test-required-windows-summary.py"
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
