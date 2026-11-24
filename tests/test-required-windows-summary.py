#!/usr/bin/env python3
"""Test the exact stable aggregate check used by Windows CI, without Release."""
import importlib.util
from pathlib import Path
import os
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "required_windows_summary.py"
spec = importlib.util.spec_from_file_location("summary", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

VERIFIED = ("WINDOWS REQUIRED SUMMARY VERIFIED: full maintained-PG Windows matrix "
            "completed successfully\n")
DENIED = ("WINDOWS REQUIRED SUMMARY DENIED: full maintained-PG Windows matrix "
          "was not successful\n")
REUSE_SOURCE = {
    "REUSE_SOURCE_PR": "42",
    "REUSE_SOURCE_RUN_ID": "65",
    "REUSE_SOURCE_ATTEMPT": "1",
}


class WindowsSummaryTests(unittest.TestCase):
    def run_summary(self, matrix_result, **overrides):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("REUSE_") and key != "GITHUB_REPOSITORY"}
        env.update(WINDOWS_MATRIX_RESULT=matrix_result, **overrides)
        return subprocess.run([sys.executable, str(SCRIPT)], env=env,
                              capture_output=True, text=True)

    def test_success_only(self):
        self.assertTrue(module.verified_matrix_result("success"))
        for value in ("failure", "cancelled", "skipped", "", "Success",
                      "success ", True, 1, None):
            with self.subTest(value=value):
                self.assertFalse(module.verified_matrix_result(value))

    def test_real_exit_status_allow_and_deny(self):
        for value, expected in (("success", 0), ("failure", 2),
                                ("cancelled", 2), ("skipped", 2), ("", 2)):
            with self.subTest(result=value):
                res = self.run_summary(value)
                self.assertEqual(res.returncode, expected)
                self.assertEqual(res.stdout, VERIFIED if expected == 0 else "")
                self.assertEqual(res.stderr, DENIED if expected == 2 else "")

    def test_successful_reuse_shows_pr_and_run_attempt_links(self):
        res = self.run_summary("success", REUSE_APPLIED="true", **REUSE_SOURCE,
                               GITHUB_REPOSITORY="pgextwin/pg_permissions")
        self.assertEqual(res.returncode, 0)
        self.assertEqual(
            res.stdout,
            VERIFIED + "WINDOWS CI REUSED: PR #42 "
            "(https://github.com/pgextwin/pg_permissions/pull/42), Run 65, attempt 1 "
            "(https://github.com/pgextwin/pg_permissions/actions/runs/65/attempts/1)\n",
        )
        self.assertEqual(res.stderr, "")

    def test_successful_reuse_without_usable_repository_shows_plain_reference(self):
        for repo_env in ({}, {"GITHUB_REPOSITORY": "pgextwin/.."},
                         {"GITHUB_REPOSITORY": "pgextwin/pg_permissions\nignored"}):
            with self.subTest(repo_env=repo_env):
                res = self.run_summary("success", REUSE_APPLIED="true", **REUSE_SOURCE, **repo_env)
                self.assertEqual(res.returncode, 0)
                self.assertEqual(
                    res.stdout, VERIFIED + "WINDOWS CI REUSED: PR #42, Run 65, attempt 1\n"
                )
                self.assertEqual(res.stderr, "")

    def test_inactive_or_invalid_reuse_preserves_success_output(self):
        for env in (REUSE_SOURCE, dict(REUSE_SOURCE, REUSE_APPLIED="false"),
                    dict(REUSE_SOURCE, REUSE_APPLIED="True"), {"REUSE_APPLIED": "true"},
                    dict(REUSE_SOURCE, REUSE_APPLIED="true", REUSE_SOURCE_PR="42\nignored"),
                    dict(REUSE_SOURCE, REUSE_APPLIED="true", REUSE_SOURCE_RUN_ID="abc"),
                    dict(REUSE_SOURCE, REUSE_APPLIED="true", REUSE_SOURCE_ATTEMPT="0")):
            with self.subTest(env=env):
                res = self.run_summary("success", **env)
                self.assertEqual(res.returncode, 0)
                self.assertEqual(res.stdout, VERIFIED)
                self.assertEqual(res.stderr, "")

    def test_reuse_cannot_override_a_denied_matrix_result(self):
        for value in ("failure", "cancelled", "skipped", ""):
            with self.subTest(result=value):
                res = self.run_summary(value, REUSE_APPLIED="true", **REUSE_SOURCE,
                                       GITHUB_REPOSITORY="pgextwin/pg_permissions")
                self.assertEqual(res.returncode, 2)
                self.assertEqual(res.stdout, "")
                self.assertEqual(res.stderr, DENIED)

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
