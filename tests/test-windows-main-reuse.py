#!/usr/bin/env python3
"""Offline coverage for the resolved Windows input record and reuse decision."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "windows-main-reuse.py"
spec = importlib.util.spec_from_file_location("windows_main_reuse", SCRIPT)
reuse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reuse)

REPO = "pgextwin/pg_hint_plan"
BASE = f"/repos/{REPO}"
PUSH, HEAD, CHECKOUT, TREE, BUILD, UPSTREAM = (char * 40 for char in "abcdef")
PULLS = f"{BASE}/commits/{PUSH}/pulls?per_page=100"
RUNS = f"{BASE}/actions/workflows/windows.yml/runs?event=pull_request&head_sha={HEAD}&per_page=100"
CHECKS = f"{BASE}/check-suites/98/check-runs?per_page=100"
JOBS = f"{BASE}/actions/runs/65/attempts/2/jobs?per_page=100"
LOGS = f"{BASE}/actions/jobs/77/logs"
SUCCESS = {"status": "completed", "conclusion": "success"}


def record_env():
    return {
        "GITHUB_REPOSITORY": REPO,
        "CHECKOUT_COMMIT": PUSH,
        "CHECKOUT_TREE": TREE,
        "BUILD_SHA": BUILD,
        "EXTENSION_NAME": "pg_hint_plan",
        "UPSTREAM_REPOSITORY": "ossc-db/pg_hint_plan",
        "UPSTREAM_MODE": "perPostgresql",
        "UPSTREAM_REF": "",
        "UPSTREAM_VERSION": "",
        "VERIFY_UPSTREAM_LICENSE": "true",
        "LICENSE_FILES": "",
        "MATRIX": json.dumps({"include": [{
            "major": 17, "minor": "17.9", "upstreamCommit": UPSTREAM,
            "upstreamRef": "REL17", "upstreamVersion": "1.7.1",
            "chocolateyPackage": "postgresql17", "chocolateyVersion": "17.9.0",
            "licenseFiles": [{"upstream": 'a"b\\c.txt', "packaging": "LICENSE"}],
        }]}),
    }


def collection(key, items, *, total=None):
    return {key: items, "total_count": len(items) if total is None else total}


class MainReuseTests(unittest.TestCase):
    def setUp(self):
        self.current = reuse.record_inputs(record_env())
        self.source = dict(copy.deepcopy(self.current), checkout_commit=CHECKOUT, pr_head_sha=HEAD)
        self.pr = {"number": 42, "merged_at": "2026-11-22T00:23:18Z",
                   "merge_commit_sha": PUSH, "base": {"ref": "main"}, "head": {"sha": HEAD}}
        self.run = {
            **SUCCESS, "event": "pull_request", "id": 65, "run_attempt": 2, "check_suite_id": 98,
            "head_sha": HEAD, "head_repository": {"full_name": REPO}, "pull_requests": [{"number": 42}],
            "referenced_workflows": [{"path": reuse.WORKFLOW_PATH + "@windows-ci", "sha": BUILD}],
        }
        self.responses = {
            PULLS: [self.pr],
            RUNS: collection("workflow_runs", [self.run]),
            CHECKS: collection("check_runs", [{"id": 81, "name": reuse.SUMMARY_NAME, **SUCCESS}]),
            JOBS: collection("jobs", [{"id": 77, "name": "windows / " + reuse.MATRIX_JOB_NAME, **SUCCESS}]),
            f"{BASE}/git/commits/{HEAD}": {"tree": {"sha": TREE}},
            f"{BASE}/git/commits/{CHECKOUT}": {"tree": {"sha": TREE}},
        }
        self.get = Mock(side_effect=lambda path: copy.deepcopy(self.responses[path]))

    def determine(self, *, repository=REPO, build_sha=BUILD):
        self.responses.setdefault(LOGS, "2026-11-22T00:00:00.000Z starting step\n"
                                  f"2026-11-22T00:00:00.500Z {reuse.RECORD_PREFIX}"
                                  f"{reuse.encode_record(self.source)}\n")
        return reuse.determine(
            enabled_list=ROOT / "metadata" / "main-reuse.json",
            current_record=reuse.encode_record(self.current),
            current_tree=TREE,
            current_build_sha=build_sha,
            env={"GITHUB_REPOSITORY": repository, "GITHUB_SHA": PUSH},
            get=self.get,
        )

    def assert_fallback(self, reason):
        self.assertEqual(self.determine(), {
            "reuse_applied": "false", "reuse_reason": reason,
            "reuse_source_pr": "", "reuse_source_run_id": "",
            "reuse_source_attempt": "", "reuse_source_build_sha": "",
        })

    def test_record_cli_emits_one_reversible_line(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "record"], check=True,
                              capture_output=True, text=True, env=record_env())
        self.assertEqual(proc.stdout.splitlines(), [reuse.RECORD_PREFIX + reuse.encode_record(self.current)])
        self.assertEqual(reuse.record_from_log(proc.stdout), self.current)
        self.assertEqual(self.current["pr_head_sha"], "")

    def test_exact_inputs_reuse_with_pr_checkout_and_attempt_provenance(self):
        self.assertTrue(reuse.same_inputs(self.current, self.source))
        self.assertEqual(self.determine(), {
            "reuse_applied": "true", "reuse_reason": "matched",
            "reuse_source_pr": 42, "reuse_source_run_id": 65,
            "reuse_source_attempt": 2, "reuse_source_build_sha": BUILD,
        })
        for path in (JOBS, LOGS, f"{BASE}/git/commits/{HEAD}", f"{BASE}/git/commits/{CHECKOUT}"):
            self.get.assert_any_call(path)

    def test_changed_inputs_fall_back(self):
        self.source["matrix"]["include"][0]["upstreamCommit"] = "9" * 40
        self.assertFalse(reuse.same_inputs(self.current, self.source))
        self.assert_fallback("resolved_inputs_differ")

    def test_compare_all_resolved_inputs_and_schema(self):
        for field, value in (("license_files", "[]"), ("upstream_mode", "uniform"),
                             ("schemaVersion", True), ("build_sha", "0" * 40),
                             ("extra", "value")):
            with self.subTest(field=field):
                self.assertFalse(reuse.same_inputs(self.current, dict(self.source, **{field: value})))

    def test_unpinned_upstream_falls_back_even_with_equal_records(self):
        for record in (self.current, self.source):
            record["matrix"]["include"][0]["upstreamCommit"] = ""
        self.assertTrue(reuse.same_inputs(self.current, self.source))
        self.assert_fallback("upstream_not_pinned")

    def test_checkout_tree_mismatch_falls_back(self):
        self.responses[f"{BASE}/git/commits/{CHECKOUT}"]["tree"]["sha"] = "1" * 40
        self.assert_fallback("tree_mismatch")

    def test_a_distinct_source_checkout_commit_must_also_match_the_tree(self):
        checkout = "2" * 40
        self.source["checkout_commit"] = checkout
        self.responses[f"{BASE}/git/commits/{checkout}"] = {"tree": {"sha": "3" * 40}}
        self.assert_fallback("tree_mismatch")

    def test_two_merged_pull_requests_fall_back(self):
        self.responses[PULLS].append(dict(self.pr, number=43))
        self.assert_fallback("merged_pr_not_unique")

    def test_commit_associated_with_a_different_merge_falls_back(self):
        self.pr["merge_commit_sha"] = HEAD
        self.assert_fallback("merged_pr_not_unique")

    def test_unsuccessful_run_falls_back(self):
        self.run["conclusion"] = "failure"
        self.assert_fallback("pr_run_not_successful")

    def test_run_with_a_different_head_falls_back(self):
        self.run["head_sha"] = "2" * 40
        self.assert_fallback("pr_run_not_unique")

    def test_ambiguous_runs_on_separate_pages_fall_back(self):
        unrelated = [dict(self.run, id=i) for i in range(100, 199)]
        self.responses[RUNS] = collection("workflow_runs", [self.run, *unrelated], total=101)
        self.responses[RUNS + "&page=2"] = collection("workflow_runs", [dict(self.run, id=66)], total=101)
        self.assert_fallback("pr_run_not_unique")

    def test_referenced_build_sha_must_match(self):
        self.run["referenced_workflows"][0]["sha"] = "0" * 40
        self.assert_fallback("referenced_workflow_mismatch")

    def test_workflow_build_sha_must_match_current_record(self):
        self.assertEqual(self.determine(build_sha="0" * 40)["reuse_reason"], "current_record_mismatch")
        self.get.assert_not_called()

    def test_missing_summary_falls_back(self):
        self.responses[CHECKS] = collection("check_runs", [])
        self.assert_fallback("required_summary_missing")

    def test_missing_record_falls_back(self):
        self.responses[LOGS] = "2026-11-22T00:00:00.000Z no input record"
        self.assert_fallback("input_record_not_unique")

    def test_duplicate_records_fall_back(self):
        self.responses[LOGS] = (reuse.RECORD_PREFIX + reuse.encode_record(self.source) + "\n") * 2
        self.assert_fallback("input_record_not_unique")

    def test_disabled_repository_does_not_call_github(self):
        self.assertEqual(self.determine(repository="pgextwin/pgaudit")["reuse_reason"], "not_enabled")
        self.get.assert_not_called()

    def test_api_error_falls_back(self):
        self.get.side_effect = HTTPError("https://api.github.com" + RUNS, 503, "unavailable", {}, None)
        self.assert_fallback("evidence_unavailable")

    def test_determine_cli_writes_false_and_no_summary_when_evidence_is_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            outputs = Path(tmp) / "outputs"
            summary = Path(tmp) / "summary"
            env = {
                **os.environ, "GITHUB_OUTPUT": str(outputs), "GITHUB_STEP_SUMMARY": str(summary),
                "GITHUB_REPOSITORY": REPO, "GITHUB_SHA": PUSH,
            }
            subprocess.run([
                sys.executable, str(SCRIPT), "determine",
                "--enabled-list", str(ROOT / "metadata" / "main-reuse.json"),
                "--current-record", "invalid JSON", "--current-tree", TREE, "--current-build-sha", BUILD,
            ], env=env, check=True, capture_output=True)
            self.assertIn("reuse_applied=false", outputs.read_text().splitlines())
            self.assertFalse(summary.exists())

    def test_reuse_outputs_include_the_source_in_the_step_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            outputs = Path(tmp) / "outputs"
            summary = Path(tmp) / "summary"
            with patch.dict(os.environ, GITHUB_OUTPUT=str(outputs), GITHUB_STEP_SUMMARY=str(summary),
                            GITHUB_REPOSITORY=REPO):
                reuse.write_result(self.determine())
            self.assertIn("reuse_applied=true", outputs.read_text().splitlines())
            self.assertIn("reuse_source_attempt=2", outputs.read_text().splitlines())
            for value in (f"{REPO}/pull/42", f"{REPO}/actions/runs/65/attempts/2", BUILD):
                self.assertIn(value, summary.read_text())

    def test_logs_redirect_does_not_forward_the_github_token(self):
        with patch.dict(os.environ, GITHUB_API_URL="https://api.github.com", GITHUB_TOKEN="test-token"):
            with patch.object(reuse, "urlopen") as urlopen:
                urlopen.return_value.__enter__.return_value.read.return_value = b"job log"
                self.assertEqual(reuse.get(LOGS), "job log")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
        redirect = HTTPRedirectHandler().redirect_request(
            request, None, 302, "Found", {}, "https://logs.example.com/signed-job-log")
        self.assertFalse(redirect.has_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
