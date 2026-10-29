#!/usr/bin/env python3
"""R06 read-only scan rejects partial, stale, fake and event-kind spoofing."""
from pathlib import Path
import importlib.util
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan = load("scan_r06_tests", "scripts/issue311-r06-request-scan.py")
verify = load("verify_r06_tests", "scripts/issue311-r06-request-preflight.py")


class RequestScanTests(unittest.TestCase):
    def report(self):
        return {"schemaVersion": 1, "scope": "STABLE_UPSTREAM_GET_ONLY",
                "publication": "DENY", "candidatePrCreated": False,
                "fleetSize": 17, "indeterminate": 0, "updatesDetected": 0,
                "extensions": [{"repository": repo, "mainSha": sha,
                                "status": "up-to-date", "updates": []}
                               for repo, sha in scan.win.TARGETS.items()]}

    def test_full_17_exact_original_preflight(self):
        found = scan.inspect_report(self.report(), scan.win.TARGETS)
        self.assertEqual(set(found), set(scan.win.TARGETS))

    def test_no_missing_or_duplicate_or_moved_mains(self):
        cases = []
        report = self.report()
        report["extensions"] = report["extensions"][:-1]
        cases.append(report)
        report = self.report()
        report["extensions"][0]["mainSha"] = "a" * 40
        cases.append(report)
        report = self.report()
        report["extensions"][0] = report["extensions"][1].copy()
        cases.append(report)
        for report in cases:
            with self.subTest(report=report["extensions"][0]):
                with self.assertRaisesRegex(ValueError, "R06_SCAN_DENY"):
                    scan.inspect_report(report, scan.win.TARGETS)

    def test_no_indeterminate_candidate_or_publication(self):
        for key, value in (("indeterminate", 1),
                           ("publication", "PUBLISH"),
                           ("candidatePrCreated", True),
                           ("fleetSize", 16)):
            report = self.report()
            report[key] = value
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "R06_SCAN_DENY"):
                    scan.inspect_report(report, scan.win.TARGETS)

    def test_invalid_original_completion_event_denied_prior_to_network(self):
        for key, value in (("path", "fleet-upstream-watch.yml"),
                           ("event", "schedule"),
                           ("head_branch", "unprotected"),
                           ("conclusion", "failure"),
                           ("run_attempt", 2)):
            payload = {"id": 99, "name": scan.WORKFLOW,
                       "path": scan.WORKFLOW_PATH, "event": "push",
                       "head_branch": "main", "run_attempt": 1,
                       "status": "completed", "conclusion": "success",
                       "actor": {"login": "ShutenOishi"}, "head_sha": "a" * 40}
            payload[key] = value
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "R06_PREFLIGHT_DENY"):
                    verify.authenticated_source({"action": "completed",
                        "repository": {"full_name": "pgextwin/build"},
                        "workflow_run": payload})

    def test_no_cron_or_dispatch_in_original_only_workflow(self):
        wf = (ROOT / ".github/workflows/issue311-r06-request-scan.yml").read_text()
        self.assertIn("r-20261029-r06scanproof001.json", wf)
        self.assertNotIn("schedule:", wf)
        self.assertNotIn("workflow_dispatch:", wf)


if __name__ == "__main__":
    unittest.main()
