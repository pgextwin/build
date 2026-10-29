#!/usr/bin/env python3
"""Issue 311 R06: PREPARE is separate from AUDIT and genuine schedule; fail closed."""
import importlib.util
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("r06_prepare", ROOT / "scripts/issue311-r06-prepare-scan.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)

class PrepareContractTests(TestCase):
    def report(self):
        targets = prepare.win.TARGETS
        return {"schemaVersion": 1, "scope": "STABLE_UPSTREAM_GET_ONLY",
                "publication": "DENY", "candidatePrCreated": False, "fleetSize": 17,
                "indeterminate": 0, "updatesDetected": 0,
                "extensions": [{"repository": r, "mainSha": s, "status": "up-to-date",
                                "updates": []} for r, s in targets.items()]}

    def test_prepare_workflow_requires_single_protected_push_and_read_only_permissions(self):
        wf = (ROOT / prepare.WORKFLOW_PATH).read_text(encoding="utf-8")
        self.assertIn(prepare.REQUEST_PATH, wf)
        self.assertIn("branches: [main]", wf)
        self.assertIn("contents: read", wf)
        self.assertIn("actions: read", wf)
        for banned in ("schedule:", "workflow_dispatch:", "contents: write",
                       "pull-requests: write", "issues: write", "secrets.",
                       "id-token: write", "gh release ", "PUBLISH=ALLOW"):
            self.assertNotIn(banned, wf)
        self.assertNotEqual(prepare.WORKFLOW, prepare.scan.__module__)

    def test_source_requires_prepare_and_still_does_not_grant_candidate(self):
        code = (ROOT / "scripts/issue311-r06-prepare-scan.py").read_text(encoding="utf-8")
        self.assertIn('declaration["mode"] == "PREPARE"', code)
        self.assertIn('"PREPARE_REQUEST_ORIGINAL_READONLY_SCAN_NO_WRITER"', code)
        self.assertIn('"publicationAuthorized": False', code)
        self.assertNotIn('"schedule"', code)
        self.assertNotIn("candidate-update.py", code)
        self.assertNotIn("create_pull_request", code)

    def test_complete_original_zip_source_is_readonly_even_with_update(self):
        data = self.report()
        self.assertEqual(len(prepare.inspect_report(data, prepare.win.TARGETS)), 17)
        row = data["extensions"][0]
        row["status"] = "update-available"
        row["updates"] = [{"version": "v99", "commit": "c" * 40}]
        data["updatesDetected"] = 1
        self.assertEqual(len(prepare.inspect_report(data, prepare.win.TARGETS)), 17)
        self.assertEqual(data["publication"], "DENY")
        self.assertIs(data["candidatePrCreated"], False)

    def test_missing_indeterminate_drift_and_replay_are_denied(self):
        for mode in ("missing", "indeterminate", "drift", "duplicate", "publication"):
            data = self.report()
            if mode == "missing": data["extensions"].pop()
            if mode == "indeterminate": data["indeterminate"] = 1
            if mode == "drift": data["extensions"][0]["mainSha"] = "f" * 40
            if mode == "duplicate": data["extensions"][1] = data["extensions"][0].copy()
            if mode == "publication": data["publication"] = "ALLOW"
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "R06_SCAN_DENY"):
                prepare.inspect_report(data, prepare.win.TARGETS)

if __name__ == "__main__":
    main()
