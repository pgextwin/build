#!/usr/bin/env python3
"""Regression: invalid GitHub expression truncation may create silent failing workflows."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/".github/workflows/requalify-merged-candidate-signed.yml"

class ReusableSignedScheduleWorkflow(unittest.TestCase):
    def test_github_expressions_must_be_balanced_per_line(self):
        workflow=PATH.read_text("utf-8")
        for index,line in enumerate(workflow.splitlines(),1):
            self.assertEqual(line.count("${{"),line.count("}}"),
                f"line {index} has malformed GitHub expression: {line}")
            self.assertNotIn("ZZ{",line)
        self.assertIn("workflow_call:",workflow)
        self.assertNotIn("workflow_dispatch:",workflow)
        self.assertNotIn("cron:",workflow)

    def test_complete_nonpublishing_four_stage_signer(self):
        workflow=PATH.read_text("utf-8")
        for stage in ("signing_intent:","signed_windows:","signed_audit_first:",
                      "signed_audit_second:","dual_audit_join:"):
            self.assertIn("  "+stage,workflow)
        self.assertIn("verify-merged-schedule-signing-intent.py",workflow)
        self.assertIn("5756b3c5136a8bf4db710016cfe97555f0a71c6d",workflow)
        self.assertIn("audit-merged-scheduled-signed-candidate.py",workflow)
        self.assertIn("join-merged-scheduled-oidc-audits.py",workflow)
        self.assertNotIn("environment: publisher",workflow.lower())
        self.assertNotIn("GH_TOKEN: ${{ secrets.",workflow)

if __name__=="__main__":
    unittest.main()
