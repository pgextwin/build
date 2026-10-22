#!/usr/bin/env python3
"""Fail-closed signed-build readiness output; NEVER a publisher permit."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / ".github/workflows/automatic-postmerge-audit-readonly.yml"

def verify(source):
    required = [
        "  workflow_call:\n    outputs:\n      verified_signed_build_intent:",
        "jobs.observe.outputs.verified_signed_build_intent",
        "steps.intent_result.outputs.allowed",
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
        "github.event.created == false",
        "github.event.deleted == false",
        "      contents: read\n      actions: read\n      pull-requests: read",
        "automatic-postmerge-audit-live.py",
        "automatic-signed-build-intent-live.py",
        "      - name: Mark verified candidate for fresh attested build only\n        id: intent_result\n        if: steps.original_decision.outcome == 'success'",
        "id: intent_result",
        "echo 'allowed=true'",
        "name: automatic-signed-build-intent-nonpublishing",
    ]
    for value in required:
        if value not in source:
            raise ValueError("original decision or signed-build output contract missing")
    if source.count("id: intent_result") != 1:
        raise ValueError("multiple producer steps")
    header = source.split("    steps:", 1)[0]
    for forbidden in ("contents: write", "actions: write", "attestations: write", "id-token: write"):
        if forbidden in header:
            raise ValueError("witness gained write permission")
    for forbidden in ("gh release create", "gh workflow run", "publishableReceipt=true", "ref: main"):
        if forbidden in source:
            raise ValueError("witness bypassed real signing and publication")

class TestSharedReadyOutput(unittest.TestCase):
    def test_nonpublishing_trust_boundary(self):
        verify(FILE.read_text("utf-8"))
    def test_forged_gate_denials(self):
        source = FILE.read_text("utf-8")
        mutations = [
            ("github.event_name == 'push'", "github.event_name == 'workflow_dispatch'"),
            ("github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/main-or-bot'"),
            ("github.event.deleted == false", "github.event.deleted == true"),
            ("      - name: Mark verified candidate for fresh attested build only\n        id: intent_result\n        if: steps.original_decision.outcome == 'success'",
             "      - name: Mark verified candidate for fresh attested build only\n        id: intent_result\n        if: steps.original_decision.outcome != 'success'"),
            ("steps.intent_result.outputs.allowed", "steps.original_decision.outcome"),
            ("      contents: read\n      actions: read\n      pull-requests: read",
             "      contents: write\n      actions: read\n      pull-requests: read"),
            ("automatic-signed-build-intent-live.py", "candidate-update.py"),
            ("automatic-postmerge-audit-live.py", "candidate-update.py"),
        ]
        for a,b in mutations:
            with self.subTest(case=a), self.assertRaises(ValueError):
                self.assertIn(a,source)
                verify(source.replace(a,b,1))

if __name__ == "__main__":
    unittest.main()
