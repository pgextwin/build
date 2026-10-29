#!/usr/bin/env python3
"""R06 hostile source negative unit tests. No GitHub credentials or writes."""
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("issue311_r06_hostile", ROOT / "scripts/issue311-r06-hostile17-live.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ControlledHostileTest(unittest.TestCase):
    def test_copy_only_hostile_zip_deny(self):
        report = {"extensions": [{"repository": f"pgextwin/ext{i}"} for i in range(17)]}
        proof = {"report": report, "targetMainSha": {f"pgextwin/ext{i}": "a"*40 for i in range(17)}}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(mod.RECEIPT_ENTRY, json.dumps(proof))
        original_path = ".github/execution-requests/r-20261029-r06prepare17pin03.json"
        original_request = (ROOT / original_path).read_bytes()
        def inspect(item, targets):
            mod.need(len(item["extensions"]) == len(targets) == 17, "partial original")
        with patch.object(mod.scan, "inspect_report", side_effect=inspect):
            checks, expired_now = mod.controlled_denials(
                buf.getvalue(), proof, original_request, original_path)
        self.assertEqual(set(checks), {
            "tamperedOriginalZip", "missingTargetOuterDigest",
            "missingTargetSchema", "expiredOriginalRequest"})
        self.assertIsInstance(expired_now, bool)

    def test_persisted_terminal_replay_denied_before_write(self):
        targets = [f"pgextwin/ext{i}" for i in range(17)]
        state = mod.life.new(mod.REQ, "c"*64, "d"*40, targets,
                             "2026-10-30T00:00:00Z", max_events=25)
        bound = mod.life.bind_source(state, 0, "source", run_id=7, attempt=1, head_sha="d"*40)
        terminal = mod.life.record_completion(
            bound, 1, "terminal", run_id=8, attempt=1, source_id=7,
            outcome="QUARANTINED", target_outcomes={t: "QUARANTINED" for t in targets},
            original_zip_sha="f"*64)
        self.assertEqual(terminal["terminal"], "QUARANTINED")
        with self.assertRaises(mod.life.Denied):
            mod.life.record_completion(terminal, 2, "replay", run_id=9, attempt=1,
                source_id=7, outcome="NO_UPDATE",
                target_outcomes={t: "SUCCESS" for t in targets}, original_zip_sha="f"*64)
        self.assertEqual(terminal["revision"], 2)
        self.assertFalse(terminal["publisherAuthorized"])


if __name__ == "__main__":
    unittest.main()
