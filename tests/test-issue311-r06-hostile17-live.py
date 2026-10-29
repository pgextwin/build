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


    def test_original_receipt_publisher_flag_strict(self):
        original = {"id": 40876766677, "head_sha": "7cefe10b6ac3d70e2fd0c8378cae2bc763c064c0"}
        declaration = {"rawSha256": "c" * 64}
        proof = {
            "result": "CONTROLLED_DENY_VERIFIED", "requestId": mod.REQ,
            "sourceHeadSha": original["head_sha"], "sourceRunId": original["id"],
            "sourceAttempt": 1, "requestSha256": declaration["rawSha256"],
            "targetCount": 17, "centralRunId": mod.ORIGINAL_RUN,
            "centralArtifactId": mod.ORIGINAL_ARTIFACT,
            "centralZipSha256": mod.ORIGINAL_DIGEST,
            "publisherAuthorized": False,
            "negativeDenials": {key: "DENY" for key in [
                "tamperedOriginalZip", "missingTargetOuterDigest",
                "missingTargetSchema", "expiredOriginalRequest"]}
        }
        mod.validate_original_source_receipt(proof, original, declaration)
        for invalid in [
            {**proof, "publicationAuthorized": False},
            {key: value for key, value in proof.items() if key != "publisherAuthorized"},
            {**proof, "publisherAuthorized": True},
            {**proof, "sourceAttempt": 2}
        ]:
            with self.assertRaises(ValueError):
                mod.validate_original_source_receipt(invalid, original, declaration)

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
