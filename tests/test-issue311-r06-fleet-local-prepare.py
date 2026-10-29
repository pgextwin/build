#!/usr/bin/env python3
"""Adversarial contract tests for shared, read-only local PREPARE gate."""
import importlib.util
import os
from pathlib import Path
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/issue311-r06-fleet-local-prepare.py"
spec = importlib.util.spec_from_file_location("fleet_local_prepare", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class ReadonlyFleetTests(TestCase):
    def test_all_17_allowed_and_outside_denied(self):
        self.assertEqual(len(gate.prepare.win.TARGETS), 17)
        for repo in gate.prepare.win.TARGETS:
            with mock.patch.dict(os.environ, {"GH_TOKEN": "test"}, clear=False):
                with mock.patch.object(gate.prepare.win.old, "get_json",
                                       return_value={"name": "main", "protected": True}):
                    self.assertTrue(gate.remote_branch(repo)["protected"])
        with self.assertRaisesRegex(ValueError, "unapproved extension"):
            gate.remote_branch("attacker/fake")

    def test_duplicate_json_and_broken_utc_rejected(self):
        with self.assertRaises(ValueError):
            gate.strict('{"requestId":"a","requestId":"b"}')
        for s in ("2026-10-29T12:00:00+09:00", "not-a-time"):
            with self.assertRaises((ValueError, TypeError)):
                gate.utc(s)

    def test_no_authorization_in_any_terminal(self):
        src = SCRIPT.read_text()
        for required in ("bridge.original_zip(", "contract.validate_declaration(",
                         "sourceArtifactId", "sourceZipSha256", "targetMainSha",
                         "GITHUB_RUN_ATTEMPT", "GITHUB_ACTOR", "protected",
                         "originalOuterZipSha256Verified", "NO_UPDATE",
                         "UPDATE_PRESENT_NOT_AUTHORIZED", "A\\t",
                         "candidateAdmissionAuthorized", "publisherSourceKindAuthorized"):
            self.assertIn(required, src)
        for forbidden in ("workflow_dispatch", "create_pull_request(", "git push",
                          "PUBLISH=ALLOW", "contents: write", "release create"):
            self.assertNotIn(forbidden, src)

    def test_unregistered_repository_never_opens_github_event(self):
        with mock.patch.object(gate, "REPO", "untrusted/private"):
            with self.assertRaisesRegex(ValueError, "unregistered local repository"):
                gate.authenticate_local()

    def test_original_denial_stays_failed_and_writes_receipt(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(gate, "OUTPUT", str(Path(d) / "receipt.json")):
                with mock.patch.object(gate, "authenticate_local", side_effect=ValueError("DENY")):
                    self.assertEqual(gate.run(), 1)
                    import json
                    receipt=json.loads(Path(gate.OUTPUT).read_text())
                    self.assertEqual(receipt["result"], "FAILED")
                    for flag in ("candidateAdmissionAuthorized", "publisherSourceKindAuthorized",
                                 "publicationAuthorized", "genuineSchedule"):
                        self.assertIs(receipt[flag], False)

if __name__ == "__main__":
    main()
