#!/usr/bin/env python3
"""R10-01 real formal Publisher code boundary: controlled missing write ACK.

NO GitHub API, network, release, tag, credentials, request or dispatch. This
exercises the production formal Publisher's one-shot commands with mock-only
failure and must NOT be cited as a real Release POST result.
"""
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "r10_formal_publisher", ROOT / "scripts" / "fleet-publish-release.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class FormalPublisherUnknownWrite(TestCase):
    def case(self, fail_at):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            recovery = folder / "immutable-recovery.json"
            writes = []

            def fake_command(*args):
                # The code under test must never reach a real mutation.
                self.assertEqual(args[0], "gh")
                writes.append(args)
                if len(writes) == fail_at:
                    raise p.Denied("CONTROLLED_ACK_LOSS_AFTER_UNKNOWN_WRITE")
                return ""

            with mock.patch.object(p, "absent") as absent, \
                 mock.patch.object(p, "run", side_effect=fake_command), \
                 mock.patch.object(p, "staged_release_id", return_value=501) as stage, \
                 mock.patch.object(p, "check_remote") as verify:
                with self.assertRaisesRegex(p.Denied, "write outcome UNKNOWN"):
                    p.publish_preverified(
                        folder, {"name": "orafce"},
                        {"releaseTag": "v1.2.3-windows.99", "authorizationMode": "manual-dispatch"},
                        "a" * 40, {"original.zip": "b" * 64}, recovery,
                        publish_run_id=123)
                # A missing response is NEVER treated as permission to repeat
                # the POST/PATCH, to create a new tag, or to go on publishing.
                self.assertEqual(len(writes), fail_at)
                self.assertEqual(sum(1 for c in writes if c == writes[-1]), 1)
                self.assertEqual(json.loads(recovery.read_text())["state"],
                                 ("WRITE_OUTCOME_UNKNOWN_TAG_RESERVATION",
                                  "WRITE_OUTCOME_UNKNOWN_DRAFT_CREATION",
                                  "WRITE_OUTCOME_UNKNOWN_DRAFT_PUBLICATION")[fail_at - 1])
                absent.assert_called_once()
                if fail_at < 3:
                    self.assertEqual(stage.call_count, 1 if fail_at == 2 else 0)
                    self.assertEqual(verify.call_count, 1 if fail_at == 2 else 0)
                else:
                    stage.assert_called_once()
                    verify.assert_called_once()
                self.assertNotEqual(json.loads(recovery.read_text())["state"],
                                    "PUBLISHED_VERIFIED")
                self.assertFalse(any("gh release upload" in " ".join(c) for c in writes))

    def test_unknown_tag_reservation_is_durable_and_no_retry(self):
        self.case(1)

    def test_unknown_draft_create_is_durable_and_no_retry(self):
        self.case(2)

    def test_unknown_publication_patch_is_durable_and_no_retry(self):
        self.case(3)

    def test_full_controlled_success_has_bounded_three_mutations(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            writes = []
            with mock.patch.object(p, "absent"), \
                 mock.patch.object(p, "run", side_effect=lambda *c: writes.append(c) or ""), \
                 mock.patch.object(p, "staged_release_id", return_value=501), \
                 mock.patch.object(p, "check_remote") as verify:
                result = p.publish_preverified(
                    folder, {"name": "orafce"},
                    {"releaseTag": "v1.2.3-windows.99", "authorizationMode": "manual-dispatch"},
                    "a" * 40, {"original.zip": "b" * 64}, folder / "recovery.json",
                    publish_run_id=123)
                self.assertEqual(result, 0)
                self.assertEqual(len(writes), 3)
                self.assertEqual(verify.call_count, 2)
                self.assertEqual(json.loads((folder / "recovery.json").read_text())["state"],
                                 "PUBLISHED_VERIFIED")

if __name__ == "__main__":
    main()
