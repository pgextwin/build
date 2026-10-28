#!/usr/bin/env python3
"""Hostile, offline R04 independent contender, immutable request and final ZIP tests."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("race", ROOT / "scripts" / "issue311-r04-claim-race.py")
race = importlib.util.module_from_spec(spec)
spec.loader.exec_module(race)

BASE = {
    "schemaVersion": 1, "requestId": race.REQUEST_ID, "mode": "AUDIT_ONLY",
    "kind": "issue311-r04-claim-race-proof",
    "candidate": {"repo": race.CANDIDATE, "sha": race.CANDIDATE_SHA},
    "competitors": list(race.IDS), "baseMainSha": "a" * 40,
    "publicReleaseAuthorized": False,
}
HASH = "7" * 64


class Tests(unittest.TestCase):
    def test_declared_scope_denies_replay_and_privilege(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            with mock.patch.object(race, "REQUEST_PATH", path):
                for addition in ({}, {"publicReleaseAuthorized": True},
                                 {"competitors": [race.IDS[0], race.IDS[0]]},
                                 {"candidate": {"repo": "pgextwin/build", "sha": "a"*40}},
                                 {"mode": "PUBLISH_ELIGIBLE"},
                                 {"unexpected": "claim"}):
                    data = dict(BASE, **addition)
                    path.write_text(json.dumps(data))
                    if not addition:
                        value, digest = race.request_data()
                        self.assertEqual(value, BASE)
                        self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
                    else:
                        with self.assertRaises(race.writer.Denied):
                            race.request_data()
                path.write_text('{"schemaVersion":1,"schemaVersion":1}')
                with self.assertRaises(race.writer.Denied):
                    race.request_data()

    def test_durable_claim_only_one_request_owner(self):
        initial = race.writer.new_ledger(HASH)
        original = json.dumps(initial, sort_keys=True)
        first = race.writer.claim_candidate(initial, race.IDS[0],
                                           race.CANDIDATE, race.CANDIDATE_SHA)
        self.assertEqual(json.dumps(initial, sort_keys=True), original)
        self.assertEqual(first["revision"], initial["revision"] + 1)
        with self.assertRaises(race.writer.Denied):
            race.writer.claim_candidate(first, race.IDS[1],
                                        race.CANDIDATE, race.CANDIDATE_SHA)
        self.assertEqual(race.writer.claim_candidate(first, race.IDS[0],
                         race.CANDIDATE, race.CANDIDATE_SHA), first)
        self.assertFalse(first["publisherAuthorized"])

    def test_identity_guard_denies_untrusted_actor_before_token(self):
        with mock.patch.dict("os.environ", {"GITHUB_REPOSITORY": "pgextwin/build",
                             "GITHUB_EVENT_NAME": "push",
                             "GITHUB_REF": "refs/heads/main",
                             "GITHUB_ACTOR": "malicious-bot"}, clear=True):
            with self.assertRaises(race.writer.Denied):
                race.provenance()

    def test_verify_missing_artifact_denied_before_state_claim(self):
        artifact_index = json.dumps({"total_count": 0, "artifacts": []}).encode()
        with mock.patch.object(race, "provenance", return_value=(BASE, HASH)), \
             mock.patch.dict("os.environ", {"GITHUB_RUN_ID": "123",
                                            "GITHUB_RUN_ATTEMPT": "1", "GH_TOKEN": "opaque"}), \
             mock.patch.object(race, "public_api", return_value=artifact_index):
            with self.assertRaises(race.writer.Denied):
                race.verify()

    def test_no_publication_or_dispatch_authority(self):
        src = Path(race.__file__).read_text()
        for forbidden in ("/releases", "/git/refs/tags", "/dispatches",
                          "PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY", "PUBLISH_ELIGIBLE"):
            self.assertNotIn(forbidden, src)
        self.assertIn('candidateClaims', Path(race.writer.__file__).read_text())
        self.assertEqual(race.writer.STATE_BRANCH, "issue311-state")


if __name__ == "__main__":
    unittest.main()
