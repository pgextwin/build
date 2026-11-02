#!/usr/bin/env python3
"""Offline adversarial checks of the Chat-only fleet read-only scan request."""
import importlib.util
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "chat_fleet_scan_auth", ROOT / "scripts/chat-fleet-scan-auth.py"
)
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)


def actor():
    return {"login": "ShutenOishi", "id": 27071164, "type": "User"}


def env():
    return {
        "GITHUB_EVENT_NAME": "issue_comment",
        "GITHUB_REPOSITORY": "pgextwin/build",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_ACTOR": "ShutenOishi",
        "GITHUB_TRIGGERING_ACTOR": "ShutenOishi",
        "GITHUB_ACTOR_ID": "27071164",
    }


def event():
    return {
        "action": "created",
        "issue": {"number": 311},
        "comment": {
            "id": 4321,
            "body": "/pgextwin scan",
            "issue_url": auth.ISSUE_URL,
            "created_at": "2026-11-03T00:00:00Z",
            "updated_at": "2026-11-03T00:00:00Z",
            "user": actor(),
        },
        "sender": actor(),
    }


def live():
    return dict(event()["comment"])


class ChatFleetScanSecurity(TestCase):
    def test_owner_new_unedited_comment_passes_observation_only(self):
        self.assertEqual(auth.validate_event(event(), env()), 4321)
        self.assertEqual(auth.validate_live(event(), live(), env()), 4321)

    def test_unauthorized_env_and_replayed_attempt_denied(self):
        for key, replacement in (
            ("GITHUB_EVENT_NAME", "schedule"),
            ("GITHUB_REPOSITORY", "other/build"),
            ("GITHUB_REF", "refs/heads/untrusted"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_ACTOR", "another"),
            ("GITHUB_TRIGGERING_ACTOR", "another"),
            ("GITHUB_ACTOR_ID", "12"),
        ):
            with self.subTest(key=key):
                bad = env()
                bad[key] = replacement
                with self.assertRaises(auth.ScanDenied):
                    auth.validate_event(event(), bad)

    def test_forged_changed_deleted_or_wrong_issue_comment_denied(self):
        for bad in (
            {"action": "edited"},
            {"issue": {"number": 311, "pull_request": {}}},
            {"issue": {"number": 75}},
            {"comment": {**event()["comment"], "body": "/pgextwin publish pgextwin/hypopg"}},
            {"comment": {**event()["comment"], "id": "4321"}},
            {"comment": {**event()["comment"], "updated_at": "2026-11-03T00:00:01Z"}},
            {"comment": {**event()["comment"], "user": {"login": "ShutenOishi", "id": 1, "type": "User"}}},
            {"sender": {"login": "ShutenOishi", "id": 1, "type": "User"}},
        ):
            with self.subTest(bad=bad):
                payload = event()
                payload.update(bad)
                with self.assertRaises(auth.ScanDenied):
                    auth.validate_event(payload, env())

        for altered in (
            None,
            {},
            {**live(), "body": "/pgextwin scan modified"},
            {**live(), "updated_at": "2026-11-03T00:01:00Z"},
            {**live(), "issue_url": "https://api.github.com/repos/other/build/issues/311"},
            {**live(), "id": 9999},
        ):
            with self.subTest(altered=altered):
                with self.assertRaises(auth.ScanDenied):
                    auth.validate_live(event(), altered, env())

    def test_same_shared_scanner_no_candidate_or_publisher_capability(self):
        yaml = (ROOT / ".github/workflows/chat-fleet-scan.yml").read_text("utf-8")
        self.assertIn("issue_comment:", yaml)
        self.assertIn("types: [created]", yaml)
        self.assertIn("github.event.comment.body == '/pgextwin scan'", yaml)
        self.assertIn("scripts/chat-fleet-scan-auth.py", yaml)
        self.assertIn("scripts/fleet-upstream-watch.py", yaml)
        self.assertIn("metadata/automation-fleet.json", yaml)
        self.assertIn("permissions:\n  contents: read\n  issues: read", yaml)
        self.assertIn("if-no-files-found: warn", yaml)
        for forbidden in (
            "contents: write", "issues: write", "actions: write",
            "pull-requests: write", "id-token: write", "secrets.",
            "workflow_dispatch:", "schedule:", "gh release", "gh pr create",
            "pull_request_target:",
        ):
            self.assertNotIn(forbidden, yaml)


if __name__ == "__main__":
    main()
