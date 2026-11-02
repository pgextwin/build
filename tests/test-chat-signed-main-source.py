#!/usr/bin/env python3
"""Adversarial local checks for distinct genuine owner main-signing source."""
import importlib.util
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "chat_signed_main_auth", ROOT / "scripts/chat-signed-main-auth.py")
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)
REPO = "pgextwin/plpgsql_check"
SHA = "a" * 40
USER = {"login": "ShutenOishi", "id": 27071164, "type": "User"}


def env():
    return {
        "GITHUB_REPOSITORY": REPO, "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "8888",
        "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "issue_comment",
        "GITHUB_ACTOR": "ShutenOishi", "GITHUB_ACTOR_ID": "27071164",
        "GITHUB_TRIGGERING_ACTOR": "ShutenOishi",
    }


def event():
    return {
        "action": "created", "repository": {"full_name": REPO},
        "sender": dict(USER), "issue": {"number": 78},
        "comment": {
            "id": 123456, "issue_url": "https://api.github.com/repos/" + REPO + "/issues/78",
            "body": "/pgextwin sign-main", "user": dict(USER),
            "created_at": "2026-11-03T00:00:00Z",
            "updated_at": "2026-11-03T00:00:00Z",
        },
    }


def live():
    return dict(event()["comment"])


def branch():
    return {"name": "main", "protected": True, "commit": {"sha": SHA}}


def run():
    return {"id": 8888, "run_attempt": 1, "event": "issue_comment",
            "path": ".github/workflows/chat-signed-main.yml",
            "head_branch": "main", "head_sha": SHA,
            "repository": {"full_name": REPO}}


def fleet():
    return {"schemaVersion": 1, "entries": [
        {"repository": REPO}, {"repository": "pgextwin/orafce"}]}


def check(**overrides):
    x = {"event": event(), "live": live(), "branch": branch(),
         "run": run(), "fleet": fleet(), "env": env(), "issue_number": 78}
    x.update(overrides)
    return auth.check(**x)


class MainSigningSourceTests(TestCase):
    def test_genuine_and_nonpublishing(self):
        r = check()
        self.assertEqual(r["sourceKind"], "OWNER_ISSUE_COMMENT_MAIN_SIGNING")
        self.assertEqual(r["sourceEvent"], "issue_comment")
        self.assertFalse(r["publisherEligible"])
        self.assertFalse(r["publicationAuthorized"])
        self.assertEqual(r["PUBLISH"], "DENY")

    def test_replay_foreign_actor_ref_and_source_kind(self):
        for key, replacement in (
            ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_REF", "refs/heads/fake"), ("GITHUB_SHA", "b" * 40),
            ("GITHUB_ACTOR", "attacker"), ("GITHUB_TRIGGERING_ACTOR", "attacker"),
            ("GITHUB_ACTOR_ID", "1"), ("GITHUB_REPOSITORY", "pgextwin/other"),
        ):
            with self.subTest(key=key):
                bad = env()
                bad[key] = replacement
                with self.assertRaises(auth.Denied):
                    check(env=bad)

    def test_edited_comment_wrong_issue_and_forged_sender(self):
        for key, value in (
            ("action", "edited"), ("sender", {"login": "ShutenOishi", "id": 1}),
            ("issue", {"number": 78, "pull_request": {}}),
            ("issue", {"number": 311}),
            ("comment", {**event()["comment"], "body": "/pgextwin publish pgextwin/plpgsql_check"}),
            ("comment", {**event()["comment"], "updated_at": "2026-11-03T00:01:00Z"}),
        ):
            with self.subTest(key=key):
                v = event()
                v[key] = value
                with self.assertRaises(auth.Denied):
                    check(event=v)
        for k, v in (
            ("body", "/pgextwin scan"), ("id", 123457),
            ("updated_at", "2026-11-03T00:01:00Z"),
        ):
            x = live()
            x[k] = v
            with self.assertRaises(auth.Denied):
                check(live=x)

    def test_drift_nonprotected_incorrect_run_and_unregistered(self):
        for bad in ({"name": "main", "protected": False, "commit": {"sha": SHA}},
                    {"name": "main", "protected": True, "commit": {"sha": "b" * 40}}):
            with self.assertRaises(auth.Denied):
                check(branch=bad)
        for key, value in (("event", "push"), ("run_attempt", 2),
                           ("path", ".github/workflows/update-watch.yml"),
                           ("head_sha", "b" * 40)):
            r = run()
            r[key] = value
            with self.assertRaises(auth.Denied):
                check(run=r)
        with self.assertRaises(auth.Denied):
            check(fleet={"schemaVersion": 1, "entries": [{"repository": "pgextwin/orafce"}]})
        with self.assertRaises(auth.Denied):
            check(fleet={"schemaVersion": 1, "entries": [{"repository": REPO}, {"repository": REPO}]})

    def test_reusable_workflow_has_no_publish_credentials(self):
        workflow = (ROOT / ".github/workflows/chat-signed-main-source.yml").read_text("utf-8")
        self.assertIn("workflow_call:", workflow)
        self.assertIn("scripts/chat-signed-main-auth.py", workflow)
        self.assertIn("build-extension-attested.yml@", workflow)
        self.assertIn("sourceKind", workflow)
        for forbidden in ("schedule:", "workflow_dispatch:", "contents: write",
                          "pull-requests: write", "PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY",
                          "gh release create", "environment: publisher"):
            self.assertNotIn(forbidden, workflow)


    def test_dual_audit_must_match_original_bytes_source_and_two_jobs(self):
        import copy
        a_spec = importlib.util.spec_from_file_location(
            "chat_owner_audit", ROOT / "scripts/chat-signed-main-audit.py")
        audit = importlib.util.module_from_spec(a_spec)
        a_spec.loader.exec_module(audit)
        first = {
            "schemaVersion": 1,
            "status": "VERIFIED_OWNER_MAIN_SIGNED_NONPUBLISHING",
            "sourceKind": audit.SOURCE_KIND,
            "repository": REPO, "mainSha": SHA,
            "runId": 8888, "runAttempt": 1, "commentId": 123456,
            "auditor": "first", "majors": [14, 15, 16, 17, 18],
            "SHA256": {"real-pg14.zip": "f" * 64},
            "publisherEligible": False, "publicationAuthorized": False,
            "PUBLISH": "DENY",
        }
        second = {**first, "auditor": "second"}
        result = audit.join(first, second)
        self.assertEqual(result["status"], "DUAL_VERIFIED_OWNER_MAIN_SIGNED_NONPUBLISHING")
        for key, forged in (
            ("mainSha", "b" * 40),
            ("runId", 8889),
            ("commentId", 123457),
            ("SHA256", {"real-pg14.zip": "0" * 64}),
            ("publisherEligible", True),
            ("publicationAuthorized", True),
            ("sourceKind", "PUSH"),
        ):
            with self.subTest(key=key):
                bad = copy.deepcopy(second)
                bad[key] = forged
                with self.assertRaises(audit.Denied):
                    audit.join(first, bad)
        with self.assertRaises(audit.Denied):
            audit.join(first, first)


if __name__ == "__main__":
    main()
