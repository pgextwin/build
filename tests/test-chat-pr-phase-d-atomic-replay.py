#!/usr/bin/env python3
"""Issue #75 Phase D: inert authorization/JIT and simulated atomic-tag/replay acceptance.

All GitHub API writes are an in-memory fake; no token, network, real tag, or
PUBLISH authorization is used. This is NOT live create-ref/E2E acceptance.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]
REPO = "pgextwin/pgaudit"
TAG = "v18.1-windows.3"
SHA = "a" * 40


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publisher = load("phase_d_atomic_publisher", "scripts/fleet-publish-release.py")
authorization = load("phase_d_atomic_auth", "scripts/chat-pr-authorization.py")
typed = load("phase_d_atomic_typed", "scripts/release-authorization.py")
phase_case = load("phase_d_atomic_jit_fixture", "tests/test-chat-pr-phase-d-prepublish.py")
approval_case = load("phase_d_atomic_pr_fixture", "tests/test-chat-pr-authorization.py")
read_only = load("phase_d_atomic_reader", "scripts/chat-pr-phase-d-github-readonly.py")


class SimulatedGitHub:
    """Deliberately non-atomic GET, API-atomic create-only POST, no real I/O."""

    def __init__(self, *, fail_draft=False):
        self.tags = {}
        self.releases = {}
        self.next_id = 701
        self.fail_draft = fail_draft
        self.stale_preflight_get = False
        self.commands = []
        self.reads = []
        self.created_tags = 0

    def get(self, path):
        self.reads.append(path)
        if path in ("git/ref/tags/" + TAG, "releases/tags/" + TAG):
            # Demonstrate a stale/incorrect preflight GET; the POST must still
            # be exclusively atomic in the fake API to avoid double creation.
            if self.stale_preflight_get:
                return None
            if path.startswith("git/"):
                return {"ref": "refs/tags/" + TAG} if TAG in self.tags else None
            for release in self.releases.values():
                if release["tag_name"] == TAG and not release["draft"]:
                    return deepcopy(release)
            return None  # GitHub tag lookup cannot reliably see a Draft
        if path == "releases?per_page=100":
            return deepcopy(list(self.releases.values()))
        if path.startswith("releases/"):
            return deepcopy(self.releases.get(int(path.split("/")[-1])))
        raise AssertionError("unexpected mocked GET " + path)

    def run(self, *command):
        self.commands.append(command)
        if command[:4] == ("gh", "api", "-X", "POST"):
            assert command[4] == "repos/" + REPO + "/git/refs"
            assert "ref=refs/tags/" + TAG in command
            assert "sha=" + SHA in command
            if TAG in self.tags:
                raise publisher.Denied("simulated GitHub HTTP 422: Reference already exists")
            self.tags[TAG] = SHA
            self.created_tags += 1
            return ""
        if command[:3] == ("gh", "release", "create"):
            assert command[3] == TAG and "--draft" in command
            assert "--verify-tag" in command and "--target" in command
            assert TAG in self.tags
            rid = self.next_id
            self.next_id += 1
            self.releases[rid] = {
                "id": rid, "tag_name": TAG, "target_commitish": SHA,
                "draft": True, "assets": [],
            }
            if self.fail_draft:
                raise publisher.Denied("simulated partial Draft stage failure")
            return ""
        if command[:4] == ("gh", "api", "-X", "PATCH"):
            rid = int(command[4].split("/")[-1])
            assert command[4] == "repos/" + REPO + "/releases/" + str(rid)
            assert "draft=false" in command
            assert rid in self.releases and self.releases[rid]["draft"]
            self.releases[rid]["draft"] = False
            return ""
        raise AssertionError("prohibited or unexpected simulated GitHub write " + repr(command))

    def verbs(self):
        return [c[:4] for c in self.commands]


def invoke(fake, directory, *, recovery="recovery.json"):
    """Execute the ACTUAL existing publisher control flow with every I/O mocked.

    Only the tag/draft transaction is under test. check_assets and check_remote
    are replaced because no genuine signed bytes exist in these synthetic tests.
    They must never be interpreted as acceptance of actual signed artifacts.
    """
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schemaVersion": 1, "authorizationMode": "manual-dispatch",
        "status": "VERIFIED_MANUAL_DISPATCH", "operator": "HumanOperator",
        "repository": REPO, "trustedCommit": SHA, "releaseTag": TAG,
        "majors": [14], "sources": [],
    }
    (folder / "receipt.json").write_text(json.dumps(receipt))
    (folder / "manifest.json").write_text('{"name":"pgaudit"}')
    (folder / "lifecycle.json").write_text("{}")
    args = ["fleet-publish-release.py", "--receipt", str(folder / "receipt.json"),
            "--manifest", str(folder / "manifest.json"), "--tag", TAG,
            "--dist", str(folder), "--recovery", str(folder / recovery),
            "--lifecycle", str(folder / "lifecycle.json")]
    env = {"GITHUB_REPOSITORY": REPO, "GITHUB_REF": "refs/heads/main",
           "GITHUB_SHA": SHA, "GITHUB_ACTOR": "HumanOperator",
           "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ID": "77"}
    with mock.patch.dict(os.environ, env), mock.patch.object(publisher, "REPO", REPO), \
         mock.patch.object(publisher, "get", side_effect=fake.get), \
         mock.patch.object(publisher, "run", side_effect=fake.run), \
         mock.patch.object(publisher, "check_assets", return_value={"sample.zip": "f" * 64}), \
         mock.patch.object(publisher, "check_remote"), \
         mock.patch.object(sys, "argv", args), \
         mock.patch.object(publisher.subprocess, "run",
                           side_effect=AssertionError("live subprocess forbidden")), \
         mock.patch.object(publisher, "urlopen",
                           side_effect=AssertionError("live HTTP forbidden")):
        # A real typed manual receipt is validated; no fake Chat-PUBLISH is made.
        return publisher.main()


class AtomicReplayTests(TestCase):
    def test_preflight_get_absence_is_not_atomic_post_422_wins(self):
        api = SimulatedGitHub()
        with TemporaryDirectory() as directory:
            self.assertEqual(invoke(api, directory, recovery="first.json"), 0)
            state = json.loads((Path(directory) / "first.json").read_text())
            self.assertEqual(state["state"], "PUBLISHED_VERIFIED")
            self.assertEqual(api.created_tags, 1)
            release_id = next(iter(api.releases))
            self.assertFalse(api.releases[release_id]["draft"])
            # The losing concurrent writer has a stale GET snapshot and sees
            # ABSENT despite the winning reservation. Only create-ref POST is
            # exclusive; this second POST must be rejected as GitHub HTTP 422.
            api.stale_preflight_get = True
            self.assertEqual(invoke(api, directory, recovery="loser.json"), 2)
            self.assertEqual(api.created_tags, 1)
            self.assertEqual(len(api.releases), 1)
            posts = [c for c in api.commands if c[:4] == ("gh", "api", "-X", "POST")]
            drafts = [c for c in api.commands if c[:3] == ("gh", "release", "create")]
            patches = [c for c in api.commands if c[:4] == ("gh", "api", "-X", "PATCH")]
            self.assertEqual((len(posts), len(drafts), len(patches)), (2, 1, 1))
            # Now a coherent GET sees occupancy and rejects a replay BEFORE POST.
            api.stale_preflight_get = False
            before = list(api.commands)
            self.assertEqual(invoke(api, directory, recovery="replay.json"), 2)
            self.assertEqual(api.commands, before)
            self.assertEqual(api.releases[release_id]["id"], release_id)
            self.assertEqual(json.loads((Path(directory) / "first.json").read_text()), state)

    def test_partial_draft_failure_quarantines_existing_tag_and_draft(self):
        api = SimulatedGitHub(fail_draft=True)
        with TemporaryDirectory() as directory:
            self.assertEqual(invoke(api, directory), 2)
            saved = json.loads((Path(directory) / "recovery.json").read_text())
            self.assertEqual(saved["state"], "TAG_RESERVED")
            self.assertEqual(api.created_tags, 1)
            release_id = next(iter(api.releases))
            self.assertTrue(api.releases[release_id]["draft"])
            # GitHub releases/tags can hide an authenticated draft, but tag
            # create-only reservation is already occupied.
            self.assertIsNone(api.get("releases/tags/" + TAG))
            count = len(api.commands)
            api.fail_draft = False
            self.assertEqual(invoke(api, directory), 2)
            self.assertEqual(len(api.commands), count)
            self.assertEqual(api.created_tags, 1)
            self.assertEqual(list(api.releases), [release_id])
            self.assertTrue(api.releases[release_id]["draft"])
            self.assertEqual(json.loads((Path(directory) / "recovery.json").read_text()), saved)

    def test_release_id_or_draft_state_mismatch_never_patches(self):
        api = SimulatedGitHub()
        api.tags[TAG] = SHA
        api.releases[701] = {"id": 702, "tag_name": TAG, "target_commitish": SHA,
                             "draft": True, "assets": []}
        with mock.patch.object(publisher, "get", side_effect=api.get):
            with self.assertRaises(publisher.Denied):
                publisher.check_remote(TAG, {}, True, 701)
            # Wrong target commit during draft enumeration must fail, too.
            api.releases[701]["target_commitish"] = "f" * 40
            with self.assertRaises(publisher.Denied):
                publisher.staged_release_id(TAG, SHA)
        self.assertEqual(api.commands, [])

    def test_authorization_exact_pr_ci_and_jit_are_inert(self):
        result = phase_case.phase_d.verify_inert_prepublication_recheck(
            phase_case.FakeReader(phase_case.snapshot()),
            expected_main_sha=phase_case.SHA, expected_operator=phase_case.OPERATOR)
        self.assertEqual(result["status"], "DRY_RUN_PHASE_D_RECHECK_ONLY")
        self.assertIs(result["publishableReceipt"], False)
        self.assertIs(result["signedArtifactsVerified"], False)
        self.assertIs(result["publishingEnabled"], False)
        with self.assertRaises(typed.Denied):
            typed.validate_receipt(result, repository="pgextwin/plpgsql_check",
                                   commit=phase_case.SHA, actor=phase_case.OPERATOR,
                                   event="push")
        for mutation in (
            lambda x: x["event"].update(before="9" * 40),  # stale squash parent
            lambda x: x["pr"]["merged_by"].update(login="other-human"),
            lambda x: x["pr"]["user"].update(login="github-actions[bot]"),
            lambda x: x["commit"]["files"].append(
                {"filename": "config/release-promotion.json", "status": "modified"}),
            lambda x: x["ci"].update(headSha="9" * 40),
            lambda x: x["ci"].update(allRequiredChecksPassed=False),
            lambda x: x["effective_rules"].update(restrictDirectPush=False),
        ):
            item = approval_case.fixture()
            mutation(item)
            with self.subTest(mutation=mutation), self.assertRaises(authorization.Denied):
                approval_case.verify_fixture(item)

    def test_changed_snapshots_unknown_and_transport_timeout_fail_closed(self):
        for field, value in (("mainSha", "9" * 40), ("tagRef", "PRESENT"),
                             ("release", {"id": 7}), ("artifactSignatures", "VERIFIED")):
            first = phase_case.snapshot()
            second = deepcopy(first)
            second[field] = value
            with self.subTest(field=field), self.assertRaises(phase_case.phase_d.PhaseDDenied):
                phase_case.phase_d.verify_inert_prepublication_recheck(
                    phase_case.FakeReader(first, second),
                    expected_main_sha=phase_case.SHA,
                    expected_operator=phase_case.OPERATOR)
        api = read_only.PilotReadOnly("synthetic-never-real-token")
        api._open = mock.Mock(side_effect=TimeoutError("offline simulated timeout"))
        with self.assertRaises(read_only.Blocked):
            api.get("repos/pgextwin/plpgsql_check/branches/main")

    def test_central_manual_policy_and_no_live_publication_entrypoint(self):
        central = json.loads((ROOT / "metadata/release-promotion.json").read_text())
        self.assertEqual(central["releasePolicy"], "manual-dispatch")
        self.assertFalse(hasattr(read_only.PhaseDGitHubAdapter, "publish"))
        for source in ("scripts/chat-pr-phase-d-prepublish.py",
                       "scripts/chat-pr-authorization.py"):
            text = (ROOT / source).read_text()
            self.assertNotIn('if __name__ == "__main__"', text)
            self.assertNotIn("gh release create", text)
            self.assertNotIn("git/refs", text)


if __name__ == "__main__":
    main()
