#!/usr/bin/env python3
"""Adversarial contract tests for shared, read-only local PREPARE gate."""
import importlib.util
import os
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
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

    def test_frozen_central_source_allows_sequential_local_request_mains(self):
        # Central SCANNED original ZIP already binds 17 protected refs.
        # Later request-only local main commits must not invalidate the frozen
        # source as long as this local push exactly matches its own original ref.
        import inspect
        original = inspect.getsource(gate.authenticate_original)
        self.assertIn('targets.get(REPO) == base_sha', original)
        self.assertIn('original.get("targetMainSha") == targets', original)
        self.assertIn('prepare.inspect_report(original.get("report"), targets)', original)
        self.assertNotIn('remote_branch(repo)', original)
        self.assertIn('remote_branch(REPO)', inspect.getsource(gate.authenticate_local))
        self.assertIn('and branch.get("commit", {}).get("sha") == head',
                      inspect.getsource(gate.authenticate_local))

    def test_original_local_push_denies_expiry_replay_and_privilege_before_any_github_get(self):
        repo = "pgextwin/orafce"
        head, prior = "b" * 40, "a" * 40
        request = "r-20261029-r06localhostile001"
        path = ".github/execution-requests/" + request + ".json"
        def utc(delta):
            return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")
        fresh = {
            "schemaVersion": 1, "kind": "pgextwin-local-prepare",
            "requestId": request, "mode": "PREPARE", "sourceRunId": 100,
            "sourceHeadSha": "c" * 40, "sourceArtifactId": 200,
            "sourceZipSha256": "d" * 64,
            "centralRequestId": "r-20261029-r06preparehostile01",
            "targetMainSha": prior, "expiresAt": utc(timedelta(minutes=10)),
            "publicReleaseAuthorized": False,
        }
        event = {
            "ref": "refs/heads/main", "before": prior, "after": head,
            "created": False, "deleted": False,
            "repository": {"full_name": repo},
            "sender": {"login": "ShutenOishi"},
        }
        env = {
            "GITHUB_REPOSITORY": repo, "GITHUB_WORKFLOW": gate.WORKFLOW,
            "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
            "GITHUB_ACTOR": "ShutenOishi", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": head,
        }
        def evaluate(values=None, ev=None, environment=None, changed=None, protected=True):
            original = fresh if values is None else values
            with TemporaryDirectory() as tmp:
                source = Path(tmp) / "event.json"
                source.write_text(json.dumps(event if ev is None else ev))
                values_env = dict(env, GITHUB_EVENT_PATH=str(source))
                if environment:
                    values_env.update(environment)
                changed_path = "A\t" + path + "\n" if changed is None else changed
                def git(cmd, **kwargs):
                    if cmd[:3] == ["git", "rev-parse", "HEAD"]:
                        return head
                    if cmd[:3] == ["git", "diff", "--name-status"]:
                        return changed_path.splitlines()
                    if cmd[:2] == ["git", "show"]:
                        return json.dumps(original).encode()
                    raise AssertionError("unexpected subprocess")
                with mock.patch.dict(os.environ, values_env), \
                     mock.patch.object(gate, "REPO", repo), \
                     mock.patch.object(gate.subprocess, "check_output", side_effect=git), \
                     mock.patch.object(gate, "remote_branch",
                         return_value={"name": "main", "protected": protected,
                                       "commit": {"sha": head}}) as remote:
                    try:
                        result = gate.authenticate_local()
                        return result, remote.call_count
                    except (ValueError, TypeError) as exc:
                        return exc, remote.call_count

        value, gets = evaluate()
        self.assertEqual(value[0], fresh)
        self.assertEqual(value[2], prior)
        self.assertEqual(gets, 1)
        bad_values = [
            dict(fresh, expiresAt=utc(timedelta(minutes=-1))),
            dict(fresh, expiresAt=utc(timedelta(hours=13))),
            dict(fresh, sourceZipSha256="e" * 63),
            dict(fresh, targetMainSha="e" * 40),
            dict(fresh, publicReleaseAuthorized=True),
            dict(fresh, sourceRunId=0),
            dict(fresh, mode="PUBLISH_ELIGIBLE"),
            dict(fresh, requestId="r-20261029-r06localother001"),
            dict(fresh, centralRequestId="r-20261029-r06preparewrong"),
        ]
        # A syntactically valid *different* central ID is not rejected at
        # this initial gate; authenticate_original separately binds the actual
        # central request. Test here only schema and pre-GET denial.
        bad_values.pop()
        for candidate in bad_values:
            with self.subTest(candidate=candidate):
                result, gets = evaluate(values=candidate)
                self.assertIsInstance(result, ValueError)
                self.assertEqual(gets, 0)
        for environment in (
            {"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_EVENT_NAME": "schedule"},
            {"GITHUB_ACTOR": "attacker"}, {"GITHUB_REF": "refs/heads/dev"},
        ):
            with self.subTest(environment=environment):
                result, gets = evaluate(environment=environment)
                self.assertIsInstance(result, ValueError)
                self.assertEqual(gets, 0)
        for poisoned in (dict(event, before=head),
                         dict(event, sender={"login": "attacker"}),
                         dict(event, repository={"full_name": "attacker/orafce"})):
            result, gets = evaluate(ev=poisoned)
            self.assertIsInstance(result, ValueError)
            self.assertEqual(gets, 0)
        result, gets = evaluate(changed="M\t" + path + "\n")
        self.assertIsInstance(result, ValueError)
        self.assertEqual(gets, 0)
        result, gets = evaluate(protected=False)
        self.assertIsInstance(result, ValueError)
        self.assertEqual(gets, 1)

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
