#!/usr/bin/env python3
"""Issue #75 nonpublishing Phase D real-GitHub negative probe hostile tests."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest import TestCase, main, mock
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
HEAD = "b" * 40
TOKEN = "test-read-only-token"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load("issue75_phase_d_live_denial_test", "chat-pr-phase-d-live-deny-probe.py")
adapter = load("issue75_phase_d_github_adapter_test", "chat-pr-phase-d-github-readonly.py")


def event():
    return {
        "ref": "refs/heads/main", "after": SHA,
        "repository": {"full_name": probe.REPO},
        "sender": {"login": "ShutenOishi", "type": "User"},
    }


def draft():
    return {
        "number": probe.CANDIDATE_PR,
        "state": "open", "draft": True, "merged": False,
        "head": {"ref": probe.BRANCH, "sha": HEAD},
    }


def windows():
    return {
        "id": probe.CANDIDATE_RUN,
        "head_branch": probe.BRANCH,
        "head_sha": HEAD,
        "event": "workflow_dispatch",
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": probe.REPO},
    }


class API:
    def __init__(self, *, authorization=None, candidate=None, run=None):
        self.requested = []
        self.auth = authorization
        self.candidate = draft() if candidate is None else candidate
        self.run = windows() if run is None else run

    def get(self, path, *, allow_404=False):
        self.requested.append((path, allow_404))
        if path.endswith("/branches/main"):
            return {"protected": True, "commit": {"sha": SHA}}
        if path.endswith("/contents/.github/release-authorizations?ref=" + SHA):
            assert allow_404
            return self.auth
        if path.endswith("/pulls/" + str(probe.CANDIDATE_PR)):
            return self.candidate
        if path.endswith("/actions/runs/" + str(probe.CANDIDATE_RUN)):
            return self.run
        raise AssertionError("unplanned GitHub read " + path)


class PhaseDLiveNegativeTests(TestCase):
    def test_real_probes_deny_absent_authorization_and_draft(self):
        api = API()
        self.assertEqual(probe.inspect_authorization(api, SHA),
                         "AUTHORIZATION_DIRECTORY_ABSENT")
        self.assertEqual(probe.inspect_candidate(api), "CANDIDATE_DRAFT_UNMERGED")
        self.assertEqual(len(api.requested), 4)
        self.assertTrue(api.requested[1][1])

    def test_auth_proof_is_sha_bound_and_only_absence(self):
        for auth in ([], [{"name": "v1-windows.1.json"}], {"x": "secret"}):
            with self.subTest(value=auth), self.assertRaises(probe.Denied):
                probe.inspect_authorization(API(authorization=auth), SHA)
        with self.assertRaises(probe.Denied):
            probe.inspect_authorization(API(), "0" * 40)

    def test_candidate_mutations_deny(self):
        bad_candidate = [
            {"draft": False}, {"merged": True}, {"state": "closed"},
            {"head": {"ref": probe.BRANCH, "sha": "invalid"}},
            {"head": {"ref": "main", "sha": HEAD}},
            {"number": 30},
        ]
        for edit in bad_candidate:
            candidate = draft()
            candidate.update(edit)
            with self.subTest(edit=edit), self.assertRaises(probe.Denied):
                probe.inspect_candidate(API(candidate=candidate))
        bad_runs = [
            {"conclusion": "failure"}, {"status": "queued"},
            {"head_sha": "0" * 40}, {"head_branch": "main"},
            {"run_attempt": 2}, {"repository": {"full_name": "evil/repo"}},
            {"event": "pull_request"}, {"id": 77},
        ]
        for edit in bad_runs:
            run = windows()
            run.update(edit)
            with self.subTest(edit=edit), self.assertRaises(probe.Denied):
                probe.inspect_candidate(API(run=run))

    def test_exact_directory_only_404_from_git_api(self):
        reader = adapter.PilotReadOnly(TOKEN)
        valid = "repos/" + probe.REPO + "/contents/.github/release-authorizations?ref=" + SHA
        adapter.PilotReadOnly.allowed(valid, True)
        for invalid in (
            valid.replace(SHA, "main"),
            valid.replace("release-authorizations?", "workflows?"),
            valid + "&per_page=1",
            "repos/pgextwin/catalog/contents/.github/release-authorizations?ref=" + SHA,
        ):
            with self.subTest(invalid=invalid), self.assertRaises(adapter.Blocked):
                adapter.PilotReadOnly.allowed(invalid, True)
        def not_found(*_args, **_kwargs):
            raise HTTPError("https://api.github.com/" + valid, 404, "missing", {}, None)
        reader._open = not_found
        self.assertIsNone(reader.get(valid, allow_404=True))
        with self.assertRaises(adapter.Blocked):
            reader.get("repos/" + probe.REPO + "/branches/main", allow_404=True)

    def fake_command(self, *, verify_rc=1, sbom_rc=1, download_rc=0,
                     copies=1):
        calls = []
        def fake(args):
            calls.append(args)
            if args[:3] == ("gh", "run", "download"):
                if download_rc != 0:
                    return download_rc
                self.assertEqual(args[3], str(probe.CANDIDATE_RUN))
                self.assertEqual(args[args.index("--name") + 1], probe.ARTIFACT_NAME)
                out = Path(args[args.index("--dir") + 1])
                out.mkdir(parents=True, exist_ok=True)
                for i in range(copies):
                    (out / ("candidate" + str(i) + ".zip")).write_bytes(b"candidate-fixture")
                return 0
            self.assertEqual(args[:3], ("gh", "attestation", "verify"))
            self.assertEqual(args[args.index("--signer-workflow") + 1], probe.SIGNER)
            return sbom_rc if "--predicate-type" in args else verify_rc
        return fake, calls

    def test_real_byte_signature_failure_is_expected_denial_not_a_pass(self):
        for signer, sbom in ((1, 1), (0, 1), (1, 0)):
            command, calls = self.fake_command(verify_rc=signer, sbom_rc=sbom)
            with self.subTest(signer=signer, sbom=sbom):
                result = probe.inspect_signed_candidate(command)
                self.assertEqual(result, "CANDIDATE_SIGNATURE_NOT_VERIFIED")
                self.assertEqual(len(calls), 3)
        command, _ = self.fake_command(verify_rc=0, sbom_rc=0)
        with self.assertRaises(probe.Denied):
            probe.inspect_signed_candidate(command)

    def test_missing_or_duplicate_actual_zip_or_failed_download_denies(self):
        for args in (dict(download_rc=1), dict(copies=0), dict(copies=2)):
            command, _ = self.fake_command(**args)
            with self.subTest(args=args), self.assertRaises(probe.Denied):
                probe.inspect_signed_candidate(command)

    def test_probe_runtime_event_mismatch_is_rejected_before_api(self):
        common = {
            "adapter_module": adapter,
            "evidence_token": TOKEN,
            "admin_token": TOKEN,
            "event": event(),
            "sha": SHA,
            "actor": "ShutenOishi",
            "attempt": "1",
            "repo": probe.REPO,
            "ref": "refs/heads/main",
            "event_name": "push",
        }
        bad = [
            {"actor": "github-actions[bot]"},
            {"attempt": "2"},
            {"repo": "pgextwin/catalog"},
            {"ref": "refs/heads/dev"},
            {"event_name": "workflow_dispatch"},
            {"sha": "0" * 40},
            {"event": dict(event(), sender={"login": "attacker", "type": "User"})},
        ]
        for edit in bad:
            with self.subTest(edit=edit), self.assertRaises(probe.Denied):
                probe.verify_live_negative_probe(**(common | edit))

    def test_end_to_end_mock_three_denials_and_real_adapter_denial(self):
        """Fixture only: real GitHub acceptance must be proved by protected main."""
        class HarnessAdapter:
            class Blocked(ValueError):
                pass
            class PhaseDGitHubAdapter:
                def __init__(self, *_a, **_kw):
                    pass
                def capture(self):
                    raise HarnessAdapter.Blocked("no unique real authorization file")
            class PilotReadOnly:
                def __init__(self, token):
                    self.token = token
                def get(self, path, *, allow_404=False):
                    return API().get(path, allow_404=allow_404)
        with mock.patch.object(probe, "inspect_signed_candidate",
                               return_value="CANDIDATE_SIGNATURE_NOT_VERIFIED"):
            result = probe.verify_live_negative_probe(
                adapter_module=HarnessAdapter,
                evidence_token=TOKEN,
                admin_token=TOKEN,
                event=event(), sha=SHA, actor="ShutenOishi",
                attempt="1", repo=probe.REPO,
                ref="refs/heads/main", event_name="push")
        self.assertEqual(result, (
            "AUTHORIZATION_DIRECTORY_ABSENT",
            "CANDIDATE_DRAFT_UNMERGED",
            "CANDIDATE_SIGNATURE_NOT_VERIFIED",
            "REAL_ADAPTER_AUTHORIZATION_DENIED",
        ))

    def test_probe_has_no_write_or_publisher(self):
        text = (ROOT / "scripts/chat-pr-phase-d-live-deny-probe.py").read_text()
        self.assertNotIn("workflow_dispatch:", text)
        self.assertNotIn("gh release ", text)
        self.assertNotIn("publishableReceipt=true", text)
        self.assertNotIn("def publish(", text)
        self.assertNotIn("requests.post(", text)


if __name__ == "__main__":
    main()
