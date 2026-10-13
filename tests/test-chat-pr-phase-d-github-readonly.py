#!/usr/bin/env python3
"""Issue #75: adversarial no-network Phase D real-reader and artifact tests."""
from __future__ import annotations

from copy import deepcopy
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock
from urllib.error import HTTPError, URLError
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lib = load("phase_d_github_test", "scripts/chat-pr-phase-d-github-readonly.py")
fixture_lib = load("phase_d_fleet_fixture", "tests/test-fleet-promotion-gate.py")
SHA = "a" * 40
TOKEN = "test-token-never-log"


class Response(io.BytesIO):
    def __init__(self, body, status=200, link=""):
        super().__init__(body)
        self.status = status
        self.headers = {"Link": link}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class GitHubReadOnlyTests(TestCase):
    def api(self, data, *, link="", status=200):
        r = lib.PilotReadOnly(TOKEN)
        r._open = lambda request, timeout=20: Response(
            data if type(data) is bytes else json.dumps(data).encode(), status, link)
        return r

    def test_only_one_repository_fixed_read_paths_and_get_verb(self):
        reader = lib.PilotReadOnly(TOKEN)
        for path in (
            "repos/pgextwin/catalog/branches/main",
            "repos/pgextwin/plpgsql_check/actions/workflows/promote.yml/dispatches",
            "repos/pgextwin/plpgsql_check/git/refs",
            "repos/pgextwin/plpgsql_check/actions/runs/1/artifacts",
            "repos/pgextwin/plpgsql_check/contents/.github/workflows/promote.yml?ref=" + SHA,
            "repos/pgextwin/plpgsql_check/branches/main?per_page=1",
            "installation/repositories?per_page=1",
            "https://evil.example/",
            "../private",
        ):
            with self.subTest(path=path), self.assertRaises(lib.Blocked):
                reader.get(path)
        response = self.api({"total_count": 1, "repositories": [
            {"full_name": "pgextwin/plpgsql_check"}]})
        self.assertEqual(
            response.get("installation/repositories?per_page=100")["total_count"], 1)

    def test_bounded_no_redirect_duplicate_and_pagination(self):
        base = "repos/pgextwin/plpgsql_check/branches/main"
        self.assertEqual(self.api({"protected": True}).get(base)["protected"], True)
        bad = (
            (b'{"protected":true,"protected":true}', ""),
            (b"not-json", ""),
            (b"[]", '<https://api.github.com/x?page=2>; rel="next"'),
            (b"1" * (lib.MAX_JSON + 1), ""),
        )
        for data, link in bad:
            with self.subTest(data_size=len(data)), self.assertRaises(lib.Blocked):
                self.api(data, link=link).get(base)
        with self.assertRaises(lib.Blocked):
            self.api({}).get(base, allow_404=True)
        missing = lib.PilotReadOnly(TOKEN)
        def deny(*_args, **_kwargs):
            raise HTTPError("https://api.github.com/x", 404, "missing", {}, None)
        missing._open = deny
        with self.assertRaises(lib.Blocked):
            missing.get(base)
        self.assertIsNone(missing.get("repos/pgextwin/plpgsql_check/git/ref/tags/v1-windows.1",
                                      allow_404=True))
        with self.assertRaises(lib.Blocked):
            missing.get("repos/pgextwin/plpgsql_check/pulls/5")

    def test_committed_blob_sha_does_not_trust_self_asserted_json(self):
        body = b'{"name":"plpgsql_check"}'
        sha = lib.approval_lib.git_blob_sha(body)
        class Fake:
            def __init__(self, obj):
                self.obj = obj
                self.calls = []
            def get(self, path):
                self.calls.append(path)
                return self.obj
        good = Fake({"sha": sha, "encoding": "base64",
                     "content": base64.b64encode(body).decode()})
        self.assertEqual(lib.trusted_json_file(good, "config/extension.json", SHA),
                         {"name": "plpgsql_check"})
        self.assertTrue(good.calls[0].endswith("?ref=" + SHA))
        for tamper in ({"sha": "0" * 40}, {"content": "!!not-base64!!"},
                       {"encoding": "text"}, {"sha": None}):
            obj = deepcopy(good.obj);obj.update(tamper)
            with self.subTest(tamper=tamper), self.assertRaises(lib.Blocked):
                lib.trusted_json_file(Fake(obj), "config/extension.json", SHA)

    def test_reject_gh_write_commands_even_if_test_stub_attempts(self):
        for args in (("release", "create"), ("workflow", "run"),
                     ("api", "--method", "POST"),
                     ("auth", "login"), ("git", "push")):
            with self.assertRaises(lib.Blocked):
                lib.gh_read(*args)
        with mock.patch.object(lib, "subprocess") as command:
            command.run.return_value.returncode = 1
            with self.assertRaises(lib.Blocked):
                lib.gh_read("run", "download", "42", "--repo", lib.REPO,
                            "--dir", "/tmp/fixture")
            command.run.assert_called_once()
            self.assertEqual(command.run.call_args[1]["timeout"], 120)

    def test_real_authorization_is_missing_so_no_publishing_possible(self):
        adapter = lib.PhaseDGitHubAdapter(
            TOKEN, TOKEN, event={"ref": "refs/heads/main"}, main_sha=SHA,
            actor="HumanOperator", allowed_operators={"HumanOperator"})
        adapter.admin_api.get = lambda path, **kwargs: {"total_count": 0, "repositories": []}
        with self.assertRaises(lib.Blocked):
            adapter.capture()
        self.assertEqual(adapter.signed_digests, [])
        self.assertFalse(hasattr(adapter, "publish"))
        self.assertFalse(hasattr(adapter, "dispatch"))


class SignedBytesTests(TestCase):
    def specimen(self):
        ext = fixture_lib.fixture()["ext"]
        return ext, 15, lib.fleet_lib.ident.asset_stem(ext, 15)

    def downloader(self, ext, major, stem, *, bad_sha=False, unsigned=False,
                   package_bad=False, sbom_bad=False):
        data = io.BytesIO()
        with ZipFile(data, "w") as archive:
            archive.writestr("PACKAGE-INFO.json", json.dumps({
                "package": {"name": ext["name"] if not package_bad else "evil"},
                "postgresql": {"major": major},
                "upstream": {"repository": ext["upstream"]["repository"],
                             "commit": "c" * 40},
                "workflowRun": {"id": 900},
            }))
        zip_bytes = data.getvalue()
        digest = hashlib.sha256(zip_bytes).hexdigest()
        audit = {"majors": [{
            "major": major, "zip": stem + ".zip",
            "sbom": stem + ".spdx.json",
            "grype": stem + ".vulnerabilities.json",
            "zipSha256": ("f" * 64 if bad_sha else digest),
        }]}
        decision = {"schemaVersion": 1, "status": "candidate"}

        def fake(*args):
            if args[:2] == ("attestation", "verify"):
                if unsigned:
                    raise lib.Blocked("signature not verified")
                self.assertIn("--signer-workflow", args)
                self.assertIn(lib.SIGNER, args)
                return
            self.assertEqual(args[:2], ("run", "download"))
            where = Path(args[args.index("--dir") + 1])
            where.mkdir(parents=True, exist_ok=True)
            if "--name" in args:
                name = args[args.index("--name") + 1]
                (where / (name + ".json")).write_text(json.dumps(
                    decision if name == "candidate-decision" else audit))
            else:
                (where / (stem + ".zip")).write_bytes(zip_bytes)
                (where / (stem + ".spdx.json")).write_text(json.dumps(
                    {"spdxVersion": "not-SPDX" if sbom_bad else "SPDX-2.3"}))
                (where / (stem + ".vulnerabilities.json")).write_text(
                    json.dumps({"matches": []}))
        return fake, digest

    def verify(self, **kwargs):
        ext, major, stem = self.specimen()
        fake, sha = self.downloader(ext, major, stem, **kwargs)
        with mock.patch.object(lib, "gh_read", side_effect=fake) as gh:
            decision, audit, digests = lib.verified_artifacts(
                900, 901, [major], ext, {major: {"commit": "c" * 40}})
        self.assertEqual(decision["status"], "candidate")
        self.assertEqual(digests, {str(major): sha})
        calls = [z.args for z in gh.call_args_list]
        self.assertEqual(sum(1 for z in calls if z[:2] == ("attestation", "verify")), 2)
        self.assertTrue(any(lib.SPDX_PREDICATE in z for z in calls))
        return audit

    def test_zip_digest_package_spdx_and_two_attestations(self):
        self.assertEqual(len(self.verify()["majors"]), 1)

    def test_unsigned_zip_tampered_sha_package_and_spdx_deny(self):
        for issue in ("bad_sha", "unsigned", "package_bad", "sbom_bad"):
            with self.subTest(issue=issue), self.assertRaises(lib.Blocked):
                self.verify(**{issue: True})

    def test_bad_matrix_denied_before_download(self):
        ext, major, stem = self.specimen()
        with self.assertRaises(lib.Blocked):
            lib.verified_artifacts(900, 901, [15, True], ext, {})
        with self.assertRaises(lib.Blocked):
            lib.verified_artifacts(0, 901, [15], ext, {})


if __name__ == "__main__":
    main()
