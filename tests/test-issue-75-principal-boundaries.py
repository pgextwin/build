#!/usr/bin/env python3
"""Issue75 hostile fixtures: this is NOT a real Signer/Writer acceptance."""
import copy
import importlib.util
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "scripts/issue-75-principal-boundaries.py"
spec = importlib.util.spec_from_file_location("principal_negative", path)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

SHA = "8d6b81697bee53632f8a035bac8fc045419fba9f"
def env(role="reader"):
    d = {"GITHUB_REPOSITORY": "pgextwin/build", "GITHUB_EVENT_NAME": "push",
         "GITHUB_REF": "refs/heads/main",
         "GITHUB_WORKFLOW_REF":
             "pgextwin/build/.github/workflows/issue-75-principal-boundaries.yml@refs/heads/main",
         "GITHUB_JOB": p.ROLE_JOBS[role], "GITHUB_SHA": SHA,
         "GITHUB_RUN_ID": "39099999999", "GITHUB_RUN_ATTEMPT": "1"}
    if role == "reader":
        d["GH_TOKEN"] = "SYNTHETIC-NEVER-A-REAL-TOKEN"
    return d

def fake_get():
    calls = []
    run = {"id": 39099999999, "run_attempt": 1, "head_sha": SHA,
           "event": "push", "head_branch": "main",
           "path": p.WORKFLOW, "status": "in_progress"}
    branch = {"protected": True, "commit": {"sha": SHA}}
    def get(path):
        calls.append(path)
        if path == "actions/runs/39099999999":
            return copy.deepcopy(run)
        if path == "branches/main":
            return copy.deepcopy(branch)
        raise AssertionError("unexpected endpoint")
    return get, calls, run, branch

class BoundaryTests(TestCase):
    def test_synthetic_get4_remains_not_proven_and_no_go(self):
        get, calls, _, _ = fake_get()
        out = p.inspect("reader", env(), get)
        self.assertEqual(calls, ["actions/runs/39099999999", "branches/main"]*2)
        self.assertEqual(out["decision"], "READER_GET4_NEGATIVE_ONLY")
        self.assertTrue(out["readerAuthenticatedGetObserved"])
        for key in ("readerEffectiveScopesVerified", "signerRealIdentityVerified",
                    "writerRealIdentityVerified",
                    "crossRoleTokenDistinctnessVerified", "writerCredentialMinted",
                    "publicationAuthorized", "runtimeClosureProven",
                    "signedPublisherPositivePrewriteVerified"):
            self.assertFalse(out[key], key)
        self.assertEqual(out["authenticationBoundary"], "NOT_PROVEN")
        self.assertEqual((out["goB"], out["g4"], out["g5"]),
                         ("NO_GO", "NO_GO", "NO_GO"))

    def test_trusted_main_context_denials(self):
        changes = {
            "GITHUB_REPOSITORY": "pgextwin/plpgsql_check",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/pull/4/merge",
            "GITHUB_WORKFLOW_REF": "pgextwin/build/.github/workflows/validate.yml@refs/heads/main",
            "GITHUB_JOB": "publish",
            "GITHUB_SHA": "main",
            "GITHUB_RUN_ID": "0",
            "GITHUB_RUN_ATTEMPT": "2",
        }
        for key, val in changes.items():
            with self.subTest(key=key):
                x = env()
                x[key] = val
                get, _, _, _ = fake_get()
                with self.assertRaises(p.Deny):
                    p.inspect("reader", x, get)

    def test_no_partial_or_mutable_double_get_acceptance(self):
        for key, bad in (("id", 1), ("run_attempt", 2),
                         ("head_sha", "f"*40), ("event", "workflow_dispatch"),
                         ("head_branch", "branch"), ("path", "promote.yml"),
                         ("status", "failure")):
            with self.subTest(key=key):
                get, calls, run, branch = fake_get()
                run[key] = bad
                with self.assertRaises(p.Deny):
                    p.inspect("reader", env(), get)
        for change in (lambda b: b.update(protected=False),
                       lambda b: b["commit"].update(sha="f"*40),
                       lambda b: b.pop("commit")):
            get, _, run, branch = fake_get()
            change(branch)
            with self.assertRaises(p.Deny):
                p.inspect("reader", env(), get)

    def test_second_read_race_denied(self):
        get, calls, run, branch = fake_get()
        def race(path):
            v = get(path)
            if len(calls) == 3:
                v["head_sha"] = "0"*40
            return v
        with self.assertRaises(p.Deny):
            p.inspect("reader", env(), race)
        get, calls, run, branch = fake_get()
        def protected_race(path):
            v = get(path)
            if len(calls) == 4:
                v["protected"] = False
            return v
        with self.assertRaises(p.Deny):
            p.inspect("reader", env(), protected_race)

    def test_signer_writer_are_unprovisioned_not_real_identity(self):
        for role in ("signer", "writer"):
            with self.subTest(role=role):
                out = p.inspect(role, env(role), lambda _: self.fail("GET"))
                self.assertEqual(out["decision"], role.upper()+"_UNPROVISIONED_NO_WRITE")
                self.assertFalse(out["writerCredentialMinted"])
                self.assertFalse(out["signerRealIdentityVerified"])
                for key in ("GH_TOKEN", "GITHUB_TOKEN"):
                    x = env(role)
                    x[key] = "SYNTHETIC"
                    with self.assertRaises(p.Deny):
                        p.inspect(role, x, lambda _: self.fail("GET"))

    def test_inert_role_rejects_secret_named_variables_even_when_empty(self):
        # Do not read or log secret VALUES. An empty injected variable still
        # means credential custody/environment isolation was not demonstrated.
        names = (
            "GH_TOKEN", "GITHUB_TOKEN", "GH_APP_PRIVATE_KEY", "GH_APP_JWT",
            "GITHUB_APP_TOKEN", "GITHUB_INSTALLATION_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
            "SIGSTORE_ID_TOKEN", "COSIGN_PASSWORD", "COSIGN_PRIVATE_KEY",
            "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS", "PGEXTWIN_WRITER_CREDENTIAL",
            "CUSTOM_CLIENT_SECRET", "SYNTHETIC_API_TOKEN",
            "FAKE_PRIVATE_KEY", "UNKNOWN_PASSWORD", "UNSAFE_SECRET",
            "gIthUb_InstallatIon_Token",
        )
        for role in ("signer", "writer"):
            for name in names:
                with self.subTest(role=role,key=name):
                    e=env(role)
                    e[name]=""
                    with self.assertRaises(p.Deny):
                        p.inspect(role,e,lambda _: self.fail("no real GET"))
                    e[name]="SYNTHETIC_TOKEN_MUST_NOT_APPEAR_IN_OUTPUT"
                    with self.assertRaises(p.Deny):
                        p.inspect(role,e,lambda _: self.fail("no real GET"))
            out=p.inspect(role,env(role),lambda _: self.fail("no real GET"))
            self.assertTrue(out["inertProcessCredentialKeysAbsent"])
            self.assertFalse(out["crossRoleTokenDistinctnessVerified"])
            self.assertFalse(out["publicationAuthorized"])

    def test_runtime_denial_sanitizes_injected_credential_value(self):
        for role in ("signer","writer"):
            dirty=env(role)
            dirty["GITHUB_APP_PRIVATE_KEY"]="SECRET_KEY_SHOULD_NEVER_BE_ECHOED"
            capture=io.StringIO()
            with mock.patch.dict(os.environ,dirty,clear=True), \
                 mock.patch("sys.argv",["main","--role",role]), \
                 redirect_stdout(capture):
                result=p.main()
            self.assertEqual(result,2)
            self.assertNotIn("SECRET_KEY_SHOULD_NEVER_BE_ECHOED",
                             capture.getvalue())
            self.assertEqual(json.loads(capture.getvalue())["goB"],"NO_GO")

    def test_allowlist_malformed_json_duplicate_keys_and_redirect_deny(self):
        self.assertFalse(p.SHA.fullmatch("x"*40))
        with self.assertRaises(p.Deny):
            p.unique([("a", 1), ("a", 2)])
        for endpoint in ("releases", "git/refs/tags/evil",
                         "actions/runs/0", "actions/runs/2/jobs",
                         "https://evil.example/"):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(p.Deny):
                    p.get_json(endpoint, "SYNTHETIC",
                               opener=lambda *_args, **_kw: self.fail("HTTP"))
        with self.assertRaises(p.Deny):
            p.NoRedirect().redirect_request(None, None, 302, "", {},
                                            "https://evil.example/")

    def test_credential_never_printed_even_when_runtime_get_fails(self):
        with mock.patch.dict(os.environ, env(), clear=True), \
             mock.patch("sys.argv", ["prog", "--role", "reader"]), \
             mock.patch.object(p, "get_json", side_effect=RuntimeError("SYNTHETIC-SECRET")):
            output = io.StringIO()
            with redirect_stdout(output):
                rc = p.main()
        # main() uses sys.argv, so this path rejects untrusted args or GET; either
        # outcome MUST fail closed without printing injected exception text.
        self.assertEqual(rc, 2)
        value = json.loads(output.getvalue())
        self.assertEqual(value["decision"], "DENY_MISSING_OR_MISMATCHED_RUNTIME_EVIDENCE")
        self.assertNotIn("SYNTHETIC-SECRET", output.getvalue())
        self.assertFalse(value["publicationAuthorized"])

    def test_static_trusted_main_only_nonpublishing_roles(self):
        text = (ROOT/".github/workflows/issue-75-principal-boundaries.yml").read_text()
        self.assertIn("  push:\n    branches:\n      - main", text)
        self.assertIn("permissions: {}", text)
        self.assertNotIn("pull_request:", text)
        self.assertNotIn("pull_request_target:", text)
        self.assertNotIn("workflow_dispatch:", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("upload-artifact", text)
        self.assertNotIn("download-artifact", text)
        self.assertNotIn("create-github-app-token", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("id-token: write", text)
        self.assertNotIn("attestations: write", text)
        self.assertNotIn("gh release", text)
        import re
        blocks = dict(re.findall(r"(?ms)^  (reader|signer_denied|writer_denied):\n(.*?)(?=^  (?:reader|signer_denied|writer_denied):|\Z)", text))
        # A boundary reordering/scope expansion must not silently pass CI.
        self.assertEqual(set(blocks), {"reader", "signer_denied", "writer_denied"})
        for name, job in blocks.items():
            self.assertIn("github.event_name == 'push'", job)
            self.assertIn("github.ref == 'refs/heads/main'", job)
            self.assertIn("persist-credentials: false", job)
            self.assertIn("contents: read", job)
            self.assertNotIn("secrets.", job)
            self.assertNotIn("contents: write", job)
            self.assertNotIn("id-token: write", job)
            for forbidden in ("needs:", "outputs:", "GITHUB_OUTPUT",
                              "GITHUB_ENV", "upload-artifact", "download-artifact",
                              "actions/cache@", "GH_APP_TOKEN:", "GITHUB_APP_",
                              "secrets.", "gh release", "gh api", "gh workflow run"):
                self.assertNotIn(forbidden, job)
        self.assertIn("actions: read", blocks["reader"])
        self.assertEqual(text.count("GH_TOKEN:"), 1)
        self.assertIn("--role reader", blocks["reader"])
        self.assertIn("--role signer", blocks["signer_denied"])
        self.assertIn("--role writer", blocks["writer_denied"])
        self.assertNotIn("GH_TOKEN:", blocks["signer_denied"])
        self.assertNotIn("GH_TOKEN:", blocks["writer_denied"])

if __name__ == "__main__":
    main()
