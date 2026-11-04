#!/usr/bin/env python3
"""Offline hostile source, identity, scoped token and revocation proofs."""
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
from io import StringIO
from pathlib import Path
import unittest
from urllib.error import HTTPError

_spec = importlib.util.spec_from_file_location(
    "external_probe", Path(__file__).resolve().parents[1]
    / "scripts/probe-external-direct-provider-app.py")
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)

TOKEN = "synthetic-not-an-actual-app-installation-token"
SHA = "a" * 40


class FakeApi:
    def __init__(self, bad=None):
        self.bad = bad
        self.calls = []
        self.revoked = False

    def __call__(self, method, path, token, body=None):
        self.calls.append((method, path))
        if path == "/repos/pgextwin/build/branches/main":
            return {"protected": self.bad != "unprotected",
                    "commit": {"sha": "b" * 40 if self.bad == "stale" else SHA}}
        if path == "/app":
            return {"id": 15368 if self.bad == "wrong-app" else probe.APP_ID,
                    "slug": probe.APP_SLUG}
        if path == "/app/installations/" + str(probe.INSTALLATION_ID):
            return {"id": probe.INSTALLATION_ID, "app_id": probe.APP_ID,
                    "repository_selection": "all" if self.bad == "all" else "selected",
                    "permissions": {**probe.PERMISSIONS,
                                    **({"actions": "write"} if self.bad == "permissions" else {})},
                    "account": {"login": "pgextwin"}, "suspended_at": None}
        if path.endswith("/access_tokens"):
            assert body == {"repositories": ["catalog"], "permissions": probe.PERMISSIONS}
            return {"token": TOKEN, "repository_selection": "selected",
                    "permissions": probe.PERMISSIONS,
                    "expires_at": (datetime.now(timezone.utc) +
                                   timedelta(minutes=30)).isoformat().replace("+00:00", "Z")}
        if path == "/installation/repositories?per_page=100":
            if self.revoked:
                if self.bad != "unrevoked":
                    raise HTTPError("https://api.github.com", 403 if self.bad == "403"
                                    else 401, "revoked", {}, None)
            return {"total_count": 2 if self.bad == "extra-repo" else 1,
                    "repositories": [{"full_name": "pgextwin/build"
                                      if self.bad == "wrong-repo" else probe.TARGET_REPO,
                                      "id": probe.TARGET_REPO_ID}]}
        if path == "/repos/pgextwin/catalog/git/blobs":
            import base64
            content = base64.b64decode(body["content"])
            expected = hashlib.sha1(b"blob " + str(len(content)).encode()
                                    + b"\0" + content).hexdigest()
            return {"sha": "f" * 40 if self.bad == "blob" else expected}
        if path == "/installation/token":
            self.revoked = True
            return {}
        raise AssertionError("unexpected path: " + path)


def env(**edits):
    data = {"GITHUB_REPOSITORY": "pgextwin/build", "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": SHA, "GITHUB_TOKEN": "synthetic-github-read",
            "EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY": "synthetic-private-key"}
    data.update(edits)
    return data


class Tests(unittest.TestCase):
    def call(self, bad=None, **edits):
        api = FakeApi(bad)
        output = StringIO()
        with contextlib.redirect_stdout(output):
            if bad or edits:
                with self.assertRaises(probe.Denied):
                    probe.verify(api, lambda key, app: "synthetic-app-jwt",
                                 env(**edits), sleep=lambda _: None)
                result = None
            else:
                result = probe.verify(api, lambda key, app: "synthetic-app-jwt",
                                      env(), sleep=lambda _: None)
        self.assertNotIn(TOKEN, output.getvalue())
        self.assertNotIn("synthetic-private-key", output.getvalue())
        return api, result

    def test_exact_source_identity_one_catalog_and_revocation(self):
        api, receipt = self.call()
        self.assertFalse(receipt["publicationAuthorized"])
        self.assertTrue(receipt["tokenRevokedAnd401Confirmed"])
        self.assertEqual(receipt["permissions"], probe.PERMISSIONS)
        self.assertEqual(api.calls[-2:], [
            ("DELETE", "/installation/token"),
            ("GET", "/installation/repositories?per_page=100")])
        self.assertEqual([path for method, path in api.calls
                          if method == "POST" and path.endswith("/git/blobs")],
                         ["/repos/pgextwin/catalog/git/blobs"])
        self.assertFalse(any("/releases" in p or "/refs" in p or "/pulls" in p
                             for _, p in api.calls))

    def test_identity_scope_write_and_revoke_hostile(self):
        for problem in ("unprotected", "stale", "wrong-app", "all",
                        "permissions", "extra-repo", "wrong-repo",
                        "blob", "403", "unrevoked"):
            with self.subTest(problem=problem):
                api, _ = self.call(problem)
                if problem in ("blob", "403", "unrevoked"):
                    self.assertTrue(api.revoked)
                if problem in ("wrong-app", "all", "permissions", "unprotected", "stale"):
                    self.assertFalse(any(path.endswith("/access_tokens")
                                         for _, path in api.calls))
                self.assertFalse(any("/releases" in p for _, p in api.calls))

    def test_spoofed_push_or_replay_denied_without_private_key(self):
        for field, value in (("GITHUB_REPOSITORY", "pgextwin/catalog"),
                             ("GITHUB_REF", "refs/heads/feature"),
                             ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                             ("GITHUB_EVENT_NAME", "pull_request"),
                             ("GITHUB_RUN_ATTEMPT", "2"),
                             ("GITHUB_SHA", "invalid"),
                             ("GITHUB_TOKEN", "")):
            with self.subTest(field=field, value=value):
                api, _ = self.call(None, **{field: value})
                self.assertFalse(any("/app" == path for _, path in api.calls))


if __name__ == "__main__":
    unittest.main()
