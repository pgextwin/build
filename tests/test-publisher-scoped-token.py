#!/usr/bin/env python3
"""Hostile offline tests for Publisher App token lifecycle; NEVER mint live keys."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import importlib.util
from pathlib import Path
import unittest
from contextlib import redirect_stderr
from io import StringIO
from urllib.error import HTTPError
from unittest.mock import patch

path = Path(__file__).resolve().parents[1] / "scripts/publisher-scoped-token.py"
spec = importlib.util.spec_from_file_location("publisher_scoped_token", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
REPO = "pgextwin/plpgsql_check"
TOKEN = "synthetic-scoped-not-a-valid-GitHub-token"

def fixture():
    return {"schemaVersion": 1, "releasePolicy": "manual-only", "entries": [
        {"repository": REPO, "mode": "BUILD", "candidateEnabled": True,
         "releasePolicy": "manual-only"}]}

class FakeAPI:
    def __init__(self, bad=None):
        self.bad = bad
        self.calls = []
        self.revoked = False
        self.revocation_probes = 0
    def __call__(self, method, path, token, body=None):
        self.calls.append((method, path))
        if path == "/app":
            return {"id":15368 if self.bad=="signer" else 5451798,
                    "slug":"pgextwin-publisher"}
        if path == "/app/installations/174720074":
            return {"id":174720074, "app_id":5451798,
                    "account":{"login":"pgextwin"},
                    "repository_selection":"all",
                    "permissions":{"contents":"write","metadata":"read"},
                    "suspended_at":None}
        if path.endswith("/access_tokens"):
            if self.bad == "mint-failed":
                raise ValueError("mint unavailable")
            return {"token": TOKEN,
                    "repository_selection":"all" if self.bad=="all" else "selected",
                    "permissions":{"contents":"write","metadata":"read",
                                   **({"actions":"write"} if self.bad=="overbroad" else {})},
                    "expires_at":(datetime.now(timezone.utc) +
                                  timedelta(minutes=(-1 if self.bad=="expired" else 30))).isoformat().replace("+00:00","Z")}
        if path == "/installation/repositories?per_page=100":
            if self.revoked:
                self.revocation_probes += 1
            if self.revoked and self.bad != "revoke-still-live" and not (
                    self.bad == "revoke-delayed" and self.revocation_probes < 3):
                raise HTTPError("https://api.github.com", 403 if self.bad=="revoke-forbidden"
                                else 401, "invalid token", {}, None)
            return {"total_count":2 if self.bad=="two-repos" else 1,
                    "repositories":[{"full_name": "pgextwin/orafce"
                                     if self.bad=="wrong-repo" else REPO}]}
        if path == "/installation/token":
            if self.bad == "revoke-failed":
                raise PermissionError("revocation failed")
            self.revoked = True
            return {}
        raise AssertionError("unexpected API operation " + method + " " + path)

def args(api, repo=REPO, fleet=None):
    return {"api":api, "jwt":lambda key,app: "synthetic-JWT",
            "key":"synthetic-private-key",
            "app":5451798, "installation":174720074,
            "repository":repo, "fleet":fixture() if fleet is None else fleet}

class TokenLifecycleTests(unittest.TestCase):
    def test_one_repo_future_extension_and_revocation(self):
        api = FakeAPI()
        with mod.single_repository_token(**args(api)) as (token,minted,scope):
            self.assertEqual(token,TOKEN)
            self.assertEqual(scope["total_count"],1)
            self.assertEqual(minted["permissions"],{"contents":"write","metadata":"read"})
        self.assertEqual(api.calls[-2:], [
            ("DELETE","/installation/token"),
            ("GET","/installation/repositories?per_page=100")])
        self.assertEqual([v for v in api.calls if v[0]=="POST"],
                         [("POST","/app/installations/174720074/access_tokens")])
        fleet = fixture()
        fleet["entries"].append({**deepcopy(fleet["entries"][0]),
                                 "repository":"pgextwin/future_extension"})
        with mod.single_repository_token(**args(FakeAPI(),fleet=fleet)) as (token,_,__):
            self.assertEqual(token,TOKEN)

    def test_explicit_auto_mode_requires_exact_full_policy_and_revokes(self):
        fleet=fixture()
        fleet["releasePolicy"]="automatic-signed-schedule"
        fleet["entries"][0]["releasePolicy"]="automatic-signed-schedule"
        api=FakeAPI()
        with self.assertRaises(mod.Denied):
            with mod.single_repository_token(**args(api,fleet=fleet)):
                pass
        self.assertEqual(api.calls,[])
        with mod.single_repository_token(**args(api,fleet=fleet),
                                         release_policy="automatic-signed-schedule") as (token,_,__):
            self.assertEqual(token,TOKEN)
        self.assertEqual(api.calls[-2:], [
            ("DELETE","/installation/token"),
            ("GET","/installation/repositories?per_page=100")])
        with self.assertRaises(mod.Denied):
            with mod.single_repository_token(**args(FakeAPI(),fleet=fixture()),
                                             release_policy="automatic-signed-schedule"):
                pass
        with self.assertRaises(mod.Denied):
            with mod.single_repository_token(**args(FakeAPI(),fleet=fleet),
                                             release_policy="unknown"):
                pass

    def test_caller_failure_always_revokes(self):
        api=FakeAPI()
        with self.assertRaisesRegex(RuntimeError,"caller failed"):
            with mod.single_repository_token(**args(api)):
                raise RuntimeError("caller failed")
        self.assertEqual(api.calls[-2:], [
            ("DELETE","/installation/token"),
            ("GET","/installation/repositories?per_page=100")])

    def test_issuer_mismatch_prevents_token_mint(self):
        api=FakeAPI("signer")
        with self.assertRaises(mod.Denied):
            with mod.single_repository_token(**args(api)):
                pass
        self.assertFalse(any(c[0]=="POST" for c in api.calls))

    def test_overscope_expiry_and_missing_repo_fail_closed(self):
        for problem in ("all","overbroad","expired","two-repos","wrong-repo"):
            with self.subTest(problem=problem):
                api=FakeAPI(problem)
                with self.assertRaises(mod.Denied):
                    with mod.single_repository_token(**args(api)):
                        pass
                self.assertEqual(api.calls[-2:], [
                    ("DELETE","/installation/token"),
                    ("GET","/installation/repositories?per_page=100")])
        for member in ([],[{"repository":"pgextwin/orafce",
                            "mode":"BUILD","candidateEnabled":True,
                            "releasePolicy":"manual-only"}]):
            with self.assertRaises(mod.Denied):
                with mod.single_repository_token(**args(FakeAPI(),fleet={
                    "schemaVersion":1,"releasePolicy":"manual-only","entries":member})):
                    pass

    def test_revocation_requires_proof_token_is_no_longer_usable(self):
        for fault in ("revoke-still-live", "revoke-forbidden"):
            with self.subTest(fault=fault):
                api=FakeAPI(fault)
                stderr=StringIO()
                with redirect_stderr(stderr):
                    with self.assertRaises(mod.Denied):
                        with mod.single_repository_token(**args(api)):
                            pass
                marker=("PUBLISHER_REVOKE_PROBE_TOKEN_STILL_ACTIVE"
                        if fault=="revoke-still-live" else
                        "PUBLISHER_REVOKE_PROBE_HTTP_403")
                self.assertIn(marker,stderr.getvalue())
                self.assertNotIn(TOKEN,stderr.getvalue())
                self.assertTrue(api.revoked)
                if fault == "revoke-still-live":
                    self.assertEqual(api.revocation_probes, 4)
                else:
                    self.assertEqual(api.calls[-2:], [
                        ("DELETE","/installation/token"),
                        ("GET","/installation/repositories?per_page=100")])

    def test_revocation_propagation_retries_but_requires_actual_401(self):
        api = FakeAPI("revoke-delayed")
        with patch.object(mod.time, "sleep") as sleeper:
            with mod.single_repository_token(**args(api)):
                pass
        self.assertEqual(api.revocation_probes, 3)
        self.assertEqual(sleeper.call_count, 2)
        self.assertEqual(api.calls[-3:], [
            ("GET", "/installation/repositories?per_page=100")] * 3)

    def test_revocation_still_live_is_bounded_and_denied(self):
        api = FakeAPI("revoke-still-live")
        with patch.object(mod.time, "sleep") as sleeper:
            with self.assertRaises(mod.Denied):
                with mod.single_repository_token(**args(api)):
                    pass
        self.assertEqual(api.revocation_probes, 4)
        self.assertEqual(sleeper.call_count, 3)

    def test_revocation_error_not_suppressed(self):
        api=FakeAPI("revoke-failed")
        with self.assertRaises(PermissionError):
            with mod.single_repository_token(**args(api)) as (token,_,__):
                self.assertEqual(token,TOKEN)
        self.assertEqual(api.calls[-1],("DELETE","/installation/token"))

    def test_issuer_and_fleet_bad_values(self):
        for field,value in (("app",15368),("installation",1),
                            ("key",""),("app",True)):
            with self.subTest(field=field,value=value):
                a=args(FakeAPI())
                a[field]=value
                with self.assertRaises(mod.Denied):
                    with mod.single_repository_token(**a):
                        pass
        fleet=fixture()
        fleet["entries"].append(deepcopy(fleet["entries"][0]))
        with self.assertRaises(mod.Denied):
            with mod.single_repository_token(**args(FakeAPI(),fleet=fleet)):
                pass

if __name__=="__main__":
    unittest.main()
