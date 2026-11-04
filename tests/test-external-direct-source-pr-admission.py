#!/usr/bin/env python3
"""Offline hostile checks of the central source-specific PR-only Publisher job."""
import copy
from datetime import datetime, timezone, timedelta
import importlib.util
from pathlib import Path
import unittest
from urllib.error import HTTPError

spec = importlib.util.spec_from_file_location(
    "direct_publisher",
    Path(__file__).resolve().parents[1] / "scripts/external-direct-source-pr-admission.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
TOKEN = "synthetic-test-token-long-enough-to-validate"
HEAD = "a" * 40


class FakeAPI:
    def __init__(self, bad=None):
        self.bad = bad
        self.calls = []
        self.revoked = False

    def __call__(self, method, path, auth, body=None):
        self.calls.append((method, path))
        if path == "/repos/pgextwin/build/branches/main":
            return {"protected": self.bad != "unprotected",
                    "commit": {"sha": HEAD if self.bad != "wrong-head" else "b" * 40}}
        if path == "/repos/pgextwin/build/issues/comments/123456":
            return {"id": 123456, "body": mod.COMMAND,
                    "html_url": "https://github.com/pgextwin/build/issues/112#issuecomment-123456",
                    "user": {"login": "ShutenOishi"}}
        if path == "/repos/pgextwin/build/actions/runs/789":
            return {"id":789, "event":"issue_comment", "head_sha":HEAD,
                    "head_branch":"main", "run_attempt":1, "status":"in_progress",
                    "actor":{"login":"ShutenOishi"},
                    "triggering_actor":{"login":"ShutenOishi"},
                    "path":".github/workflows/publisher-candidate-intake.yml"}
        if path == "/app":
            return {"id": 15368 if self.bad == "wrong-app" else mod.APP,
                    "slug": mod.APP_SLUG}
        if path == f"/app/installations/{mod.INSTALL}":
            return {"id": mod.INSTALL, "app_id": mod.APP,
                    "repository_selection": "all" if self.bad == "all" else "selected",
                    "permissions": {**mod.PERMISSIONS,
                                    **({"actions": "write"} if self.bad == "overprivileged" else {})},
                    "account": {"login": "pgextwin"}, "suspended_at": None}
        if path == f"/app/installations/{mod.INSTALL}/access_tokens":
            if self.bad == "token-wrong-repo":
                raise mod.Denied("synthetic bad token")
            return {"token": TOKEN, "repository_selection": "selected",
                    "permissions": mod.PERMISSIONS,
                    "expires_at": (datetime.now(timezone.utc)+
                                   timedelta(minutes=30)).isoformat().replace("+00:00","Z")}
        if path == "/installation/repositories?per_page=100":
            if self.revoked:
                if self.bad != "token-still-live":
                    raise HTTPError("https://api.github.com", 403 if self.bad == "revoke-403"
                                    else 401, "revoked", {}, None)
            return {"total_count": 2 if self.bad == "two-repos" else 1,
                    "repositories": [{"full_name": "pgextwin/build"
                                      if self.bad == "other-repo" else mod.CATALOG,
                                      "id": 1405939279}]}
        if path == "/installation/token":
            self.revoked = True
            return {}
        if path == "/repos/pgextwin/catalog/branches/main":
            return {"protected": True, "commit": {"sha": HEAD}}
        if path == "/repos/pgextwin/catalog/git/refs":
            assert body == {"ref": "refs/heads/issue112-external-direct-pg18-aaaaaaaaaaaa",
                            "sha": HEAD}
            return {}
        if path == "/repos/pgextwin/catalog/contents/" + mod.TARGET_PATH:
            assert body["branch"] == "issue112-external-direct-pg18-aaaaaaaaaaaa"
            return {}
        if path == "/repos/pgextwin/catalog/pulls":
            assert body["base"] == "main" and not body["draft"]
            return {"number": 999, "head": {"ref": body["head"]},
                    "base": {"ref": "main"}}
        raise AssertionError("Unexpected API route " + method + " " + path)


def env():
    return {"GITHUB_EVENT_NAME": "issue_comment", "GITHUB_REPOSITORY": "pgextwin/build",
            "GITHUB_REF": "refs/heads/main", "GITHUB_ACTOR": "ShutenOishi",
            "GITHUB_TRIGGERING_ACTOR": "ShutenOishi", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": HEAD, "GITHUB_RUN_ID":"789",
            "GITHUB_TOKEN": "synthetic-read-only-token"}


def event():
    return {"action": "created", "repository": {"full_name": "pgextwin/build"},
            "sender": {"login": "ShutenOishi"}, "issue": {"number": 112},
            "comment": {"id": 123456, "body": mod.COMMAND,
                        "user": {"login": "ShutenOishi"}}}


class Tests(unittest.TestCase):
    def test_genuine_owner_requires_online_confirmation(self):
        api=FakeAPI()
        sha, n, run = mod.check_owner_event(env(),event(),api)
        self.assertEqual((sha,n,run),(HEAD,123456,789))
        self.assertIn(("GET","/repos/pgextwin/build/issues/comments/123456"),api.calls)

    def test_spoofed_schedule_replay_issue_or_owner_denied(self):
        for key,value in (("GITHUB_EVENT_NAME","schedule"),
                          ("GITHUB_EVENT_NAME","workflow_dispatch"),
                          ("GITHUB_REF","refs/heads/feature"),
                          ("GITHUB_RUN_ATTEMPT","2"),
                          ("GITHUB_ACTOR","attacker"),
                          ("GITHUB_TRIGGERING_ACTOR","attacker"),
                          ("GITHUB_SHA","f"),
                          ("GITHUB_RUN_ID","0")):
            with self.subTest(key=key,value=value):
                e=env()
                e[key]=value
                with self.assertRaises(mod.Denied):
                    mod.check_owner_event(e,event(),FakeAPI())
        for key,value in (("action","edited"),("sender",{"login":"attacker"}),
                          ("issue",{"number":311}),("repository",{"full_name":"attacker/build"})):
            with self.subTest(key=key):
                e=event()
                e[key]=value
                with self.assertRaises(mod.Denied):
                    mod.check_owner_event(env(),e,FakeAPI())
        for bad in ("unprotected","wrong-head"):
            with self.subTest(bad=bad),self.assertRaises(mod.Denied):
                mod.check_owner_event(env(),event(),FakeAPI(bad))

    def test_expanded_scope_or_malformed_app_denied_and_token_revoked(self):
        for bad in ("wrong-app","all","overprivileged",
                    "two-repos","other-repo","revoke-403","token-still-live"):
            with self.subTest(bad=bad):
                api=FakeAPI(bad)
                with self.assertRaises(mod.Denied):
                    with mod.scoped_catalog_token(api,lambda k,a:"synthetic-jwt",
                                                  "synthetic-private-key",sleep=lambda _:None):
                        pass
                self.assertFalse(any("/releases" in p for _,p in api.calls))
                if bad in ("two-repos","other-repo","revoke-403","token-still-live"):
                    self.assertTrue(api.revoked)

    def test_scoped_token_and_create_only_proposal(self):
        api=FakeAPI()
        with mod.scoped_catalog_token(api,lambda k,a:"synthetic-jwt",
                                      "synthetic-private-key",sleep=lambda _:None) as token:
            r=mod.create_protected_pr(api,token,source_sha=HEAD,payload=b"test")
        self.assertEqual(r["catalogPr"],999)
        self.assertFalse(r["downloadAuthorized"])
        self.assertTrue(api.revoked)
        self.assertEqual(api.calls[-2:],[
            ("DELETE","/installation/token"),
            ("GET","/installation/repositories?per_page=100")])
        writes={(m,p) for m,p in api.calls if m in ("POST","PUT","PATCH")}
        self.assertEqual(writes,{
            ("POST",f"/app/installations/{mod.INSTALL}/access_tokens"),
            ("POST","/repos/pgextwin/catalog/git/refs"),
            ("PUT","/repos/pgextwin/catalog/contents/"+mod.TARGET_PATH),
            ("POST","/repos/pgextwin/catalog/pulls"),
        })

    def test_release_ref_update_and_unapproved_file_never_write(self):
        for m,p in (("POST","/repos/pgextwin/catalog/releases"),
                    ("PATCH","/repos/pgextwin/catalog/git/refs/heads/main"),
                    ("POST","/repos/pgextwin/catalog/actions/workflows/publish.yml/dispatches"),
                    ("PUT","/repos/pgextwin/build/contents/README.md"),
                    ("DELETE","/repos/pgextwin/catalog/git/refs/heads/main")):
            with self.subTest(path=p),self.assertRaises(mod.Denied):
                mod.require_catalog_writer(m,p)

    def test_proposal_malformed_or_unsigned_source_denied(self):
        data={"catalogCommit":HEAD,"records":[{"sourceRepo":"laurenz/oracle_fdw",
            "releaseId":335861225, "assetId":442625860, "pgMajor":"18",
            "referenceLinkReviewed":True, "sourcePublisherAuthorized":False,
            "downloadAuthorized":False, "mirrorAuthorized":False,
            "originalProviderUrl":"https://github.com/laurenz/oracle_fdw/safe"}]}
        proofs=[{"sourceRepo":"laurenz/oracle_fdw","releaseId":335861225,
                 "assetId":442625860,"bytesVerified":True}]
        with self.assertRaises(mod.Denied):
            mod.proposal_bytes(data,proofs,HEAD,HEAD,123456,789)
        data["records"].append(dict(data["records"][0]))
        data["records"][0]["downloadAuthorized"]=True
        with self.assertRaises(mod.Denied):
            mod.proposal_bytes(data,proofs,HEAD,HEAD,123456,789)


if __name__=="__main__":
    unittest.main()
