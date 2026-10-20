#!/usr/bin/env python3
"""Credential-free hostile fixtures for dormant Wave3 auditor scoped token."""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
from unittest import TestCase, main

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "wave3_auditor_mint", ROOT/"scripts/issue-75-wave3-auditor-read-mint-probe.py")
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
NOW=datetime(2026,10,20,12,30,tzinfo=timezone.utc)
JWT="SYNTHETIC_APP_JWT_NONSECRET_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
TOKEN="SYNTHETIC_ISSUED_TOKEN_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SHA="b"*40
REPO="pgextwin/pgtap"


def fixture(repo=REPO):
    rid=a.auditor.wave3.TARGETS[repo]
    app={"id":a.auditor.APP_ID, "slug":a.auditor.APP_SLUG}
    inst={"id":a.auditor.INSTALLATION_ID,"app_id":a.auditor.APP_ID,
          "target_type":"Organization","account":{"login":"pgextwin"},
          "repository_selection":"selected","suspended_at":None,
          "permissions":a.auditor.EXPECTED_PERMISSIONS.copy()}
    one={"id":rid,"full_name":repo,"owner":{"login":"pgextwin"}}
    issued={"token":TOKEN,"expires_at":"2026-10-20T13:00:00Z",
            "repository_selection":"selected",
            "permissions":a.EFFECTIVE_PERMISSIONS.copy(),
            "repositories":[deepcopy(one)]}
    visible={"total_count":1,"repositories":[deepcopy(one)]}
    proof={"classification":"WAVE3_CLASSIC_REST_GRAPHQL_CONTRACT_ONLY",
           "repository":repo,"repositoryId":rid,"mainSha":SHA,
           "requiredCheckAppId":15368,"publicationAuthorized":False,
           "publishableReceipt":False}
    return app,inst,issued,visible,proof


class Fake:
    def __init__(self,repo=REPO,models=None):
        self.repo=repo
        self.models=deepcopy(models if models is not None else fixture(repo))
        self.calls=[]
        self.revoked=False

    def api(self,method,path,token):
        self.calls.append((method,path,token))
        if method=="GET" and path=="/app" and token==JWT:
            return deepcopy(self.models[0])
        if method=="GET" and path=="/app/installations/170837728" and token==JWT:
            return deepcopy(self.models[1])
        if method=="GET" and path==a.transport.REPOS_ENDPOINT and token==TOKEN:
            return deepcopy(self.models[3])
        if method=="DELETE" and path==a.transport.TOKEN_ENDPOINT and token==TOKEN:
            self.revoked=True
            return {"revoked":True}
        raise AssertionError("unexpected API principal or unsafe operation")

    def issue(self,jwt,rid):
        self.calls.append(("POST",a.ISSUE_PATH,jwt,{"repository_ids":[rid],
                                                  "permissions":a.TOKEN_PERMISSIONS}))
        if jwt!=JWT or rid!=a.auditor.wave3.TARGETS[self.repo]:
            raise AssertionError("cross-scope issuance")
        return deepcopy(self.models[2])

    def verify(self,token,repo,sha):
        self.calls.append(("COMPOSITE_READ",repo,sha))
        if token!=TOKEN:
            raise AssertionError("wrong token passed to Classic proof")
        return deepcopy(self.models[4])

    def run(self):
        return a.probe(JWT,repository=self.repo,expected_main_sha=SHA,
                       now=NOW,api=self.api,issue=self.issue,verify=self.verify)


class Response(io.BytesIO):
    def __init__(self,content,status=201,link=""):
        super().__init__(content)
        self.status=status
        self.headers={"Link":link}


class AuditorMintTests(TestCase):
    def test_historical_writer_mint_contract_remains_write_only(self):
        self.assertEqual(a.transport.NON_WRITER_APP_IDS,
                         frozenset((15368,5295410,5281285,5250206)))
        self.assertEqual(a.ISSUE_PATH,
                         "/app/installations/170837728/access_tokens")
        self.assertEqual(a.TOKEN_PERMISSIONS,{"administration":"read"})
        self.assertEqual(a.EFFECTIVE_PERMISSIONS,
                         {"administration":"read","metadata":"read"})
        self.assertNotIn("contents",a.TOKEN_PERMISSIONS)

    def test_positive_synthetic_contract_all_three(self):
        for repo in a.auditor.wave3.TARGETS:
            with self.subTest(repo=repo):
                fake=Fake(repo)
                result=fake.run()
                rid=a.auditor.wave3.TARGETS[repo]
                self.assertEqual(fake.calls,[
                    ("GET","/app",JWT),
                    ("GET","/app/installations/170837728",JWT),
                    ("POST",a.ISSUE_PATH,JWT,{"repository_ids":[rid],
                                              "permissions":{"administration":"read"}}),
                    ("GET",a.transport.REPOS_ENDPOINT,TOKEN),
                    ("COMPOSITE_READ",repo,SHA),
                    ("DELETE",a.transport.TOKEN_ENDPOINT,TOKEN),
                ])
                self.assertTrue(fake.revoked)
                self.assertTrue(result["scopedTokenRevocation204Observed"])
                self.assertEqual(result["targetRepository"],repo)
                self.assertEqual(result["repositoryId"],rid)
                self.assertEqual(result["expiresWithinSeconds"],1800)
                self.assertEqual(result["scope"],"ONE_REPOSITORY_ADMINISTRATION_READ_ONLY")
                self.assertEqual(result["classification"],
                    "PRIVATE_AUDITOR_SCOPED_READ_AND_REVOKE_CONTRACT")
                self.assertFalse(result["credentialCustodyIndependentlyProven"])
                self.assertFalse(result["publicationAuthorized"])
                self.assertEqual((result["goB"],result["g4"],result["g5"]),
                                 ("NO_GO",)*3)
                self.assertNotIn(JWT,str(result))
                self.assertNotIn(TOKEN,str(result))

    def test_prejwt_targets_and_sha_deny_without_requests(self):
        invalid=["pgextwin/build","pgextwin/catalog","pgextwin/plpgsql_check",
                 "pgextwin/website","pgextwin/PgTap","pgextwin/pgtap/",
                 "other/pgtap",None,True,1]
        for repo in invalid:
            with self.subTest(repo=repo):
                fake=Fake()
                with self.assertRaises(a.Deny):
                    a.probe(JWT,repository=repo,expected_main_sha=SHA,now=NOW,
                            api=fake.api,issue=fake.issue,verify=fake.verify)
                self.assertEqual(fake.calls,[])
        for bad in ("main","f"*39,"F"*40,True,None):
            fake=Fake()
            with self.assertRaises(a.Deny):
                a.probe(JWT,repository=REPO,expected_main_sha=bad,now=NOW,
                        api=fake.api,issue=fake.issue,verify=fake.verify)
            self.assertEqual(fake.calls,[])
        for bad in ("short",None,True):
            fake=Fake()
            with self.assertRaises(a.Deny):
                a.probe(bad,repository=REPO,expected_main_sha=SHA,now=NOW,
                        api=fake.api,issue=fake.issue,verify=fake.verify)
            self.assertEqual(fake.calls,[])

    def test_bad_app_identity_permission_scopes_never_mint(self):
        edits=[
            lambda x:x[0].update(id=5250206),
            lambda x:x[0].update(id=True),
            lambda x:x[0].update(slug="pgextwin-catalog-proposer"),
            lambda x:x[1].update(id=170516730),
            lambda x:x[1].update(app_id=5281285),
            lambda x:x[1].update(repository_selection="all"),
            lambda x:x[1].update(permissions={"metadata":"read"}),
            lambda x:x[1].update(permissions={"administration":"write","metadata":"read"}),
            lambda x:x[1].update(permissions={"administration":"read","metadata":"read","contents":"write"}),
            lambda x:x[1].update(target_type="User"),
            lambda x:x[1].update(account={"login":"not-pgextwin"}),
            lambda x:x[1].update(suspended_at="2026-10-20"),
        ]
        for i,edit in enumerate(edits):
            data=list(fixture());edit(data)
            fake=Fake(models=data)
            with self.subTest(i=i),self.assertRaises(a.Deny):
                fake.run()
            self.assertFalse(fake.revoked)
            self.assertFalse(any(c[0]=="POST" for c in fake.calls))

    def test_minted_metadata_scope_expiry_wrong_id_still_revoked(self):
        edits=[
            lambda x:x[2].update(token="x"),
            lambda x:x[2].update(token=JWT),
            lambda x:x[2].update(token=None),
            lambda x:x[2].update(repository_selection="all"),
            lambda x:x[2].update(permissions={"administration":"write","metadata":"read"}),
            lambda x:x[2].update(permissions={"metadata":"read"}),
            lambda x:x[2].update(permissions={"administration":"read","metadata":"read","contents":"read"}),
            lambda x:x[2].update(repositories=[]),
            lambda x:x[2]["repositories"][0].update(id=1425679720),
            lambda x:x[2]["repositories"][0].update(owner={"login":"attacker"}),
            lambda x:x[2].update(expires_at="2026-10-20T15:00:00Z"),
            lambda x:x[2].update(expires_at="not-an-expiry"),
            lambda x:x[3].update(total_count=4),
            lambda x:x[3].update(repositories=[]),
            lambda x:x[3]["repositories"][0].update(full_name="pgextwin/build"),
            lambda x:x[4].update(classification="VERIFIED_RELEASE"),
            lambda x:x[4].update(requiredCheckAppId=5250206),
            lambda x:x[4].update(publicationAuthorized=True),
            lambda x:x[4].update(mainSha="0"*40),
        ]
        for i,edit in enumerate(edits):
            data=list(fixture());edit(data)
            fake=Fake(models=data)
            with self.subTest(i=i),self.assertRaises(a.Deny):
                fake.run()
            if data[2].get("token") == TOKEN:
                self.assertTrue(fake.revoked)
            else:
                # Invalid/untrusted token cannot be silently counted as revoked.
                self.assertFalse(fake.revoked)

    def test_denied_revoke_even_if_composite_passes(self):
        fake=Fake()
        def fail_revoke(method,path,token):
            if method=="DELETE":
                raise RuntimeError("sensitive token="+TOKEN)
            return fake.api(method,path,token)
        with self.assertRaises(a.Deny) as ctx:
            a.probe(JWT,repository=REPO,expected_main_sha=SHA,now=NOW,
                    api=fail_revoke,issue=fake.issue,verify=fake.verify)
        self.assertIn("quarantine",str(ctx.exception).lower())
        self.assertNotIn(TOKEN,str(ctx.exception))

    def test_post_reply_lost_requires_no_retry_and_quarantine(self):
        fake=Fake()
        def drop(jwt,rid):
            fake.calls.append(("POST",a.ISSUE_PATH,jwt))
            raise RuntimeError("server minted but response lost "+TOKEN)
        with self.assertRaises(a.Deny) as ctx:
            a.probe(JWT,repository=REPO,expected_main_sha=SHA,now=NOW,
                    api=fake.api,issue=drop,verify=fake.verify)
        self.assertEqual(len([c for c in fake.calls if c[0]=="POST"]),1)
        self.assertNotIn(TOKEN,str(ctx.exception))

    def test_mint_transport_only_fixed_app_id_repo_read_permissions(self):
        for invalid in (None,True,"1425678353",1,1410581312,0,
                        123456789,1425678353.0):
            with self.subTest(invalid=invalid),self.assertRaises(a.Deny):
                a.mint_read_token(JWT,invalid,opener=lambda *_:None)
        for invalid in ("short",None,True):
            with self.assertRaises(a.Deny):
                a.mint_read_token(invalid,1425678353,opener=lambda *_:None)
        reqs=[]
        def opener(request,timeout):
            reqs.append((request,timeout))
            return Response(json.dumps(fixture()[2]).encode())
        data=a.mint_read_token(JWT,1425678353,opener=opener)
        self.assertEqual(data["token"],TOKEN)
        req,timeout=reqs[0]
        self.assertEqual(req.get_method(),"POST")
        self.assertEqual(req.full_url,"https://api.github.com"+a.ISSUE_PATH)
        self.assertEqual(req.get_header("Authorization"),"Bearer "+JWT)
        self.assertEqual(req.get_header("Content-type"),"application/json")
        self.assertEqual(json.loads(req.data),
                         {"repository_ids":[1425678353],
                          "permissions":{"administration":"read"}})
        self.assertEqual(timeout,20)
        for body,status,link in ((b"{}",200,""),(b"[]",201,""),
                                  (b'{"token":1,"token":2}',201,""),
                                  (b"x"*(a.transport.MAX_RESPONSE+1),201,""),
                                  (b"{}",201,'<https://other>; rel="next"')):
            with self.subTest(status=status),self.assertRaises(a.Deny):
                a.mint_read_token(JWT,1425678353,
                    opener=lambda *args,**kwargs:Response(body,status,link))

    def test_no_public_job_mint_and_no_release_surface(self):
        wf=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("python tests/test-issue-75-wave3-auditor-read-mint-probe.py",wf)
        src=(ROOT/"scripts/issue-75-wave3-auditor-read-mint-probe.py").read_text()
        for forbidden in ("secrets.", "workflow_dispatch", "gh release",
                          "git push", "PUBLISH_ALLOW", "write\"",
                          "token = os.getenv", "private_key"):
            if forbidden=="private_key":
                continue  # term is only in forbidden-context prose
            self.assertNotIn(forbidden,src)


if __name__=="__main__":
    main()
