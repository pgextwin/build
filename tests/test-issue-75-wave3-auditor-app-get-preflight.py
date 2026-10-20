#!/usr/bin/env python3
"""Adversarial GET-only auditor App identity contracts; synthetic, no secrets."""
from __future__ import annotations
from copy import deepcopy
import importlib.util
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "issue75_auditor_get", ROOT / "scripts/issue-75-wave3-auditor-app-get-preflight.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
JWT = "SYNTHETIC_APP_JWT_NEVER_PRINT_1234567890"
TOKEN = "SYNTHETIC_APP_INSTALLATION_TOKEN_NEVER_PRINT_1234567890"

def fixture():
    return [
        {"id": a.APP_ID, "slug": a.APP_SLUG},
        {"id": a.INSTALLATION_ID, "app_id": a.APP_ID,
         "target_type": "Organization", "account": {"login": "pgextwin"},
         "repository_selection": "selected", "suspended_at": None,
         "permissions": a.EXPECTED_PERMISSIONS.copy()},
        {"total_count": 4, "repositories": [
            {"id": ident, "full_name": repo, "owner": {"login": "pgextwin"}}
            for repo,ident in sorted(a.EXPECTED.items())]},
    ]

class Fake:
    def __init__(self, values=None):
        self.values=deepcopy(values if values is not None else fixture())
        self.calls=[]

    def __call__(self, method, path, credential):
        self.calls.append((method,path,credential))
        assert method=="GET" and len(self.calls)<=3
        return deepcopy(self.values[len(self.calls)-1])

class AuditAppContracts(TestCase):
    def test_explicit_four_identity_pins_existing_pilot_kept(self):
        self.assertEqual(a.APP_ID,5295410)
        self.assertEqual(a.INSTALLATION_ID,170837728)
        self.assertEqual(a.APP_SLUG,"pgextwin-classic-protection-audit")
        self.assertEqual(a.EXPECTED, {
            "pgextwin/plpgsql_check":1410581312,
            "pgextwin/pgtap":1425678353,
            "pgextwin/pg_variables":1425679720,
            "pgextwin/pg_store_plans":1425680909})
        self.assertEqual(a.EXPECTED_PERMISSIONS,
                         {"administration":"read","metadata":"read"})
        self.assertEqual(a.writer.NON_WRITER_APP_IDS,
                         frozenset((15368,5295410,5281285,5250206)))

    def test_all_four_exact_get_only_requests_no_privilege_claim(self):
        fake=Fake()
        output=a.preflight(JWT,TOKEN,api=fake)
        self.assertEqual(fake.calls,[
            ("GET","/app",JWT),
            ("GET","/app/installations/170837728",JWT),
            ("GET","/installation/repositories?per_page=100&page=1",TOKEN)])
        self.assertEqual(output["expectedRepositoryIds"],a.EXPECTED)
        self.assertEqual(output["classification"],
                         "AUDITOR_APP_AND_TOKEN_SCOPE_GET_CONTRACT_ONLY")
        for field in ("mintOrRevokePerformed","externalTokenBoundToJwtIssuer",
                      "independentHostCredentialIsolationProven",
                      "wave3EffectiveClassicProtectionProven","publicationAuthorized"):
            self.assertIs(output[field],False)
        self.assertTrue(output["readOnlyTransport"])
        self.assertEqual((output["goB"],output["g4"],output["g5"]),
                         ("NO_GO",)*3)
        self.assertNotIn(JWT,str(output))
        self.assertNotIn(TOKEN,str(output))

    def test_invalid_jwt_and_install_token_denied_without_get(self):
        for jwt,token in ((JWT,JWT),("",TOKEN),(JWT,""),
                          (None,TOKEN),(JWT,True),
                          ("too-short",TOKEN),(JWT,"short"),(True,TOKEN)):
            with self.subTest(jwt=type(jwt),token=type(token)):
                fake=Fake()
                with self.assertRaises(a.Deny):
                    a.preflight(jwt,token,api=fake)
                self.assertEqual(fake.calls,[])

    def test_app_identity_and_permissions_fail_closed(self):
        edits=[
            lambda x:x[0].update(id=5281285),
            lambda x:x[0].update(id=True),
            lambda x:x[0].update(slug="pgextwin-catalog-proposer"),
            lambda x:x[0].pop("slug"),
            lambda x:x[1].update(id=170516730),
            lambda x:x[1].update(app_id=5250206),
            lambda x:x[1].update(app_id=True),
            lambda x:x[1].update(target_type="User"),
            lambda x:x[1].update(account={"login":"attacker"}),
            lambda x:x[1].update(repository_selection="all"),
            lambda x:x[1].update(suspended_at="2026-10-20T00:00:00Z"),
            lambda x:x[1].update(permissions={"metadata":"read"}),
            lambda x:x[1].update(permissions={"contents":"write","metadata":"read"}),
            lambda x:x[1].update(permissions={"administration":"write","metadata":"read"}),
            lambda x:x[1].update(permissions={"administration":"read","metadata":"read","issues":"read"}),
            lambda x:x[1].update(permissions=None),
        ]
        for index,edit in enumerate(edits):
            item=fixture()
            edit(item)
            with self.subTest(index=index),self.assertRaises(a.Deny):
                a.preflight(JWT,TOKEN,api=Fake(item))

    def test_repository_scope_missing_extra_swapped_or_overbroad_denied(self):
        edits=[
            lambda x:x[2].update(total_count=3),
            lambda x:x[2].update(total_count=True),
            lambda x:x[2].update(total_count=5),
            lambda x:x[2]["repositories"].pop(),
            lambda x:x[2]["repositories"].append(
                {"id":12,"full_name":"pgextwin/build","owner":{"login":"pgextwin"}}),
            lambda x:x[2]["repositories"][0].update(id=0),
            lambda x:x[2]["repositories"][0].update(id=True),
            lambda x:x[2]["repositories"][0].update(
                full_name="pgextwin/catalog"),
            lambda x:x[2]["repositories"][0].update(
                owner={"login":"attacker"}),
            lambda x:x[2]["repositories"][0].update(
                full_name="pgextwin/pg_variables"),
            lambda x:x[2].update(repositories=None),
            lambda x:x[2].update(repositories={}),
            lambda x:x[2]["repositories"][0].pop("id"),
            lambda x:x[2]["repositories"].__setitem__(
                1,deepcopy(x[2]["repositories"][0])),
        ]
        for index,edit in enumerate(edits):
            item=fixture()
            edit(item)
            with self.subTest(index=index),self.assertRaises(a.Deny):
                a.preflight(JWT,TOKEN,api=Fake(item))
        # The *actual* current Work GUI observation: selected pilot only.
        pilot=fixture()
        pilot[2]["total_count"]=1
        pilot[2]["repositories"]=[
            {"id":1410581312,"full_name":"pgextwin/plpgsql_check",
             "owner":{"login":"pgextwin"}}]
        with self.assertRaises(a.Deny):
            a.preflight(JWT,TOKEN,api=Fake(pilot))

    def test_http_failures_hide_sensitive_values(self):
        for stage in (1,2,3):
            fake=Fake()
            def failing(method,path,credential):
                if len(fake.calls)==stage-1:
                    raise RuntimeError(JWT+" "+TOKEN+" SERVER_FAIL")
                return fake(method,path,credential)
            with self.assertRaises(a.Deny) as ctx:
                a.preflight(JWT,TOKEN,api=failing)
            for secret in (JWT,TOKEN,"SERVER_FAIL"):
                self.assertNotIn(secret,str(ctx.exception))

    def test_no_unsafe_production_wiring(self):
        source=(ROOT/"scripts/issue-75-wave3-auditor-app-get-preflight.py").read_text()
        for bad in ("secrets.","gh release","workflow_dispatch",
                    "create-github-app-token@","access_tokens","DELETE",
                    "github.token","git push"):
            self.assertNotIn(bad,source)
        wf=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("python tests/test-issue-75-wave3-auditor-app-get-preflight.py",wf)

if __name__=="__main__":
    main()
