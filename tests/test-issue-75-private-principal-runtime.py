#!/usr/bin/env python3
"""Hostile private runtime proof tests: mock success NEVER means live proof."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest import TestCase, main, mock

ROOT=Path(__file__).resolve().parents[1]
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

s=load("scripts/issue-75-private-signer-verify.py","private_signer")
w=load("scripts/issue-75-private-writer-app-probe.py","private_writer")
NOW=datetime(2026,10,18,6,0,tzinfo=timezone.utc)
JWT="SYNTHETIC_APP_JWT_NO_LOG_1234567890"
TOKEN="SYNTHETIC_INSTALLATION_TOKEN_NO_LOG_1234567890"
INSTALL=120000
APP=67890
RID=54321
EXP=(NOW+timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ")

class FakeApp:
    def __init__(self):
        self.calls=[]
        self.responses={
            ("GET","/app"):{"id":APP},
            ("GET",f"/app/installations/{INSTALL}"):{"id":INSTALL,"app_id":APP,
                "target_type":"Organization","account":{"login":"pgextwin"},
                "suspended_at":None,"permissions":{"contents":"write","metadata":"read"}},
            ("POST",f"/app/installations/{INSTALL}/access_tokens"):{"token":TOKEN,
                "expires_at":EXP,"permissions":{"contents":"write","metadata":"read"},
                "repository_selection":"selected",
                "repositories":[{"id":RID,"full_name":"pgextwin/plpgsql_check"}]},
            ("GET",w.REPOS_ENDPOINT):{"total_count":1,
                "repositories":[{"id":RID,"full_name":"pgextwin/plpgsql_check"}]},
            ("DELETE",w.TOKEN_ENDPOINT):{"revoked":True}}
    def __call__(self,method,path,credential,payload=None):
        self.calls.append((method,path,credential,payload))
        if (method,path) not in self.responses:
            raise RuntimeError("SYNTHETIC_APP_JWT_NO_LOG_1234567890")
        if method in ("GET","POST") and path != w.REPOS_ENDPOINT:
            assert credential == JWT
        if path == w.REPOS_ENDPOINT or method=="DELETE":
            assert credential == TOKEN
        return self.responses[(method,path)]

def run_writer(api):
    return w.probe(JWT,app_id=APP,installation_id=INSTALL,
                   repository_id=RID,now=NOW,api=api)

class PrivateProbes(TestCase):
    def test_crypto_command_pins_digest_issuer_workflow_and_ref(self):
        path=Path("/tmp/pgextwin-untrusted-file.zip")
        argv=s.command(path,packaging_sha="a"*40,predicate=s.preflight.PROVENANCE)
        self.assertEqual(len(argv),21)
        self.assertEqual(argv[:4],["gh","attestation","verify",str(path)])
        self.assertEqual(argv[argv.index("--signer-digest")+1],s.SIGNER_SHA)
        self.assertEqual(argv[argv.index("--signer-workflow")+1],s.SIGNER)
        self.assertEqual(argv[argv.index("--source-digest")+1],"a"*40)
        self.assertEqual(argv[argv.index("--source-ref")+1],"refs/heads/main")
        self.assertEqual(argv[argv.index("--cert-oidc-issuer")+1],s.ISSUER)
        self.assertIn("--deny-self-hosted-runners",argv)
        self.assertEqual(argv[-2:],["--format","json"])
        for sha,predicate in ((True,s.preflight.PROVENANCE),
                              ("f"*39,s.preflight.PROVENANCE),
                              ("a"*40,"untrusted-predicate")):
            with self.assertRaises(s.Deny):
                s.command(path,packaging_sha=sha,predicate=predicate)

    def test_crypto_transport_requires_actual_zero_exit_and_bounded_json(self):
        args=s.command(Path("/tmp/trusted.zip"),packaging_sha="a"*40,
                       predicate=s.preflight.SPDX)
        for outcome in (
            SimpleNamespace(returncode=1,stdout="{}"),
            SimpleNamespace(returncode=0,stdout=""),
            SimpleNamespace(returncode=0,stdout="x"*(s.MAX_ATTEST_STDOUT+1)),
            SimpleNamespace(returncode=True,stdout="{}"),
        ):
            with self.subTest(code=outcome.returncode,length=len(outcome.stdout)):
                with self.assertRaises(s.Deny):
                    s.invoke_crypto(args,runner=lambda *a,**k:outcome)
        with self.assertRaises(s.Deny):
            s.invoke_crypto(args,runner=lambda *a,**k:
                            (_ for _ in ()).throw(RuntimeError("PRIVATE_SECRET")))
        self.assertEqual(s.invoke_crypto(args,runner=lambda *a,**k:
                                         SimpleNamespace(returncode=0,stdout="[]")),"[]")

    def test_crypto_forged_verified_json_does_not_generate_go_or_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            zip_file=Path(folder)/"plpgsql_check-pg18-windows-x64.zip"
            sbom_file=Path(folder)/"test.spdx.json"
            zip_file.write_bytes(b"synthetic ZIP, not genuine")
            sbom_file.write_text('{"spdxVersion":"SPDX-2.3"}')
            calls=[]
            def runner(argv,**kwargs):
                calls.append(argv)
                return SimpleNamespace(returncode=0,stdout=json.dumps([
                    {"verificationResult":{"statement":{"predicateType":
                        s.preflight.PROVENANCE},"signature":{"certificate":{
                        "issuer":s.ISSUER}}}}]))
            with self.assertRaises(s.Deny):
                s.verify_pair(zip_file,sbom_file,packaging_sha="a"*40,
                              run_id=12345,attempt=1,gh_runner=runner)
            self.assertEqual(len(calls),1)
            for issue in (0,True,"1",2):
                with self.assertRaises(s.Deny):
                    s.verify_pair(zip_file,sbom_file,packaging_sha="a"*40,
                                  run_id=12345,attempt=issue,gh_runner=runner)
        self.assertNotIn("publicationAuthorized\": true",str(calls))

    def test_runtime_signer_has_no_authorizing_entrypoint(self):
        raw=(ROOT/"scripts/issue-75-private-signer-verify.py").read_text()
        self.assertNotIn("if __name__ ==",raw)
        for forbidden in ("gh release", "gh workflow run", "git push",
                          "create-github-app-token", "secrets."):
            self.assertNotIn(forbidden,raw)

    def test_private_app_token_mint_scope_then_revoke_contract(self):
        fake=FakeApp()
        out=run_writer(fake)
        self.assertEqual(out["classification"],"PRIVATE_APP_SCOPED_MINT_AND_REVOKE_CONTRACT")
        self.assertFalse(out["publicationAuthorized"])
        self.assertFalse(out["independentReaderSignerCustodyProven"])
        self.assertEqual(out["goB"],"NO_GO")
        self.assertEqual(out["g4"],"NO_GO")
        self.assertEqual(out["g5"],"NO_GO")
        self.assertNotIn(TOKEN,json.dumps(out))
        self.assertNotIn(JWT,json.dumps(out))
        self.assertEqual([v[0] for v in fake.calls],["GET","GET","POST","GET","DELETE"])
        self.assertEqual(fake.calls[2][3],{"repository_ids":[RID],
                                          "permissions":{"contents":"write"}})
        self.assertEqual(fake.calls[-1][2],TOKEN)

    def test_app_issuer_installation_and_repo_mismatch_denied(self):
        changes=(
            (("GET","/app"),"id",APP+1),
            (("GET",f"/app/installations/{INSTALL}"),"id",INSTALL+1),
            (("GET",f"/app/installations/{INSTALL}"),"app_id",APP+1),
            (("GET",f"/app/installations/{INSTALL}"),"target_type","User"),
            (("GET",f"/app/installations/{INSTALL}"),"suspended_at","2026-10-18T06:00:00Z"),
            (("GET",f"/app/installations/{INSTALL}"),"permissions",{"contents":"read"}),
            (("POST",f"/app/installations/{INSTALL}/access_tokens"),"token",JWT),
            (("POST",f"/app/installations/{INSTALL}/access_tokens"),"token",""),
            (("POST",f"/app/installations/{INSTALL}/access_tokens"),"repository_selection","all"),
            (("POST",f"/app/installations/{INSTALL}/access_tokens"),"permissions",
             {"contents":"write","actions":"write"}),
            (("POST",f"/app/installations/{INSTALL}/access_tokens"),"permissions",
             {"contents":"read"}),
            (("GET",w.REPOS_ENDPOINT),"total_count",2),
        )
        for key,field,value in changes:
            with self.subTest(key=key,field=field):
                f=FakeApp()
                f.responses[key][field]=value
                with self.assertRaises(w.Deny):run_writer(f)

    def test_writer_expiry_early_late_invalid_and_replay_denied(self):
        bad=[
            (NOW-timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            (NOW+timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            (NOW+timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "2026-10-18 06:45:00",
            True,
            None,
        ]
        for expiry in bad:
            with self.subTest(expiry=expiry):
                f=FakeApp()
                f.responses[("POST",f"/app/installations/{INSTALL}/access_tokens")]["expires_at"]=expiry
                with self.assertRaises(w.Deny):run_writer(f)
        for i in (True,-1,0,"1"):
            with self.assertRaises(w.Deny):
                w.probe(JWT,app_id=i,installation_id=INSTALL,
                        repository_id=RID,now=NOW,api=FakeApp())

    def test_wrong_repository_or_extra_access_and_pagination_denied(self):
        for kind in ("mint_repo","mint_many","get_repo","get_many","mismatch_owner"):
            fake=FakeApp()
            if kind=="mint_repo":
                fake.responses[("POST",f"/app/installations/{INSTALL}/access_tokens")]["repositories"][0]["id"]+=1
            if kind=="mint_many":
                fake.responses[("POST",f"/app/installations/{INSTALL}/access_tokens")]["repositories"].append({"id":9})
            if kind=="get_repo":
                fake.responses[("GET",w.REPOS_ENDPOINT)]["repositories"][0]["full_name"]="pgextwin/catalog"
            if kind=="get_many":
                fake.responses[("GET",w.REPOS_ENDPOINT)]["repositories"].append({"id":9})
            if kind=="mismatch_owner":
                fake.responses[("GET",f"/app/installations/{INSTALL}")]["account"]["login"]="attacker"
            with self.subTest(kind=kind):
                with self.assertRaises(w.Deny):run_writer(fake)

    def test_failed_revoke_or_failed_issuer_probe_never_returns_success(self):
        f=FakeApp()
        f.responses[("DELETE",w.TOKEN_ENDPOINT)]={"revoked":False}
        with self.assertRaises(w.Deny):run_writer(f)
        f=FakeApp()
        f.responses[("DELETE",w.TOKEN_ENDPOINT)]=None
        with self.assertRaises(w.Deny):run_writer(f)
        f=FakeApp()
        f.responses.pop(("GET","/app"))
        with self.assertRaises(w.Deny):run_writer(f)
        self.assertEqual(len(f.calls),1)

    def test_writer_api_strict_endpoint_and_redirect_with_zero_transport(self):
        for method,path in (
            ("PUT","/releases"),("POST","/repos/pgextwin/plpgsql_check/releases"),
            ("GET","/repos/pgextwin/plpgsql_check/releases"),
            ("POST","/app/installations/1/access_tokens/other"),
            ("POST","/app/installations/0/access_tokens"),
            ("GET","/app/installations/0"),
            ("GET","https://attacker.invalid"),
            ("DELETE","/repos/pgextwin/plpgsql_check/git/refs"),
        ):
            with self.subTest(method=method,path=path):
                with self.assertRaises(w.Deny):w.permitted(method,path)
        with self.assertRaises(w.Deny):
            w.NoRedirect().redirect_request(None,None,302,"",{},
                                             "https://attacker.invalid")
        with self.assertRaises(w.Deny):
            w.unique([("token","one"),("token","two")])
        with self.assertRaises(w.Deny):
            w.authenticated_call("GET","/app",JWT,
                                 opener=lambda *args,**kw:
                                 (_ for _ in ()).throw(RuntimeError(TOKEN)))

    def test_no_live_job_secrets_or_write_in_public_ci(self):
        validate=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("tests/test-issue-75-private-principal-runtime.py",validate)
        self.assertNotIn("issue-75-private-writer-app-probe.py --mode",validate)
        self.assertNotIn("issue-75-private-signer-verify.py --mode",validate)
        for fname in ("scripts/issue-75-private-signer-verify.py",
                      "scripts/issue-75-private-writer-app-probe.py"):
            text=(ROOT/fname).read_text()
            self.assertNotIn("if __name__ ==",text)
            self.assertNotIn("gh release",text)
            self.assertNotIn("workflow_dispatch:",text)

if __name__=="__main__":
    main()
