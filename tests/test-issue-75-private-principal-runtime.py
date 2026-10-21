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
RID=1410581312  # actual plpgsql_check immutable GitHub repo ID
EXP=(NOW+timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ")

class FakeApp:
    def __init__(self):
        self.calls=[]
        self.responses={
            ("GET","/app"):{"id":APP},
            ("GET",f"/app/installations/{INSTALL}"):{"id":INSTALL,"app_id":APP,
                "target_type":"Organization","account":{"login":"pgextwin"},
                "repository_selection":"selected",
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

    def test_four_original_signer_caller_targets_are_exact_and_fail_closed(self):
        self.assertEqual(s.TARGET_REPOSITORIES, {
            "pgextwin/plpgsql_check", "pgextwin/pgtap",
            "pgextwin/pg_variables", "pgextwin/pg_store_plans",
        })
        observed_refs={
            "plpgsql_check":"v2.10.15",
            "pgtap":"v1.3.4",
            "pg_variables":"v1.2.1",
            "pg_store_plans":"1.10",
        }
        for repo in sorted(s.TARGET_REPOSITORIES):
            ref=observed_refs[repo.split("/")[1]]
            path=Path("/tmp/" + repo.split("/")[1] + "-" + ref + "-pg18-windows-x64.zip")
            self.assertIsNotNone(s.ASSET_NAME.fullmatch(path.name))
            cmd=s.command(path,packaging_sha="a"*40,
                          predicate=s.preflight.SPDX,repository=repo)
            self.assertEqual(cmd[cmd.index("--repo")+1],repo)
            self.assertEqual(cmd[cmd.index("--signer-digest")+1],s.SIGNER_SHA)
            self.assertEqual(cmd[cmd.index("--cert-oidc-issuer")+1],s.ISSUER)
        for bad in ("pgextwin/catalog", "pgextwin/build", "pgextwin/website",
                    "pgextwin/PgTap", "attacker/pgtap", "", None, True):
            with self.subTest(repo=bad),self.assertRaises(s.Deny):
                s.command(Path("/tmp/test.zip"),packaging_sha="a"*40,
                          predicate=s.preflight.SPDX,repository=bad)

    def test_wave3_cross_repo_zip_spdx_and_pg_binding_rejected_before_crypto(self):
        for repo in ("pgextwin/pgtap", "pgextwin/pg_variables",
                     "pgextwin/pg_store_plans"):
            with self.subTest(repo=repo), tempfile.TemporaryDirectory() as folder:
                ext=repo.split("/")[1]
                ref={"pgtap":"v1.3.4",
                     "pg_variables":"v1.2.1",
                     "pg_store_plans":"1.10"}[ext]
                good=Path(folder)/(ext+"-"+ref+"-pg18-windows-x64.zip")
                sbom=Path(folder)/(ext+"-"+ref+"-pg18-windows-x64.spdx.json")
                good.write_bytes(b"synthetic unsigned ZIP")
                sbom.write_text('{"spdxVersion":"SPDX-2.3"}')
                invoked=[]
                def should_not_run(*args,**kwargs):
                    invoked.append(True)
                    self.fail("cross-asset mismatch reached credentialed verifier")
                foreign=Path(folder)/("other-v1.2.3-pg18-windows-x64.zip")
                wrong_ver=Path(folder)/(ext+"-v9.9-pg18-windows-x64.spdx.json")
                wrong_major=Path(folder)/(ext+"-"+ref+"-pg17-windows-x64.spdx.json")
                pg19=Path(folder)/(ext+"-"+ref+"-pg19-windows-x64.zip")
                foreign.write_bytes(b"wrong extension")
                wrong_ver.write_text('{"spdxVersion":"SPDX-2.3"}')
                wrong_major.write_text('{"spdxVersion":"SPDX-2.3"}')
                pg19.write_bytes(b"unsupported major")
                bad_names=[
                    ("pgextwin/plpgsql_check",good,sbom),
                    (repo,foreign,sbom),
                    (repo,good,wrong_ver),
                    (repo,good,wrong_major),
                    (repo,pg19,sbom),
                ]
                for target,z,sp in bad_names:
                    with self.subTest(target=target,zip=z.name,sbom=sp.name):
                        with self.assertRaises(s.Deny):
                            s.verify_pair(z,sp,packaging_sha="a"*40,
                                          run_id=12345,attempt=1,
                                          repository=target,gh_runner=should_not_run)
                self.assertEqual(invoked,[])
                # The exact pair advances to an independent gh crypto call,
                # whose mocked zero-exit forged JSON is still denied.
                forged=[]
                def forged_verify(argv,**kwargs):
                    forged.append(argv)
                    return SimpleNamespace(returncode=0,stdout="[]")
                with self.assertRaises(s.Deny):
                    s.verify_pair(good,sbom,packaging_sha="a"*40,
                                  run_id=12345,attempt=1,
                                  repository=repo,gh_runner=forged_verify)
                self.assertEqual(len(forged),1)
                self.assertEqual(forged[0][forged[0].index("--repo")+1],repo)

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
            sbom_file=Path(folder)/"plpgsql_check-pg18-windows-x64.spdx.json"
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
        self.assertTrue(out["scopedTokenRevocation204Observed"])
        self.assertFalse(out["positivePublisherPrewriteAuthorized"])
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
            (("GET",f"/app/installations/{INSTALL}"),"permissions",{"contents":"write","metadata":"read","issues":"write"}),
            (("GET",f"/app/installations/{INSTALL}"),"repository_selection","all"),
            (("GET",f"/app/installations/{INSTALL}"),"repository_selection",None),
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

    def test_known_unapproved_gui_apps_are_not_writer_before_any_network(self):
        # Real owned App IDs were observed in the authorized Work GUI audit;
        # neither the installed auditor/proposer nor the dormant dispatcher
        # has an approved independent Wave3 Writer identity today.
        self.assertEqual(w.NON_WRITER_APP_IDS,
                         frozenset((15368,5295410,5281285,5250206)))
        for app_id in (*sorted(w.NON_WRITER_APP_IDS),True,0,-1):
            with self.subTest(app_id=app_id):
                f=FakeApp()
                with self.assertRaises(w.Deny):
                    w.probe(JWT,app_id=app_id,installation_id=INSTALL,
                            repository_id=RID,now=NOW,api=f)
                self.assertEqual(f.calls,[])  # no JWT GET / token POST
        for repository in sorted(w.WAVE3_REPOS):
            # A correct Wave3 target ID does not override the deny list.
            with self.subTest(repository=repository):
                f=FakeApp()
                with self.assertRaises(w.Deny):
                    w.probe(JWT,app_id=5250206,installation_id=INSTALL,
                            repository_id=w.TARGET_REPO_IDS[repository],
                            now=NOW,repository=repository,api=f)
                self.assertEqual(f.calls,[])

    def test_writer_lifetime_bounds_and_revoke_failure_cannot_pass(self):
        mint=("POST",f"/app/installations/{INSTALL}/access_tokens")
        for seconds in (30,31,3599,3600,3601,7200):
            f=FakeApp()
            f.responses[mint]["expires_at"]=(
                NOW+timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
            with self.subTest(ttl_seconds=seconds):
                if 30 < seconds <= 3600:
                    out=run_writer(f)
                    self.assertTrue(out["scopedTokenRevocation204Observed"])
                    self.assertEqual(out["expiresWithinSeconds"],seconds)
                else:
                    with self.assertRaises(w.Deny):
                        run_writer(f)
                self.assertEqual(f.calls[-1][0],"DELETE")
        for broken in ("lost-delete","revoke-not-ack"):
            f=FakeApp()
            if broken=="lost-delete":
                del f.responses[("DELETE",w.TOKEN_ENDPOINT)]
            else:
                f.responses[("DELETE",w.TOKEN_ENDPOINT)]={"revoked":False}
            with self.subTest(kind=broken), self.assertRaises(w.Deny):
                run_writer(f)
            self.assertEqual(f.calls[-1][0],"DELETE")
            self.assertEqual(f.calls[-1][2],TOKEN)

    def test_app_mint_ambiguous_response_is_not_retried(self):
        mint=("POST",f"/app/installations/{INSTALL}/access_tokens")
        for mode in ("lost-response","malformed-response","missing-token"):
            f=FakeApp()
            if mode=="lost-response":
                del f.responses[mint]
            elif mode=="malformed-response":
                f.responses[mint]="untrusted-response"
            else:
                f.responses[mint]={"repository_selection":"selected"}
            with self.subTest(mode=mode), self.assertRaises(w.Deny):
                run_writer(f)
            self.assertEqual([method for method,*_ in f.calls].count("POST"),1)
            self.assertNotIn("publicationAuthorized",json.dumps(f.calls[-1][3]))
            # A lost token response cannot be revoked by token value; record
            # as unknown. This test does not turn a lost POST into permission.
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

    def test_wave_three_independent_writer_scope_is_explicit_and_single_repo(self):
        # Entirely synthetic: each target must be bound to BOTH authenticated
        # mint evidence and token-scoped /installation/repositories response.
        mint=("POST",f"/app/installations/{INSTALL}/access_tokens")
        listing=("GET",w.REPOS_ENDPOINT)
        self.assertEqual(w.WAVE3_REPOS, {
            "pgextwin/pgtap", "pgextwin/pg_variables",
            "pgextwin/pg_store_plans",
        })
        for target in sorted(w.WAVE3_REPOS):
            with self.subTest(target=target):
                f=FakeApp()
                target_id=w.TARGET_REPO_IDS[target]
                f.responses[mint]["repositories"][0].update(
                    {"id":target_id,"full_name":target})
                f.responses[listing]["repositories"][0].update(
                    {"id":target_id,"full_name":target})
                out=w.probe(JWT,app_id=APP,installation_id=INSTALL,
                            repository_id=target_id,now=NOW,repository=target,api=f)
                self.assertEqual(out["targetRepository"],target)
                self.assertFalse(out["publicationAuthorized"])
                self.assertFalse(out["independentReaderSignerCustodyProven"])
                self.assertEqual(out["goB"],"NO_GO")
                self.assertEqual(f.calls[-1][0],"DELETE")
                for mismatched in ("mint", "listing"):
                    bad=FakeApp()
                    if mismatched=="mint":
                        bad.responses[listing]["repositories"][0].update(
                            {"id":target_id,"full_name":target})
                    else:
                        bad.responses[mint]["repositories"][0].update(
                            {"id":target_id,"full_name":target})
                    with self.assertRaises(w.Deny):
                        w.probe(JWT,app_id=APP,installation_id=INSTALL,
                                repository_id=target_id,now=NOW,repository=target,api=bad)
                    self.assertEqual(bad.calls[-1][0],"DELETE")
        for target in (
            "pgextwin/catalog", "pgextwin/website",
            "someone/pgtap", "pgextwin/PgTap", "pgextwin/pgtap/",
            "pgextwin/../pgtap", "", None, True, 7,
        ):
            with self.subTest(invalid=target):
                f=FakeApp()
                with self.assertRaises(w.Deny):
                    w.probe(JWT,app_id=APP,installation_id=INSTALL,
                            repository_id=RID,now=NOW,repository=target,api=f)
                self.assertEqual(f.calls,[])  # no JWT use or token mint

    def test_pre_mint_immutable_real_github_repository_ids(self):
        self.assertEqual(w.TARGET_REPO_IDS,{
            "pgextwin/pgtap":1425678353,
            "pgextwin/pg_variables":1425679720,
            "pgextwin/pg_store_plans":1425680909,
            "pgextwin/plpgsql_check":1410581312})
        self.assertEqual(set(w.TARGET_REPO_IDS),w.ALLOWED_TARGETS)
        for repo,expected_id in w.TARGET_REPO_IDS.items():
            for bad_id in (True,0,-1,expected_id+1,RID
                           if expected_id != RID else 1425678353):
                f=FakeApp()
                with self.subTest(repo=repo,id=bad_id),self.assertRaises(w.Deny):
                    w.probe(JWT,app_id=APP,installation_id=INSTALL,
                            repository_id=bad_id,now=NOW,repository=repo,api=f)
                self.assertEqual(f.calls,[]) # preflight must occur before GET or POST

    def test_rest_post_has_json_content_type_and_strict_body_no_network(self):
        class FakeResponse:
            status=201
            headers={}
            def __enter__(self):return self
            def __exit__(self,*a):return False
            def read(self,n):return b'{"token":"SYNTHETIC_BODY_ONLY"}'
        observed=[]
        def fake_open(request, timeout):
            observed.append((request,timeout))
            return FakeResponse()
        result=w.authenticated_call("POST",
            f"/app/installations/{INSTALL}/access_tokens",JWT,
            {"repository_ids":[RID],"permissions":{"contents":"write"}},
            opener=fake_open)
        self.assertEqual(result,{"token":"SYNTHETIC_BODY_ONLY"})
        self.assertEqual(len(observed),1)
        req,timeout=observed[0]
        self.assertEqual(req.get_method(),"POST")
        self.assertEqual(timeout,20)
        self.assertEqual(req.get_header("Content-type"),"application/json")
        self.assertEqual(req.get_header("Accept"),"application/vnd.github+json")
        self.assertEqual(json.loads(req.data),{
            "repository_ids":[RID],"permissions":{"contents":"write"}})
        for malformed in (
            {"repositories":["pgtap"],"permissions":{"contents":"write"}},
            {"repository_ids":[RID],"permissions":{"contents":"write"},
             "unexpected":"silent_scope"},
            None):
            with self.subTest(body=malformed),self.assertRaises(w.Deny):
                w.authenticated_call("POST",
                    f"/app/installations/{INSTALL}/access_tokens",JWT,
                    malformed,opener=lambda *_a,**_k:
                    self.fail("invalid payload should never touch network"))
        self.assertEqual(len(observed),1)

    def test_direct_writer_mint_transport_denies_overbroad_scope_before_network(self):
        # A future caller might bypass probe() entirely. The lowest-level
        # authenticated POST helper must still reject foreign IDs or grants.
        allowed=w.TARGET_REPO_IDS["pgextwin/pgtap"]
        valid={"repository_ids":[allowed],
               "permissions":{"contents":"write"}}
        cases=(
            {"repository_ids":[1405939279],
             "permissions":{"contents":"write"}},  # catalog
            {"repository_ids":[1405931353],
             "permissions":{"contents":"write"}},  # central build
            {"repository_ids":[allowed,1425679720],
             "permissions":{"contents":"write"}},
            {"repository_ids":[],
             "permissions":{"contents":"write"}},
            {"repository_ids":[True],
             "permissions":{"contents":"write"}},
            {"repository_ids":[float(allowed)],
             "permissions":{"contents":"write"}},
            {"repository_ids":[str(allowed)],
             "permissions":{"contents":"write"}},
            {"repository_ids":allowed,
             "permissions":{"contents":"write"}},
            {"repository_ids":[allowed],
             "permissions":{"contents":"read"}},
            {"repository_ids":[allowed],
             "permissions":{"contents":"write","issues":"write"}},
            {"repository_ids":[allowed],
             "permissions":{"contents":"write","metadata":"read"}},
            {"repository_ids":[allowed],
             "permissions":{"administration":"write"}},
            {"repository_ids":[allowed],
             "permissions":["contents:write"]},
            {"repository_ids":[allowed],"permissions":{"contents":"write"},
             "expiration":"two hours"},
        )
        for bad in cases:
            called=[]
            def do_not_send(*args,**kwargs):
                called.append(True)
                self.fail("unsafe token POST escaped local guard")
            with self.subTest(bad=bad),self.assertRaises(w.Deny):
                w.authenticated_call(
                    "POST",f"/app/installations/{INSTALL}/access_tokens",
                    JWT,bad,opener=do_not_send)
            self.assertEqual(called,[])
        # The transport still accepts the exact single-target least-privilege
        # POST shape. Existing test validates its JSON body and content type.
        self.assertEqual(valid["repository_ids"],[allowed])

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
