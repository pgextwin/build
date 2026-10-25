#!/usr/bin/env python3
"""Synthetic in-process schedule->scoped App->existing Publisher routing tests.

These fixtures NEVER use GitHub or perform cryptographic verification or WRITE.
Passing here is only a code-path regression, not a real signed Release E2E.
"""
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch
import importlib.util
import json
import os
import sys

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

runtime=load("synthetic_runtime","scripts/automatic-publisher-run.py")
fixture=load("synthetic_issuer_fixtures","tests/test-automatic-publisher-receipt-issuer.py")
REPO=fixture.REPO
SHA=fixture.SHA
CENTRAL=fixture.CENTRAL_SHA
ORIGINAL=fixture.SOURCE_RUN
PUBLISHER=fixture.SCHEDULE_RUN

def setup(root,ready):
    item=fixture.switched() if ready else fixture.inputs()
    paths={}
    mapping={
        "manifest":item["manifest"],
        "lifecycle":item["lifecycle"],
        "original":{"synthetic":True},
        "second":{"synthetic":True},
        "proposal":{
            "schemaVersion":1,
            "status":"PROPOSED_TAG_NONPUBLISHING",
            "runId":ORIGINAL,"runAttempt":1,
            "repository":REPO,"mainMergeSha":SHA,
            "releaseTagProposal":item["tag"],
            "publicationAuthorized":False,
            "publishableReceipt":False,
            "publisherWriteEnabled":False,
            "requiresIndependentLiveRecheckAndAtomicTagReservation":True},
        "fleet":item["fleet"],
        "central-policy":item["central"],
        "local-policy":item["local"],
        "unattended":item["unattended"],
        "publisher-boundary":item["boundary"],
    }
    for name,data in mapping.items():
        path=root/(name+".json")
        path.write_text(json.dumps(data))
        paths[name]=path
    (root/"dist").mkdir()
    paths.update(dist=root/"dist",recovery=root/"recovery.json",
                 output=root/"published.json")
    argv=["automatic-publisher-run.py",
          "--repository",REPO,"--sha",SHA,
          "--source-run",str(ORIGINAL)]
    for name,path in paths.items():
        argv.extend(["--"+name,str(path)])
    env={
        "GITHUB_REPOSITORY":"pgextwin/build",
        "GITHUB_EVENT_NAME":"schedule",
        "GITHUB_REF":"refs/heads/main",
        "GITHUB_RUN_ATTEMPT":"1",
        "GITHUB_RUN_ID":str(PUBLISHER),
        "GITHUB_SHA":CENTRAL,
        "GITHUB_ACTOR":"scheduled-workflow-editor",
        "GH_TOKEN":"synthetic-github-read-token",
        "PUBLISHER_APP_ID":"5451798",
        "PUBLISHER_INSTALLATION_ID":"174720074",
        "PUBLISHER_PRIVATE_KEY":"synthetic-key-never-used-for-genuine-JWT",
    }
    return item,argv,env,paths

class TrustedRuntimeOffline(TestCase):
    def test_all_conditions_jointly_call_the_existing_formal_writer(self):
        self.check_runtime(False)
        self.check_runtime(True)

    def check_runtime(self,change_job_on_recheck):
        with TemporaryDirectory() as d:
            item,argv,env,paths=setup(Path(d),True)
            token="synthetic-one-repository-token-not-a-secret"
            revoked=[]
            writes=[]
            job_reads=0
            def github(repo,route):
                nonlocal job_reads
                if route=="branches/main":
                    return item["central_branch"] if repo=="pgextwin/build" else item["signed_branch"]
                if route==f"actions/runs/{PUBLISHER}/attempts/1/jobs?per_page=100":
                    job_reads+=1
                    jobs=fixture.independent_jobs()
                    if change_job_on_recheck and job_reads==2:
                        jobs["jobs"][0]["id"]=999
                    return jobs
                self.assertEqual((repo,route),
                                 ("pgextwin/build",f"actions/runs/{PUBLISHER}"))
                return item["schedule_run"]
            def api(method,path,credential,body=None):
                self.assertEqual(method,"GET")
                if path=="/app":return item["app_identity"]
                if path=="/app/installations/174720074":
                    return item["installation_identity"]
                self.fail("unexpected external network operation")
            @contextmanager
            def scoped(**arguments):
                self.assertEqual(arguments["release_policy"],
                                 "automatic-signed-schedule")
                self.assertEqual(arguments["repository"],REPO)
                self.assertEqual(arguments["app"],5451798)
                try:
                    yield token,item["minted"],item["scoped"]
                finally:
                    revoked.append(True)
            def publish(*args,**kwargs):
                self.assertEqual(os.environ["GH_TOKEN"],token)
                self.assertEqual(args[3],SHA)
                self.assertEqual(kwargs["publish_run_id"],PUBLISHER)
                self.assertEqual(args[2]["sourceRunId"],ORIGINAL)
                writes.append(True)
            expected={
                runtime.formal.ident.asset_stem(item["manifest"],m)+".zip":"b"*64
                for m in range(14,19)}
            with patch.dict(os.environ,env),patch.object(sys,"argv",argv), \
                 patch.object(runtime.source,"verify_completed_source",
                              return_value=item["proof"]) as verifier, \
                 patch.object(runtime.source,"github",side_effect=github), \
                 patch.object(runtime.probe,"jwt",return_value="synthetic-JWT"), \
                 patch.object(runtime.probe,"api",side_effect=api), \
                 patch.object(runtime.scope,"single_repository_token",
                              side_effect=scoped), \
                 patch.object(runtime.formal,"check_assets",return_value=expected) as formal_check, \
                 patch.object(runtime.formal,"publish_preverified",
                              side_effect=publish), \
                 patch.object(runtime.formal,"absent") as absent, \
                 patch.object(runtime.formal,"REPO",runtime.formal.REPO):
                result=runtime.main()
                self.assertEqual(result,2 if change_job_on_recheck else 0)
                self.assertEqual(os.environ["GH_TOKEN"],env["GH_TOKEN"])
                self.assertEqual(len(revoked),1)
                self.assertEqual(len(writes),0 if change_job_on_recheck else 1)
                self.assertEqual(job_reads,2)
                self.assertEqual(verifier.call_count,1)
                self.assertEqual(formal_check.call_count,1)
                self.assertEqual(absent.call_count,2)
                if change_job_on_recheck:
                    self.assertFalse(paths["output"].exists())
                else:
                    output=json.loads(paths["output"].read_text())
                    self.assertEqual(output["status"],"PUBLISHED_VERIFIED")
                    self.assertTrue(output["publisherTokenRevoked"])

    def test_current_real_policy_denies_before_secret_access_or_network(self):
        with TemporaryDirectory() as d:
            _,argv,env,paths=setup(Path(d),False)
            with patch.dict(os.environ,env),patch.object(sys,"argv",argv), \
                 patch.object(runtime.source,"verify_completed_source") as real, \
                 patch.object(runtime.probe,"jwt") as jwt, \
                 patch.object(runtime.scope,"single_repository_token") as token, \
                 patch.object(runtime.formal,"publish_preverified") as publish:
                self.assertEqual(runtime.main(),2)
                self.assertIn("PUBLISHER_PRIVATE_KEY",os.environ)
                self.assertFalse(paths["output"].exists())
                real.assert_not_called()
                jwt.assert_not_called()
                token.assert_not_called()
                publish.assert_not_called()

    def test_failed_separate_repository_proof_denies_before_key_or_token(self):
        with TemporaryDirectory() as d:
            item,argv,env,paths=setup(Path(d),True)
            jobs=fixture.independent_jobs()
            jobs["jobs"][0]["conclusion"]="failure"
            def github(repo,route):
                if route=="branches/main":
                    return item["central_branch"] if repo=="pgextwin/build" else item["signed_branch"]
                if route.endswith("/attempts/1/jobs?per_page=100"):
                    return jobs
                return item["schedule_run"]
            with patch.dict(os.environ,env),patch.object(sys,"argv",argv), \
                 patch.object(runtime.source,"verify_completed_source",return_value=item["proof"]), \
                 patch.object(runtime.source,"github",side_effect=github), \
                 patch.object(runtime.formal,"absent"), \
                 patch.object(runtime.formal,"REPO",runtime.formal.REPO), \
                 patch.object(runtime.probe,"jwt") as jwt, \
                 patch.object(runtime.scope,"single_repository_token") as token, \
                 patch.object(runtime.formal,"publish_preverified") as publish:
                self.assertEqual(runtime.main(),2)
                self.assertIn("PUBLISHER_PRIVATE_KEY",os.environ)
                jwt.assert_not_called()
                token.assert_not_called()
                publish.assert_not_called()
                self.assertFalse(paths["output"].exists())

    def test_workflow_preserves_whole_matrix_success_and_repository_identity(self):
        workflow=(ROOT/".github/workflows/publisher-candidate-intake.yml").read_text()
        self.assertIn("signed original (${{ matrix.name }})",workflow)
        publisher=workflow.split("  isolated_formal_publisher:",1)[1]
        for required in ("needs.nonpublishing_intake.result == 'success'",
                         "needs.nonpublishing_intake.outputs.publisher_ready == 'true'",
                         "needs.independent_real_signed_source.result == 'success'"):
            self.assertIn(required,publisher)
        self.assertNotIn("needs.independent_real_signed_source.result == 'failure'",publisher)

    def test_scoped_token_revoked_on_rejected_issuer(self):
        with TemporaryDirectory() as d:
            item,argv,env,paths=setup(Path(d),True)
            item["scoped"]={"total_count":2,"repositories":[
                {"full_name":REPO},{"full_name":"pgextwin/other"}]}
            revoked=[]
            @contextmanager
            def scoped(**_):
                try:
                    yield item["minted"]["token"],item["minted"],item["scoped"]
                finally:
                    revoked.append(True)
            def github(repo,route):
                if route=="branches/main":
                    return item["central_branch"] if repo=="pgextwin/build" else item["signed_branch"]
                if route==f"actions/runs/{PUBLISHER}/attempts/1/jobs?per_page=100":
                    return fixture.independent_jobs()
                return item["schedule_run"]
            def api(_,path,__):
                return item["app_identity"] if path=="/app" else item["installation_identity"]
            with patch.dict(os.environ,env),patch.object(sys,"argv",argv), \
                 patch.object(runtime.source,"verify_completed_source",
                              return_value=item["proof"]), \
                 patch.object(runtime.source,"github",side_effect=github), \
                 patch.object(runtime.probe,"jwt",return_value="fake"), \
                 patch.object(runtime.probe,"api",side_effect=api), \
                 patch.object(runtime.scope,"single_repository_token",side_effect=scoped), \
                 patch.object(runtime.formal,"absent"), \
                 patch.object(runtime.formal,"publish_preverified") as publish, \
                 patch.object(runtime.formal,"REPO",runtime.formal.REPO):
                self.assertEqual(runtime.main(),2)
                self.assertEqual(revoked,[True])
                publish.assert_not_called()
                self.assertFalse(paths["output"].exists())

if __name__=="__main__":main()
