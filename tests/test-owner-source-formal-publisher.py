#!/usr/bin/env python3
"""Hostile offline checks for isolated owner-source formal Release entrypoint.

No network, App key, Attestation claims or GitHub WRITE is used in fixtures.
Real publication still requires the actual protected Environment same-job E2E.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase,main
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj
mod=load("owner_source_isolated_formal_tests","scripts/owner-source-formal-publisher.py")
fixture=load("owner_source_admission_fixture","tests/test-publisher-owner-source-admission.py")
old=load("owner_source_formal_old_fixture","tests/test-automatic-publisher-receipt-issuer.py")
REPO="pgextwin/plpgsql_check"
SHA="a"*40
SOURCE_RUN=41486380278
CENTRAL_RUN=5555

class OwnerFormalRuntimeTests(TestCase):
    def test_original_same_run_source_admission_requires_success_not_any_job(self):
        title="Authenticate owner formal-source request and reverify original (DENY)"
        jobs={"total_count":2,"jobs":[
            {"id":100,"run_attempt":1,"run_id":CENTRAL_RUN,"head_sha":SHA,
             "status":"completed","conclusion":"success","name":title},
            {"id":101,"status":"in_progress","name":"Other job"}]}
        with patch.object(mod.owner,"get",return_value=jobs):
            self.assertEqual(mod.original_job(REPO,CENTRAL_RUN,SHA),100)
        for field,value in (("run_attempt",2),("run_id",123),
                            ("head_sha","b"*40),("conclusion","failure"),
                            ("status","in_progress"),("id",True),
                            ("name","another job")):
            failed=json.loads(json.dumps(jobs))
            failed["jobs"][0][field]=value
            with self.subTest(field=field),patch.object(
                mod.owner,"get",return_value=failed),self.assertRaises(mod.Denied):
                mod.original_job(REPO,CENTRAL_RUN,SHA)
        broken=json.loads(json.dumps(jobs))
        broken["total_count"]=3
        with patch.object(mod.owner,"get",return_value=broken),self.assertRaises(mod.Denied):
            mod.original_job(REPO,CENTRAL_RUN,SHA)

    def test_owner_request_authentication_requires_fresh_original(self):
        with TemporaryDirectory() as d:
            event=fixture.event()
            event["comment"]["body"]="/pgextwin publish-owner-source "+REPO+" "+str(SOURCE_RUN)
            event["comment"]["created_at"]="2026-11-03T00:00:00Z"
            event["comment"]["updated_at"]="2026-11-03T00:00:00Z"
            file=Path(d)/"event.json"
            file.write_text(json.dumps(event),"utf-8")
            env=fixture.env()
            env.update(GITHUB_EVENT_PATH=str(file),GH_TOKEN="synthetic-read-only-token",
                       GITHUB_RUN_ID=str(CENTRAL_RUN))
            original=fixture.signed_run()
            original["updated_at"]="2026-11-02T23:00:00Z"
            central=fixture.run()
            central["created_at"]="2026-11-03T00:00:02Z"
            responses={
                ("pgextwin/build","branches/main"):fixture.branch(),
                ("pgextwin/build","actions/runs/"+str(CENTRAL_RUN)):central,
                ("pgextwin/build","issues/comments/3333"):event["comment"],
                (REPO,"actions/runs/"+str(SOURCE_RUN)):original,
            }
            with patch.object(mod.owner,"get",side_effect=lambda r,p:responses[(r,p)]):
                result=mod.authenticate(REPO,SOURCE_RUN,SHA,env)
                self.assertEqual(result[-1],3333)
                bad=dict(original,updated_at="2026-01-01T00:00:00Z")
                responses[(REPO,"actions/runs/"+str(SOURCE_RUN))]=bad
                with self.assertRaises(mod.Denied):
                    mod.authenticate(REPO,SOURCE_RUN,SHA,env)
                responses[(REPO,"actions/runs/"+str(SOURCE_RUN))]=original
                event["comment"]["body"]="/pgextwin publish "+REPO
                file.write_text(json.dumps(event),"utf-8")
                with self.assertRaises(mod.owner.Denied):
                    mod.authenticate(REPO,SOURCE_RUN,SHA,env)

    def test_no_prior_locator_source_run_replay_can_generate_next_tag(self):
        manifest,lifecycle,_=old.old.fixture() if hasattr(old,"old") else (None,None,None)
        # Use the actual registered fixture from the established issuer suite.
        ext,_,_=old.old.fixture() if hasattr(old,"old") else load(
            "owner_source_tag_test_fixture","tests/test-fleet-publish-release.py").fixture()
        root=mod.ident.tag_stem(ext)+"-windows."
        values=[
            {"id":1,"tag_name":root+"1","draft":False,"body":""},
        ]
        refs=[{"ref":"refs/tags/"+root+"1"}]
        with patch.object(mod.tagplan,"get_listing",
                          side_effect=[values,refs]):
            self.assertEqual(mod.tag_from_live("pgextwin/pgaudit",ext,100),root+"2")
        claim={"schemaVersion":1,"authorizationMode":"owner-signed-main-issue-comment",
               "repository":"pgextwin/pgaudit","releaseTag":root+"1",
               "packagingCommit":SHA,"sourceRunId":100,"sourceRunAttempt":1,
               "sourceWorkflow":".github/workflows/chat-signed-main.yml",
               "publisherRepository":"pgextwin/build","publisherRunId":1000,
               "publisherRunAttempt":1,"publisherMainSha":"c"*40,
               "publisherWorkflow":".github/workflows/publisher-candidate-intake.yml",
               "publisherAppId":5451798,
               "approvalProvenance":"INDEPENDENT_LIVE_OWNER_MAIN_SIGNING_AND_PUBLISH_REQUEST",
               "requestCommentId":123,"sourceSigningCommentId":456,
               "sourceKind":"OWNER_ISSUE_COMMENT_MAIN_SIGNING"}
        values[0]["body"]=mod.provenance.PREFIX+json.dumps(claim)+mod.provenance.SUFFIX
        with patch.object(mod.tagplan,"get_listing",
                          side_effect=[values,refs]),self.assertRaises(mod.Denied):
            mod.tag_from_live("pgextwin/pgaudit",ext,100)

    def test_grype_denies_missing_broken_or_blocking_original_bytes(self):
        ext,lifecycle,_=old.old.fixture()
        majors=mod.ident.maintained_majors(ext,lifecycle)
        assets=mod.ident.expected_assets(ext,majors)-{"SHA256SUMS.txt"}
        with TemporaryDirectory() as d:
            folder=Path(d)
            for name in assets:
                (folder/name).write_bytes(b"test-bytes")
            hashes={name:hashlib.sha256(b"test-bytes").hexdigest() for name in assets}
            proof={"SHA256":hashes,"maintainedMajors":majors}
            with patch.object(mod.owner,"read_file",return_value={"matches":[]}),patch.object(
                mod.owner.audit.vuln,"review",
                return_value={"status":"NO_BLOCKING_FINDINGS","blockingFindingCount":0}):
                self.assertEqual(mod.package_and_grype(folder,ext,lifecycle,proof),hashes)
            with patch.object(mod.owner,"read_file",return_value={"matches":[{}]}),patch.object(
                mod.owner.audit.vuln,"review",
                return_value={"status":"BLOCKING_FINDINGS","blockingFindingCount":1}):
                with self.assertRaises(mod.Denied):
                    mod.package_and_grype(folder,ext,lifecycle,proof)
            proof["SHA256"][next(iter(proof["SHA256"]))]="0"*64
            with self.assertRaises(mod.Denied):
                mod.package_and_grype(folder,ext,lifecycle,proof)

    def test_workflow_requires_separate_completed_evidence_and_environment(self):
        workflow=(ROOT/".github/workflows/publisher-candidate-intake.yml").read_text("utf-8")
        job=workflow.split("  isolated_owner_source_formal_publisher:",1)[1]
        self.assertIn("needs: independent_owner_source_publish_request",job)
        self.assertIn("environment: publisher",job)
        self.assertIn("outputs.owner_source_selected == 'true'",job)
        self.assertIn("owner-source-formal-publisher.py",job)
        self.assertIn("PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY",job)
        self.assertIn("github.run_attempt == 1",job)
        self.assertNotIn("event_name == 'push'",job)
        self.assertNotIn("event_name == 'schedule'",job)
        self.assertNotIn("gh release create",job)
        # No front door can be considered verified without exact protected
        # central AND local opt-ins (default DENY remains the starting policy).
        central=json.loads((ROOT/"metadata/owner-source-publication.json").read_text("utf-8"))
        self.assertEqual(central["mode"],"ENFORCE")
        self.assertEqual(central["allowedRepositories"],["pgextwin/plpgsql_check", "pgextwin/pg_ivm"])

if __name__=="__main__":
    main()
