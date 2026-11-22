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
from types import SimpleNamespace
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
        title="Select protected owner formal-source request (DENY)"
        jobs={"total_count":2,"jobs":[
            {"id":100,"run_attempt":1,"run_id":CENTRAL_RUN,"head_sha":SHA,
             "status":"completed","conclusion":"success","name":title},
            {"id":101,"status":"in_progress","name":"Other job"}]}
        with patch.object(mod.owner,"get",return_value=jobs):
            self.assertEqual(mod.original_job(CENTRAL_RUN,SHA),100)
        for field,value in (("run_attempt",2),("run_id",123),
                            ("head_sha","b"*40),("conclusion","failure"),
                            ("status","in_progress"),("id",True),
                            ("name","another job")):
            failed=json.loads(json.dumps(jobs))
            failed["jobs"][0][field]=value
            with self.subTest(field=field),patch.object(
                mod.owner,"get",return_value=failed),self.assertRaises(mod.Denied):
                mod.original_job(CENTRAL_RUN,SHA)
        broken=json.loads(json.dumps(jobs))
        broken["total_count"]=3
        with patch.object(mod.owner,"get",return_value=broken),self.assertRaises(mod.Denied):
            mod.original_job(CENTRAL_RUN,SHA)

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

    def test_live_recheck_only_reads_metadata_and_denies_source_drift(self):
        proof = {"repository": REPO, "sourceRunId": SOURCE_RUN, "mainSha": SHA,
                 "maintainedMajors": [14, 15, 16, 17, 18]}
        state = {"proof": proof, "intent": fixture.intent(), "requestCommentId": 3333,
                 "selectorJobId": 100}
        responses = {
            (REPO, "issues/comments/4444"): fixture.live_signing(),
            (REPO, "branches/main"): fixture.branch(),
            ("pgextwin/build", "branches/main"): fixture.branch(),
        }
        env = fixture.env()
        with patch.object(mod, "authenticate", return_value=(
                fixture.event(), fixture.branch(), fixture.run(), fixture.signed_run(), 3333)), patch.object(
                mod, "original_job", return_value=100), patch.object(
                mod.owner, "get", side_effect=lambda r, p: responses[(r, p)]), patch.object(
                mod.owner.audit, "audit") as verifier, patch.object(mod.owner, "fetch_artifact") as fetch:
            self.assertEqual(mod.recheck(state, env),
                             (fixture.branch(), fixture.run(), fixture.branch()))
            for route, altered in (
                    ("branches/main", dict(fixture.branch(), protected=False)),
                    ("branches/main", dict(fixture.branch(), commit={"sha": "b"*40})),
                    ("issues/comments/4444", dict(fixture.live_signing(), body="edited"))):
                before = responses[(REPO, route)]
                responses[(REPO, route)] = altered
                with self.subTest(route=route), self.assertRaises((mod.Denied, mod.owner.Denied)):
                    mod.recheck(state, env)
                responses[(REPO, route)] = before
            verifier.assert_not_called()
            fetch.assert_not_called()

    def test_upload_rechecks_exact_bytes_without_reclassifying_grype(self):
        ext, lifecycle, _ = old.old.fixture()
        majors = mod.ident.maintained_majors(ext, lifecycle)
        assets = mod.ident.expected_assets(ext, majors) - {"SHA256SUMS.txt"}
        with TemporaryDirectory() as d, patch.object(mod.owner.audit.vuln, "review") as review:
            folder = Path(d)
            for name in assets:
                (folder / name).write_bytes(b"test-bytes")
            hashes = {name: hashlib.sha256(b"test-bytes").hexdigest() for name in assets}
            proof = {"SHA256": hashes, "maintainedMajors": majors}
            self.assertEqual(mod.verify_upload_bytes(folder, ext, lifecycle, proof), hashes)
            path = folder / next(iter(assets))
            path.write_bytes(b"tampered")
            with self.assertRaisesRegex(mod.Denied, "SHA256"):
                mod.verify_upload_bytes(folder, ext, lifecycle, proof)
            path.unlink()
            with self.assertRaises(mod.Denied):
                mod.verify_upload_bytes(folder, ext, lifecycle, proof)
            review.assert_not_called()

    def test_prepare_retains_existing_blocking_grype_policy(self):
        a = SimpleNamespace(repository=REPO, source_run=str(SOURCE_RUN), source_sha=SHA,
                            **dict.fromkeys(mod.POLICY_ARGS, "fixture"))
        with TemporaryDirectory() as d, patch.object(
                mod, "authenticate", return_value=(None, None, None, None, 3333)), patch.object(
                mod.issuer.fleet_policy, "read", return_value={}), patch.object(
                mod.selector, "protected_local", return_value={}), patch.object(
                mod.policy, "gate"), patch.object(mod.issuer, "owner_policy_gate"), patch.object(
                mod.owner, "admit", return_value=({"blockingGrypeFindings": 1}, {}, {})) as admit:
            scratch = Path(d)
            with self.assertRaisesRegex(mod.Denied, "blocking .* Grype"):
                mod.prepare(a, scratch, fixture.env())
            self.assertFalse((scratch / mod.STATE_FILE).exists())
            admit.assert_called_once()

    def test_changed_preparation_is_denied_before_app_access(self):
        with TemporaryDirectory() as d, patch.object(mod.probe, "jwt") as jwt:
            scratch = Path(d)
            (scratch / mod.STATE_FILE).write_bytes(b'{"proof":{}}')
            env = {"OWNER_SOURCE_PREPARED_SHA256": hashlib.sha256(b"original").hexdigest()}
            with self.assertRaisesRegex(mod.Denied, "preparation changed"):
                mod.publish(SimpleNamespace(), scratch, env)
            jwt.assert_not_called()

    def test_workflow_requires_separate_completed_evidence_and_environment(self):
        workflow=(ROOT/".github/workflows/publisher-candidate-intake.yml").read_text("utf-8")
        job=workflow.split("  isolated_owner_source_formal_publisher:",1)[1]
        self.assertIn("needs: independent_owner_source_publish_request",job)
        self.assertIn("environment: publisher",job)
        self.assertIn("outputs.owner_source_selected == 'true'",job)
        self.assertIn("owner-source-formal-publisher.py",job)
        prepare, publish = job.split("      - name: Recheck live authorization", 1)
        self.assertIn("owner-source-formal-publisher.py prepare", prepare)
        self.assertNotIn("PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY", prepare)
        self.assertIn("owner-source-formal-publisher.py publish", publish)
        self.assertIn("PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY", publish)
        self.assertIn("steps.prepare.outputs.prepared_sha256", publish)
        self.assertIn("github.run_attempt == 1",job)
        self.assertNotIn("event_name == 'push'",job)
        self.assertNotIn("event_name == 'schedule'",job)
        self.assertNotIn("gh release create",job)

if __name__=="__main__":
    main()
