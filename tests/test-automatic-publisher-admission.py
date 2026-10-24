#!/usr/bin/env python3
"""Synthetic-only signed source / genuine schedule joins: NEVER a Release grant."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
guard=load("automatic_scheduled_admission","scripts/automatic-publisher-admission.py")
plan=load("automatic_scheduled_tag_plan","tests/test-automatic-release-tag-plan.py")

REPO=plan.REPO
SHA=plan.SHA
RUN=plan.RUN
CENTRAL_SHA="c"*40
SCHEDULE_RUN=987654

def fixture():
    signed,unused,manifest=plan.fixture()
    proposal=plan.run_plan()
    fleet=json.loads((ROOT/"metadata/automation-fleet.json").read_text())
    central=json.loads((ROOT/"metadata/release-promotion.json").read_text())
    unattended=json.loads((ROOT/"metadata/unattended-publication.json").read_text())
    boundary=json.loads((ROOT/"metadata/publisher-write-boundary.json").read_text())
    source={
        "schemaVersion":1,
        "status":"REAL_COMPLETED_SIGNED_SOURCE_VERIFIED_NONPUBLISHING",
        "repository":REPO,"mainMergeSha":SHA,
        "sourceRunId":RUN,"sourceRunAttempt":1,
        "realSigstoreRechecked":True,"blockingGrypeFindings":0,
        "publisherTokenRequested":False,"publicationAuthorized":False,
        "publishableReceipt":False,"automaticReleaseEnabled":False,
        "maintainedMajors":signed["maintainedMajors"],
    }
    for asset in ("zip","spdx","grype"):
        source[asset+"Sha256ByMajor"]=signed[asset+"Sha256ByMajor"]
    schedule_run={
        "id":SCHEDULE_RUN,"run_attempt":1,
        "repository":{"full_name":"pgextwin/build"},
        "head_sha":CENTRAL_SHA,"head_branch":"main",
        "event":"schedule","path":guard.SCHEDULE_WORKFLOW,
        "status":"in_progress","conclusion":None}
    return {
        "source":source,"proposal":proposal,"manifest":manifest,
        "fleet":fleet,"central":central,
        "local":{"schemaVersion":1,"enabled":True,"releasePolicy":"manual-dispatch"},
        "unattended":unattended,"boundary":boundary,
        "schedule_run":schedule_run,
        "repository":REPO,"sha":SHA,"source_run_id":RUN,
        "central_sha":CENTRAL_SHA,
        "schedule_run_id":SCHEDULE_RUN,"schedule_attempt":1,
        "event":"schedule","ref":"refs/heads/main",
        "central_branch":{"name":"main","protected":True,
                          "commit":{"sha":CENTRAL_SHA}},
    }

class ScheduledAdmission(unittest.TestCase):
    def test_signed_schedule_produces_denied_witness_not_auth(self):
        out=guard.assess(**fixture())
        self.assertEqual(out["status"],"SIGNED_SCHEDULE_PUBLISHER_ADMISSION_EVIDENCE_ONLY")
        self.assertEqual(out["releaseTagProposal"],"v18.1-windows.1")
        self.assertEqual(out["sourceRunId"],RUN)
        self.assertEqual(out["scheduleRunId"],SCHEDULE_RUN)
        self.assertNotEqual(out["mainMergeSha"],out["centralMainSha"])
        self.assertEqual(len(out["zipSha256ByMajor"]),5)
        self.assertIn("INDEPENDENT_LIVE_PUBLISHER_AUTHORIZATION_REQUIRED",
                      out["policyBlockers"])
        for name in ("publicationAuthorized","publishableReceipt",
                     "publisherWriteAuthorized","publisherTokenRequested"):
            self.assertIs(out[name],False)
        for k in ("goB","g4","g5"):
            self.assertEqual(out[k],"NO_GO")
        for key in ("GH_TOKEN","privateKey","publisherToken","authorizationMode",
                    "operator","signedArtifactsVerified"):
            self.assertNotIn(key,out)

    def test_forged_schedule_run_and_cross_event_denied(self):
        changes=[
            lambda x:x.update(event="push"),
            lambda x:x.update(event="workflow_dispatch"),
            lambda x:x.update(ref="refs/tags/v1"),
            lambda x:x.update(schedule_attempt=2),
            lambda x:x.update(schedule_attempt=True),
            lambda x:x.update(schedule_run_id=0),
            lambda x:x.update(central_sha="z"*40),
            lambda x:x["central_branch"].update(protected=False),
            lambda x:x["central_branch"]["commit"].update(sha="d"*40),
            lambda x:x["schedule_run"].update(event="push"),
            lambda x:x["schedule_run"].update(path="other.yml"),
            lambda x:x["schedule_run"].update(run_attempt=2),
            lambda x:x["schedule_run"].update(status="completed",conclusion="success"),
            lambda x:x["schedule_run"].update(status="in_progress",conclusion="success"),
            lambda x:x["schedule_run"].update(head_sha="d"*40),
            lambda x:x["schedule_run"].update(repository={"full_name":REPO}),
            lambda x:x["schedule_run"].update(id=SCHEDULE_RUN+1),
        ]
        self.deny(changes)

    def test_unverified_replayed_signed_source_denied(self):
        changes=[
            lambda x:x["source"].update(status="MOCK_VERIFIED"),
            lambda x:x["source"].update(sourceRunAttempt=2),
            lambda x:x["source"].update(sourceRunId=RUN+1),
            lambda x:x["source"].update(mainMergeSha="d"*40),
            lambda x:x["source"].update(realSigstoreRechecked=False),
            lambda x:x["source"].update(publicationAuthorized=True),
            lambda x:x["source"].update(publishableReceipt=True),
            lambda x:x["source"].update(blockingGrypeFindings=1),
            lambda x:x["source"]["zipSha256ByMajor"].pop("14"),
            lambda x:x["source"]["spdxSha256ByMajor"].update({"14":"x"*64}),
            lambda x:x["source"].update(maintainedMajors=[14,14,15,16,17,18]),
            lambda x:x["source"].update(maintainedMajors=[19]),
            lambda x:x.update(source_run_id=RUN+1),
            lambda x:x.update(repository="pgextwin/evil"),
            lambda x:x.update(sha="e"*40),
            lambda x:x["manifest"].update(name="pg_cron"),
            lambda x:x["manifest"]["upstream"].update(repository="evil/repo"),
        ]
        self.deny(changes)

    def test_publisher_policies_remain_explicit_denial(self):
        changes=[
            lambda x:x["fleet"].update(releasePolicy="automatic"),
            lambda x:x["fleet"]["entries"].append(deepcopy(x["fleet"]["entries"][0])),
            lambda x:x["central"].update(releasePolicy="automatic"),
            lambda x:x["central"]["allowedRepositories"].pop(),
            lambda x:x["local"].update(releasePolicy="automatic"),
            lambda x:x["unattended"].update(mode="UNATTENDED"),
            lambda x:x["unattended"]["controls"].update(automaticFormalRelease=True),
            lambda x:x["boundary"].update(mode="ENFORCE"),
            lambda x:x["boundary"].update(publisherAppId=5451798),
            lambda x:x["boundary"].update(signerAppId=5451798),
            lambda x:x["proposal"].update(publicationAuthorized=True),
            lambda x:x["proposal"].update(releaseTagProposal="v17.1-windows.1"),
            lambda x:x["proposal"].update(runAttempt=2),
            lambda x:x["proposal"].update(runId=RUN+1),
        ]
        self.deny(changes)

    def test_dynamic_registry_not_fixed_17(self):
        values=fixture()
        values["fleet"]["entries"].pop()
        values["central"]["allowedRepositories"].pop()
        self.assertEqual(guard.assess(**values)["status"],
                         "SIGNED_SCHEDULE_PUBLISHER_ADMISSION_EVIDENCE_ONLY")
        values["central"]["allowedRepositories"].append("pgextwin/evil")
        with self.assertRaises((guard.Denied,guard.scope.Denied)):
            guard.assess(**values)

    def deny(self,changes):
        for i,change in enumerate(changes):
            with self.subTest(case=i),self.assertRaises(
                    (guard.Denied,guard.scope.Denied)):
                values=fixture()
                change(values)
                guard.assess(**values)

    def test_existing_publisher_cannot_consume_observational_witness(self):
        releaseauth=load("schedule_does_not_authorize_release",
                         "scripts/release-authorization.py")
        result=guard.assess(**fixture())
        with self.assertRaises(releaseauth.Denied):
            releaseauth.validate_receipt(
                result,repository=REPO,commit=SHA,
                actor="github-actions[bot]",event="schedule")

if __name__=="__main__":
    unittest.main()
