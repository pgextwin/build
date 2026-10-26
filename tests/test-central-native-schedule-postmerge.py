#!/usr/bin/env python3
"""Real schedule-vs-workflow_run provenance regression (NO RELEASE)."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("legacy_live_fixture",
    ROOT/"tests"/"test-automatic-postmerge-audit-live.py")
fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
mod=fixtures.mod
CENTRAL="pgextwin/build"
SHA="f"*40
RUN,JOB,ART=601,602,603
PATH=".github/workflows/fleet-upstream-watch.yml"
NAME="Hourly stable upstream updates for all 17 extensions"
JOBNAME="Independent original PR artifacts audit (genuine fleet schedule only; NO PUBLISH)"


def central_fixture():
    event,original,context,audit=fixtures.fixture()
    original["actions/runs?event=workflow_run&head_sha="+fixtures.OLD+
             "&per_page=100"]={"total_count":0,"workflow_runs":[]}
    run={"id":RUN,"name":NAME,"path":PATH,
         "event":"schedule","run_attempt":1,
         "repository":{"full_name":CENTRAL},"head_sha":SHA,"head_branch":"main",
         "status":"completed","conclusion":"success"}
    job={"id":JOB,"run_id":RUN,"name":JOBNAME,"status":"completed","conclusion":"success"}
    art={"id":ART,"name":"registered-original-native-pr-audits",
         "size_in_bytes":9876,"expired":False,
         "workflow_run":{"id":RUN}}
    receipt={"schemaVersion":1,"status":
             "CENTRAL_GENUINE_SCHEDULE_ORIGINAL_NATIVE_CI_BYTES_VERIFIED_NONPUBLISHING",
             "auditorRepository":CENTRAL,"auditorEvent":"schedule",
             "auditorSourceSha":SHA,"targetRepository":fixtures.REPO,
             "targetMainSha":fixtures.OLD,"native":context,"candidateAudit":audit,
             "signedArtifactsVerified":False,"publicationAuthorized":False,
             "publishableReceipt":False}
    calls={
        "branches/main":{"name":"main","protected":True,"commit":{"sha":SHA}},
        "actions/runs?event=schedule&per_page=100":{
            "total_count":1,"workflow_runs":[run]},
        "actions/runs/"+str(RUN):run,
        "actions/runs/"+str(RUN)+"/jobs?per_page=100":{
            "total_count":1,"jobs":[job]},
        "actions/runs/"+str(RUN)+"/artifacts?per_page=100":{
            "total_count":1,"artifacts":[art]},
    }
    return event,original,calls,receipt


class CentralNativeSchedulePostmergeTests(unittest.TestCase):
    def verify(self,change=None):
        event,local,central,receipt=central_fixture()
        if change:change(event,local,central,receipt)
        def api(repo,endpoint):
            if repo==fixtures.REPO:
                if endpoint not in local: raise mod.Denied("untrusted changed original native GET")
                return deepcopy(local[endpoint])
            if repo==CENTRAL:
                if endpoint not in central: raise mod.Denied("untrusted changed central schedule GET")
                return deepcopy(central[endpoint])
            raise AssertionError(repo)
        def download(run,asset,target):
            self.assertEqual(target,fixtures.REPO)
            self.assertEqual(asset["id"],ART)
            self.assertEqual(run["id"],RUN)
            return deepcopy(receipt)
        return mod.live(fixtures.REPO,event,deepcopy(fixtures.FLEET),
                        deepcopy(fixtures.LIFE),auth_api=api,
                        central_api=api,central_retrieve=download)

    def test_genuine_schedule_distinct_from_skipped_local_audit(self):
        result=self.verify()
        self.assertEqual(result["nativeAuditEvent"],"schedule")
        self.assertEqual(result["nativeAuditRepository"],CENTRAL)
        self.assertEqual(result["nativeAuditRunId"],RUN)
        self.assertEqual(result["candidateCiRunId"],fixtures.CI)
        self.assertEqual(result["mainParentAtAudit"],fixtures.OLD)
        self.assertEqual(result["status"],"MERGED_NATIVE_CANDIDATE_NONPUBLISHING")
        for k in ("signedArtifactsVerified","publishableReceipt",
                  "publicationAuthorized","automaticReleaseEnabled"):
            self.assertIs(result[k],False)

    def test_tampering_cannot_convert_nonpublishing_schedule_to_authority(self):
        changes=[
            lambda e,l,c,r:c["actions/runs/"+str(RUN)].update(event="workflow_dispatch"),
            lambda e,l,c,r:c["actions/runs/"+str(RUN)].update(run_attempt=2),
            lambda e,l,c,r:c["actions/runs/"+str(RUN)].update(conclusion="failure"),
            lambda e,l,c,r:c["actions/runs/"+str(RUN)].update(path=".github/workflows/publisher-candidate-intake.yml"),
            lambda e,l,c,r:c["actions/runs/"+str(RUN)]["repository"].update(full_name=fixtures.REPO),
            lambda e,l,c,r:c["branches/main"].update(protected=False),
            lambda e,l,c,r:c["branches/main"]["commit"].update(sha="e"*40),
            lambda e,l,c,r:c["actions/runs/"+str(RUN)+"/jobs?per_page=100"]["jobs"][0].update(conclusion="skipped"),
            lambda e,l,c,r:c["actions/runs/"+str(RUN)+"/jobs?per_page=100"]["jobs"][0].update(run_id=123),
            lambda e,l,c,r:c["actions/runs/"+str(RUN)+"/artifacts?per_page=100"]["artifacts"][0].update(expired=True),
            lambda e,l,c,r:c["actions/runs/"+str(RUN)+"/artifacts?per_page=100"]["artifacts"][0].update(name="fake-audit"),
            lambda e,l,c,r:r.update(targetMainSha="e"*40),
            lambda e,l,c,r:r.update(auditorEvent="workflow_run"),
            lambda e,l,c,r:r.update(auditorSourceSha="e"*40),
            lambda e,l,c,r:r.update(publicationAuthorized=True),
            lambda e,l,c,r:r["native"].update(candidateHeadSha="e"*40),
            lambda e,l,c,r:r["candidateAudit"]["majors"][0].update(zipSha256="not-a-hash"),
            lambda e,l,c,r:e["sender"].update(login="github-actions[bot]"),
            lambda e,l,c,r:e.update(before="e"*40),
        ]
        for idx,change in enumerate(changes):
            with self.subTest(case=idx),self.assertRaises(mod.Denied):
                self.verify(change)

    def test_missing_real_schedule_refuses_to_guess_a_run(self):
        with self.assertRaises(mod.Denied):
            self.verify(lambda e,l,c,r:c["actions/runs?event=schedule&per_page=100"].update(
                total_count=0,workflow_runs=[]))

if __name__=="__main__":
    unittest.main()
