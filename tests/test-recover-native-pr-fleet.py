#!/usr/bin/env python3
"""Independent central scheduled native audit: fail-closed policy fixtures."""
import importlib.util
from copy import deepcopy
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("audit_fleet",ROOT/"scripts"/"recover-native-pr-fleet.py")
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
fixtures=mod.load("fleet_native_fixtures","tests/test-native-pr-candidate-audit.py")
artifacts=mod.load("fleet_artifact_fixtures","tests/test-pr-candidate-artifacts.py")

def dispatch_data():
    x=fixtures.fixture()
    held=deepcopy(x["run"])
    held.update(conclusion="action_required",workflow_id=70)
    run=deepcopy(x["run"])
    run.update(id=held["id"]+1,event="workflow_dispatch",workflow_id=70,check_suite_id=800)
    check=x["checks"]["check_runs"][0]
    check.update(check_suite={"id":800},details_url="https://github.com/"+fixtures.REPO+
                 "/actions/runs/"+str(run["id"])+"/job/"+str(check["id"]))
    inventory={"total_count":1,"workflow_runs":[held]}
    responses={
        "actions/runs/"+str(held["id"]):held,
        "actions/runs/"+str(held["id"])+"/jobs?per_page=100":{"total_count":0,"jobs":[]},
        "actions/runs?event=workflow_dispatch&head_sha="+fixtures.SHA+"&per_page=100":
            {"total_count":1,"workflow_runs":[run]},
        "actions/runs/"+str(run["id"]):run,
        "commits/"+fixtures.SHA+"/pulls?per_page=100":fixtures.association(),
        "pulls/"+str(fixtures.PR):x["pr"],
        "branches/main":x["main"],
        "commits/"+fixtures.SHA+"/check-runs?per_page=100":x["checks"],
    }
    return x,inventory,responses

class FleetRecoveryTests(TestCase):
    def test_roster_dynamic_no_fixed_repositories(self):
        live=mod.membership(ROOT/"metadata/automation-fleet.json")
        self.assertIn("pgextwin/hypopg",live)
        self.assertGreater(len(live),1)
        self.assertEqual(len(set(live)),len(live))

    def test_membership_rejects_duplicates_and_untrusted_repositories(self):
        data={"schemaVersion":1,"entries":[{"mode":"BUILD","candidateEnabled":True,
                                            "repository":"pgextwin/hypopg"}]}
        with TemporaryDirectory() as t:
            p=Path(t)/"fleet.json"
            p.write_text(json.dumps(data))
            self.assertEqual(mod.membership(p),["pgextwin/hypopg"])
            data["entries"].append(data["entries"][0])
            p.write_text(json.dumps(data))
            with self.assertRaises(mod.Denied): mod.membership(p)
            data["entries"][1]={"mode":"BUILD","candidateEnabled":True,
                                "repository":"rogue/hypopg"}
            p.write_text(json.dumps(data))
            with self.assertRaises(mod.Denied): mod.membership(p)

    def test_only_real_central_main_schedule_trusted(self):
        good={"GITHUB_EVENT_NAME":"schedule","GITHUB_REPOSITORY":"pgextwin/build",
              "GITHUB_REF":"refs/heads/main","GITHUB_SHA":"a"*40,"GH_TOKEN":"fixture"}
        with patch.dict(os.environ,good,clear=True),patch.object(mod,"gh_json",return_value={
              "name":"main","protected":True,"commit":{"sha":"a"*40}}):
            mod.central_schedule_gate()
        for key,invalid in (("GITHUB_EVENT_NAME","workflow_dispatch"),
                            ("GITHUB_EVENT_NAME","push"),
                            ("GITHUB_REPOSITORY","pgextwin/hypopg"),
                            ("GITHUB_REF","refs/heads/evil"),
                            ("GITHUB_SHA","b"*40),
                            ("GH_TOKEN","")):
            with self.subTest(key=key,value=invalid),patch.dict(os.environ,{**good,key:invalid},clear=True):
                with patch.object(mod,"gh_json",return_value={
                    "name":"main","protected":True,"commit":{"sha":"a"*40}}):
                    with self.assertRaises(mod.Denied): mod.central_schedule_gate()

    def test_no_candidate_is_empty_and_no_artifact_download(self):
        with patch.object(mod.recovery,"get_json",return_value=[]):
            self.assertIsNone(mod.recover_one("pgextwin/hypopg",{}))

    def test_jobless_approval_hold_uses_distinct_dispatch_suite(self):
        x,inv,api=dispatch_data()
        with self.assertRaisesRegex(mod.Denied,"not successfully completed"):
            mod.recovery.choose_candidate(fixtures.REPO,[x["pr"]],inv)
        with patch.object(mod,"gh_json",side_effect=lambda repo,path:api[path]):
            result=mod.dispatch_after_approval_hold(fixtures.REPO,[x["pr"]],inv,x["main"])
        self.assertEqual(result["candidateRunId"],fixtures.RUN+1)
        self.assertEqual(result["candidateCheckSuiteId"],800)
        self.assertEqual(result["blockedNativePrRunId"],fixtures.RUN)
        self.assertNotIn("packagingMergeSha",result)
        self.assertIn("NOT_NATIVE_PR",result["status"])
        self.assertFalse(result["publicationAuthorized"])
        self.assertFalse(result["signedArtifactsVerified"])

    def test_successful_native_still_reconciles_and_rehashes_merge_bytes(self):
        x=fixtures.fixture()
        inv={"total_count":1,"workflow_runs":[x["run"]]}
        api={"actions/runs/"+str(fixtures.RUN):x["run"],
             "commits/"+fixtures.SHA+"/pulls?per_page=100":fixtures.association(),
             "pulls/"+str(fixtures.PR):x["pr"],
             "pulls/"+str(fixtures.PR)+"/files?per_page=100":x["pr_files"],
             "git/ref/pull/"+str(fixtures.PR)+"/merge":x["merge_ref"],
             "branches/main":x["main"],
             "commits/"+fixtures.SHA+"/check-runs?per_page=100":x["checks"]}
        def download(args,**kwargs):
            from types import SimpleNamespace
            self.assertEqual(args[3],str(fixtures.RUN))
            for major in (14,15):
                artifacts.emit(Path(args[-1])/f"pg_ivm-pg{major}-windows-x64",major)
            return SimpleNamespace(returncode=0,stderr="")
        with patch.object(mod.recovery,"get_json",side_effect=lambda repo,path:
                          [x["pr"]] if path.startswith("pulls?") else inv),\
             patch.object(mod.native,"gh_get",side_effect=lambda repo,path:api[path]),\
             patch.object(mod,"gh_json",return_value=x["main"]),\
             patch.object(mod,"candidate_bytes",return_value=artifacts.EXT),\
             patch.object(mod.subprocess,"run",side_effect=download),\
             patch.object(mod,"dispatch_after_approval_hold",side_effect=AssertionError("native fallback")),\
             patch.dict(os.environ,{"GITHUB_SHA":"f"*40}):
            receipt=mod.recover_one(fixtures.REPO,artifacts.LIFECYCLE)
        self.assertIn("native",receipt)
        self.assertNotIn("dispatch",receipt)
        self.assertEqual(receipt["candidateAudit"]["originEvent"],"pull_request")
        self.assertEqual(receipt["native"]["packagingMergeSha"],fixtures.MERGE)
        self.assertEqual(receipt["candidateAudit"]["status"],"VERIFIED")

    def test_incomplete_failed_or_job_bearing_native_still_denied(self):
        for status,conclusion,jobs in (
            ("queued",None,[]),("in_progress",None,[]),("completed","failure",[]),
            ("completed","cancelled",[]),("completed","timed_out",[]),
            ("completed","action_required",[{"id":999}]),
        ):
            with self.subTest(status=status,conclusion=conclusion,jobs=jobs):
                x,inv,api=dispatch_data()
                inv["workflow_runs"][0].update(status=status,conclusion=conclusion)
                api["actions/runs/"+str(fixtures.RUN)+"/jobs?per_page=100"].update(
                    total_count=len(jobs),jobs=jobs)
                with self.assertRaises(mod.Denied):
                    mod.recovery.choose_candidate(fixtures.REPO,[x["pr"]],inv)
                with patch.object(mod,"gh_json",side_effect=lambda repo,path:api[path]):
                    with self.assertRaises(mod.Denied):
                        mod.dispatch_after_approval_hold(fixtures.REPO,[x["pr"]],inv,x["main"])

    def test_dispatch_forgery_missing_proof_and_stale_base_denied(self):
        for variant in ("head","repository","workflow","path","running","failure","missing",
                        "ambiguous","truncated","suite","app","check-head","check-url",
                        "check-failure","missing-required","duplicate-check","base","association",
                        "ownership","marker","native-changed","native-jobs-incomplete"):
            with self.subTest(variant=variant):
                x,inv,api=dispatch_data()
                run=api["actions/runs/"+str(fixtures.RUN+1)]
                dispatch_inv=api["actions/runs?event=workflow_dispatch&head_sha="+fixtures.SHA+"&per_page=100"]
                check=x["checks"]["check_runs"][0]
                if variant=="head":run["head_sha"]="f"*40
                elif variant=="repository":run["head_repository"]["full_name"]="evil/pg_ivm"
                elif variant=="workflow":run["workflow_id"]=71
                elif variant=="path":run["path"]=".github/workflows/other.yml"
                elif variant=="running":run["status"]="in_progress"
                elif variant=="failure":run["conclusion"]="failure"
                elif variant=="missing":dispatch_inv.update(total_count=0,workflow_runs=[])
                elif variant=="ambiguous":
                    dispatch_inv["workflow_runs"].append(deepcopy(run));dispatch_inv["total_count"]=2
                elif variant=="truncated":dispatch_inv["total_count"]=100
                elif variant=="suite":check["check_suite"]["id"]=700
                elif variant=="app":check["app"]["id"]=999
                elif variant=="check-head":check["head_sha"]="f"*40
                elif variant=="check-url":check["details_url"]="https://example.com/forged"
                elif variant=="check-failure":check["conclusion"]="failure"
                elif variant=="missing-required":check["name"]="other successful check"
                elif variant=="duplicate-check":
                    x["checks"]["check_runs"].append(deepcopy(check));x["checks"]["total_count"]=2
                elif variant=="base":x["pr"]["base"]["sha"]="f"*40
                elif variant=="association":api["commits/"+fixtures.SHA+"/pulls?per_page=100"]=[]
                elif variant=="ownership":x["pr"]["user"]["login"]="attacker"
                elif variant=="marker":x["pr"]["body"]="unowned"
                elif variant=="native-changed":
                    live=deepcopy(inv["workflow_runs"][0]);live["run_attempt"]=2
                    api["actions/runs/"+str(fixtures.RUN)]=live
                elif variant=="native-jobs-incomplete":
                    api["actions/runs/"+str(fixtures.RUN)+"/jobs?per_page=100"]["total_count"]=1
                with patch.object(mod,"gh_json",side_effect=lambda repo,path:api[path]):
                    with self.assertRaises(mod.Denied):
                        mod.dispatch_after_approval_hold(fixtures.REPO,[x["pr"]],inv,x["main"])

    def test_fleet_rehashes_dispatch_bytes_without_native_merge_relabel(self):
        # Exercise the actual existing ZIP auditor, including its event/ref/SHA
        # distinction. A dispatch cannot satisfy the native postmerge binder.
        for corrupt in (False,True):
            with self.subTest(corrupt=corrupt):
                x,inv,api=dispatch_data()
                def discovery(repo,path):
                    return [x["pr"]] if path.startswith("pulls?") else inv
                def download(args,**kwargs):
                    from types import SimpleNamespace
                    root=Path(args[-1])
                    self.assertEqual(args[3],str(fixtures.RUN+1))
                    for major in (14,15):
                        artifacts.emit(root/f"pg_ivm-pg{major}-windows-x64",major,
                            event="workflow_dispatch",packaging=fixtures.SHA,
                            run_id=fixtures.RUN+1,ref="refs/heads/"+fixtures.BRANCH)
                    if corrupt:
                        (root/"pg_ivm-pg14-windows-x64/file.spdx.json").unlink()
                    return SimpleNamespace(returncode=0,stderr="")
                with patch.object(mod.recovery,"get_json",side_effect=discovery),\
                     patch.object(mod,"gh_json",side_effect=lambda repo,path:api[path]),\
                     patch.object(mod,"candidate_bytes",return_value=artifacts.EXT),\
                     patch.object(mod.subprocess,"run",side_effect=download),\
                     patch.dict(os.environ,{"GITHUB_SHA":"f"*40}):
                    if corrupt:
                        with self.assertRaisesRegex(mod.Denied,"byte audit failed"):
                            mod.recover_one(fixtures.REPO,artifacts.LIFECYCLE)
                        continue
                    receipt=mod.recover_one(fixtures.REPO,artifacts.LIFECYCLE)
                self.assertNotIn("native",receipt)
                self.assertIn("dispatch",receipt)
                self.assertEqual(receipt["candidateAudit"]["originEvent"],"workflow_dispatch")
                self.assertEqual(receipt["candidateAudit"]["status"],"VERIFIED")
                self.assertTrue(all(len(r["zipSha256"])==64 for r in receipt["candidateAudit"]["majors"]))
                binder=mod.load("fleet_binder","scripts/bind-native-candidate-audit.py")
                with self.assertRaises(binder.Denied):
                    binder.join(context=receipt["dispatch"],audit=receipt["candidateAudit"],
                        ext=artifacts.EXT,lifecycle=artifacts.LIFECYCLE,ci_run={},audit_run={},
                        artifact={},repository=fixtures.REPO,current_main_sha=fixtures.BASE)

    def test_workflow_is_exact_schedule_and_nonprivileged(self):
        src=(ROOT/".github/workflows/recover-native-pr-fleet.yml").read_text()
        self.assertIn('cron: "47 * * * *"',src)
        self.assertIn("github.event_name == 'schedule'",src)
        self.assertIn("actions: read",src)
        self.assertNotIn("workflow_dispatch:",src)
        self.assertNotIn("contents: write",src)
        self.assertNotIn("id-token: write",src)
        self.assertNotIn("attestations: write",src)
        # The first :47 schedule may be dropped by GitHub. Reuse the
        # established scanner's true schedule without granting any publish
        # rights or accepting its push/dispatch smoke as an audit.
        fallback=(ROOT/".github/workflows/fleet-upstream-watch.yml").read_text()
        self.assertIn("original-native-audit-fallback:",fallback)
        self.assertIn("github.event_name == 'schedule'",fallback)
        self.assertIn("python scripts/recover-native-pr-fleet.py",fallback)
        self.assertIn("registered-original-native-pr-audits",fallback)
        self.assertNotIn("contents: write",fallback)
        self.assertNotIn("id-token: write",fallback)
        code=(ROOT/"scripts/recover-native-pr-fleet.py").read_text()
        self.assertIn("recovery.reconcile(",code)
        self.assertIn("candidate.audit(",code)
        self.assertNotIn("gh pr merge",code)
        self.assertNotIn("gh workflow run",code)

if __name__=="__main__":main()
