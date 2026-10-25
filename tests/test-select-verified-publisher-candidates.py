#!/usr/bin/env python3
"""Proof selection is read-only; failed peers never enter Publisher Environment."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
m=load("verified_selector_test","scripts/select-verified-publisher-candidates.py")
fixtures=load("verified_selector_fixtures","tests/test-automatic-publisher-receipt-issuer.py")
SHA=fixtures.CENTRAL_SHA;RUN=fixtures.SCHEDULE_RUN
R1=fixtures.REPO;R2="pgextwin/hypopg"

def inputs():
    f=fixtures.switched()
    candidates=[{"repository":repo,"name":repo.split("/")[1],
                 "sha":str(i)*40,"source_run":i+100}
                for i,repo in enumerate((R1,R2),1)]
    jobs=fixtures.independent_jobs()
    jobs["jobs"][1].update(id=222,run_id=RUN,run_attempt=1,head_sha=SHA,
        name="Fresh independent ZIP/SPDX/Grype/Sigstore GET for signed original (hypopg)")
    return dict(candidates=candidates,fleet=f["fleet"],jobs=jobs,
                run=f["schedule_run"],branch=f["central_branch"],sha=SHA,run_id=RUN)

class VerifiedSelector(unittest.TestCase):
    def test_verified_peer_proceeds_after_other_repository_fails(self):
        args=inputs()
        self.assertEqual(m.select(**args),[args["candidates"][0]])
        args["jobs"]["jobs"][1]["conclusion"]="success"
        self.assertEqual(m.select(**args),args["candidates"])

    def test_failed_skipped_replayed_and_forged_rows_never_enter_environment(self):
        for change in (
            lambda j:j.update(conclusion="failure"),
            lambda j:j.update(conclusion="skipped"),
            lambda j:j.update(status="in_progress"),
            lambda j:j.update(name="another-source"),
            lambda j:j.update(run_id=RUN+1),
            lambda j:j.update(run_attempt=2),
            lambda j:j.update(run_attempt=True),
            lambda j:j.update(head_sha="d"*40),
        ):
            args=inputs();change(args["jobs"]["jobs"][0])
            with self.subTest(change=str(change)):
                self.assertEqual(m.select(**args),[])

    def test_missing_or_ambiguous_proof_is_never_selected(self):
        args=inputs();args["jobs"]["jobs"].pop(0);args["jobs"]["total_count"]=1
        self.assertEqual(m.select(**args),[])
        args=inputs();duplicate=copy.deepcopy(args["jobs"]["jobs"][0])
        duplicate["id"]=333;args["jobs"]["jobs"].append(duplicate)
        args["jobs"]["total_count"]=3
        self.assertEqual(m.select(**args),[])

    def test_inventory_and_candidate_forgery_fail_closed(self):
        for change in (
            lambda a:a["jobs"].update(total_count=100),
            lambda a:a["jobs"].update(total_count=3),
            lambda a:a["jobs"]["jobs"][1].update(id=111),
            lambda a:a["jobs"]["jobs"][1].update(id=True),
            lambda a:a["candidates"].append(copy.deepcopy(a["candidates"][0])),
            lambda a:a["candidates"][0].update(repository="pgextwin/unknown"),
            lambda a:a["candidates"][0].update(name="hypopg"),
            lambda a:a["candidates"][0].update(sha="c"*39),
            lambda a:a["candidates"][0].update(source_run=True),
            lambda a:a["candidates"][0].update(source_run=RUN),
            lambda a:a["candidates"][0].update(publicationAuthorized=True),
        ):
            args=inputs();change(args)
            with self.subTest(change=str(change)),self.assertRaises(m.Denied):
                m.select(**args)

    def test_wrong_run_policy_main_or_event_cannot_select_anything(self):
        for change in (
            lambda a:a["run"].update(event="workflow_dispatch"),
            lambda a:a["run"].update(path=".github/workflows/fleet-status.yml"),
            lambda a:a["run"].update(id=RUN+1),
            lambda a:a["run"].update(run_attempt=2),
            lambda a:a["run"].update(head_sha="b"*40),
            lambda a:a["run"].update(status="completed",conclusion="success"),
            lambda a:a["run"].update(repository={"full_name":"pgextwin/hypopg"}),
            lambda a:a["branch"].update(protected=False),
            lambda a:a["branch"].update(commit={"sha":"b"*40}),
        ):
            args=inputs();change(args)
            with self.subTest(change=str(change)),self.assertRaises(m.Denied):
                m.select(**args)
        args=inputs();args["fleet"]["releasePolicy"]="manual-only"
        for row in args["fleet"]["entries"]:row["releasePolicy"]="manual-only"
        with self.assertRaises(m.Denied):m.select(**args)

    def test_live_reads_real_run_jobs_and_rechecks_identity(self):
        args=inputs();calls=[]
        env={"GITHUB_REPOSITORY":"pgextwin/build","GITHUB_EVENT_NAME":"schedule",
             "GITHUB_REF":"refs/heads/main","GITHUB_RUN_ATTEMPT":"1",
             "GITHUB_SHA":SHA,"GITHUB_RUN_ID":str(RUN),"GH_TOKEN":"unit-read-only"}
        def get(repo,path):
            calls.append((repo,path))
            if repo==R1:
                if path=="branches/main":return {"name":"main","protected":True,
                    "commit":{"sha":args["candidates"][0]["sha"]}}
                return {"id":args["candidates"][0]["source_run"],"run_attempt":1,
                    "event":"push","path":m.issuer.SOURCE,
                    "head_sha":args["candidates"][0]["sha"],"head_branch":"main",
                    "repository":{"full_name":R1},"status":"completed","conclusion":"success"}
            if path=="branches/main":return args["branch"]
            if path==f"actions/runs/{RUN}":return args["run"]
            self.assertEqual(path,f"actions/runs/{RUN}/attempts/1/jobs?per_page=100")
            return args["jobs"]
        self.assertEqual(m.live(args["candidates"],args["fleet"],env=env,get=get),
                         [args["candidates"][0]])
        self.assertEqual(len(calls),7)
        self.assertEqual(len([repo for repo,_ in calls if repo==R1]),2)
        env["GITHUB_EVENT_NAME"]="workflow_dispatch";calls.clear()
        with self.assertRaises(m.Denied):
            m.live(args["candidates"],args["fleet"],env=env,get=get)
        self.assertEqual(calls,[])

    def test_source_advanced_or_failed_after_independent_proof_is_excluded(self):
        args=inputs()
        env={"GITHUB_REPOSITORY":"pgextwin/build","GITHUB_EVENT_NAME":"schedule",
             "GITHUB_REF":"refs/heads/main","GITHUB_RUN_ATTEMPT":"1",
             "GITHUB_SHA":SHA,"GITHUB_RUN_ID":str(RUN),"GH_TOKEN":"unit-read-only"}
        for advanced in (True,False):
            def get(repo,path):
                if repo==R1:
                    if path=="branches/main":return {"name":"main","protected":True,
                        "commit":{"sha":"f"*40 if advanced else args["candidates"][0]["sha"]}}
                    return {"id":args["candidates"][0]["source_run"],"run_attempt":1,
                        "event":"push","path":m.issuer.SOURCE,
                        "head_sha":args["candidates"][0]["sha"],"head_branch":"main",
                        "repository":{"full_name":R1},"status":"completed","conclusion":"failure"}
                if path=="branches/main":return args["branch"]
                if path==f"actions/runs/{RUN}":return args["run"]
                return args["jobs"]
            with self.subTest(advanced=advanced):
                self.assertEqual(m.live(args["candidates"],args["fleet"],env=env,get=get),[])

    def test_dynamic_registered_future_repository_requires_its_own_real_proof(self):
        args=inputs();name="pgextwin/future_extension"
        args["fleet"]["entries"].append({"repository":name,"mode":"BUILD",
            "candidateEnabled":True,"releasePolicy":m.issuer.MODE})
        row={"repository":name,"name":"future_extension","sha":"e"*40,"source_run":777}
        args["candidates"].append(row)
        self.assertEqual(m.select(**args),[args["candidates"][0]])
        args["jobs"]["jobs"].append({"id":444,"run_id":RUN,"run_attempt":1,
            "head_sha":SHA,"status":"completed","conclusion":"success",
            "name":"Fresh independent ZIP/SPDX/Grype/Sigstore GET for signed original (future_extension)"})
        args["jobs"]["total_count"]+=1
        self.assertEqual(m.select(**args),[args["candidates"][0],row])

if __name__=="__main__":unittest.main()
