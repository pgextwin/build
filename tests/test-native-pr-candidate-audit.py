#!/usr/bin/env python3
"""Hostile fixture suite for native PR Windows CI authentication."""
import importlib.util
from copy import deepcopy
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "native", ROOT/"scripts"/"verify-native-pr-run.py")
native=importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
SHA="a"*40
MERGE="b"*40
BASE="c"*40
REPO="pgextwin/pg_ivm"
BRANCH="auto-candidate/"+"d"*20
PR=28
RUN=39760879597

def fixture():
    return dict(
        repo=REPO,
        run={"id":RUN,"name":"Windows CI/CD","event":"pull_request",
             "status":"completed","conclusion":"success",
             "head_repository":{"full_name":REPO},
             "head_sha":SHA,"head_branch":BRANCH,
             "pull_requests":[{"number":PR,
                                "head":{"ref":BRANCH,"sha":SHA,
                                        "repo":{"name":"pg_ivm"}},
                                "base":{"ref":"main","sha":BASE,
                                        "repo":{"name":"pg_ivm"}}}]},
        pr={"number":PR,"state":"open","merged":False,"draft":True,
            "body":"<!-- pgextwin-candidate:v1:"+"d"*20+" -->",
            "head":{"ref":BRANCH,"sha":SHA,"repo":{"full_name":REPO}},
            "base":{"ref":"main","sha":BASE,"repo":{"full_name":REPO}},
            "user":{"login":"github-actions[bot]"},
            "merge_commit_sha":MERGE},
        pr_files=[{"filename":"config/extension.json",
                   "status":"modified","sha":"e"*40}],
        merge_ref={"object":{"type":"commit","sha":MERGE}},
        main={"name":"main","protected":True,"commit":{"sha":BASE},
              "protection":{"required_status_checks":{"checks":[
                  {"context":"Windows required summary","app_id":15368}]}}},
        checks={"total_count":1,"check_runs":[
            {"name":"Windows required summary","head_sha":SHA,
             "app":{"id":15368},"status":"completed","conclusion":"success"}]}
    )

def association():
    return [{"number":PR,
             "head":{"sha":SHA,"ref":BRANCH,"repo":{"full_name":REPO}},
             "base":{"ref":"main","repo":{"full_name":REPO}}}]

class NativeRunTests(unittest.TestCase):
    def test_pass_is_not_release_authorization(self):
        x=native.validate(**fixture())
        self.assertEqual(x["status"],"NATIVE_PR_CI_AUTHENTICATED_NOT_PUBLISHABLE")
        self.assertEqual(x["packagingMergeSha"],MERGE)
        self.assertEqual(x["candidateRunId"],RUN)
        for field in ("candidateAuditVerified","signedArtifactsVerified",
                      "publishableReceipt","publicationAuthorized"):
            self.assertIs(x[field],False)

    def test_empty_real_run_pr_inventory_with_independent_exact_head_join(self):
        # GitHub actually returned pull_requests=[] for HypoPG PR #37
        # Windows Run 40185975511 while the independent commit PR API
        # returned a single, correct matching PR.
        values=fixture()
        values["run"]["pull_requests"]=[]
        values["associated_pulls"]=association()
        output=native.validate(**values)
        self.assertEqual(output["candidatePr"],PR)
        self.assertEqual(output["candidateHeadSha"],SHA)
        self.assertFalse(output["publicationAuthorized"])
        self.assertFalse(output["signedArtifactsVerified"])

    def test_independent_association_must_be_unique_and_exact(self):
        for kind in ("missing","duplicate","number","sha","ref",
                     "head-repo","base-ref","base-repo","invalid-object"):
            with self.subTest(kind=kind),self.assertRaises(native.Denied):
                values=fixture()
                values["run"]["pull_requests"]=[]
                associated=association()
                if kind=="missing":
                    associated=[]
                elif kind=="duplicate":
                    associated.append(deepcopy(associated[0]))
                elif kind=="number":
                    associated[0]["number"]=PR+1
                elif kind=="sha":
                    associated[0]["head"]["sha"]=MERGE
                elif kind=="ref":
                    associated[0]["head"]["ref"]="auto-candidate/"+"f"*20
                elif kind=="head-repo":
                    associated[0]["head"]["repo"]["full_name"]="attacker/hypopg"
                elif kind=="base-ref":
                    associated[0]["base"]["ref"]="release/bypass"
                elif kind=="base-repo":
                    associated[0]["base"]["repo"]["full_name"]="attacker/hypopg"
                elif kind=="invalid-object":
                    associated=[None]
                values["associated_pulls"]=associated
                native.validate(**values)

    def test_run_metadata_disagreement_not_overridden_by_good_association(self):
        values=fixture()
        values["associated_pulls"]=association()
        values["run"]["pull_requests"][0]["number"]=999
        with self.assertRaises(native.Denied):
            native.validate(**values)

    def test_live_get_allowlist_is_exact_and_read_only(self):
        script=(ROOT/"scripts"/"verify-native-pr-run.py").read_text()
        self.assertIn('commits/[a-f0-9]{40}/pulls\\?per_page=100',script)
        self.assertIn('associated=gh_get(repo,"commits/"+run["head_sha"]+',script)
        self.assertNotIn("pull_request_target",script)
        self.assertNotIn("gh pr create",script)
        self.assertNotIn("gh pr merge",script)
        self.assertNotIn("publicationAuthorized\":True",script)

    def test_forged_ci_and_pr_provenance_denied(self):
        mutations=[
            lambda x:x.update(repo="evil/pg_ivm"),
            lambda x:x["run"].update(event="workflow_dispatch"),
            lambda x:x["run"].update(status="queued"),
            lambda x:x["run"].update(conclusion="failure"),
            lambda x:x["run"].update(head_sha=MERGE),
            lambda x:x["run"].update(head_branch="main"),
            lambda x:x["run"].update(pull_requests=[]),
            lambda x:x["run"]["pull_requests"].append(
                deepcopy(x["run"]["pull_requests"][0])),
            lambda x:x["run"]["head_repository"].update(full_name="evil/repo"),
            lambda x:x["run"]["pull_requests"][0].update(number=999),
            lambda x:x["pr"].update(merged=True),
            lambda x:x["pr"].update(state="closed"),
            lambda x:x["pr"].update(merge_commit_sha=SHA),
            lambda x:x["pr"].update(body=""),
            lambda x:x["pr"].update(number=0),
            lambda x:x["pr"]["head"].update(sha=MERGE),
            lambda x:x["pr"]["head"].update(ref="untrusted"),
            lambda x:x["pr"]["base"].update(ref="release/bypass"),
            lambda x:x["pr"]["user"].update(login="attacker"),
            lambda x:x["pr_files"].append(
                {"filename":".github/workflows/promote.yml",
                 "sha":"f"*40,"status":"modified"}),
            lambda x:x["pr_files"][0].update(filename="config/approval.json"),
            lambda x:x["pr_files"][0].update(status="added"),
            lambda x:x["merge_ref"]["object"].update(sha=SHA),
            lambda x:x["merge_ref"]["object"].update(type="tag"),
            lambda x:x["main"].update(protected=False),
            lambda x:x["main"]["commit"].update(sha=MERGE),
            lambda x:x["main"]["protection"]["required_status_checks"].update(checks=[]),
            lambda x:x["main"]["protection"]["required_status_checks"]["checks"][0].update(app_id=999),
            lambda x:x["checks"].update(total_count=100),
            lambda x:x["checks"]["check_runs"][0].update(head_sha=MERGE),
            lambda x:x["checks"]["check_runs"][0].update(conclusion="action_required"),
            lambda x:x["checks"]["check_runs"][0].update(status="in_progress"),
            lambda x:x["checks"]["check_runs"][0]["app"].update(id=999),
            lambda x:x["checks"]["check_runs"].append(
                deepcopy(x["checks"]["check_runs"][0])),
        ]
        for i,mutate in enumerate(mutations):
            with self.subTest(i=i),self.assertRaises(native.Denied):
                values=fixture()
                mutate(values)
                native.validate(**values)

if __name__=="__main__":
    unittest.main()
