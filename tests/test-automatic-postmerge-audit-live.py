#!/usr/bin/env python3
"""Denial suite for first real native main-push artifact binding (no publishing)."""
import base64
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "live", ROOT/"scripts"/"automatic-postmerge-audit-live.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

REPO="pgextwin/pg_ivm"
OLD,NEW,HEAD,BLOB,SYNTH = "a"*40,"b"*40,"c"*40,"d"*40,"e"*40
SOURCE = "678c37861080aa221b859cefaca98725646dbf7c"
BRANCH = "auto-candidate/"+"f"*20
CI,AUDIT,ART,PR=123,124,125,28
FLEET=json.loads((ROOT/"metadata/automation-fleet.json").read_text("utf-8"))
LIFE={"schemaVersion":1,"postgresql":[
    {"major":m,"eol":"2030-11-12"} for m in range(14,19)]}


def fixture():
    ext={"name":"pg_ivm","postgresql":{"majors":list(range(14,19))},
         "upstream":{"repository":"sraoss/pg_ivm","ref":"v1.17",
                     "version":"1.17","commit":SOURCE}}
    event={"ref":"refs/heads/main","repository":{"full_name":REPO},
           "sender":{"login":"ShutenOishi"},"created":False,
           "deleted":False,"before":OLD,"after":NEW,
           "commits":[{"id":NEW}]}
    context={"schemaVersion":1,
             "status":"NATIVE_PR_CI_AUTHENTICATED_NOT_PUBLISHABLE",
             "repository":REPO,"candidatePr":PR,"candidateHeadSha":HEAD,
             "branch":BRANCH,"packagingMergeSha":SYNTH,
             "candidateRunId":CI,"matrixResult":"success",
             "candidateAuditVerified":False,
             "signedArtifactsVerified":False,
             "publishableReceipt":False,"publicationAuthorized":False}
    audit={"schemaVersion":1,"extension":"pg_ivm","runId":CI,
           "branch":BRANCH,"branchSha":HEAD,"originEvent":"pull_request",
           "matrixResult":"success","status":"VERIFIED",
           "majors":[{"major":m,"status":"SUCCESS","sourceSha":SOURCE,
                      "zipSha256":"0"*64,
                      "zip":f"pg_ivm-v1.17-pg{m}-windows-x64.zip",
                      "sbom":f"pg_ivm-v1.17-pg{m}-windows-x64.spdx.json",
                      "grype":f"pg_ivm-v1.17-pg{m}-windows-x64.vulnerabilities.json"}
                     for m in range(14,19)]}
    p="config/extension.json"
    artifact={"id":ART,"name":"candidate-audit-native-pr",
              "size_in_bytes":1500,"expired":False,
              "workflow_run":{"id":AUDIT}}
    entries={
        "commits/"+NEW:{"sha":NEW,"parents":[{"sha":OLD}],
                        "files":[{"filename":p,"status":"modified","sha":BLOB}]},
        "commits/"+NEW+"/pulls?per_page=100":[{"number":PR}],
        "pulls/"+str(PR):{"number":PR,"state":"closed","merged":True,"draft":False,
            "user":{"login":"github-actions[bot]"},
            "merged_by":{"login":"ShutenOishi"},
            "merge_commit_sha":NEW,
            "head":{"sha":HEAD,"ref":BRANCH,"repo":{"full_name":REPO}},
            "base":{"ref":"main","repo":{"full_name":REPO}},
            "body":"<!-- pgextwin-candidate:v1:"+"f"*20+" -->"},
        "pulls/"+str(PR)+"/files?per_page=100":[
            {"filename":p,"status":"modified","sha":BLOB}],
        "branches/main":{"name":"main","protected":True,
                         "commit":{"sha":NEW},
                         "protection":{"required_status_checks":{"checks":[
                            {"context":"Windows required summary","app_id":15368}]}}},
        "commits/"+HEAD+"/check-runs?per_page=100":{
            "total_count":1,"check_runs":[{
                "name":"Windows required summary","head_sha":HEAD,
                "status":"completed","conclusion":"success","app":{"id":15368}}]},
        "contents/config/extension.json?ref="+NEW:{
            "path":p,"encoding":"base64","sha":BLOB,
            "content":base64.b64encode(json.dumps(ext).encode()).decode()},
        "actions/runs?event=workflow_run&head_sha="+OLD+"&per_page=100":{
            "total_count":1,"workflow_runs":[{
                "id":AUDIT,"name":"Upstream candidate after verified central daily fleet scan",
                "path":".github/workflows/update-watch.yml",
                "event":"workflow_run","status":"completed","conclusion":"success",
                "head_sha":OLD,"head_branch":"main"}]},
        "actions/runs/"+str(AUDIT)+"/artifacts?per_page=100":{
            "total_count":1,"artifacts":[artifact]},
        "actions/runs/"+str(CI):{"id":CI,"name":"Windows CI/CD",
            "head_repository":{"full_name":REPO},"head_branch":BRANCH,
            "head_sha":HEAD,"event":"pull_request",
            "status":"completed","conclusion":"success"},
    }
    return event,entries,context,audit


class NativePostmergeLiveTests(unittest.TestCase):
    def verify(self,mutate=None):
        event,dicts,context,audit=fixture()
        if mutate: mutate(event,dicts,context,audit)
        def api(repo,endpoint):
            if repo!=REPO: raise AssertionError("unexpected repo")
            return deepcopy(dicts[endpoint])
        def retrieve(run,a):
            self.assertEqual(run["id"],AUDIT)
            self.assertEqual(a["id"],ART)
            return deepcopy(context),deepcopy(audit)
        return mod.live(REPO,event,deepcopy(FLEET),deepcopy(LIFE),
                        auth_api=api,retrieve=retrieve)

    def test_exact_main_push_and_real_original_audit_stay_nonpublishing(self):
        v=self.verify()
        self.assertEqual(v["status"],"MERGED_NATIVE_CANDIDATE_NONPUBLISHING")
        self.assertEqual(v["nativeAuditArtifactId"],ART)
        self.assertEqual(v["candidateCiRunId"],CI)
        self.assertEqual(v["mainParentAtAudit"],OLD)
        for k in ("signedArtifactsVerified","publishableReceipt",
                  "publicationAuthorized","automaticReleaseEnabled"):
            self.assertIs(v[k],False)

    def test_forged_main_push_and_cross_run_artifacts_fail_closed(self):
        changes=[
            lambda e,d,c,a:e.update(ref="refs/heads/feature"),
            lambda e,d,c,a:e.update(before="f"*40),
            lambda e,d,c,a:e["sender"].update(login="github-actions[bot]"),
            lambda e,d,c,a:e.update(commits=[]),
            lambda e,d,c,a:d["commits/"+NEW].update(parents=[{"sha":HEAD}]),
            lambda e,d,c,a:d["pulls/"+str(PR)].update(merged=False),
            lambda e,d,c,a:d["pulls/"+str(PR)].update(draft=True),
            lambda e,d,c,a:d["pulls/"+str(PR)]["user"].update(login="rogue"),
            lambda e,d,c,a:d["pulls/"+str(PR)]["head"].update(sha=OLD),
            lambda e,d,c,a:d["pulls/"+str(PR)+"/files?per_page=100"].append(
                {"filename":".github/workflows/promote.yml","status":"modified","sha":BLOB}),
            lambda e,d,c,a:d["branches/main"].update(protected=False),
            lambda e,d,c,a:d["branches/main"]["protection"]["required_status_checks"].update(checks=[]),
            lambda e,d,c,a:d["commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0].update(conclusion="failure"),
            lambda e,d,c,a:d["contents/config/extension.json?ref="+NEW].update(sha=HEAD),
            lambda e,d,c,a:d["actions/runs?event=workflow_run&head_sha="+OLD+"&per_page=100"].update(total_count=100),
            lambda e,d,c,a:d["actions/runs?event=workflow_run&head_sha="+OLD+"&per_page=100"]["workflow_runs"][0].update(conclusion="failure"),
            lambda e,d,c,a:d["actions/runs/"+str(AUDIT)+"/artifacts?per_page=100"]["artifacts"][0].update(expired=True),
            lambda e,d,c,a:d["actions/runs/"+str(AUDIT)+"/artifacts?per_page=100"]["artifacts"].append(
                deepcopy(d["actions/runs/"+str(AUDIT)+"/artifacts?per_page=100"]["artifacts"][0])),
            lambda e,d,c,a:c.update(candidateHeadSha=OLD),
            lambda e,d,c,a:c.update(publishableReceipt=True),
            lambda e,d,c,a:a["majors"][0].update(sourceSha=HEAD),
            lambda e,d,c,a:a["majors"].pop(),
            lambda e,d,c,a:d["actions/runs/"+str(CI)].update(conclusion="action_required"),
        ]
        for i,change in enumerate(changes):
            with self.subTest(case=i),self.assertRaises(mod.Denied):
                self.verify(change)

    def test_duplicate_and_paginated_run_inventories_are_rejected(self):
        run={"id":13,"status":"completed","conclusion":"success",
             "name":"Upstream candidate after verified central daily fleet scan",
             "path":".github/workflows/update-watch.yml","event":"workflow_run"}
        for args in ({"total_count":100,"workflow_runs":[run]},
                     {"total_count":2,"workflow_runs":[run]},
                     {"total_count":2,"workflow_runs":[run,run]}):
            with self.subTest(args=args),self.assertRaises(mod.Denied):
                mod.audit_inventory(args)
        art={"id":5,"name":"candidate-audit-native-pr",
             "expired":False,"workflow_run":{"id":13}}
        with self.assertRaises(mod.Denied):
            mod.eligible_artifact({"total_count":2,"artifacts":[art,art]},13)

    def test_gh_allowlist_does_not_touch_network_for_invalid_paths(self):
        for suffix in ("git/refs", "releases", "actions/runs/0",
                       "contents/.github/workflows/promote.yml",
                       "commits/"+HEAD+"/check-runs?per_page=100&evil=true"):
            with self.subTest(suffix=suffix),self.assertRaises(mod.Denied):
                mod.gh(REPO,suffix)


if __name__ == "__main__":
    unittest.main()
