#!/usr/bin/env python3
"""Offline main-only/manual-dispatch promotion fail-closed tests. No API mutation."""
import importlib.util
from pathlib import Path
import copy
import unittest
from unittest.mock import patch

p = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "historical-scripts" / "promotion-gate.py"
spec = importlib.util.spec_from_file_location("promotion_gate", p)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

COMMIT = "a" * 40
MAIN = "b" * 40
HEAD = "c" * 40
IDENT = "d" * 20
TAG = "v2.10.14-windows.1"

def fixtures():
    policy = {"schemaVersion":1,"allowedRepositories":[g.REPO],"releasePolicy":"manual-dispatch"}
    local = {"schemaVersion":1,"enabled":True,"releasePolicy":"manual-dispatch"}
    ext = {"name":"plpgsql_check","upstream":{"repository":"okbob/plpgsql_check",
           "ref":"v2.10.14","version":"2.10.14","commit":COMMIT},
           "postgresql":{"majors":[15,16,17,18]}}
    lifecycle = {"schemaVersion":1,"postgresql":
                 [{"major":m,"eol":"2099-11-12"} for m in [14,15,16,17,18,19]]}
    branch = "auto-candidate/" + IDENT
    candidate_pr = {"number":123,"head":{"ref":branch,"sha":HEAD},
                    "body":"<!-- pgextwin-candidate:v1:" + IDENT + " -->",
                    "user":{"login":"github-actions[bot]"}}
    candidate_run = {"id":555,"status":"completed","conclusion":"success",
                     "event":"workflow_dispatch","head_branch":branch,"head_sha":HEAD}
    decision_run = {"id":444,"status":"completed","conclusion":"success",
                    "head_branch":"main"}
    decision = {"schemaVersion":1,"status":"candidate","branch":branch,
                "candidateId":IDENT,"extension":"plpgsql_check",
                "repository":"okbob/plpgsql_check","releasePolicy":"manual-only",
                "updates":[{"major":None,"commit":COMMIT,"ref":"v2.10.14","version":"2.10.14"}]}
    audit = {"schemaVersion":1,"status":"VERIFIED","matrixResult":"success",
             "extension":"plpgsql_check","runId":555,"branch":branch,
             "branchSha":HEAD,"majors":[
                {"major":m,"status":"SUCCESS","sourceSha":COMMIT,
                 "zipSha256":"f"*64,"zip":"x.zip","sbom":"x.spdx.json",
                 "grype":"x.vulnerabilities.json"} for m in [15,16,17,18]]}
    return [policy,local,ext,lifecycle,decision,audit,candidate_pr,
            candidate_run,decision_run,MAIN,TAG,"ShutenOishi","PUBLISH"]

class Promotion(unittest.TestCase):
    def test_matching_manual_candidate_allowed_without_independent_review_or_approval_json(self):
        receipt = g.verify(*fixtures())
        self.assertEqual(receipt["status"],"VERIFIED_MANUAL_DISPATCH")
        self.assertEqual(receipt["authorizationMode"],"manual-dispatch")
        self.assertEqual(receipt["operator"],"ShutenOishi")
        self.assertEqual(receipt["candidateRunId"],555)
        self.assertNotIn("approvalPr",receipt)

    def test_denial_matrix(self):
        changes = {
            "no-manual-confirmation":(12,lambda x:None), # independently tested below
            "central-policy-off":(0,lambda x:x.update(allowedRepositories=[])),
            "central-policy-old":(0,lambda x:x.update(releasePolicy="manual-approval")),
            "local-off":(1,lambda x:x.update(enabled=False)),
            "wrong-upstream":(2,lambda x:x["upstream"].update(commit="e"*40)),
            "missing-major":(5,lambda x:x["majors"].pop()),
            "duplicate-major":(5,lambda x:x["majors"][3].update(major=17)),
            "bad-spdx":(5,lambda x:x["majors"][0].update(sbom="")),
            "no-verified-audit":(5,lambda x:x.update(status="FAILED")),
            "audit-wrong-run":(5,lambda x:x.update(runId=900)),
            "not-a-bot-candidate":(6,lambda x:x["user"].update(login="ordinary-user")),
            "not-owned":(6,lambda x:x.update(body="hi")),
            "candidate-ci-failed":(7,lambda x:x.update(conclusion="failure")),
            "candidate-ci-event-wrong":(7,lambda x:x.update(event="pull_request")),
            "candidate-ci-sha-wrong":(7,lambda x:x.update(head_sha="f"*40)),
            "watch-ci-failed":(8,lambda x:x.update(conclusion="failure")),
            "PG19-included":(2,lambda x:x["postgresql"]["majors"].append(19)),
            "decision-sha-changed":(4,lambda x:x["updates"][0].update(commit="c"*40)),
        }
        changes.pop("no-manual-confirmation")
        for name,(index,change) in changes.items():
            with self.subTest(name=name):
                f = fixtures()
                change(f[index])
                with self.assertRaises(g.Denied):
                    g.verify(*f)

    def test_explicit_operator_confirmation_cannot_be_omitted_or_bot(self):
        for operator,ack in [("ShutenOishi",""),("ShutenOishi","YES"),
                             ("github-actions[bot]","PUBLISH"),("dependabot","PUBLISH"),
                             ("","PUBLISH")]:
            with self.subTest(operator=operator,ack=ack):
                f=fixtures()
                f[11]=operator
                f[12]=ack
                with self.assertRaises(g.Denied):
                    g.verify(*f)

    def test_release_tag_must_match_version(self):
        f=fixtures()
        f[10]="v2.10.13-windows.1"
        with self.assertRaises(g.Denied):
            g.verify(*f)

    def test_postgresql14_supported_with_matching_full_matrix(self):
        f=fixtures()
        f[2]["postgresql"]["majors"]=[14,15,16,17,18]
        sample=dict(f[5]["majors"][0])
        sample["major"]=14
        f[5]["majors"].insert(0,sample)
        self.assertEqual(g.verify(*f)["majors"],[14,15,16,17,18])

    def test_postgresql14_eol_excludes_major(self):
        f=fixtures()
        f[2]["postgresql"]["majors"]=[14,15,16,17,18]
        f[3]["postgresql"][0]["eol"]="2000-01-01"
        self.assertEqual(g.verify(*f)["majors"],[15,16,17,18])

    def test_merged_bot_candidate_needs_main_ancestry_and_manifest_only_not_review(self):
        pr={"number":123,"merged":True,"state":"closed",
            "base":{"ref":"main"},"merged_at":"2026-10-11T07:00:00Z",
            "merge_commit_sha":"e"*40,
            "head":{"ref":"auto-candidate/"+IDENT,"sha":HEAD},
            "user":{"login":"github-actions[bot]"}}
        seen=[]
        def fake_api(path):
            seen.append(path)
            if "/files?" in path:
                return [{"filename":"config/extension.json"}]
            if "/pulls/" in path:
                return pr
            raise AssertionError("unexpected endpoint: "+path)
        with patch.object(g,"api",side_effect=fake_api),patch.object(g,"command",return_value=""):
            self.assertEqual(g.merged_pr(123,MAIN,"config/extension.json",True),pr)
        self.assertFalse(any("reviews" in x for x in seen))
        def extra_file(path):
            return ([{"filename":"config/extension.json"},{"filename":".github/workflows/promote.yml"}]
                    if "/files?" in path else pr)
        with patch.object(g,"api",side_effect=extra_file),patch.object(g,"command",return_value=""):
            with self.assertRaises(g.Denied):
                g.merged_pr(123,MAIN,"config/extension.json",True)
        with patch.object(g,"api",side_effect=fake_api),patch.object(g,"command",side_effect=g.Denied("not ancestor")):
            with self.assertRaises(g.Denied):
                g.merged_pr(123,MAIN,"config/extension.json",True)

if __name__=="__main__":
    unittest.main()
