#!/usr/bin/env python3
"""No-network deny/allow tests for 14-fleet human-only candidate approval receipt."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("gate",ROOT/"scripts"/"fleet-promotion-gate.py")
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
SHA="a"*40
HEAD="b"*40
UPSTREAM="c"*40
PR_HEAD="d"*40
BRANCH="auto-candidate/"+"f"*20

def fixture(name="plpgsql_check"):
    repo="pgextwin/"+name
    upstream={"repository":gate.ident.UPSTREAMS[name]}
    if name=="pgaudit":
        upstream["perPostgresql"]={
            str(m):{"ref":f"REL{m}_1_0_0","version":f"{m}.0","commit":UPSTREAM}
            for m in range(14,19)}
        tag="v18.0-windows.3"
        update={"major":18,"ref":"REL18_1_0_0","version":"18.0","commit":UPSTREAM}
    elif name=="pg_bigm":
        upstream.update(ref="v1.2-20250903",version="1.2",commit=UPSTREAM)
        tag="v1.2-20250903-windows.3"
        update={"major":None,"ref":"v1.2-20250903","version":"1.2","commit":UPSTREAM}
    else:
        upstream.update(ref="v2.10.14",version="2.10.14",commit=UPSTREAM)
        tag="v2.10.14-windows.2"
        update={"major":None,"ref":"v2.10.14","version":"2.10.14","commit":UPSTREAM}
    ext={"name":name,"upstream":upstream,"postgresql":{"majors":[14,15,16,17,18]}}
    lifecycle={"schemaVersion":1,"postgresql":[{"major":m,"eol":"2030-12-31"} for m in range(14,19)]}
    pr={"number":12,"merged":True,"state":"closed","base":{"ref":"main"},
        "user":{"login":"github-actions[bot]"},"head":{"ref":BRANCH,"sha":PR_HEAD},
        "merge_commit_sha":HEAD,
        "body":"<!-- pgextwin-candidate:v1:"+"f"*20+" -->"}
    run={"id":900,"status":"completed","conclusion":"success",
         "event":"workflow_dispatch","head_branch":BRANCH,"head_sha":PR_HEAD}
    watch={"id":901,"status":"completed","conclusion":"success","head_branch":"main"}
    decision={"schemaVersion":1,"status":"candidate","candidateId":"f"*20,
              "branch":BRANCH,"extension":name,
              "repository":gate.ident.UPSTREAMS[name],"releasePolicy":"manual-only",
              "updates":[update]}
    audit={"schemaVersion":1,"extension":name,"runId":900,"branch":BRANCH,
           "branchSha":PR_HEAD,"matrixResult":"success","status":"VERIFIED",
           "majors":[{"major":m,"status":"SUCCESS",
             "sourceSha":UPSTREAM,"zipSha256":"a"*64,
             "zip":gate.ident.asset_stem(ext,m)+".zip",
             "sbom":gate.ident.asset_stem(ext,m)+".spdx.json",
             "grype":gate.ident.asset_stem(ext,m)+".vulnerabilities.json"}
             for m in range(14,19)]}
    return dict(repo=repo,main_sha=SHA,tag=tag,confirmation="PUBLISH",
        actor="HumanOperator",policy={"schemaVersion":1,"allowedRepositories":[repo],
                "releasePolicy":"manual-dispatch"},
        fleet={"releasePolicy":"manual-only","scheduleUtc":"0 0 * * *","entries":[
                {"repository":repo,"mode":"BUILD","candidateEnabled":True,
                 "releasePolicy":"manual-only"}]},
        local={"schemaVersion":1,"enabled":True,"releasePolicy":"manual-dispatch"},
        ext=ext,lifecycle=lifecycle,pr=pr,
        pr_files=[{"filename":"config/extension.json"}],
        run=run,watch_run=watch,decision=decision,audit=audit)

class GateTests(unittest.TestCase):
    def check(self,case):
        return gate.verify(**case)

    def test_uniform_dated_and_per_pg_receipts(self):
        for name in ("plpgsql_check","pg_bigm","pgaudit"):
            with self.subTest(name=name):
                x=fixture(name);a=self.check(x)
                self.assertEqual(a["authorizationMode"],"manual-dispatch")
                self.assertEqual(a["trustedCommit"],SHA)
                self.assertEqual(a["releaseTag"],x["tag"])
                self.assertEqual(a["candidateRunId"],900)
                self.assertEqual(len(a["sources"]),5)
                self.assertEqual(a["operator"],"HumanOperator")

    def test_mutated_policy_and_operator_fail_closed(self):
        examples=[
            lambda x:x.update(confirmation=""),
            lambda x:x.update(confirmation="publish"),
            lambda x:x.update(actor="github-actions[bot]"),
            lambda x:x.update(actor="Fakebot"),
            lambda x:x["policy"].update(allowedRepositories=["pgextwin/other"]),
            lambda x:x["policy"].update(releasePolicy="automatic"),
            lambda x:x["fleet"]["entries"][0].update(mode="OFF",candidateEnabled=False),
            lambda x:x["local"].update(enabled=False),
            lambda x:x["ext"]["upstream"].update(repository="attacker/fork"),
            lambda x:x.update(tag="v2.10.15-windows.1"),
        ]
        for mutate in examples:
            x=fixture();mutate(x)
            with self.subTest(change=str(mutate)),self.assertRaises((gate.Denied,gate.ident.Denied)):
                self.check(x)

    def test_tampered_candidate_and_artifacts_fail_closed(self):
        examples=[
            lambda x:x["pr"].update(merged=False),
            lambda x:x["pr"]["user"].update(login="untrusted-user"),
            lambda x:x["pr"].update(body=""),
            lambda x:x["pr_files"].append({"filename":".github/workflows/windows.yml"}),
            lambda x:x["run"].update(head_sha="1"*40),
            lambda x:x["run"].update(conclusion="failure"),
            lambda x:x["watch_run"].update(conclusion="failure"),
            lambda x:x["decision"].update(branch="auto-candidate/"+"0"*20),
            lambda x:x["decision"]["updates"][0].update(commit="1"*40),
            lambda x:x["audit"].update(status="FAILED"),
            lambda x:x["audit"]["majors"][0].update(sourceSha="1"*40),
            lambda x:x["audit"]["majors"][0].update(zipSha256="g"*64),
            lambda x:x["audit"]["majors"][0].update(sbom="evil.spdx.json"),
            lambda x:x["audit"]["majors"].pop(),
        ]
        for mutate in examples:
            x=fixture();mutate(x)
            with self.subTest(change=str(mutate)),self.assertRaises((gate.Denied,gate.ident.Denied)):
                self.check(x)

    def test_per_pg_single_update_and_mismatched_major_denied(self):
        x=fixture("pgaudit")
        self.assertEqual(len(x["decision"]["updates"]),1)
        x["decision"]["updates"][0]["major"]=17
        with self.assertRaises(gate.Denied):self.check(x)
        x=fixture("pgaudit")
        x["ext"]["upstream"]["perPostgresql"]["14"]["commit"]="1"*40
        with self.assertRaises(gate.Denied):self.check(x)

if __name__=="__main__":
    unittest.main()
