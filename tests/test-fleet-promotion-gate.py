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

    def test_version_named_candidate_evidence_keeps_exact_source_identity(self):
        # The real pgTAP Run 39501699629 audit uses pgtap-1.3.4-...,
        # although its immutable upstream ref is v1.3.4. Reuse that evidence.
        for name in gate.ident.UPSTREAMS:
            with self.subTest(extension=name):
                x=fixture(name)
                for item in x["audit"]["majors"]:
                    source=gate.ident.sources(x["ext"])[item["major"]]
                    stem=f"{name}-{source['version']}-pg{item['major']}-windows-x64"
                    item.update(zip=stem+".zip",sbom=stem+".spdx.json",
                                grype=stem+".vulnerabilities.json")
                self.assertEqual(self.check(x)["candidateRunId"],900)
                for mutation in ("source", "digest", "version", "major", "mixed", "path"):
                    bad=deepcopy(x); item=bad["audit"]["majors"][0]
                    if mutation=="source": item["sourceSha"]="0"*40
                    elif mutation=="digest": item["zipSha256"]="short"
                    elif mutation=="version": item["zip"]=name+"-0.0-pg14-windows-x64.zip"
                    elif mutation=="major": item["zip"]=item["zip"].replace("-pg14-","-pg15-")
                    elif mutation=="mixed": item["sbom"]="unrelated.spdx.json"
                    else: item["zip"]="../"+item["zip"]
                    with self.subTest(mutation=mutation),self.assertRaises(gate.Denied):
                        self.check(bad)

    def test_candidate_filename_conventions_cannot_be_mixed(self):
        x=fixture("pgtap")
        item=x["audit"]["majors"][0]
        item["zip"]=item["zip"].replace("-v2.10.14-","-2.10.14-")
        with self.assertRaises(gate.Denied):
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

    def test_inert_chat_mode_requires_explicit_central_and_local_opt_in(self):
        x=fixture()
        x["authorization_mode"]="chat-pr-authorization"
        with self.assertRaises(gate.Denied):
            self.check(x)  # Existing central/local manual modes forbid PR mode.
        x["policy"]["releasePolicy"]="chat-pr-authorization"
        with self.assertRaises(gate.Denied):
            self.check(x)  # Local policy still manual-only.
        x["local"]["releasePolicy"]="chat-pr-authorization"
        receipt=self.check(x)
        self.assertEqual(receipt["status"],"VERIFIED_CHAT_PR_AUTHORIZATION")
        self.assertEqual(receipt["authorizationMode"],"chat-pr-authorization")
        self.assertNotIn("authorizationPr",receipt)  # Only live PR gate may attach it.
        self.assertEqual(receipt["candidateHeadSha"],PR_HEAD)
        x["authorization_mode"]="unknown"
        with self.assertRaises(gate.Denied):
            self.check(x)


    def test_pre_g4_exact_pin_manual_parity_offline(self):
        """Execute the immutable old gate and current gate on the SAME synthetic data."""
        import hashlib
        import shutil
        import subprocess
        from tempfile import TemporaryDirectory
        from unittest.mock import patch

        frozen=ROOT/"tests"/"fixtures"/"issue-75-pre-g4"/"fleet-promotion-gate.py"
        data=frozen.read_bytes()
        blob=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
        self.assertEqual(blob,"6abf79d6a037a9ca5e77d5ce7803d520701e290c")
        with TemporaryDirectory() as tmp:
            location=Path(tmp)
            shutil.copyfile(frozen,location/"fleet-promotion-gate.py")
            shutil.copyfile(ROOT/"tests"/"fixtures"/"issue-75-pre-g4"/"fleet-release-identity.py",
                            location/"fleet-release-identity.py")
            spec=importlib.util.spec_from_file_location(
                "issue75_frozen_gate",location/"fleet-promotion-gate.py")
            legacy=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(legacy)
            # Historic 14-extension identity remains byte-identical to pre-G4; current\n            # live helper may grow with new explicitly gated fleet entries.
            ident_bytes=(location/"fleet-release-identity.py").read_bytes()
            identity=hashlib.sha1(b"blob "+str(len(ident_bytes)).encode()+
                                  b"\0"+ident_bytes).hexdigest()
            self.assertEqual(identity,"e8c63f6f7f26a883cf898ca1c3e386d9ed2f1d7c")
            with patch.object(subprocess,"run",side_effect=AssertionError("NO SUBPROCESS")), patch("urllib.request.urlopen",side_effect=AssertionError("NO NETWORK")):
                for extension in ("plpgsql_check","pg_bigm","pgaudit"):
                    with self.subTest(extension=extension):
                        item=fixture(extension)
                        old=legacy.verify(**deepcopy(item))
                        new=gate.verify(**deepcopy(item))
                        self.assertEqual(old,new)
                        self.assertEqual(old["status"],"VERIFIED_MANUAL_DISPATCH")
                        self.assertEqual(old["authorizationMode"],"manual-dispatch")
                        self.assertNotIn("publishableReceipt",old)
                        self.assertNotIn("signedArtifactsVerified",old)
                cases={
                    "wrong PUBLISH":lambda x:x.update(confirmation="publish"),
                    "wrong actor":lambda x:x.update(actor="github-actions[bot]"),
                    "wrong policy":lambda x:x["policy"].update(releasePolicy="chat-pr-authorization"),
                    "wrong local mode":lambda x:x["local"].update(releasePolicy="chat-pr-authorization"),
                    "wrong main SHA":lambda x:x.update(main_sha="short"),
                    "wrong candidate event":lambda x:x["run"].update(event="push"),
                    "wrong candidate run":lambda x:x["run"].update(id=999),
                    "wrong candidate head":lambda x:x["pr"]["head"].update(sha="1"*40),
                    "wrong upstream SHA":lambda x:x["ext"]["upstream"].update(commit="1"*40),
                    "wrong decision":lambda x:x["decision"].update(candidateId="0"*20),
                    "wrong audit digest":lambda x:x["audit"]["majors"][0].update(zipSha256="0"*63),
                    "expired PG":lambda x:x["lifecycle"]["postgresql"][0].update(eol="2020-01-01"),
                }
                for title,change in cases.items():
                    item=fixture()
                    change(item)
                    with self.subTest(deny=title):
                        for impl in (legacy,gate):
                            with self.assertRaises((impl.Denied,impl.ident.Denied)):
                                impl.verify(**deepcopy(item))
                chat=fixture()
                chat["authorization_mode"]="chat-pr-authorization"
                with self.assertRaises(TypeError):
                    legacy.verify(**chat)  # Legacy executable has no Chat mode.
                with self.assertRaises(gate.Denied):
                    gate.verify(**chat)  # Actual central/local policy is manual-only.

if __name__=="__main__":
    unittest.main()
