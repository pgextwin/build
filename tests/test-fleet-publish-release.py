#!/usr/bin/env python3
"""Offline fail-closed 14-extension attested publisher and draft-ID fixtures."""
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch
from zipfile import ZipFile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("fleetpub",ROOT/"scripts"/"fleet-publish-release.py")
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
COMMIT="a"*40
UPSTREAM="b"*40
REPO="pgextwin/pgaudit"

def fixture():
    ext={"schemaVersion":1,"name":"pgaudit","upstream":{
        "repository":"pgaudit/pgaudit","perPostgresql":{
            str(n):{"ref":str(n)+".1","version":str(n)+".1","commit":UPSTREAM}
            for n in range(14,19)}},"postgresql":{"majors":[14,15,16,17,18]}}
    # pgaudit synthetic per-major versions, intentionally NOT a shared pin.
    lc={"schemaVersion":1,"postgresql":[{"major":n,"eol":"2030-12-31"} for n in range(14,19)]}
    receipt={"schemaVersion":1,"status":"VERIFIED_MANUAL_DISPATCH",
        "authorizationMode":"manual-dispatch","operator":"HumanOperator",
        "repository":REPO,"trustedCommit":COMMIT,"extension":"pgaudit",
        "releaseTag":"v18.1-windows.3","majors":list(range(14,19)),
        "sources":[p.ident.sources(ext)[n] for n in range(14,19)]}
    return ext,lc,receipt

def make_assets(folder,ext,run=123,workflow_event="workflow_dispatch"):
    for m,s in p.ident.sources(ext).items():
        stem=p.ident.asset_stem(ext,m)
        info={"buildMode":"release-attested","package":{"name":"pgaudit"},
            "postgresql":{"major":m},"upstream":{
                "repository":ext["upstream"]["repository"],
                "ref":s["ref"],"version":s["version"],"commit":s["commit"]},
            "source":{"packagingRepository":REPO,"packagingCommit":COMMIT},
            "workflowRun":{"id":run,"event":workflow_event,"ref":"refs/heads/main"}}
        with ZipFile(folder/(stem+".zip"),"w") as z:
            z.writestr("PACKAGE-INFO.json",json.dumps(info))
        (folder/(stem+".spdx.json")).write_text('{"spdxVersion":"SPDX-2.3"}')
        (folder/(stem+".vulnerabilities.json")).write_text('{"matches":[]}')

class FleetPublisherTests(TestCase):
    def test_exact_per_pg_15_files_5_distinct_sources(self):
        ext,lc,receipt=fixture()
        with TemporaryDirectory() as tmp,patch.object(p,"REPO",REPO):
            folder=Path(tmp)
            make_assets(folder,ext)
            got=p.check_assets(folder,ext,receipt,COMMIT,123,lc,verify_signatures=False)
            self.assertEqual(len(got),15)
            self.assertEqual(set(got),p.ident.expected_assets(ext,[14,15,16,17,18])-{"SHA256SUMS.txt"})

    def test_wrong_source_matrix_operator_or_asset_denied(self):
        ext,lc,receipt=fixture()
        with TemporaryDirectory() as tmp,patch.object(p,"REPO",REPO):
            folder=Path(tmp)
            make_assets(folder,ext)
            cases=[
                {"receipt":{"operator":""}},
                {"receipt":{"authorizationMode":"automatic"}},
                {"receipt":{"trustedCommit":"e"*40}},
                {"receipt":{"releaseTag":"v17.1-windows.3"}},
                {"receipt":{"majors":[15,16,17,18]}},
                {"receipt":{"sources":receipt["sources"][:4]}},
            ]
            for case in cases:
                test=dict(receipt)
                test.update(case["receipt"])
                with self.subTest(case=case),self.assertRaises((p.Denied,p.ident.Denied)):
                    p.check_assets(folder,ext,test,COMMIT,123,lc,False)
            bad=list(folder.glob("*-pg14-windows-x64.zip"))[0]
            with ZipFile(bad,"w") as z:
                z.writestr("PACKAGE-INFO.json",json.dumps({"malicious":True}))
            with self.assertRaises((p.Denied,KeyError)):
                p.check_assets(folder,ext,receipt,COMMIT,123,lc,False)

    def test_extra_asset_and_expired_pg14_fail_closed(self):
        ext,lc,receipt=fixture()
        with TemporaryDirectory() as tmp,patch.object(p,"REPO",REPO):
            folder=Path(tmp)
            make_assets(folder,ext)
            (folder/"unapproved.txt").write_text("x")
            with self.assertRaises(p.Denied):
                p.check_assets(folder,ext,receipt,COMMIT,123,lc,False)
            (folder/"unapproved.txt").unlink()
            lc["postgresql"][0]["eol"]="2026-01-01"
            with self.assertRaises(p.Denied):
                p.check_assets(folder,ext,receipt,COMMIT,123,lc,False)

    def test_push_mode_requires_complete_pr_receipt_and_signed_package_event(self):
        ext,lc,receipt=fixture()
        receipt.update(status="VERIFIED_CHAT_PR_AUTHORIZATION",
                       authorizationMode="chat-pr-authorization",
                       authorizationPr=35, authorizationCommit=COMMIT,
                       authorizationHeadSha="c"*40, authorizationBaseSha="d"*40,
                       candidateHeadSha="e"*40,
                       candidatePr=12, candidateRunId=900, decisionRunId=901,
                       signedArtifactsVerified=True, publishingEnabled=True,
                       publishableReceipt=True)
        with TemporaryDirectory() as tmp,patch.object(p,"REPO",REPO):
            folder=Path(tmp)
            make_assets(folder,ext,workflow_event="push")
            with patch.object(p,"run",return_value="") as verifier:
                ok=p.check_assets(folder,ext,receipt,COMMIT,123,lc,True,
                                  workflow_event="push")
                # Two independent attestation verifications per PG major.
                self.assertEqual(verifier.call_count,10)
                self.assertEqual(sum(
                    "--predicate-type" in c.args for c in verifier.call_args_list),5)
            self.assertEqual(len(ok),15)
            with self.assertRaises(p.Denied):
                p.check_assets(folder,ext,receipt,COMMIT,123,lc,False,
                               workflow_event="push")
            # A verified-run metadata flag is not itself signature proof;
            # Chat-PR mode must have explicitly trusted signed evidence.
            unverified=dict(receipt, signedArtifactsVerified=False)
            with self.assertRaises(p.Denied):
                p.check_assets(folder,ext,unverified,COMMIT,123,lc,False,
                               workflow_event="push")
            with self.assertRaises(p.Denied):
                p.check_assets(folder,ext,receipt,COMMIT,123,lc,False,
                               workflow_event="workflow_dispatch")
            # Typed receipt is correct; PACKAGE-INFO was produced by the wrong event.
            make_assets(folder,ext,workflow_event="workflow_dispatch")
            with self.assertRaises(p.Denied):
                p.check_assets(folder,ext,receipt,COMMIT,123,lc,False,
                               workflow_event="push")

    def test_draft_must_be_unique_exact_commit_and_verified_by_id(self):
        tag="v18.1-windows.3"
        release={"id":879,"tag_name":tag,"target_commitish":COMMIT,"draft":True,
            "assets":[{"name":"sample.zip","state":"uploaded","digest":"sha256:"+"d"*64}]}
        with patch.object(p,"get",return_value=[release]):
            self.assertEqual(p.staged_release_id(tag,COMMIT),879)
        for bad in ([],[release,release],[release]*100,[{**release,"draft":False}],
                    [{**release,"target_commitish":"f"*40}]):
            with patch.object(p,"get",return_value=bad),self.assertRaises(p.Denied):
                p.staged_release_id(tag,COMMIT)
        with patch.object(p,"get",return_value=release),patch.object(
                p,"run",side_effect=AssertionError("draft must not download by tag")):
            p.check_remote(tag,{"sample.zip":"d"*64},True,879)
        duplicate={**release,"assets":[release["assets"][0],release["assets"][0]]}
        with patch.object(p,"get",return_value=duplicate),self.assertRaises(p.Denied):
            p.check_remote(tag,{"sample.zip":"d"*64},True,879)
        bad={**release,"assets":[{**release["assets"][0],"digest":"sha256:"+"e"*64}]}
        with patch.object(p,"get",return_value=bad),self.assertRaises(p.Denied):
            p.check_remote(tag,{"sample.zip":"d"*64},True,879)


    def test_pre_g4_real_historical_publisher_manual_offline(self):
        """Both exact pinned scripts read local synthetic ZIPs; no publisher main(), GET or write."""
        import hashlib
        import shutil
        import subprocess
        from copy import deepcopy
        from urllib.error import HTTPError

        frozen=ROOT/"tests"/"fixtures"/"issue-75-pre-g4"/"fleet-publish-release.py"
        raw=frozen.read_bytes()
        blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        self.assertEqual(blob,"85cbe8e6893477210831c6a813fe796f23d7eb08")
        with TemporaryDirectory() as tmp:
            local=Path(tmp)/"legacy"
            local.mkdir()
            shutil.copyfile(frozen,local/"fleet-publish-release.py")
            shutil.copyfile(ROOT/"scripts"/"fleet-release-identity.py",
                            local/"fleet-release-identity.py")
            spec=importlib.util.spec_from_file_location(
                "issue75_frozen_publisher",local/"fleet-publish-release.py")
            legacy=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(legacy)
            ext,lc,receipt=fixture()
            dist=Path(tmp)/"dist"
            dist.mkdir()
            make_assets(dist,ext)
            def simulate_attestation(*args):
                self.assertEqual(args[:3],("gh","attestation","verify"))
                self.assertIn("--signer-workflow",args)
                self.assertEqual(args[args.index("--signer-workflow")+1],
                                 "pgextwin/build/.github/workflows/build-extension-attested.yml")
                if "--predicate-type" in args:
                    self.assertEqual(args[args.index("--predicate-type")+1],
                                     "https://spdx.dev/Document/v2.3")
                return ""  # Stub only. NEVER a signed-evidence PASS.
            with patch.object(subprocess,"run",side_effect=AssertionError("NO COMMAND")), patch("urllib.request.urlopen",side_effect=AssertionError("NO NETWORK")):
                for implementation in (legacy,p):
                    with self.subTest(implementation=implementation.__name__), patch.object(implementation,"REPO",REPO):
                        result=implementation.check_assets(dist,ext,deepcopy(receipt),
                              COMMIT,123,lc,verify_signatures=False)
                        self.assertEqual(len(result),15)
                        with patch.object(implementation,"run",side_effect=simulate_attestation) as signer:
                            verified_by_stub=implementation.check_assets(
                                dist,ext,deepcopy(receipt),COMMIT,123,lc,verify_signatures=True)
                            self.assertEqual(result,verified_by_stub)
                            self.assertEqual(signer.call_count,10)
                            self.assertEqual(sum("--predicate-type" in call.args for call in signer.call_args_list),5)
                        negative=(
                            ("wrong status",{"status":"VERIFIED_CHAT_PR_AUTHORIZATION"}),
                            ("wrong mode",{"authorizationMode":"chat-pr-authorization"}),
                            ("wrong trusted SHA",{"trustedCommit":"f"*40}),
                            ("wrong repo",{"repository":"pgextwin/other"}),
                            ("wrong actor empty",{"operator":""}),
                            ("wrong PG major",{"majors":[15,16,17,18]}),
                            ("wrong source SHA",{"sources":[dict(receipt["sources"][0],commit="f"*40)]+receipt["sources"][1:]}),
                        )
                        for title,change in negative:
                            with self.subTest(implementation=implementation.__name__,deny=title):
                                mutated=deepcopy(receipt)
                                mutated.update(change)
                                with self.assertRaises((implementation.Denied,implementation.ident.Denied)):
                                    implementation.check_assets(dist,ext,mutated,COMMIT,123,lc,False)
                        expired=deepcopy(lc)
                        expired["postgresql"][0]["eol"]="2020-01-01"
                        with self.assertRaises((implementation.Denied,implementation.ident.Denied)):
                            implementation.check_assets(dist,ext,receipt,COMMIT,123,expired,False)
                        # The actual manual executable needs exact event=workflow_dispatch and main ref.
                        make_assets(dist,ext,run=999)
                        with self.assertRaises((implementation.Denied,implementation.ident.Denied)):
                            implementation.check_assets(dist,ext,receipt,COMMIT,123,lc,False)
                        make_assets(dist,ext,workflow_event="push")
                        with self.assertRaises((implementation.Denied,implementation.ident.Denied)):
                            implementation.check_assets(dist,ext,receipt,COMMIT,123,lc,False)
                        make_assets(dist,ext)
                # Adversarial API: neither executable treats 503 as an absent tag.
                for implementation in (legacy,p):
                    with patch.object(implementation,"REPO",REPO), patch.object(
                        implementation,"urlopen",side_effect=HTTPError("https://api.github.com",503,"unavailable",{},None)):
                        with self.assertRaises(implementation.Denied):
                            implementation.get("releases/tags/v18.1-windows.3")
                # No release, ref, Draft, Dispatch, POST/PATCH or subprocess executed.

    def test_pre_g4_known_workflow_attempt_gap_is_not_claimed_as_verified(self):
        """Both publisher implementations ignore PACKAGE-INFO.workflowRun.attempt.

        This is a documented BLOCKED field, not a positive run-attempt acceptance.
        """
        import shutil
        with TemporaryDirectory() as tmp:
            local=Path(tmp)/"legacy"
            local.mkdir()
            shutil.copyfile(ROOT/"tests"/"fixtures"/"issue-75-pre-g4"/"fleet-publish-release.py",
                            local/"fleet-publish-release.py")
            shutil.copyfile(ROOT/"scripts"/"fleet-release-identity.py",
                            local/"fleet-release-identity.py")
            spec=importlib.util.spec_from_file_location("issue75_attempt_gap",
                                                        local/"fleet-publish-release.py")
            legacy=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(legacy)
            ext,lc,receipt=fixture()
            dist=Path(tmp)/"dist"
            dist.mkdir()
            make_assets(dist,ext)
            # The synthetic packages omit attempt altogether; both readers currently accept.
            # Do not infer authentic run_attempt or same-run signer from this check.
            for implementation in (legacy,p):
                with patch.object(implementation,"REPO",REPO):
                    self.assertEqual(len(implementation.check_assets(
                        dist,ext,receipt,COMMIT,123,lc,False)),15)

if __name__=="__main__":
    main()
