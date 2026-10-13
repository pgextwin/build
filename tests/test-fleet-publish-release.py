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
                       signedArtifactsVerified=True)
        with TemporaryDirectory() as tmp,patch.object(p,"REPO",REPO):
            folder=Path(tmp)
            make_assets(folder,ext,workflow_event="push")
            ok=p.check_assets(folder,ext,receipt,COMMIT,123,lc,False,
                              workflow_event="push")
            self.assertEqual(len(ok),15)
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
        for bad in ([],[release,release],[{**release,"draft":False}],
                    [{**release,"target_commitish":"f"*40}]):
            with patch.object(p,"get",return_value=bad),self.assertRaises(p.Denied):
                p.staged_release_id(tag,COMMIT)
        with patch.object(p,"get",return_value=release),patch.object(
                p,"run",side_effect=AssertionError("draft must not download by tag")):
            p.check_remote(tag,{"sample.zip":"d"*64},True,879)
        bad={**release,"assets":[{**release["assets"][0],"digest":"sha256:"+"e"*64}]}
        with patch.object(p,"get",return_value=bad),self.assertRaises(p.Denied):
            p.check_remote(tag,{"sample.zip":"d"*64},True,879)

if __name__=="__main__":
    main()
