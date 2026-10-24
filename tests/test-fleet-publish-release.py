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
            "buildInfrastructure":{"repository":"pgextwin/build",
                "workflow":p.guard.SIGNER_PATH,"commit":p.guard.SIGNER_SHA},
            "workflowRun":{"id":run,"attempt":1,
                "url":f"https://github.com/{REPO}/actions/runs/{run}",
                "event":workflow_event,"ref":"refs/heads/main"}}
        with ZipFile(folder/(stem+".zip"),"w") as z:
            z.writestr("PACKAGE-INFO.json",json.dumps(info))
        (folder/(stem+".spdx.json")).write_text('{"spdxVersion":"SPDX-2.3"}')
        (folder/(stem+".vulnerabilities.json")).write_text(json.dumps({
            "matches": [], "ignoredMatches": [],
            "descriptor": {
                "name": "grype", "version": "0.120.1",
                "db": {"status": {"valid": True, "schemaVersion": "v6",
                                  "built": "2026-10-23T00:00:00Z",
                                  "from": "2026-10-23T00:00:00Z"},
                       "providers": {"nvd": {}}},
                "configuration": {"match-upstream-kernel-headers": True,
                                  "ignore": [], "fail-on-severity": ""}},
            "source": {"type": "file", "target": stem},
        }))

class FleetPublisherTests(TestCase):
    def test_exact_per_pg_15_files_5_distinct_sources(self):
        ext,lc,receipt=fixture()
        with TemporaryDirectory() as tmp,patch.object(p,"REPO",REPO):
            folder=Path(tmp)
            make_assets(folder,ext)
            got=p.check_assets(folder,ext,receipt,COMMIT,123,lc,verify_signatures=False)
            self.assertEqual(len(got),15)
            self.assertEqual(set(got),p.ident.expected_assets(ext,[14,15,16,17,18])-{"SHA256SUMS.txt"})

    def test_formal_publisher_blocks_real_grype_risks_before_tag_write(self):
        ext, lc, receipt = fixture()
        with TemporaryDirectory() as tmp, patch.object(p, "REPO", REPO):
            folder = Path(tmp)
            make_assets(folder, ext)
            # Clean, complete scanner evidence is acceptable for non-signature
            # offline validation. Production signatures remain independently
            # mandatory; the test never calls the publishing entry point.
            self.assertEqual(len(p.check_assets(
                folder, ext, receipt, COMMIT, 123, lc, verify_signatures=False)), 15)
            report_path = next(folder.glob("*-pg18-windows-x64.vulnerabilities.json"))
            clean = json.loads(report_path.read_text())
            def vulnerability(severity):
                return {"vulnerability": {"id": "CVE-2026-test",
                                           "severity": severity},
                        "artifact": {"name": "library.dll"},
                        "matchDetails": [{"matcher": "dpkg"}]}
            for severity in ("Critical", "High", "Unknown"):
                with self.subTest(severity=severity):
                    report = json.loads(json.dumps(clean))
                    report["matches"] = [vulnerability(severity)]
                    report_path.write_text(json.dumps(report))
                    with self.assertRaisesRegex(p.Denied, "blocking"):
                        p.check_assets(folder, ext, receipt, COMMIT, 123, lc,
                                       verify_signatures=False)
            for name, mutate in (
                ("ignored", lambda r: r.update(ignoredMatches=[vulnerability("High")])),
                ("no-db", lambda r: r["descriptor"].pop("db")),
                ("filtered", lambda r: r["descriptor"]["configuration"].update(
                    ignore=[{"name": "library.dll"}])),
                ("wrong-scan-target", lambda r: r["source"].update(
                    target="unrelated-sbom")),
                ("missing-finding-details", lambda r: r.update(
                    matches=[{"vulnerability": {"id": "CVE-test", "severity": "Low"}}])),
                ("unknown-scanner", lambda r: r["descriptor"].update(version="floating")),
            ):
                with self.subTest(name=name):
                    report = json.loads(json.dumps(clean))
                    mutate(report)
                    report_path.write_text(json.dumps(report))
                    with self.assertRaises(p.Denied):
                        p.check_assets(folder, ext, receipt, COMMIT, 123, lc,
                                       verify_signatures=False)
            report_path.write_text(json.dumps(clean))
            self.assertEqual(len(p.check_assets(
                folder, ext, receipt, COMMIT, 123, lc, verify_signatures=False)), 15)

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
            # PRE-G4 current-main guard deliberately refuses a future push
            # publication: neither a typed receipt nor a mocked empty gh
            # verification result can bypass the active manual-run preflight.
            with patch.object(p,"run",return_value="") as verifier:
                with self.assertRaises(p.guard.Deny):
                    p.check_assets(folder,ext,receipt,COMMIT,123,lc,True,
                                   workflow_event="push")
                verifier.assert_not_called()
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

    def test_scheduled_original_completed_source_is_distinct_from_publisher_run(self):
        # Offline mocks exercise routing only: they are never signed bytes or
        # authority to publish, mint a token or create a Release.
        ext, lc, receipt = fixture()
        publisher_sha = "c" * 40
        publisher_run = 9876543
        receipt.pop("operator")
        receipt.update(
            status="VERIFIED_AUTOMATIC_SCHEDULE",
            authorizationMode="automatic-schedule",
            publisherRepository="pgextwin/build",
            publisherWorkflow=".github/workflows/publisher-candidate-intake.yml",
            publisherRunId=publisher_run,publisherRunAttempt=1,
            publisherMainSha=publisher_sha,
            signedSourceWorkflow=".github/workflows/update-watch.yml",
            sourceRunId=123,sourceRunAttempt=1,
            signedArtifactsVerified=True,publicationAuthorized=True,
            publishableReceipt=True,publisherWriteAuthorized=True,
            automaticReleaseEnabled=True,
            approvalProvenance="INDEPENDENT_LIVE_SCHEDULE_AND_SIGNED_SOURCE")
        env={"GITHUB_REPOSITORY":"pgextwin/build",
             "GITHUB_EVENT_NAME":"schedule","GITHUB_REF":"refs/heads/main",
             "GITHUB_ACTOR":"ScheduleEditor",
             "GITHUB_SHA":publisher_sha,
             "GITHUB_RUN_ID":str(publisher_run),
             "GITHUB_RUN_ATTEMPT":"1"}
        with TemporaryDirectory() as tmp, patch.object(p,"REPO",REPO), \
             patch.dict(p.os.environ,env), \
             patch.object(p,"get",return_value={"mock":True}) as github, \
             patch.object(p.guard,"validate_completed_push_snapshot",
                          return_value={"immutable":"original"} ) as snapshots, \
             patch.object(p.guard,"verified_claims") as signed, \
             patch.object(p,"run",return_value='[]') as gh:
            folder=Path(tmp)
            make_assets(folder,ext,run=123,workflow_event="push")
            result=p.check_assets(folder,ext,receipt,COMMIT,123,lc,
                                  verify_signatures=True,workflow_event="schedule")
            self.assertEqual(len(result),15)
            self.assertEqual(snapshots.call_count,2)
            self.assertEqual(signed.call_count,10)
            self.assertEqual(gh.call_count,10)
            self.assertTrue(all(call.kwargs["event"]=="push" and
                                call.kwargs["config_path"]==p.guard.PUSH_PATH
                                for call in signed.call_args_list))
            self.assertTrue(all(call.kwargs["run_id"]==123 and
                                call.kwargs["attempt"]==1
                                for call in snapshots.call_args_list))
            endpoints=[call.args[0] for call in github.call_args_list]
            self.assertEqual(endpoints.count("actions/runs/123"),2)
            self.assertEqual(endpoints.count("actions/runs/123/attempts/1/jobs?per_page=100"),2)
            self.assertEqual(endpoints.count("actions/runs/123/artifacts?per_page=100"),2)
            self.assertNotIn("actions/runs/"+str(publisher_run),endpoints)

    def test_scheduled_publisher_denies_unsigned_bypass_and_wrong_live_origin(self):
        ext,lc,receipt=fixture()
        receipt.pop("operator")
        receipt.update(
            status="VERIFIED_AUTOMATIC_SCHEDULE",
            authorizationMode="automatic-schedule",
            publisherRepository="pgextwin/build",
            publisherWorkflow=".github/workflows/publisher-candidate-intake.yml",
            publisherRunId=9876543,publisherRunAttempt=1,
            publisherMainSha="c"*40,
            signedSourceWorkflow=".github/workflows/update-watch.yml",
            sourceRunId=123,sourceRunAttempt=1,
            signedArtifactsVerified=True,publicationAuthorized=True,
            publishableReceipt=True,publisherWriteAuthorized=True,
            automaticReleaseEnabled=True,
            approvalProvenance="INDEPENDENT_LIVE_SCHEDULE_AND_SIGNED_SOURCE")
        env={"GITHUB_REPOSITORY":"pgextwin/build",
             "GITHUB_EVENT_NAME":"schedule","GITHUB_REF":"refs/heads/main",
             "GITHUB_ACTOR":"ScheduleEditor","GITHUB_SHA":"c"*40,
             "GITHUB_RUN_ID":"9876543","GITHUB_RUN_ATTEMPT":"1"}
        with TemporaryDirectory() as tmp,patch.object(p,"REPO",REPO):
            folder=Path(tmp)
            make_assets(folder,ext,run=123,workflow_event="push")
            with patch.dict(p.os.environ,env),patch.object(p,"get") as get:
                with self.assertRaises(p.Denied):
                    p.check_assets(folder,ext,receipt,COMMIT,123,lc,
                                   verify_signatures=False,workflow_event="schedule")
                get.assert_not_called()
            for key,bad in (("GITHUB_EVENT_NAME","workflow_dispatch"),
                            ("GITHUB_RUN_ID","123"),
                            ("GITHUB_REPOSITORY",REPO),
                            ("GITHUB_RUN_ATTEMPT","2"),
                            ("GITHUB_SHA","d"*40),
                            ("GITHUB_REF","refs/tags/tag")):
                with self.subTest(key=key), patch.dict(p.os.environ,{**env,key:bad}), \
                     patch.object(p,"get") as get:
                    with self.assertRaises(p.Denied):
                        p.check_assets(folder,ext,receipt,COMMIT,123,lc,
                                       verify_signatures=True,workflow_event="schedule")
                    get.assert_not_called()
            with patch.dict(p.os.environ,env), patch.object(p,"get") as get:
                forged=dict(receipt,sourceRunId=9876543)
                with self.assertRaises(p.Denied):
                    p.check_assets(folder,ext,forged,COMMIT,123,lc,
                                   verify_signatures=True,workflow_event="schedule")
                get.assert_not_called()

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
                            if implementation is legacy:
                                # Frozen production pin remains unchanged and only
                                # synthetic legacy compatibility is asserted here.
                                self.assertEqual(result,implementation.check_assets(
                                    dist,ext,deepcopy(receipt),COMMIT,123,lc,True))
                                self.assertEqual(signer.call_count,10)
                            else:
                                # Current-main guard requires authenticated active
                                # run GET + genuine strict JSON before publication.
                                with self.assertRaises(implementation.guard.Deny):
                                    implementation.check_assets(
                                        dist,ext,deepcopy(receipt),COMMIT,123,lc,True)
                                signer.assert_not_called()
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
                                with self.assertRaises((implementation.Denied,implementation.ident.Denied,p.guard.Deny)):
                                    implementation.check_assets(dist,ext,mutated,COMMIT,123,lc,False)
                        expired=deepcopy(lc)
                        expired["postgresql"][0]["eol"]="2020-01-01"
                        with self.assertRaises((implementation.Denied,implementation.ident.Denied,p.guard.Deny)):
                            implementation.check_assets(dist,ext,receipt,COMMIT,123,expired,False)
                        # The actual manual executable needs exact event=workflow_dispatch and main ref.
                        make_assets(dist,ext,run=999)
                        with self.assertRaises((implementation.Denied,implementation.ident.Denied,p.guard.Deny)):
                            implementation.check_assets(dist,ext,receipt,COMMIT,123,lc,False)
                        make_assets(dist,ext,workflow_event="push")
                        with self.assertRaises((implementation.Denied,implementation.ident.Denied,p.guard.Deny)):
                            implementation.check_assets(dist,ext,receipt,COMMIT,123,lc,False)
                        make_assets(dist,ext)
                # Adversarial API: neither executable treats 503 as an absent tag.
                for implementation in (legacy,p):
                    with patch.object(implementation,"REPO",REPO), patch.dict("os.environ", {"GH_TOKEN":"OFFLINE_DUMMY"}, clear=False), patch.object(
                        implementation,"urlopen",side_effect=HTTPError("https://api.github.com",503,"unavailable",{},None)):
                        with self.assertRaises(implementation.Denied):
                            implementation.get("releases/tags/v18.1-windows.3")
                # No release, ref, Draft, Dispatch, POST/PATCH or subprocess executed.

    def test_pre_g4_frozen_legacy_attempt_gap_remains_not_fixed(self):
        """Frozen old pin remains unchanged; current main rejects missing attempt."""
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
            # Omit attempt deliberately only for this regression.
            for zip_path in dist.glob("*.zip"):
                with ZipFile(zip_path) as archive:
                    pkg=json.loads(archive.read("PACKAGE-INFO.json"))
                pkg["workflowRun"].pop("attempt")
                with ZipFile(zip_path,"w") as archive:
                    archive.writestr("PACKAGE-INFO.json",json.dumps(pkg))
            with patch.object(legacy,"REPO",REPO):
                self.assertEqual(len(legacy.check_assets(
                    dist,ext,receipt,COMMIT,123,lc,False)),15)
            with patch.object(p,"REPO",REPO), self.assertRaises(p.Denied):
                p.check_assets(dist,ext,receipt,COMMIT,123,lc,False)

if __name__=="__main__":
    main()
