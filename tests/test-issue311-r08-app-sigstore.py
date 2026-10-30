#!/usr/bin/env python3
"""R08 App-OIDC/dual Sigstore adversarial checks. MOCKS ARE NOT CRYPTOGRAPHY."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

audit=load("r08_app_crypto_audit","scripts/issue311-r08-audit-app-signed-candidate.py")
join=load("r08_app_crypto_join","scripts/issue311-r08-join-app-oidc-audits.py")
base=load("r08_existing_pg_fixture","tests/test-fleet-publish-release.py")
REPO="pgextwin/orafce"
SHA="a"*40
RUN=445
MAJORS=[14,15,16,17,18]

def fixture():
    manifest,lc,_=base.fixture()
    manifest["name"]="orafce"
    row={
        "schemaVersion":1,"status":join.STATUS,"sourceKind":join.SOURCE,
        "repository":REPO,"mainMergeSha":SHA,
        "requestId":"r-20261030-r06coordlocalpilot01",
        "centralRequestId":"r-20261030-r06prepareproof01",
        "centralRunId":123,"centralArtifactId":456,
        "centralHeadSha":"b"*40,"centralRequestRawSha256":"c"*64,
        "centralOuterZipSha256":"d"*64,"localWorkflow":join.CALLER,
        "localActor":join.ACTOR,"localActorId":350058024,
        "runId":RUN,"runAttempt":1,"maintainedMajors":MAJORS,
        "zipSha256ByMajor":{str(m):"a"*64 for m in MAJORS},
        "spdxSha256ByMajor":{str(m):"b"*64 for m in MAJORS},
        "grypeSha256ByMajor":{str(m):"c"*64 for m in MAJORS},
        "grypePolicyByMajor":{str(m):{"status":"NO_BLOCKING_FINDINGS"} for m in MAJORS},
        "cryptographicVerification":"REAL_GH_ATTESTATION_VERIFY",
        "signedArtifactsVerified":True,"publishableReceipt":False,
        "publicationAuthorized":False,"publisherSourceKindAuthorized":False,
        "automaticReleaseEnabled":False,
    }
    return (dict(copy.deepcopy(row),auditorJob="r08_signed_audit_first"),
            dict(copy.deepcopy(row),auditorJob="r08_signed_audit_second"),
            manifest,lc)

def check(a,b,m,lc):
    return join.verify(a,b,m,lc,repository=REPO,sha=SHA,run_id=RUN)

class R08AppSigned(unittest.TestCase):
    def test_protected_r08_signer_pin_is_not_legacy_schedule(self):
        self.assertEqual(audit.R08_SIGNER_SHA, "dc863f4047ee2bab8806a48f4b203fdee6b012ba")
        self.assertNotEqual(audit.R08_SIGNER_SHA, audit.pin.SIGNER_SHA)
        self.assertIn("R08_SIGNER_SHA", Path("scripts/issue311-r08-audit-app-signed-candidate.py").read_text())

    def test_exact_original_app_workflow_only(self):
        run={"repository":{"full_name":REPO},"id":RUN,"run_attempt":1,
             "head_sha":SHA,"head_branch":"main","event":"workflow_dispatch",
             "path":audit.CALLER,"status":"in_progress","conclusion":None,
             "actor":{"login":join.ACTOR,"id":350058024},
             "triggering_actor":{"login":join.ACTOR}}
        audit.stable_run(run,repo=REPO,sha=SHA,run_id=RUN,attempt=1)
        for key,value in (
            ("event","schedule"),("path",".github/workflows/update-watch.yml"),
            ("run_attempt",2),("head_sha","f"*40),("status","completed"),
            ("actor",{"login":"ShutenOishi","id":1}),
            ("triggering_actor",{"login":"ShutenOishi"})):
            forged=dict(run,**{key:value})
            with self.subTest(key=key),self.assertRaises(audit.Denied):
                audit.stable_run(forged,repo=REPO,sha=SHA,run_id=RUN,attempt=1)

    def test_receipt_join_is_nonpublishing_only(self):
        a,b,m,lc=fixture()
        result=check(a,b,m,lc)
        self.assertEqual(result["independentSigstoreAudits"],2)
        self.assertIs(result["publicationAuthorized"],False)
        self.assertIs(result["publisherSourceKindAuthorized"],False)
        self.assertEqual(result["centralRequestId"],"r-20261030-r06prepareproof01")

    def test_forged_cycle_signer_actor_legacy_and_bytes_denied(self):
        cases=[
            ("auditorJob","r08_signed_audit_first"),
            ("status","LEGACY_SCHEDULE"),
            ("sourceKind","MERGED_BOT_SCHEDULED_REQUALIFICATION_SIGNED_BUILD"),
            ("localWorkflow",".github/workflows/update-watch.yml"),
            ("localActor","ShutenOishi"),("localActorId",1),
            ("centralRequestId","r-20261029-r06prepareold01"),
            ("centralRunId",333),("centralArtifactId",999),
            ("centralHeadSha","e"*40),("centralRequestRawSha256","e"*64),
            ("centralOuterZipSha256","f"*64),("runId",RUN+1),
            ("runAttempt",2),("repository","pgextwin/pgaudit"),
            ("mainMergeSha","e"*40),
            ("cryptographicVerification","MOCK"),
            ("publicationAuthorized",True),("signedArtifactsVerified",False),
            ("publisherSourceKindAuthorized",True),("automaticReleaseEnabled",True),
            ("requestId","r-20261030-r06coordlocalother01"),
        ]
        for key,value in cases:
            a,b,m,lc=fixture()
            b[key]=value
            with self.subTest(key=key),self.assertRaises(join.Denied):
                check(a,b,m,lc)
        for field in ("zipSha256ByMajor","spdxSha256ByMajor","grypeSha256ByMajor"):
            for mutation in ("mismatch","missing","extra","bad"):
                a,b,m,lc=fixture()
                if mutation=="mismatch":b[field]["14"]="f"*64
                elif mutation=="missing":b[field].pop("17")
                elif mutation=="extra":b[field]["19"]="e"*64
                else:b[field]["15"]="NOT_A_SHA"
                with self.subTest(field=field,mutation=mutation),self.assertRaises(join.Denied):
                    check(a,b,m,lc)

    def test_both_matching_fake_receipts_do_not_grant_crypto(self):
        a,b,m,lc=fixture()
        a["zipSha256ByMajor"]["14"]=b["zipSha256ByMajor"]["14"]="f"*64
        result=check(a,b,m,lc)
        # The true verifier MUST run independently in each actual Actions job;
        # this shape-only fixture cannot claim real cryptographic evidence.
        self.assertIs(result["publicationAuthorized"],False)

if __name__=="__main__":
    unittest.main()
