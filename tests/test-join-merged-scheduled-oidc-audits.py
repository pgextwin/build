#!/usr/bin/env python3
"""Hostile dual-auditor agreement tests; synthetic fixtures prove NO signatures."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(label,path):
    spec=importlib.util.spec_from_file_location(label,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

guard=load("merged_dual_guard","scripts/join-merged-scheduled-oidc-audits.py")
base=load("merged_dual_fixture","tests/test-fleet-publish-release.py")
REPO=base.REPO
SHA=base.COMMIT
RUN=445
MAJORS=[14,15,16,17,18]

def fixture():
    ext,lifecycle,_=base.fixture()
    receipt={"schemaVersion":1,"status":guard.STATUS,"sourceKind":guard.SOURCE,
        "repository":REPO,"mainMergeSha":SHA,"candidatePr":12,
        "candidateHead":"a"*40,"originalFleetScheduleRun":890,
        "originalNativeWindowsRun":900,"originalRequiredCheck":901,
        "runId":RUN,"runAttempt":1,"maintainedMajors":MAJORS,
        "cryptographicVerification":"REAL_GH_ATTESTATION_VERIFY",
        "zipSha256ByMajor":{str(m):"a"*64 for m in MAJORS},
        "spdxSha256ByMajor":{str(m):"b"*64 for m in MAJORS},
        "grypeSha256ByMajor":{str(m):"c"*64 for m in MAJORS},
        "grypePolicyByMajor":{str(m):{"status":"NO_BLOCKING_FINDINGS"} for m in MAJORS},
        "signedArtifactsVerified":True,"publishableReceipt":False,
        "publicationAuthorized":False,"publisherSourceKindAuthorized":False,
        "automaticReleaseEnabled":False}
    first=dict(deepcopy(receipt),auditorJob="signed_audit_first")
    second=dict(deepcopy(receipt),auditorJob="signed_audit_second")
    return first,second,ext,lifecycle

def check(first,second,ext,lc):
    return guard.verify(first,second,ext,lc,repository=REPO,sha=SHA,run_id=RUN)

class DualSigstoreNonpublishing(unittest.TestCase):
    def test_complete_shape_must_still_deny_release(self):
        first,second,ext,lc=fixture()
        got=check(first,second,ext,lc)
        self.assertEqual(got["independentSigstoreAudits"],2)
        self.assertEqual(got["sourceKind"],guard.SOURCE)
        self.assertFalse(got["publisherSourceKindAuthorized"])
        self.assertFalse(got["publicationAuthorized"])
        self.assertEqual(got["maintainedMajors"],MAJORS)

    def test_forged_or_replayed_jobs_are_never_equivalent(self):
        for field,value in (
            ("auditorJob","signed_audit_first"),("runAttempt",2),("runId",RUN+1),
            ("mainMergeSha","f"*40),("sourceKind","MERGED_BOT_PR_REQUALIFICATION_NONPUBLISHING"),
            ("status","UNSIGNED_MANUAL"),("cryptographicVerification","MOCK"),
            ("signedArtifactsVerified",False),("publisherSourceKindAuthorized",True),
            ("publicationAuthorized",True),("publishableReceipt",True),
            ("candidatePr",0),("originalFleetScheduleRun",0),
            ("originalNativeWindowsRun",0),("candidateHead","bad")):
            first,second,ext,lc=fixture()
            second[field]=value
            with self.subTest(field=field),self.assertRaises(guard.Denied):
                check(first,second,ext,lc)

    def test_byte_matrix_drift_and_both_tampered_are_rejected(self):
        for field in ("zipSha256ByMajor","spdxSha256ByMajor","grypeSha256ByMajor"):
            for mutate in ("change","omit","extra","invalid"):
                first,second,ext,lc=fixture()
                d=second[field]
                if mutate=="change": d["14"]="f"*64
                elif mutate=="omit": d.pop("17")
                elif mutate=="extra": d["19"]="a"*64
                else: d["15"]="not-sha256"
                with self.subTest(field=field,mutate=mutate),\
                     self.assertRaises(guard.Denied):
                    check(first,second,ext,lc)
        first,second,ext,lc=fixture()
        first["zipSha256ByMajor"]["14"]="f"*64
        second["zipSha256ByMajor"]["14"]="f"*64
        # Self-consistent fake digests are only SHAPE evidence; no authority is minted.
        got=check(first,second,ext,lc)
        self.assertIs(got["publicationAuthorized"],False)

    def test_incomplete_major_and_grype_status_disagree(self):
        first,second,ext,lc=fixture()
        lc["postgresql"].pop()
        with self.assertRaises((guard.Denied,guard.ident.Denied)):
            check(first,second,ext,lc)
        first,second,ext,lc=fixture()
        second["grypePolicyByMajor"]["14"]["status"]="BLOCKING_FINDINGS"
        with self.assertRaises(guard.Denied):
            check(first,second,ext,lc)

if __name__=="__main__":
    unittest.main()
