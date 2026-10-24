#!/usr/bin/env python3
"""Reject unsafe dynamic fleet selector input; these are NONPUBLISHING fixtures."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("hourly_signed_selector",ROOT/"scripts/select-signed-publisher-candidates.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
R1="pgextwin/pg_ivm";R2="pgextwin/orafce";SHA="a"*40

def fleet():
    return {"schemaVersion":1,"releasePolicy":"manual-only","entries":[
        {"repository":n,"mode":"BUILD","candidateEnabled":True,
         "releasePolicy":"manual-only"} for n in (R1,R2)]}
def report():
    return {"schemaVersion":1,"status":"NONPUBLISHING_PUBLISHER_INTAKE",
            "repositoryCount":2,
            "publishableReceipt":False,"publicationAuthorized":False,
            "publisherWriteAuthorized":False,"verifiedSignedReleaseArtifacts":False,
            "rows":[{"repository":R1,"mainSha":SHA,"candidateRunId":123,
                     "status":"SIGNED_RUN_FOUND_REVERIFICATION_REQUIRED",
                     "publicationAuthorized":False,"publisherTokenRequested":False,
                     "needsRealSigstoreReverification":True},
                    {"repository":R2,"mainSha":"b"*40,"candidateRunId":None,
                     "status":"NO_ORIGINAL_SIGNED_PUSH_ON_CURRENT_MAIN",
                     "publicationAuthorized":False,"publisherTokenRequested":False}]}

class Selector(unittest.TestCase):
    def test_select_only_protected_publisher_candidate(self):
        self.assertEqual(m.select(report(),fleet()),[{
            "repository":R1,"name":"pg_ivm","sha":SHA,"source_run":123}])
        x=report();x["rows"][0]["status"]="NO_ORIGINAL_SIGNED_PUSH_ON_CURRENT_MAIN"
        self.assertEqual(m.select(x,fleet()),[])
    def test_not_a_release_grant(self):
        for key in ("publishableReceipt","publicationAuthorized",
                    "publisherWriteAuthorized","verifiedSignedReleaseArtifacts"):
            r=report();r[key]=True
            with self.subTest(key=key),self.assertRaises(m.Denied):
                m.select(r,fleet())
        for key in ("publicationAuthorized","publisherTokenRequested"):
            r=report();r["rows"][0][key]=True
            with self.subTest(key=key),self.assertRaises(m.Denied):
                m.select(r,fleet())
    def test_deny_forged_or_replayed_run_and_sha(self):
        for name,value in (("candidateRunId",0),("candidateRunId",True),
                           ("candidateRunId","123"),("candidateRunId",None),
                           ("mainSha","b"*39),("mainSha",None),
                           ("needsRealSigstoreReverification",False)):
            r=report();r["rows"][0][name]=value
            with self.subTest(name=name,value=value),self.assertRaises(m.Denied):
                m.select(r,fleet())
    def test_deny_partial_duplicate_or_added_fleet(self):
        for mutate in (
            lambda r:r["rows"].pop(),
            lambda r:r["rows"].append(copy.deepcopy(r["rows"][0])),
            lambda r:r["rows"][1].update(repository=R1),
            lambda r:r.update(repositoryCount=17),
            lambda r:r["rows"][1].update(status="READY_TO_PUBLISH"),
            lambda r:r.update(status="VERIFIED_AUTOMATIC_RELEASE"),
        ):
            r=report();mutate(r)
            with self.subTest(mutate=str(mutate)),self.assertRaises(m.Denied):
                m.select(r,fleet())
        f=fleet();f["entries"].append(copy.deepcopy(f["entries"][0]))
        with self.assertRaises(m.Denied):m.select(report(),f)
        f=fleet();f["entries"][0]["releasePolicy"]="automatic"
        with self.assertRaises((m.Denied,m.scope.Denied)):
            m.select(report(),f)
    def test_dynamic_future_extension_can_join_without_code_change(self):
        r=report();f=fleet();name="pgextwin/future_extension"
        f["entries"].append({"repository":name,"mode":"BUILD",
                              "candidateEnabled":True,"releasePolicy":"manual-only"})
        r["repositoryCount"]+=1
        r["rows"].append({"repository":name,"status":"INDETERMINATE",
                          "publicationAuthorized":False,"publisherTokenRequested":False})
        self.assertEqual(len(m.select(r,f)),1)
        r["rows"][-1].update(status="SIGNED_RUN_FOUND_REVERIFICATION_REQUIRED",
                             mainSha="c"*40,candidateRunId=555,
                             needsRealSigstoreReverification=True)
        self.assertEqual([x["name"] for x in m.select(r,f)],
                         ["pg_ivm","future_extension"])

if __name__=="__main__":
    unittest.main()
