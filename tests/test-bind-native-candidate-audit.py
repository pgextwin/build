#!/usr/bin/env python3
"""Denial fixtures for future use of real 17-fleet native audit artifacts.

A passing audit remains strictly nonpublishing; no publisher can use the
output as signed-Release authorization.
"""
import importlib.util
from copy import deepcopy
from datetime import date
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "binder",ROOT/"scripts"/"bind-native-candidate-audit.py")
b=importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
SHA="678c37861080aa221b859cefaca98725646dbf7c"
HEAD="a"*40
MERGE="b"*40
MAIN="c"*40
BRANCH="auto-candidate/"+"d"*20
CI_RUN=39769754052
AUDIT_RUN=39771145795
ART=12422372611
REPO="pgextwin/pg_ivm"
EXT={"name":"pg_ivm","postgresql":{"majors":[14,15,16,17,18]},
     "upstream":{"repository":"sraoss/pg_ivm","ref":"v1.17",
                 "version":"1.17","commit":SHA}}
LIFE={"schemaVersion":1,"postgresql":[
    {"major":m,"eol":"2030-11-12"} for m in range(14,19)]}


def fixture():
    return dict(
        repository=REPO,current_main_sha=MAIN,today=date(2026,10,22),
        ext=deepcopy(EXT),lifecycle=deepcopy(LIFE),
        context={"schemaVersion":1,"status":"NATIVE_PR_CI_AUTHENTICATED_NOT_PUBLISHABLE",
                 "repository":REPO,"candidatePr":28,"branch":BRANCH,
                 "candidateHeadSha":HEAD,"packagingMergeSha":MERGE,
                 "candidateRunId":CI_RUN,"matrixResult":"success",
                 "candidateAuditVerified":False,"signedArtifactsVerified":False,
                 "publishableReceipt":False,"publicationAuthorized":False},
        audit={"schemaVersion":1,"extension":"pg_ivm","runId":CI_RUN,
               "branch":BRANCH,"branchSha":HEAD,"originEvent":"pull_request",
               "matrixResult":"success","status":"VERIFIED",
               "majors":[{"major":m,"status":"SUCCESS","sourceSha":SHA,
                          "zipSha256":"e"*64,
                          "zip":f"pg_ivm-v1.17-pg{m}-windows-x64.zip",
                          "sbom":f"pg_ivm-v1.17-pg{m}-windows-x64.spdx.json",
                          "grype":f"pg_ivm-v1.17-pg{m}-windows-x64.vulnerabilities.json"}
                         for m in range(14,19)]},
        ci_run={"id":CI_RUN,"name":"Windows CI/CD",
                "head_repository":{"full_name":REPO},"head_branch":BRANCH,
                "head_sha":HEAD,"event":"pull_request",
                "status":"completed","conclusion":"success"},
        audit_run={"id":AUDIT_RUN,"name":"Upstream candidate after verified central daily fleet scan",
                   "path":".github/workflows/update-watch.yml",
                   "head_branch":"main","head_sha":MAIN,"event":"workflow_run",
                   "status":"completed","conclusion":"success"},
        artifact={"id":ART,"name":"candidate-audit-native-pr","size_in_bytes":1258,
                  "expired":False,"workflow_run":{"id":AUDIT_RUN}},
    )


class NativeArtifactBindingTests(unittest.TestCase):
    def test_provenance_binds_only_as_inert_context(self):
        x=b.join(**fixture())
        self.assertEqual(x["status"],"BOUND_NATIVE_CANDIDATE_AUDIT_NONPUBLISHING")
        self.assertEqual(x["majors"],[14,15,16,17,18])
        self.assertEqual(len(x["sourcesAndZipDigests"]),5)
        self.assertEqual(x["nativeAuditArtifactId"],ART)
        for field in ("signedArtifactsVerified","publishableReceipt",
                      "publicationAuthorized"):
            self.assertIs(x[field],False)
        self.assertNotIn("authorizationMode",x)
        self.assertNotIn("releaseTag",x)

    def test_reject_cross_run_forgery_duplicates_and_partial_receipts(self):
        cases=[
            lambda x:x.update(repository="pgextwin/orafce"),
            lambda x:x.update(current_main_sha=HEAD),
            lambda x:x["context"].update(status="VERIFIED_CHAT_PR_AUTHORIZATION"),
            lambda x:x["context"].update(publishableReceipt=True),
            lambda x:x["context"].update(signedArtifactsVerified=True),
            lambda x:x["audit"].update(status="FAILED"),
            lambda x:x["audit"].update(originEvent="workflow_dispatch"),
            lambda x:x["audit"].update(matrixResult="failure"),
            lambda x:x["audit"].update(runId=CI_RUN+1),
            lambda x:x["audit"].update(branchSha=MERGE),
            lambda x:x["audit"].update(branch="auto-candidate/"+"f"*20),
            lambda x:x["audit"].update(extension="orafce"),
            lambda x:x["audit"]["majors"].pop(),
            lambda x:x["audit"]["majors"].append(deepcopy(x["audit"]["majors"][0])),
            lambda x:x["audit"]["majors"][0].update(major=18),
            lambda x:x["audit"]["majors"][0].update(sourceSha="f"*40),
            lambda x:x["audit"]["majors"][0].update(zipSha256="0"*63),
            lambda x:x["audit"]["majors"][0].update(sbom="forged.spdx.json"),
            lambda x:x["ext"]["upstream"].update(commit="f"*40),
            lambda x:x["ext"]["upstream"].update(repository="evil/pg_ivm"),
            lambda x:x["lifecycle"].update(postgresql=[]),
            lambda x:x["ci_run"].update(id=CI_RUN+1),
            lambda x:x["ci_run"].update(event="workflow_dispatch"),
            lambda x:x["ci_run"].update(conclusion="action_required"),
            lambda x:x["ci_run"].update(head_sha=MERGE),
            lambda x:x["ci_run"]["head_repository"].update(full_name="other/pg_ivm"),
            lambda x:x["audit_run"].update(path=".github/workflows/promote.yml"),
            lambda x:x["audit_run"].update(event="workflow_dispatch"),
            lambda x:x["audit_run"].update(head_sha=HEAD),
            lambda x:x["audit_run"].update(conclusion="failure"),
            lambda x:x["artifact"].update(name="candidate-audit"),
            lambda x:x["artifact"].update(expired=True),
            lambda x:x["artifact"].update(size_in_bytes=0),
            lambda x:x["artifact"]["workflow_run"].update(id=CI_RUN),
        ]
        for i,mutate in enumerate(cases):
            with self.subTest(index=i), self.assertRaises(b.Denied):
                obj=fixture()
                mutate(obj)
                b.join(**obj)

if __name__=="__main__":
    unittest.main()
