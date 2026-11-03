#!/usr/bin/env python3
"""Typed in-process owner signed-main receipt cannot be issued from push source.

Synthetic fixtures exercise conditional guards ONLY, never signature proof,
token access, release authorization or a live Writer.
"""
import copy
import importlib.util
from pathlib import Path
from unittest import TestCase,main

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj
fixtures=load("owner_issuer_existing_tests","tests/test-automatic-publisher-receipt-issuer.py")
issuer=fixtures.issuer
REPO=fixtures.REPO
KIND=issuer.OWNER_KIND

def owner_args():
    x=fixtures.owner_dispatch()
    x["event"]="issue_comment"
    x["schedule_run"]["event"]="issue_comment"
    x["schedule_run"]["display_title"]="Publisher-issue_comment-comment-777"
    x["request_comment_id"]=777
    x["source_kind"]=KIND
    x["source_signing_comment_id"]=333
    x["owner_central"]={"schemaVersion":1,"sourceKind":KIND,"mode":"ENFORCE",
                        "allowedRepositories":[REPO],"ownerLogin":"ShutenOishi",
                        "ownerId":27071164}
    x["owner_local"]={"schemaVersion":1,"enabled":True,"sourceKind":KIND,
                      "releasePolicy":issuer.MODE}
    hashes={}
    for major in x["proof"]["maintainedMajors"]:
        stem=issuer.ident.asset_stem(x["manifest"],major)
        for suffix in (".zip",".spdx.json",".vulnerabilities.json"):
            hashes[stem+suffix]="b"*64
    x["proof"]={"schemaVersion":1,
                "status":"OWNER_MAIN_SIGNED_SOURCE_INDEPENDENTLY_VERIFIED_NONPUBLISHING",
                "sourceKind":KIND,"sourceEvent":"issue_comment",
                "repository":REPO,"mainSha":fixtures.SHA,
                "sourceRunId":fixtures.SOURCE_RUN,"sourceRunAttempt":1,
                "sourceCommentId":333,
                "maintainedMajors":x["proof"]["maintainedMajors"],
                "originalAndFreshDualSigstoreAgree":True,
                "SHA256":hashes,"blockingGrypeFindings":0,
                "publisherEligible":False,"publicationAuthorized":False,
                "publishableReceipt":False,"publisherWriteAuthorized":False,
                "PUBLISH":"DENY"}
    return x

class InProcessOwnerTests(TestCase):
    def test_synthetic_policy_and_owner_receipt_type(self):
        receipt=issuer.issue(**owner_args())
        self.assertEqual(receipt["authorizationMode"],"owner-signed-main-issue-comment")
        self.assertEqual(receipt["signedSourceWorkflow"],issuer.OWNER_SOURCE)
        self.assertEqual(receipt["sourceKind"],KIND)
        self.assertEqual(receipt["sourceSigningCommentId"],333)
        self.assertEqual(receipt["requestCommentId"],777)
        self.assertEqual(receipt["sourceRunId"],fixtures.SOURCE_RUN)
        self.assertNotIn("token",receipt)
        self.assertTrue(receipt["publicationAuthorized"])
        self.assertTrue(receipt["publishableReceipt"])

    def test_denies_missing_policy_forged_run_and_source_kind(self):
        edits=(
            lambda x:x.update(source_kind="PUSH"),
            lambda x:x.update(source_kind=None),
            lambda x:x.update(owner_central=None),
            lambda x:x["owner_central"].update(mode="DENY"),
            lambda x:x["owner_central"].update(allowedRepositories=[]),
            lambda x:x.update(owner_local=None),
            lambda x:x["owner_local"].update(enabled=False),
            lambda x:x.update(source_signing_comment_id=777),
            lambda x:x.update(source_signing_comment_id=None),
            lambda x:x.update(request_comment_id=333),
            lambda x:x.update(event="push"),
            lambda x:x["schedule_run"].update(event="push"),
            lambda x:x["schedule_run"].update(run_attempt=2),
            lambda x:x["proof"].update(sourceKind="PUSH"),
            lambda x:x["proof"].update(sourceEvent="push"),
            lambda x:x["proof"].update(mainSha="a"*39),
            lambda x:x["proof"].update(sourceCommentId=999),
            lambda x:x["proof"].update(originalAndFreshDualSigstoreAgree=False),
            lambda x:x["proof"].update(sourceRunAttempt=2),
            lambda x:x["proof"].update(publisherEligible=True),
            lambda x:x["proof"].update(publicationAuthorized=True),
            lambda x:x["proof"].update(blockingGrypeFindings=1),
            lambda x:x["proof"].update(blockingGrypeFindings=True),
            lambda x:x["proof"]["SHA256"].pop(next(iter(x["proof"]["SHA256"]))),
        )
        for i,edit in enumerate(edits):
            with self.subTest(case=i),self.assertRaises((issuer.Denied,issuer.typed.Denied)):
                x=owner_args();edit(x);issuer.issue(**x)

    def test_old_push_schedule_contract_remains_unchanged(self):
        x=fixtures.switched()
        self.assertEqual(issuer.issue(**x)["authorizationMode"],"automatic-schedule")
        x=fixtures.owner_dispatch()
        self.assertEqual(issuer.issue(**x)["authorizationMode"],"owner-dispatch")
        x=fixtures.owner_dispatch()
        x["source_kind"]=KIND
        with self.assertRaises(issuer.Denied):
            issuer.issue(**x)

    def test_live_runner_is_still_unconnected_without_distinct_source_preflight(self):
        content=(ROOT/".github/workflows/publisher-candidate-intake.yml").read_text("utf-8")
        separate=content.split("  independent_owner_source_publish_request:",1)[1].split(
            "  independent_real_signed_source:",1)[0]
        self.assertNotIn("environment: publisher",separate)
        self.assertNotIn("PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY",separate)
        self.assertIn("PUBLISH_DENY",separate)

if __name__=="__main__":
    main()
