#!/usr/bin/env python3
"""#524 offline hostile tests: distinct owner signing is not a push Release."""
from __future__ import annotations
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj
policy=load("owner_source_publish_policy_test","scripts/owner-source-publish-policy.py")
old=load("owner_source_existing_issuer_fixtures","tests/test-automatic-publisher-receipt-issuer.py")
typed=load("owner_source_typed_receipts","tests/test-release-authorization.py")
REPO="pgextwin/pgaudit"
KIND="OWNER_ISSUE_COMMENT_MAIN_SIGNING"

def synthetic():
    obj=old.switched()
    obj["owner_central"]={
        "schemaVersion":1,"sourceKind":KIND,"mode":"ENFORCE",
        "allowedRepositories":[REPO],"ownerLogin":"ShutenOishi",
        "ownerId":27071164}
    obj["owner_local"]={
        "schemaVersion":1,"enabled":True,"sourceKind":KIND,
        "releasePolicy":"automatic-signed-schedule"}
    return {key:obj[key] for key in (
        "fleet","central","local","unattended","boundary","owner_central",
        "owner_local","repository")}

def owner_receipt():
    x=typed.automatic_fixture()
    x.update(authorizationMode="owner-signed-main-issue-comment",
             status="VERIFIED_OWNER_SIGNED_MAIN_ISSUE_COMMENT",
             operator="ShutenOishi",
             signedSourceWorkflow=".github/workflows/chat-signed-main.yml",
             sourceKind=KIND,sourceEvent="issue_comment",
             sourceSigningCommentId=34343,requestCommentId=56565,
             originalAndFreshDualSigstoreAgree=True,
             approvalProvenance="INDEPENDENT_LIVE_OWNER_MAIN_SIGNING_AND_PUBLISH_REQUEST")
    return x

class OwnerSourcePolicyTests(unittest.TestCase):
    def test_dual_gate_requires_independent_real_issuer_after_static_success(self):
        result=policy.gate(**synthetic())
        self.assertEqual(result["sourceKind"],KIND)
        self.assertFalse(result["publicationAuthorized"])
        self.assertFalse(result["publishableReceipt"])

    def test_protected_default_denies_without_publisher_entry(self):
        data=synthetic()
        data["owner_central"]=json.loads(
            (ROOT/"metadata/owner-source-publication.json").read_text("utf-8"))
        self.assertEqual(data["owner_central"]["mode"],"DENY")
        self.assertEqual(data["owner_central"]["allowedRepositories"],[])
        with self.assertRaises(policy.Denied):
            policy.gate(**data)

    def test_central_local_fleet_and_existing_policy_fail_closed(self):
        edits=(
            lambda x:x.update(owner_central=None),
            lambda x:x["owner_central"].update(mode="DENY"),
            lambda x:x["owner_central"].update(sourceKind="PUSH"),
            lambda x:x["owner_central"].update(ownerLogin="attacker"),
            lambda x:x["owner_central"].update(ownerId=True),
            lambda x:x["owner_central"].update(allowedRepositories=[]),
            lambda x:x["owner_central"].update(allowedRepositories=[REPO,REPO]),
            lambda x:x["owner_central"].update(allowedRepositories=[REPO,"pgextwin/evil"]),
            lambda x:x["owner_central"].update(allowedRepositories=[REPO,7]),
            lambda x:x["owner_central"].update(unrecognized=True),
            lambda x:x.update(owner_local=None),
            lambda x:x["owner_local"].update(enabled=False),
            lambda x:x["owner_local"].update(enabled=1),
            lambda x:x["owner_local"].update(sourceKind="push"),
            lambda x:x["owner_local"].update(releasePolicy="manual-only"),
            lambda x:x["owner_local"].update(extra=True),
            lambda x:x["fleet"].update(releasePolicy="manual-only"),
            lambda x:x["central"].update(releasePolicy="manual-dispatch"),
            lambda x:x["local"].update(enabled=False),
            lambda x:x["unattended"].update(mode="OBSERVE"),
            lambda x:x["boundary"].update(mode="DENY"),
            lambda x:x.update(repository="pgextwin/evil"),
        )
        for i,edit in enumerate(edits):
            with self.subTest(i=i),self.assertRaises(policy.Denied):
                x=synthetic();edit(x);policy.gate(**x)

    def test_new_receipt_kind_is_distinct_and_only_structural(self):
        self.assertEqual(
            typed.auth.validate_receipt(owner_receipt(),
                repository=typed.REPO,commit=typed.SHA,
                actor="ShutenOishi",event="issue_comment"),
            "issue_comment")
        for field,value in (
            ("authorizationMode","owner-issue-comment"),
            ("status","VERIFIED_OWNER_ISSUE_COMMENT"),
            ("signedSourceWorkflow",".github/workflows/update-watch.yml"),
            ("sourceKind","PUSH"),("sourceEvent","push"),
            ("sourceSigningCommentId",0),("sourceSigningCommentId",True),
            ("requestCommentId",0),("requestCommentId",34343),
            ("originalAndFreshDualSigstoreAgree","true"),
            ("originalAndFreshDualSigstoreAgree",False),
            ("sourceRunAttempt",2),("sourceRunId",89753),
            ("approvalProvenance","INDEPENDENT_LIVE_OWNER_COMMENT_AND_SIGNED_SOURCE"),
        ):
            with self.subTest(field=field,value=value),self.assertRaises(typed.auth.Denied):
                x=owner_receipt();x[field]=value
                typed.auth.validate_receipt(x,repository=typed.REPO,
                    commit=typed.SHA,actor="ShutenOishi",event="issue_comment")
        for event in ("push","schedule","workflow_dispatch"):
            with self.subTest(event=event),self.assertRaises(typed.auth.Denied):
                typed.auth.validate_receipt(owner_receipt(),
                    repository=typed.REPO,commit=typed.SHA,
                    actor="ShutenOishi",event=event)

    def test_existing_push_receipt_unmodified(self):
        receipt=typed.automatic_fixture()
        self.assertEqual(typed.auth.validate_receipt(receipt,
            repository=typed.REPO,commit=typed.SHA,
            actor="ScheduleWorkflowEditor",event="schedule"),"schedule")

if __name__=="__main__":
    unittest.main()
