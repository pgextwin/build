#!/usr/bin/env python3
"""Receipt type + runtime event denial fixtures; no GitHub effects."""
import importlib.util
from pathlib import Path
from copy import deepcopy
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "releaseauth",ROOT/"scripts"/"release-authorization.py")
auth=importlib.util.module_from_spec(spec); spec.loader.exec_module(auth)
SHA="a"*40
BASE="b"*40
HEAD="c"*40
REPO="pgextwin/wal2json"

def fixture(mode="manual-dispatch"):
    obj={"schemaVersion":1,"status":"VERIFIED_MANUAL_DISPATCH",
         "authorizationMode":"manual-dispatch","operator":"HumanOperator",
         "repository":REPO,"trustedCommit":SHA,
         "releaseTag":"v2.7-windows.2","majors":[14,15,16,17,18],"sources":[{}]}
    if mode=="chat-pr-authorization":
        obj.update(status="VERIFIED_CHAT_PR_AUTHORIZATION",
                   authorizationMode=mode, authorizationPr=34,
                   authorizationCommit=SHA, authorizationHeadSha=HEAD,
                   authorizationBaseSha=BASE, candidateHeadSha="d"*40, candidatePr=3,
                   candidateRunId=31, decisionRunId=32,
                   signedArtifactsVerified=True, publishingEnabled=True,
                   publishableReceipt=True)
    return obj

def automatic_fixture():
    obj=fixture()
    obj.pop("operator")
    obj.update(
        status="VERIFIED_AUTOMATIC_SCHEDULE",
        authorizationMode="automatic-schedule",
        publisherRepository="pgextwin/build",
        publisherWorkflow=".github/workflows/publisher-candidate-intake.yml",
        publisherRunId=89753,publisherRunAttempt=1,
        publisherMainSha="e"*40,
        signedSourceWorkflow=".github/workflows/update-watch.yml",
        sourceRunId=23456,sourceRunAttempt=1,
        signedArtifactsVerified=True,publicationAuthorized=True,
        publishableReceipt=True,publisherWriteAuthorized=True,
        automaticReleaseEnabled=True,
        approvalProvenance="INDEPENDENT_LIVE_SCHEDULE_AND_SIGNED_SOURCE")
    return obj


class ReceiptTests(unittest.TestCase):
    def test_schedule_receipt_type_is_distinct_from_human_approval(self):
        # Pure schema acceptance is NOT an authorization issuer or Sigstore.
        self.assertEqual(auth.validate_receipt(
            automatic_fixture(),repository=REPO,commit=SHA,
            actor="ScheduleWorkflowEditor",event="schedule"),"schedule")
        for event in ("push","workflow_dispatch"):
            with self.assertRaises(auth.Denied):
                auth.validate_receipt(automatic_fixture(),repository=REPO,
                                      commit=SHA,actor="ScheduleWorkflowEditor",
                                      event=event)
        with self.assertRaises(auth.Denied):
            auth.validate_receipt(fixture(),repository=REPO,commit=SHA,
                                  actor="HumanOperator",event="schedule")

    def test_fake_schedule_receipt_identity_and_authority_denied(self):
        changes=[
            lambda x:x.update(operator="HumanOperator"),
            lambda x:x.update(publisherRepository=REPO),
            lambda x:x.update(publisherWorkflow=".github/workflows/evil.yml"),
            lambda x:x.update(publisherRunId=0),
            lambda x:x.update(publisherRunId=True),
            lambda x:x.update(publisherRunAttempt=2),
            lambda x:x.update(publisherRunAttempt=True),
            lambda x:x.update(publisherMainSha="invalid"),
            lambda x:x.update(signedSourceWorkflow="evil.yml"),
            lambda x:x.update(sourceRunId=0),
            lambda x:x.update(sourceRunId=89753),
            lambda x:x.update(sourceRunAttempt=2),
            lambda x:x.update(sourceRunAttempt=True),
            lambda x:x.update(approvalProvenance="FAKE"),
            lambda x:x.update(status="VERIFIED_MANUAL_DISPATCH"),
            lambda x:x.update(trustedCommit=BASE),
            lambda x:x.update(authorizationMode="automatic"),
        ]
        for field in ("signedArtifactsVerified","publicationAuthorized",
                      "publishableReceipt","publisherWriteAuthorized",
                      "automaticReleaseEnabled"):
            changes.extend((
                lambda x,f=field:x.update({f:False}),
                lambda x,f=field:x.update({f:"true"})))
        for i,change in enumerate(changes):
            with self.subTest(i=i),self.assertRaises(auth.Denied):
                obj=automatic_fixture()
                change(obj)
                auth.validate_receipt(obj,repository=REPO,commit=SHA,
                                      actor="ScheduleWorkflowEditor",event="schedule")

    def test_both_typed_modes_and_events(self):
        for mode,event in (("manual-dispatch","workflow_dispatch"),
                           ("chat-pr-authorization","push")):
            with self.subTest(mode=mode):
                self.assertEqual(auth.validate_receipt(
                    fixture(mode),repository=REPO,commit=SHA,
                    actor="HumanOperator",event=event),event)

    def test_chat_flags_are_explicit_boolean_true_only(self):
        # The future Chat route is inert, but its receipt validator must never
        # treat missing, null or truthy values as an independently verified gate.
        invalid = [None, False, 0, 1, "true", "True", [], [True], {}, {"value": True}]
        for flag in ("signedArtifactsVerified", "publishingEnabled",
                     "publishableReceipt"):
            for value in invalid:
                receipt = fixture("chat-pr-authorization")
                receipt[flag] = value
                with self.subTest(flag=flag, value=value), self.assertRaises(auth.Denied):
                    auth.validate_receipt(receipt, repository=REPO, commit=SHA,
                                          actor="HumanOperator", event="push")
            receipt = fixture("chat-pr-authorization")
            del receipt[flag]
            with self.subTest(flag=flag, value="missing"), self.assertRaises(auth.Denied):
                auth.validate_receipt(receipt, repository=REPO, commit=SHA,
                                      actor="HumanOperator", event="push")

    def test_manual_mode_does_not_require_future_chat_flags(self):
        # Preserve deployed manual-dispatch behavior exactly.
        manual = fixture()
        for field in ("signedArtifactsVerified", "publishingEnabled", "publishableReceipt"):
            self.assertNotIn(field, manual)
        self.assertEqual(auth.validate_receipt(
            manual, repository=REPO, commit=SHA, actor="HumanOperator",
            event="workflow_dispatch"), "workflow_dispatch")

    def test_cross_mode_actor_identity_and_schema_denials(self):
        cases=[
            ("manual-dispatch",{"event":"push"},None),
            ("chat-pr-authorization",{"event":"workflow_dispatch"},None),
            ("manual-dispatch",{"actor":"attacker"},None),
            ("chat-pr-authorization",{"actor":"github-actions[bot]"},None),
            ("chat-pr-authorization",{"commit":BASE},None),
            ("chat-pr-authorization",{"repository":"pgextwin/evil"},None),
            ("manual-dispatch",{},{"authorizationMode":"automatic"}),
            ("chat-pr-authorization",{},{"status":"VERIFIED_MANUAL_DISPATCH"}),
            ("chat-pr-authorization",{},{"authorizationPr":True}),
            ("chat-pr-authorization",{},{"authorizationBaseSha":"invalid"}),
            ("chat-pr-authorization",{},{"authorizationCommit":BASE}),
            ("chat-pr-authorization",{},{"authorizationHeadSha":BASE[:39]}),
            ("chat-pr-authorization",{},{"candidateRunId":0}),
            ("chat-pr-authorization",{},{"decisionRunId":None}),
            ("chat-pr-authorization",{},{"candidatePr":"1"}),
            ("chat-pr-authorization",{},{"trustedCommit":BASE}),
            ("chat-pr-authorization",{},{"signedArtifactsVerified":False}),
            ("chat-pr-authorization",{},{"signedArtifactsVerified":None}),
            ("chat-pr-authorization",{},{"publishingEnabled":False}),
            ("chat-pr-authorization",{},{"publishableReceipt":False}),
            ("manual-dispatch",{},{"operator":""}),
            ("manual-dispatch",{"actor":"github-actions[bot]"},{"operator":"github-actions[bot]"}),
            ("chat-pr-authorization",{"actor":"Evilbot"},{"operator":"Evilbot"}),
            ("manual-dispatch",{},{"schemaVersion":True}),
        ]
        for idx,(mode,kwargs,mutation) in enumerate(cases):
            obj=fixture(mode)
            if mutation:obj.update(mutation)
            arguments=dict(repository=REPO,commit=SHA,actor="HumanOperator",
                           event="push" if mode=="chat-pr-authorization" else "workflow_dispatch")
            arguments.update(kwargs)
            with self.subTest(index=idx), self.assertRaises(auth.Denied):
                auth.validate_receipt(obj,**arguments)

if __name__=="__main__":unittest.main()
