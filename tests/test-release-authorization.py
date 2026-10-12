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
                   candidateRunId=31, decisionRunId=32)
    return obj

class ReceiptTests(unittest.TestCase):
    def test_both_typed_modes_and_events(self):
        for mode,event in (("manual-dispatch","workflow_dispatch"),
                           ("chat-pr-authorization","push")):
            with self.subTest(mode=mode):
                self.assertEqual(auth.validate_receipt(
                    fixture(mode),repository=REPO,commit=SHA,
                    actor="HumanOperator",event=event),event)

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
