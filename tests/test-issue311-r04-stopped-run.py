#!/usr/bin/env python3
"""R04 separate-run interruption/recovery: hostile, isolated offline regressions."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("stopped",ROOT/"scripts"/"issue311-r04-stopped-run.py")
s=importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
NOW=datetime(2026,10,29,tzinfo=timezone.utc)
SRC=40790000001
NEW=40790000002
HASH="b"*64
SHA="a"*40


def state():
    return {"schemaVersion":1,"scope":"AUDIT_ONLY_READONLY","requestId":s.START_ID,
            "requestSha256":HASH,"revision":1,"phase":"LEASED_RUN_STOPPED",
            "sourceMainSha":SHA,"sourceRunId":SRC,"sourceRunAttempt":1,
            "lease":{"owner":f"run-{SRC}.1.stop","generation":1,
                     "expiresAt":(NOW+timedelta(seconds=120)).isoformat(),
                     "scope":"READONLY"},"completedStages":[s.STAGE],
            "resumedByRunId":None,"writeOutcomeUnknown":False,
            "publisherAuthorized":False}


class Tests(unittest.TestCase):
    def test_authoritative_first_checkpoint_and_new_run_fencing(self):
        first=state()
        self.assertIs(s.validate_state(first),first)
        second=dict(first,revision=2,phase="RECOVERED_ANOTHER_RUN",resumedByRunId=NEW,
                    lease={"owner":f"run-{NEW}.1.resume","generation":2,
                           "expiresAt":(NOW+timedelta(seconds=241)).isoformat(),
                           "scope":"READONLY"})
        self.assertIs(s.validate_state(second),second)
        self.assertEqual(second["completedStages"],first["completedStages"])
        self.assertNotEqual(second["sourceRunId"],second["resumedByRunId"])

    def test_deny_privilege_forged_resume_replay_and_state_tamper(self):
        first=state()
        failures=[
            {"publisherAuthorized":True},{"writeOutcomeUnknown":True},
            {"scope":"PUBLISH"},{"completedStages":[]},{"sourceRunAttempt":2},
            {"sourceMainSha":"main"},{"requestSha256":"broken"},{"revision":True},
            {"lease":dict(first["lease"],scope="PUBLISH")},
            {"phase":"RECOVERED_ANOTHER_RUN"},{"revision":2},
            {"someExtra":"evil"},
        ]
        for change in failures:
            with self.subTest(change=change),self.assertRaises(s.writer.Denied):
                s.validate_state(dict(first,**change))
        with self.assertRaises(s.writer.Denied):
            s.validate_state(dict(first,revision=2,phase="RECOVERED_ANOTHER_RUN",
                                  resumedByRunId=SRC,lease={
                                  "owner":f"run-{SRC}.1.resume","generation":2,
                                  "expiresAt":NOW.isoformat(),"scope":"READONLY"}))

    def test_unknown_write_never_retries_if_get_fails(self):
        current=state()
        def api(method,endpoint,token,payload=None):
            if method=="PUT":
                raise TimeoutError("lost original write response")
            if method=="GET":
                raise TimeoutError("authoritative GET unavailable")
            raise AssertionError("unrecognized method")
        with mock.patch.object(s.writer,"api",side_effect=api):
            with self.assertRaises(s.writer.UncertainWrite):
                s.save("opaque-token",current)
        # Only one mutating call. The fallback cannot retry original PUT.
        attempts=[]
        def count_api(method,endpoint,token,payload=None):
            attempts.append(method)
            raise TimeoutError("unknown")
        with mock.patch.object(s.writer,"api",side_effect=count_api):
            with self.assertRaises(s.writer.UncertainWrite):
                s.save("opaque-token",current)
        self.assertEqual(attempts,["PUT","GET"])

    def test_source_get_rejects_unfinished_or_wrong_original(self):
        import json
        source={"sourceRunId":SRC,"sourceRunAttempt":1,"sourceMainSha":SHA}
        class Reply:
            def __init__(self,payload): self.payload=payload
            def __enter__(self): return self
            def __exit__(self,*args): return False
        scenarios=[
            {"id":SRC,"status":"in_progress","conclusion":None,"event":"push",
             "head_sha":SHA,"run_attempt":1},
            {"id":SRC,"status":"completed","conclusion":"success","event":"push",
             "head_sha":SHA,"run_attempt":1},
            {"id":SRC,"status":"completed","conclusion":"failure","event":"schedule",
             "head_sha":SHA,"run_attempt":1},
        ]
        with mock.patch.dict("os.environ",{"GH_TOKEN":"read-only-token"}):
            for payload in scenarios:
                with self.subTest(payload=payload),mock.patch("urllib.request.urlopen",
                        return_value=Reply(payload)),mock.patch.object(s.json,"load",
                        side_effect=lambda stream,**kw:stream.payload):
                    with self.assertRaises(s.writer.Denied):
                        s.verify_original_failed_run(source)

    def test_no_implicit_release_or_dispatch_endpoint(self):
        text=Path(s.__file__).read_text()
        for denied in ("/releases","/dispatches","/git/refs/tags",
                       "PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY"):
            self.assertNotIn(denied,text)
        self.assertEqual(s.LEDGER,"checkpoints/issue311-cross-run-v1.json")
        self.assertEqual(s.LEASE_SECONDS,120)


if __name__=="__main__":
    unittest.main()
