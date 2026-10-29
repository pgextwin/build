#!/usr/bin/env python3
"""HTTP 429/503 fault-injection contract only; never a real provider outage claim.

Uses no GitHub API, App token, schedule, dispatcher, live source or publication.
The original source/replay evidence is intentionally not fabricated here.
"""
import importlib.util
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock

ROOT=Path(__file__).resolve().parents[1]
with mock.patch.dict(os.environ,{"ISSUE311_PROOF_CASE":"missing-event-17"}):
    spec=importlib.util.spec_from_file_location(
        "bounded_http_watchdog",ROOT/"scripts/issue311-r05-finite-watchdog.py")
    watchdog=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(watchdog)

class FakeCAS:
    def __init__(self,state):
        self.store=watchdog.store
        self.state=state
        self.sha=self.store.blob_hash(self.store.canonical(state))
        self.writes=0

    def read(self,request_id):
        if request_id!=self.state["requestId"]:
            raise AssertionError("cross-request App GET")
        return self.sha,self.state

    def write(self,proposed,*,previous,expected_blob):
        if expected_blob!=self.sha or previous!=self.state:
            raise AssertionError("missing immutable original App CAS pin")
        self.store.require_transition(previous,proposed)
        self.state=proposed
        self.sha=self.store.blob_hash(self.store.canonical(proposed))
        self.writes+=1
        return "ORIGINAL_GET_VERIFIED"

class FiniteHttpFaults(TestCase):
    def test_original17_transport_unknown_quarantines_without_success_or_retry(self):
        for status in (429,503):
            with self.subTest(controlled_http_status=status),TemporaryDirectory() as tmp:
                request_id=watchdog.REQ
                source_sha="b"*40
                deadline="2020-01-01T00:00:00Z"
                scope=sorted(watchdog.m.bridge.win17.TARGETS)
                self.assertEqual(len(scope),17)
                pending=watchdog.life.new(request_id,"a"*64,source_sha,
                                          scope,deadline,max_events=25)
                bound=watchdog.life.bind_source(pending,0,"original-source",
                    run_id=123,attempt=1,head_sha=source_sha)
                cas=FakeCAS(bound)
                observation=Path(tmp)/"observation.json"
                error=RuntimeError(f"CONTROLLED_HTTP_{status}_ORIGINAL_GET_UNAVAILABLE")
                with mock.patch.object(watchdog,"EVENT_FILE",str(observation)), \
                     mock.patch.object(watchdog,"initial_event",
                         return_value=({"expiresAt":deadline},source_sha)), \
                     mock.patch.object(watchdog,"state_get",return_value=bound), \
                     mock.patch.object(watchdog,"snapshot",side_effect=error), \
                     mock.patch.object(watchdog.m,"app_cas",
                         return_value=("synthetic-token",cas)), \
                     mock.patch.object(watchdog.writer,"revoke_and_prove_401") as revoke:
                    self.assertEqual(watchdog.observe(),0)
                    report=json.loads(observation.read_bytes())
                    self.assertEqual(report["result"],"NEEDS_TERMINAL")
                    self.assertEqual(report["observation"]["lookup"],"UNKNOWN")
                    self.assertIsNone(report["observation"]["sourceCompleted"])
                    self.assertIn(f"HTTP_{status}",report["observation"]["reason"])
                    self.assertFalse(report["publisherAuthorized"])
                    self.assertEqual(watchdog.finalize(),0)
                    revoke.assert_called_once_with("synthetic-token")
                self.assertEqual(cas.writes,1)
                terminal=cas.state
                self.assertEqual(terminal["revision"],2)
                self.assertEqual(terminal["terminal"],"QUARANTINED")
                self.assertEqual(terminal["eventTransport"],"BOUNDED_WATCHDOG")
                self.assertEqual(len(terminal["targets"]),17)
                self.assertEqual(set(terminal["targets"].values()),{"QUARANTINED"})
                self.assertFalse(terminal["publisherAuthorized"])
                self.assertFalse(terminal["writeOutcomeUnknown"])
                with self.assertRaises(watchdog.store.Denied):
                    watchdog.store.require_transition(terminal,terminal)

if __name__=="__main__":
    main()
