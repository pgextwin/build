#!/usr/bin/env python3
"""Hostile Issue311 ambiguous original protected PUT and fail-closed replay tests."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("ambiguous", ROOT/"scripts"/"issue311-r04-ambiguous-put.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
HASH="a"*64


class Tests(unittest.TestCase):
    def test_fixed_readonly_state_rejects_privilege_and_mismatch(self):
        val=m.fixed_state(HASH)
        self.assertIsNone(m.verify_state(val,HASH))
        self.assertEqual(val["revision"],1)
        for data in (dict(val,publisherAuthorized=True),
                     dict(val,writeOutcomeUnknown=True),dict(val,scope="PUBLISH"),
                     dict(val,revision=2),dict(val,requestSha256="broken"),
                     dict(val,unexpected="evil")):
            with self.subTest(data=data),self.assertRaises(m.writer.Denied):
                m.verify_state(data,HASH)

    def test_actual_commit_then_response_loss_uses_get_only(self):
        state=m.fixed_state(HASH)
        calls=[]
        def api(method,*args):
            calls.append(method)
            if method=="PUT":return {"content":{"sha":"1"*40}}
            raise AssertionError("unexpected mocked API read")
        with mock.patch.object(m.writer,"api",side_effect=api), \
             mock.patch.object(m,"read",return_value=("1"*40,state)):
            result=m.simulate_after_commit_once("opaque",state)
        self.assertEqual(result["putCount"],1)
        self.assertFalse(result["automaticPutRetry"])
        self.assertEqual(calls,["PUT"])
        self.assertEqual(result["status"],"COMMITTED_RECONCILED_BY_ORIGINAL_GET")

    def test_response_loss_server_state_changed_denied(self):
        state=m.fixed_state(HASH)
        with mock.patch.object(m.writer,"api",return_value={}), \
             mock.patch.object(m,"read",return_value=("1"*40,dict(state,revision=2))):
            with self.assertRaises(m.writer.Denied):
                m.simulate_after_commit_once("opaque",state)

    def test_before_send_unknown_quarantine_no_put(self):
        state=m.fixed_state(HASH)
        with mock.patch.object(m.writer,"api",side_effect=AssertionError("no live PUT")) as write, \
             mock.patch.object(m,"read",return_value=("1"*40,state)):
            result=m.simulated_before_send_must_quarantine("opaque",state)
        self.assertEqual(result["status"],"QUARANTINED")
        self.assertEqual(result["secondPutCount"],0)
        self.assertFalse(result["blindRetryAllowed"])
        write.assert_not_called()

    def test_no_sensitive_cross_scope_endpoint(self):
        source=Path(m.__file__).read_text()
        for denied in ("/releases","/dispatches","/git/refs/tags",
                       "PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY"):
            self.assertNotIn(denied,source)
        self.assertEqual(m.STATE_PATH,"checkpoints/issue311-ambiguous-v1.json")


if __name__=="__main__":
    unittest.main()
