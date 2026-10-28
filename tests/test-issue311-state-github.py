#!/usr/bin/env python3
"""R04 CAS in-memory storage, hostile lease and ambiguous write regressions."""
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location("adapter","scripts/issue311-state-github.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
R="r-20261029-r04probe001"
H="7a8761dd458aeb88c20d13ff5ac8e92aa5f07dd5b89e6b0c395cffa6d5aad75f"
NOW=datetime(2026,10,29,tzinfo=timezone.utc)


class FakeAPI:
    def __init__(self):
        self.state={"schemaVersion":1,"requestId":R,"revision":0,"requestSha256":H,
                    "publisherAuthorized":False,"terminal":False,"writeOutcomeUnknown":False,
                    "lease":None}
        self.sha="a"*40
        self.bad_response=False
        self.write_count=0

    def __call__(self,method,endpoint,payload):
        if method=="GET":
            return {"encoding":"base64","sha":self.sha,"content":base64.b64encode(
                json.dumps(self.state).encode()).decode()}
        if method=="PUT":
            if payload["branch"]!="issue311-state" or payload["sha"]!=self.sha:
                raise m.Conflict("stale GitHub Contents blob 409")
            self.write_count+=1
            self.state=json.loads(base64.b64decode(payload["content"]))
            self.sha=hashlib.sha1(payload["content"].encode()).hexdigest()
            if self.bad_response:
                raise TimeoutError("commit accepted but HTTP response disappeared")
            return {"content":{"sha":self.sha}}
        raise AssertionError("unexpected API operation")


class Tests(unittest.TestCase):
    def test_durable_cas_conflict_and_persistence(self):
        api=FakeAPI()
        store=m.GithubContentsCAS(api)
        first_sha,first=store.read(R)
        new=m.acquire_lease(first,R,"coordinator-A",NOW)
        store.commit_lease(R,first_sha,first,new)
        self.assertEqual(store.read(R)[1]["revision"],1)
        stale=m.acquire_lease(first,R,"coordinator-B",NOW)
        with self.assertRaises(m.Conflict):
            store.commit_lease(R,first_sha,first,stale)
        self.assertEqual(store.read(R)[1]["lease"]["owner"],"coordinator-A")
        self.assertEqual(api.write_count,1)

    def test_lease_takeover_expiry_and_live_owner_rejection(self):
        base=FakeAPI().state
        a=m.acquire_lease(base,R,"coordinator-A",NOW)
        with self.assertRaises(m.Conflict):
            m.acquire_lease(a,R,"coordinator-B",NOW+timedelta(seconds=30))
        b=m.acquire_lease(a,R,"coordinator-B",NOW+timedelta(seconds=301))
        self.assertEqual(b["lease"]["generation"],2)
        self.assertEqual(b["lease"]["scope"],"READONLY")
        with self.assertRaises(m.Denied):
            m.acquire_lease(base,R,"owner",NOW,seconds=601)

    def test_ambiguous_commit_must_be_quarantined_not_blind_retried(self):
        api=FakeAPI()
        api.bad_response=True
        store=m.GithubContentsCAS(api)
        sha,state=store.read(R)
        changed=m.acquire_lease(state,R,"owner",NOW)
        with self.assertRaises(m.UnknownWriteOutcome):
            store.commit_lease(R,sha,state,changed)
        self.assertEqual(store.read(R)[1]["revision"],1)
        with self.assertRaises(m.Conflict):
            store.commit_lease(R,sha,state,changed)

    def test_denials_and_separate_writer_authority(self):
        base=FakeAPI().state
        for bad in ["not-id","../main","r-20261029-xx/aa"]:
            with self.assertRaises(m.Denied):
                m.path_for(bad)
        for extra in ({"publisherAuthorized":True},{"writeOutcomeUnknown":True},
                      {"terminal":True}):
            val=dict(base,**extra)
            with self.assertRaises(m.Denied):
                m.acquire_lease(val,R,"owner",NOW)
        changed=m.acquire_lease(base,R,"owner",NOW)
        changed["publisherAuthorized"]=True
        with self.assertRaises(m.Denied):
            m.GithubContentsCAS(FakeAPI()).commit_lease(R,"a"*40,base,changed)
        self.assertEqual(m.STATE_REF,"refs/heads/issue311-state")


if __name__=="__main__":
    unittest.main()
