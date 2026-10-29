#!/usr/bin/env python3
"""R04 generic durable state adapter: CAS, blob and ambiguous write hostile fixtures."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("store",ROOT/"scripts"/"issue311-lifecycle-store.py")
store=importlib.util.module_from_spec(spec)
spec.loader.exec_module(store)
REQ="r-20261029-durablewriter01"
FIRST="a"*64
HEAD="b"*40
EXPIRE="2026-10-29T01:30:00Z"


class Backend:
    def __init__(self):
        self.files={}
        self.conflict=False
        self.drop=False
        self.store_before_drop=False

    def __call__(self,method,endpoint,body):
        assert endpoint.startswith(store.REPOSITORY+store.PREFIX)
        assert "issue311-state" in endpoint or method=="PUT"
        path=endpoint.split("?",1)[0]
        if method=="GET":
            if path not in self.files: raise RuntimeError("404")
            raw=self.files[path]
            return {"encoding":"base64","sha":store.blob_hash(raw),
                    "content":base64.b64encode(raw).decode()}
        if self.conflict: raise RuntimeError("409")
        if body.get("branch")!=store.BRANCH: raise RuntimeError("wrong branch")
        old=self.files.get(path)
        if old is None and "sha" in body: raise RuntimeError("404")
        if old is not None and body.get("sha")!=store.blob_hash(old): raise RuntimeError("409")
        raw=base64.b64decode(body["content"])
        if not self.drop or self.store_before_drop:self.files[path]=raw
        if self.drop:raise RuntimeError("network response lost")
        return {"content":{"sha":store.blob_hash(raw)}}


class StoreTests(unittest.TestCase):
    def state(self):
        return store.lifecycle.new(REQ,FIRST,HEAD,["pgextwin/orafce"],EXPIRE)

    def test_store_create_get_cas_and_terminal(self):
        backend=Backend(); cas=store.CAS(backend); state=self.state()
        self.assertEqual(cas.write(state),"ORIGINAL_GET_VERIFIED")
        sha,old=cas.read(REQ)
        next_state=store.lifecycle.bind_source(old,0,"source",run_id=123,attempt=1,head_sha=HEAD)
        self.assertEqual(cas.write(next_state,previous=old,expected_blob=sha),"ORIGINAL_GET_VERIFIED")
        self.assertEqual(cas.read(REQ)[1]["revision"],1)
        with self.assertRaises(store.UnknownWrite):
            cas.write(next_state,previous=old,expected_blob=sha)

    def test_lost_response_reconciled_only_when_bytes_match(self):
        backend=Backend(); cas=store.CAS(backend); initial=self.state()
        backend.drop=True;backend.store_before_drop=True
        self.assertEqual(cas.write(initial),"RECONCILED_BY_ORIGINAL_GET")
        sha,first=cas.read(REQ)
        second=store.lifecycle.bind_source(first,0,"source",run_id=123,attempt=1,head_sha=HEAD)
        backend.store_before_drop=False
        with self.assertRaises(store.UnknownWrite):
            cas.write(second,previous=first,expected_blob=sha)
        self.assertEqual(cas.read(REQ)[1],first)

    def test_wrong_scope_mutation_and_blob_tampering(self):
        s=self.state()
        bad=dict(s,publisherAuthorized=True)
        with self.assertRaises(Exception):store.require_transition(None,bad)
        for patch in ({"requestSha256":"c"*64},{"sourceHeadSha":"d"*40},
                      {"expiresAt":"2026-10-30T01:30:00Z"},
                      {"targetScope":["pgextwin/pg_ivm"]}):
            next_state=store.lifecycle.bind_source(s,0,"a",run_id=123,attempt=1,head_sha=HEAD)
            next_state.update(patch)
            with self.subTest(patch=patch),self.assertRaises(Exception):
                store.require_transition(s,next_state)
        raw=store.canonical(s)
        body={"encoding":"base64","content":base64.b64encode(raw).decode(),
              "sha":"f"*40}
        with self.assertRaises(store.Denied):store.unpack(body,REQ)
        with self.assertRaises(store.Denied):store.endpoint("r-../../release")
        with self.assertRaises(store.Denied):
            store.unpack({"encoding":"base64","content":base64.b64encode(
                 raw.replace(b'"schemaVersion":1',b'"schemaVersion":1,"schemaVersion":1')
                ).decode(),"sha":store.blob_hash(raw)},REQ)

    def test_old_terminal_can_never_be_reopened(self):
        s=self.state()
        bound=store.lifecycle.bind_source(s,0,"source",run_id=123,attempt=1,head_sha=HEAD)
        ended=store.lifecycle.event_deadline(bound,1,"timeout",now=EXPIRE,
             source_completed=True,original_source_sha=HEAD,completion_lookup="MISSING_VERIFIED")
        with self.assertRaises(store.Denied):store.require_transition(ended,ended)

if __name__=="__main__":unittest.main()
