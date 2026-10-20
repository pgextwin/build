#!/usr/bin/env python3
"""Fail-closed initial candidate and shared Release gate; no GitHub writes."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from update_watch_lib import WatchError
sp=importlib.util.spec_from_file_location("initial_candidate",ROOT/"scripts/candidate-update.py")
c=importlib.util.module_from_spec(sp);sp.loader.exec_module(c)
sp=importlib.util.spec_from_file_location("fleet_gate",ROOT/"scripts/fleet-promotion-gate.py")
g=importlib.util.module_from_spec(sp);sp.loader.exec_module(g)
sp=importlib.util.spec_from_file_location("fleet_gate_fixture",ROOT/"tests/test-fleet-promotion-gate.py")
gt=importlib.util.module_from_spec(sp);sp.loader.exec_module(gt)

SHA="a"*40
REF="v1.3.4"
EXT={"name":"pgtap","upstream":{"repository":"theory/pgtap","ref":REF,"version":"1.3.4","commit":SHA},
     "postgresql":{"majors":[14,15,16,17,18]}}
WATCH={"schemaVersion":1,"source":"github","repository":"theory/pgtap","strategy":"github-releases",
       "prereleases":False,"stableTagPattern":r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$"}
POLICY={"schemaVersion":1,"enabled":True,"releasePolicy":"manual-only","workflow":"windows.yml"}

def fetch(url):
    if url.endswith("/theory/pgtap/releases?per_page=100"):
        return [{"tag_name":REF,"prerelease":False,"draft":False}]
    if url.endswith("/theory/pgtap/git/ref/tags/"+REF):
        return {"object":{"type":"commit","sha":SHA}}
    if url.endswith("/pgextwin/pgtap/releases?per_page=100"):
        return []
    raise WatchError("Unexpected fixture API path")

class FirstRelease(unittest.TestCase):
    def test_exact_pinned_stable_first_release(self):
        plan=c.plan(EXT,WATCH,POLICY,fetch)
        self.assertEqual(plan["status"],"candidate")
        self.assertIs(plan.get("firstRelease"),True)
        self.assertEqual(plan["updates"][0]["commit"],SHA)
        self.assertIs(plan["updates"][0]["initialOnly"],True)
        self.assertEqual(c.apply(EXT,plan),EXT)
        doc=c.initial_intent(EXT,plan)
        self.assertEqual(doc["source"],EXT["upstream"])
        self.assertEqual(doc["candidateId"],plan["candidateId"])
        self.assertEqual(plan["branch"],c.plan(EXT,WATCH,POLICY,fetch)["branch"])

    def test_existing_release_ambiguous_absence_or_forged_sha_denied(self):
        def existing(url):
            if url.endswith("/pgextwin/pgtap/releases?per_page=100"):
                return [{"tag_name":"v1.3.4-windows.1"}]
            return fetch(url)
        self.assertEqual(c.plan(EXT,WATCH,POLICY,existing)["status"],"no-op")
        def ambiguous(url):
            if url.endswith("/pgextwin/pgtap/releases?per_page=100"):
                return {"message":"rate limit"}
            return fetch(url)
        with self.assertRaises(WatchError):
            c.plan(EXT,WATCH,POLICY,ambiguous)
        bad=copy.deepcopy(EXT);bad["upstream"]["commit"]="b"*40
        with self.assertRaises(WatchError):
            c.plan(bad,WATCH,POLICY,fetch)

    def test_mutated_initial_record_rejected(self):
        plan=c.plan(EXT,WATCH,POLICY,fetch)
        for mutate in (
            lambda x:x["updates"][0].update(commit="b"*40),
            lambda x:x["updates"][0].update(oldRef="forged"),
            lambda x:x["updates"][0].update(initialOnly=False),
            lambda x:x.update(firstRelease=False),
        ):
            record=copy.deepcopy(plan)
            mutate(record)
            with self.subTest(record=record),self.assertRaises(WatchError):
                c.apply(EXT,record)

    def test_shared_manual_publisher_denies_forged_first_release(self):
        self.assertEqual(g.verify(**gt.fixture())["candidateRunId"],900)
        p=gt.fixture("pgtap")
        p["decision"]["firstRelease"]=True
        item=p["decision"]["updates"][0]
        item.update(initialOnly=True,oldRef=item["ref"],oldVersion=item["version"])
        p["pr_files"]=[{"filename":"config/initial-release-candidate.json","status":"added"}]
        source=p["ext"]["upstream"]
        p["first_release_document"]={
            "schemaVersion":1,"kind":"FIRST_RELEASE_PINNED_SOURCE",
            "extension":"pgtap","repository":"pgextwin/pgtap",
            "releasePolicy":"manual-only","candidateId":"f"*20,
            "source":{k:source[k] for k in ("repository","ref","version","commit")}}
        self.assertEqual(g.verify(**p)["candidateRunId"],900)
        for variant in ("missing","sha","path","status","owner","fake-update"):
            b=copy.deepcopy(p)
            if variant=="missing":b["first_release_document"]=None
            elif variant=="sha":b["first_release_document"]["source"]["commit"]="0"*40
            elif variant=="path":b["pr_files"][0]["filename"]="config/extension.json"
            elif variant=="status":b["pr_files"][0]["status"]="modified"
            elif variant=="owner":b["pr"]["user"]["login"]="fake"
            else:b["decision"]["updates"][0]["oldVersion"]="0.0.0"
            with self.subTest(variant=variant),self.assertRaises((g.Denied,g.ident.Denied)):
                g.verify(**b)
        normal=copy.deepcopy(p);normal["decision"].pop("firstRelease")
        with self.assertRaises((g.Denied,g.ident.Denied)):
            g.verify(**normal)

if __name__=="__main__":
    unittest.main()
