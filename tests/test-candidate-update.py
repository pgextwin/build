from __future__ import annotations
import base64
import copy
import json
import os
import tempfile
from unittest.mock import patch
import importlib.util
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts"))
import update_watch_lib
from update_watch_lib import WatchError
spec = importlib.util.spec_from_file_location("candidate_update", ROOT/"scripts/candidate-update.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
SHA = "1"*40
TAG_SHA = "2"*40
EXT={"schemaVersion":1,"name":"plpgsql_check","upstream":{"repository":"test/ext","ref":"v2.10.13","version":"2.10.13"},"postgresql":{"majors":[15,16,17,18]}}
WATCH={"schemaVersion":1,"source":"github","repository":"test/ext","strategy":"github-releases","prereleases":False,"stableTagPattern":r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$"}
POLICY={"schemaVersion":1,"enabled":True,"releasePolicy":"manual-only","workflow":"windows.yml"}

def fixture(url):
    if url.endswith("/releases?per_page=100"):
        return [{"tag_name":"v2.10.13","prerelease":False,"draft":False},
                {"tag_name":"v2.10.14-rc1","prerelease":True,"draft":False},
                {"tag_name":"v2.10.14","prerelease":False,"draft":False,"html_url":"https://github.com/test/ext/releases/tag/v2.10.14"}]
    if url.endswith("/git/ref/tags/v2.10.14"): return {"object":{"type":"tag","sha":TAG_SHA}}
    if url.endswith("/git/tags/"+TAG_SHA): return {"tag":"v2.10.14","object":{"type":"commit","sha":SHA}}
    raise WatchError("unexpected fixture URL "+url)

def expect_fail(f):
    try: f()
    except WatchError: return
    raise AssertionError("expected fail-closed WatchError")

def exercise_proposer_safety():
    """Simulate existing branches/PRs and GitHub API failures; never make network writes."""
    record=c.plan(EXT,WATCH,POLICY,fixture)
    marker="<!-- "+c.MARKER_PREFIX+":"+record["candidateId"]+" -->"
    central=json.loads((ROOT/"metadata/automation-fleet.json").read_text(encoding="utf-8"))
    response={"encoding":"base64","content":base64.b64encode(json.dumps(central).encode()).decode()}
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        (root/"extension.json").write_text(json.dumps(EXT))
        (root/"watch.json").write_text(json.dumps(WATCH))
        (root/"policy.json").write_text(json.dumps(POLICY))
        scenarios=[
            ("duplicate", [{"number":1,"body":marker,"state":"OPEN","url":"https://example/1"},
                           {"number":2,"body":marker,"state":"OPEN","url":"https://example/2"}], [], True),
            ("human", [{"number":1,"body":"not owned","state":"OPEN","url":"https://example/1"}], [], True),
            ("prior-run", [{"number":1,"body":marker,"state":"OPEN","url":"https://example/1"}],
                          [{"databaseId":100,"event":"workflow_dispatch","status":"completed","conclusion":"success"}], False),
            ("closed", [{"number":1,"body":marker,"state":"CLOSED","url":"https://example/1"}], [], False),
        ]
        for name,prs,runs,must_fail in scenarios:
            calls=[]
            def execute(*args):
                calls.append(args)
                if args[:2]==("git","ls-remote"): return "ab refs/heads/"+record["branch"]
                if args[:2]==("git","fetch"): return ""
                if args[:2]==("git","log"): return "candidate branch\n"+marker
                if args[:2]==("git","show"): return json.dumps(c.apply(EXT,record))
                if args[:3]==("gh","pr","list"): return json.dumps(prs)
                if args[:3]==("gh","run","list"): return json.dumps(runs)
                raise AssertionError("unexpected or mutating command: "+repr(args))
            with patch.dict(os.environ,{"GITHUB_REPOSITORY":"pgextwin/plpgsql_check",
                                      "GITHUB_REF":"refs/heads/main","GH_TOKEN":"fixture-token"}), \
                 patch.object(update_watch_lib,"github_get_json",lambda url,token:response), \
                 patch.object(c,"execute",execute),patch.object(c,"peel_tag",lambda *args,**kwargs:SHA):
                task=lambda:c.propose(record,str(root/"extension.json"),"pgextwin/plpgsql_check",
                                      str(root/"watch.json"),str(root/"policy.json"))
                if must_fail: expect_fail(task)
                else: assert task() is None
            assert not any(x[:3]==("gh","workflow","run") for x in calls),name
        with patch.dict(os.environ,{"GITHUB_REPOSITORY":"pgextwin/plpgsql_check",
                                    "GITHUB_REF":"refs/heads/main","GH_TOKEN":"fixture-token"}), \
             patch.object(update_watch_lib,"github_get_json",
                          lambda url,token: (_ for _ in ()).throw(WatchError("API outage"))):
            expect_fail(lambda:c.propose(record,str(root/"extension.json"),"pgextwin/plpgsql_check",
                                         str(root/"watch.json"),str(root/"policy.json")))


def main():
    for mode in ("WATCH", "OFF"):
        record=c.suppressed(EXT,mode)
        assert record["status"]=="centrally-suppressed"
        assert record["mode"]==mode and record["updates"]==[]
        assert record["releasePolicy"]=="manual-only"
        assert record["repository"]=="test/ext"
    expect_fail(lambda:c.suppressed(EXT,"BUILD"))
    expect_fail(lambda:c.suppressed(EXT,"UNKNOWN"))
    p=c.plan(EXT,WATCH,POLICY,fixture)
    assert p["status"]=="candidate" and p["updates"][0]["commit"]==SHA and p["updates"][0]["version"]=="2.10.14"
    assert len(p["candidateId"])==20 and p["branch"].startswith("auto-candidate/")
    assert c.plan(EXT,WATCH,POLICY,fixture)["candidateId"]==p["candidateId"]
    upgraded=c.apply(EXT,p)
    assert upgraded["upstream"]["commit"]==SHA and upgraded["upstream"]["ref"]=="v2.10.14"
    expect_fail(lambda:c.apply(upgraded,p))
    assert c.plan(upgraded,WATCH,POLICY,fixture)["status"]=="no-op"
    expect_fail(lambda:c.plan(EXT,WATCH,POLICY,lambda u: (_ for _ in ()).throw(WatchError("API unavailable"))))
    expect_fail(lambda:c.plan(EXT,WATCH,POLICY,lambda u: {"object":{"type":"commit","sha":"BAD"}} if "/git/ref/" in u else fixture(u)))
    bogus=copy.deepcopy(POLICY);bogus["releasePolicy"]="automatic"
    expect_fail(lambda:c.plan(EXT,WATCH,bogus,fixture))
    disabled=copy.deepcopy(POLICY);disabled["enabled"]=False
    assert c.plan(EXT,WATCH,disabled,fixture)["status"]=="disabled"
    old=copy.deepcopy(EXT);old["upstream"]["version"]="2.10.15";old["upstream"]["ref"]="v2.10.15"
    assert c.plan(old,WATCH,POLICY,fixture)["status"]=="no-op"
    series=copy.deepcopy(EXT);series["upstream"]={"repository":"test/ext","perPostgresql":{
        "15":{"ref":"REL15_1_0_0","version":"1.0.0"},"16":{"ref":"REL16_1_0_0","version":"1.0.0"}}}
    watch=copy.deepcopy(WATCH);watch.pop("stableTagPattern");watch["strategy"]="github-releases-per-postgresql"
    watch["perPostgresql"]={"15":{"tagPattern":r"^REL15_(?P<version>[0-9]+_[0-9]+_[0-9]+)$"},
                            "16":{"tagPattern":r"^REL16_(?P<version>[0-9]+_[0-9]+_[0-9]+)$"},
                            "19":{"tagPattern":r"^REL19_(?P<version>[0-9]+_[0-9]+_[0-9]+)$","informational":True}}
    def series_fixture(u):
        if "/releases?" in u:
            return [{"tag_name":"REL15_1_0_1","draft":False,"prerelease":False},
                    {"tag_name":"REL19_1_0_1","draft":False,"prerelease":False}]
        if "/git/ref/tags/REL15_1_0_1" in u: return {"object":{"type":"commit","sha":SHA}}
        raise WatchError("unexpected URL "+u)
    q=c.plan(series,watch,POLICY,series_fixture)
    assert len(q["updates"])==1 and q["updates"][0]["major"]==15
    assert c.apply(series,q)["upstream"]["perPostgresql"]["16"]["ref"]=="REL16_1_0_0"
    exercise_proposer_safety()
    print("Step 19/20 candidate and proposer-safety fixture tests passed")

if __name__=="__main__":main()
