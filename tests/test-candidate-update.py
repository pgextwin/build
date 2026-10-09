from __future__ import annotations
import copy
import importlib.util
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts"))
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

def main():
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
    print("Step 19 candidate fixture tests passed")

if __name__=="__main__":main()
