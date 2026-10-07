from __future__ import annotations
import importlib.util,json,sys
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from update_watch_lib import WatchError,detect_extension_update,decide_issue_action,candidate_signature
spec=importlib.util.spec_from_file_location("pgcheck",ROOT/"scripts/check-postgresql-updates.py");pg=importlib.util.module_from_spec(spec);spec.loader.exec_module(pg)
FIX=ROOT/"tests/fixtures/update-watch"

def load(name):return json.loads((FIX/name).read_text())
def assert_eq(a,b,msg):
    if a!=b:raise AssertionError(f"{msg}: {a!r} != {b!r}")

def single(current="1.6.9"):
    return {"schemaVersion":1,"name":"x","upstream":{"repository":"example/ext","ref":f"v{current}","version":current},"postgresql":{"minMajor":14,"maxMajor":18}}
def swatch():return {"schemaVersion":1,"source":"github","repository":"example/ext","strategy":"github-releases","prereleases":False,"stableTagPattern":r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$"}
def pp_ext():return {"schemaVersion":1,"name":"h","upstream":{"repository":"example/h","perPostgresql":{"14":{"ref":"REL14_1_4_4","version":"1.4.4"},"15":{"ref":"REL15_1_5_3","version":"1.5.3"},"18":{"ref":"REL18_1_8_0","version":"1.8.0"}}},"postgresql":{"majors":[14,15,18]}}
def pp_watch():return {"schemaVersion":1,"source":"github","repository":"example/h","strategy":"github-releases-per-postgresql","prereleases":False,"perPostgresql":{"14":{"tagPattern":r"^REL14_(?P<version>[0-9]+_[0-9]+_[0-9]+)$"},"15":{"tagPattern":r"^REL15_(?P<version>[0-9]+_[0-9]+_[0-9]+)$"},"18":{"tagPattern":r"^REL18_(?P<version>[0-9]+_[0-9]+_[0-9]+)$"},"19":{"tagPattern":r"^REL19_(?P<version>[0-9]+_[0-9]+_[0-9]+)$","informational":True}}}

def main():
    schema=json.loads((ROOT/"schema/update-watch.schema.json").read_text()); Draft202012Validator.check_schema(schema); Draft202012Validator(schema).validate(swatch()); Draft202012Validator(schema).validate(pp_watch())
    releases=load("releases-single.json")
    r=detect_extension_update(single("1.6.9"),swatch(),lambda u:releases,"t","build","sha");assert_eq(r["status"],"up-to-date","same stable")
    r=detect_extension_update(single("1.6.8"),swatch(),lambda u:releases,"t","build","sha");assert_eq(r["status"],"update-available","stable update");assert_eq(r["candidate"]["version"],"1.6.9","candidate")
    assert_eq(r["candidate"]["ref"],"v1.6.9","prerelease ignored")
    try: detect_extension_update(single(),swatch(),lambda u:{"bad":1},"t","b","s"); raise AssertionError("malformed response accepted")
    except WatchError: pass
    try: detect_extension_update(single(),swatch(),lambda u:(_ for _ in ()).throw(WatchError("network")),"t","b","s"); raise AssertionError("network failure accepted")
    except WatchError: pass
    pp=load("releases-per-pg.json");r=detect_extension_update(pp_ext(),pp_watch(),lambda u:pp,"t","b","s");assert_eq(r["status"],"update-available","per pg update");assert_eq([x["postgresqlMajor"] for x in r["updates"]],[14,18],"multiple majors");assert_eq(r["informationalCandidates"][0]["postgresqlMajor"],19,"pg19 info")
    pp_one=[x for x in pp if not x["tag_name"].startswith("REL18")];r=detect_extension_update(pp_ext(),pp_watch(),lambda u:pp_one,"t","b","s");assert_eq([x["postgresqlMajor"] for x in r["updates"]],[14],"one major")
    marker="<!-- pgextwin-update-watch:v1:upstream:x -->";res={"kind":"extension-upstream","extension":"x","repository":"e/x","status":"update-available","updates":[{"candidate":{"ref":"v2"}}],"drift":[],"newMajors":[]}
    assert_eq(decide_issue_action(res,[],marker)["action"],"create","issue create")
    sig=f"<!-- pgextwin-update-watch-candidate:{candidate_signature(res)} -->";auto={"number":1,"state":"OPEN","body":marker+"\n"+sig};assert_eq(decide_issue_action(res,[auto],marker)["action"],"none","same candidate")
    res2={**res,"updates":[{"candidate":{"ref":"v3"}}]};assert_eq(decide_issue_action(res2,[auto],marker)["action"],"update","new candidate")
    caught={**res,"status":"up-to-date","updates":[]};assert_eq(decide_issue_action(caught,[auto],marker)["action"],"close","caught up")
    human={"number":2,"state":"OPEN","body":"manual issue"};assert_eq(decide_issue_action(caught,[human],marker)["action"],"none","human untouched")
    version=(FIX/"postgresql-versioning.html").read_text();beta=(FIX/"postgresql-beta.html").read_text();md={"postgresql":[{"major":14,"minor":"14.24","eol":"2026-11-12"},{"major":15,"minor":"15.19","eol":"2027-11-11"},{"major":16,"minor":"16.15","eol":"2028-11-09"},{"major":17,"minor":"17.11","eol":"2029-11-08"},{"major":18,"minor":"18.6","eol":"2030-11-14"}]}
    r=pg.detect_postgresql(md,version,beta,"t","b","s");assert_eq(r["status"],"up-to-date","same pg minor");assert_eq(r["prerelease"],{"major":19,"label":"Beta4"},"beta info")
    newer=version.replace("18.6","18.7");r=pg.detect_postgresql(md,newer,beta,"t","b","s");assert_eq(r["status"],"update-available","new minor")
    eol=version.replace("2030-11-14","2030-11-21");r=pg.detect_postgresql(md,eol,beta,"t","b","s");assert_eq(r["status"],"update-available","eol drift")
    rc=beta.replace("Beta 4","RC 1");r=pg.detect_postgresql(md,version,rc,"t","b","s");assert_eq(r["status"],"up-to-date","rc no onboarding")
    ga=version.replace("<tr><td>18",'<tr><td>19</td><td>19.0</td><td>Yes</td><td>2026-10-29</td><td>2031-11-13</td></tr><tr><td>18');r=pg.detect_postgresql(md,ga,beta,"t","b","s");assert_eq(r["status"],"update-available","pg19 ga");assert_eq(r["newMajors"][0]["major"],19,"pg19 new major")
    print("Update watch fixture tests passed.")
if __name__=="__main__":main()
