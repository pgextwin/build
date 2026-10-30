#!/usr/bin/env python3
"""R06: original GitHub Run time is immutable authority across request expiry.

Offline tests, not a claim that GitHub spontaneously dropped any event. Mocked
GitHub GET still must bind original source Run, first attempt, main, actor,
protected one-file PR and actual Git blob, before expired finalize/readback.
"""
import base64, importlib.util, json, os, tempfile
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "r06_watcher_expiry",ROOT/"scripts/issue311-r06-unattended-finite-guard.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fixed=datetime.now(timezone.utc).replace(microsecond=0)
fmt=lambda t:t.strftime("%Y-%m-%dT%H:%M:%SZ")
head="c"*40
before="b"*40
id="r-20261030-r06preparedeadlinecanary07"
path=".github/execution-requests/"+id+".json"
run_id=41099912345
req=json.loads((ROOT/path).read_text(encoding="utf-8"))
req["createdAt"]=fmt(fixed-timedelta(minutes=6))
req["expiresAt"]=fmt(fixed-timedelta(minutes=1))
req["limits"]["maxWallClockMinutes"]=10
req["source"]["centralMainSha"]=before
raw=(json.dumps(req,sort_keys=True,indent=2)+"\n").encode("utf-8")
body=base64.b64encode(raw).decode()
contents={"encoding":"base64","sha":m.store.blob_hash(raw),
          "content":body[:80]+"\n"+body[80:]}
r={"id":run_id,"head_sha":head,"name":m.NAME,
   "path":".github/workflows/issue311-r06-unattended-finite-guard.yml",
   "event":"push","head_branch":"main","run_attempt":1,
   "actor":{"login":"ShutenOishi"},
   "created_at":fmt(fixed-timedelta(minutes=2))}
commit={"parents":[{"sha":before}],"files":[{"status":"added","filename":path}]}
merged=[{"merged_at":fmt(fixed-timedelta(minutes=2)),
         "merge_commit_sha":head,"base":{"ref":"main"},
         "user":{"login":"ShutenOishi"}}]
event={"ref":"refs/heads/main","after":head,"before":before,
       "created":False,"deleted":False,"sender":{"login":"ShutenOishi"},
       "repository":{"full_name":"pgextwin/build"}}
def api(endpoint):
    if endpoint=="actions/runs/"+str(run_id):return r
    if endpoint=="contents/"+path+"?ref="+head:return contents
    if endpoint=="branches/main":return {"protected":True}
    if endpoint=="commits/"+head:return commit
    if endpoint=="commits/"+head+"/pulls?per_page=100":return merged
    raise AssertionError("unexpected original API "+endpoint)
def git(args,**kwargs):
    if args[:3]==["git","rev-parse","HEAD"]:return head+"\n"
    if args[:3]==["git","diff","--name-status"]:return "A\t"+path+"\n"
    if args[:3]==["git","show","HEAD:"+path]:return raw
    raise AssertionError("unexpected git "+str(args))
with tempfile.TemporaryDirectory() as d:
    efile=Path(d)/"event.json"
    efile.write_text(json.dumps(event))
    env={"GITHUB_REPOSITORY":"pgextwin/build","GITHUB_EVENT_NAME":"push",
         "GITHUB_WORKFLOW":m.NAME,"GITHUB_REF":"refs/heads/main",
         "GITHUB_ACTOR":"ShutenOishi","GITHUB_RUN_ATTEMPT":"1",
         "GITHUB_SHA":head,"GITHUB_RUN_ID":str(run_id),
         "GITHUB_EVENT_PATH":str(efile)}
    with patch.dict(os.environ,env,clear=True),patch.object(m,"api",side_effect=api),\
         patch.object(m.subprocess,"check_output",side_effect=git),\
         patch.object(m,"current",return_value=fixed):
        for stage in ("finalize","readback"):
            result=m.original(stage=stage)
            assert result["requestId"]==id
            assert result["headSha"]==head
            assert result["deadlineAt"]==req["expiresAt"]
            assert len(result["targets"])==17
            assert result["requestSha256"]==__import__("hashlib").sha256(raw).hexdigest()
        for stage in ("observe","not-a-stage"):
            try:m.original(stage=stage)
            except ValueError:pass
            else:raise AssertionError("expired/untrusted stage accepted: "+stage)
        r["created_at"]=fmt(fixed)
        try:m.original(stage="finalize")
        except ValueError:pass
        else:raise AssertionError("historically expired original run accepted")
        r["created_at"]=fmt(fixed-timedelta(minutes=2))
        r["run_attempt"]=2
        try:m.original(stage="readback")
        except ValueError:pass
        else:raise AssertionError("attempt2 original accepted")
        r["run_attempt"]=1
        contents["sha"]="0"*40
        try:m.original(stage="finalize")
        except ValueError:pass
        else:raise AssertionError("tampered original Git blob accepted")
        contents["sha"]=m.store.blob_hash(raw)
    with patch.dict(os.environ,env,clear=True),patch.object(m,"api",side_effect=api),\
         patch.object(m.subprocess,"check_output",side_effect=git),\
         patch.object(m,"current",return_value=fixed+timedelta(minutes=30)):
        try:m.original(stage="readback")
        except ValueError as ex:assert "grace exceeded" in str(ex)
        else:raise AssertionError("unbounded historical recovery accepted")
print("ISSUE311_R06_EXPIRED_ORIGINAL_FINITE_RECOVERY_AUTHENTICATED_OFFLINE_PASS")
