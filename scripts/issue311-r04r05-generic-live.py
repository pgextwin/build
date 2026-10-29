#!/usr/bin/env python3
"""One-shot R04/R05 generic read-only source and independent completion.

Only the existing build-scoped state Writer App may persist checkpoints on
issue311-state. The original GITHUB_TOKEN only reads GitHub. No Publisher API.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]
# These are two exact, protected-main nonpublishing test cases. Neither case
# expands credentials or publication scope. The gap case has intentionally NO
# matching workflow_run listener, but an independently push-started watcher.
_CASE=os.environ.get("ISSUE311_PROOF_CASE","normal")
_CASES={
    "normal":("r-20261029-r04r05generic03",
              "Issue 311 R04/R05 generic real App source (NONPUBLISHING)",
              ".github/workflows/issue311-r04r05-source.yml"),
    "missing-event":("r-20261029-r05eventgap001",
                     "Issue 311 R05 intentionally unbridged source (NONPUBLISHING)",
                     ".github/workflows/issue311-r05-eventgap-source.yml"),
}
if _CASE not in _CASES:
    raise ValueError("ISSUE311_CASE_DENY: unsupported privileged case")
REQUEST,SOURCE_NAME,SOURCE_PATH=_CASES[_CASE]
REQUEST_PATH=".github/execution-requests/"+REQUEST+".json"
SOURCE_ZIP="issue311-r04r05-original-source"
SOURCE_RECEIPT="issue311-r04r05-original.json"
REPO="pgextwin/build"
TARGET="pgextwin/orafce"

def load(name, path):
    spec=importlib.util.spec_from_file_location(name, ROOT/path)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

lifecycle=load("lifecycle", "scripts/issue311-request-lifecycle.py")
store=load("store", "scripts/issue311-lifecycle-store.py")
writer=load("writer", "scripts/issue311-writer-runtime.py")
contract=load("contract", "scripts/issue311-request-contract.py")
bridge=load("bridge", "scripts/issue311-r05-windows-completion-bridge.py")

def require(ok,reason):
    if not ok: raise ValueError("R04R05_GENERIC_DENY "+reason)

def json_unique(pairs):
    result={}
    for key,val in pairs:
        require(key not in result,"duplicate original JSON key")
        result[key]=val
    return result

def contents_original(head):
    record=bridge.get_json("repos/pgextwin/build/contents/"+REQUEST_PATH+"?ref="+head)
    require(record.get("encoding")=="base64","original request not base64 Contents")
    raw=base64.b64decode(record["content"],validate=False)
    require(store.blob_hash(raw)==record["sha"],"request original Git blob mismatch")
    return raw

def read_request(raw, head):
    decl=contract.validate_declaration(raw,REQUEST_PATH)
    data=json.loads(raw,object_pairs_hook=json_unique)
    require(decl["requestId"]==REQUEST and decl["mode"]=="AUDIT_ONLY"
            and decl["targets"]==(TARGET,)
            and data["approval"]["publicReleaseAuthorized"] is False
            and data["approval"]["publicationGrants"]==[]
            and data["allowFutureUpdates"] is False
            and data["limits"]["maxWallClockMinutes"] <= 10
            and data["limits"]["maxOperations"] <= 25
            and data["source"]["centralMainSha"]!=head,
            "out-of-scope generic proof")
    return data, decl

def source_context():
    ev=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                  object_pairs_hook=json_unique)
    head=os.environ["GITHUB_SHA"]
    require(os.environ["GITHUB_REPOSITORY"]==REPO
            and os.environ["GITHUB_WORKFLOW"]==SOURCE_NAME
            and os.environ["GITHUB_EVENT_NAME"]=="push"
            and os.environ["GITHUB_REF"]=="refs/heads/main"
            and os.environ["GITHUB_ACTOR"]=="ShutenOishi"
            and os.environ["GITHUB_RUN_ATTEMPT"]=="1"
            and ev.get("before")!=head and ev.get("after")==head
            and ev.get("sender",{}).get("login")=="ShutenOishi"
            and ev.get("created") is False and ev.get("deleted") is False
            and ev.get("repository",{}).get("full_name")==REPO,
            "invalid protected original push")
    checkout=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()
    require(checkout==head,"not original event checkout")
    raw=subprocess.check_output(["git","show","HEAD:"+REQUEST_PATH])
    data,decl=read_request(raw,head)
    require(data["source"]["centralMainSha"]==ev["before"],"source before commit mismatch")
    require(raw==contents_original(head),"Git show != original REST Contents")
    return data,decl,head

def app_cas():
    key=os.environ.get("STATE_WRITER_PRIVATE_KEY","")
    require(bool(key),"dedicated state Writer environment missing")
    token=writer.mint_token(key)
    return token, store.CAS(lambda m,p,b:writer.api(m,p,token,b))

def source():
    receipt={"requestId":REQUEST,"result":"FAILED","publisherAuthorized":False}
    token=None
    try:
        data,decl,head=source_context()
        repo=bridge.win17.old.get_json(
            "https://api.github.com/repos/pgextwin/orafce/branches/main",
            os.environ["GH_TOKEN"])
        require(repo.get("name")=="main" and repo.get("protected") is True
                and repo.get("commit",{}).get("sha")==data["targets"][0]["mainSha"],
                "local protected main drift")
        start=lifecycle.new(REQUEST,decl["rawSha256"],head,[TARGET],
                            data["expiresAt"],max_events=data["limits"]["maxOperations"])
        token,cas=app_cas()
        create=cas.write(start)
        blob,old=cas.read(REQUEST)
        bound=lifecycle.bind_source(old,old["revision"],"source-run",
                run_id=int(os.environ["GITHUB_RUN_ID"]),attempt=1,head_sha=head)
        committed=cas.write(bound,previous=old,expected_blob=blob)
        _,confirm=cas.read(REQUEST)
        require(confirm==bound,"source state failed readback")
        receipt.update(result="SUCCESS",sourceSha=head,originalRequestSha256=decl["rawSha256"],
                sourceRunId=int(os.environ["GITHUB_RUN_ID"]),runAttempt=1,
                targetMainSha=data["targets"][0]["mainSha"],remoteProtected=True,
                revision=bound["revision"],persistence=[create,committed])
    except Exception as exc:
        receipt["reason"]=str(exc)[:340]
    finally:
        if token:writer.revoke_and_prove_401(token)
    Path(SOURCE_RECEIPT).write_text(json.dumps(receipt,sort_keys=True)+"\n")
    print(json.dumps(receipt,sort_keys=True))
    return 0 if receipt["result"]=="SUCCESS" else 1

def authenticated_completed_source(event):
    original=event.get("workflow_run",{})
    require(event.get("action")=="completed"
            and event.get("repository",{}).get("full_name")==REPO
            and original.get("name")==SOURCE_NAME
            and original.get("path")==SOURCE_PATH
            and original.get("event")=="push"
            and original.get("head_branch")=="main"
            and original.get("actor",{}).get("login")=="ShutenOishi"
            and original.get("status")=="completed"
            and original.get("conclusion")=="success"
            and original.get("run_attempt")==1
            and type(original.get("id")) is int
            and re.fullmatch("[a-f0-9]{40}",original.get("head_sha","")),
            "foreign or unsuccessful original completion")
    current=bridge.get_json("repos/pgextwin/build/actions/runs/"+str(original["id"]))
    for key in ("id","workflow_id","run_attempt","head_sha","event","path","head_branch","conclusion"):
        require(current.get(key)==original.get(key),"original REST mismatch "+key)
    require(current.get("status")=="completed","original not terminal")
    raw=contents_original(original["head_sha"])
    data,decl=read_request(raw,original["head_sha"])
    return original,data,decl

def verify_source_zip(original,decl,data):
    sid=original["id"]
    jobs=bridge.get_json("repos/pgextwin/build/actions/runs/"+str(sid)+"/jobs?per_page=100")
    require(jobs.get("total_count")==len(jobs.get("jobs",[]))==1
            and jobs["jobs"][0].get("conclusion")=="success"
            and jobs["jobs"][0].get("run_id")==sid,
            "original source job failed or missing")
    arts=bridge.get_json("repos/pgextwin/build/actions/runs/"+str(sid)+"/artifacts?per_page=100")
    require(arts.get("total_count")==len(arts.get("artifacts",[]))==1,
            "missing or duplicated source ZIP")
    zipentry=arts["artifacts"][0]
    require(zipentry.get("name")==SOURCE_ZIP and zipentry.get("expired") is False
            and zipentry.get("workflow_run",{}).get("id")==sid,
            "foreign original ZIP")
    receipt,sha=bridge.original_zip(zipentry,SOURCE_RECEIPT)
    require(receipt.get("result")=="SUCCESS"
            and receipt.get("requestId")==REQUEST
            and receipt.get("sourceSha")==original["head_sha"]
            and receipt.get("sourceRunId")==sid
            and receipt.get("runAttempt")==1
            and receipt.get("originalRequestSha256")==decl["rawSha256"]
            and receipt.get("targetMainSha")==data["targets"][0]["mainSha"]
            and receipt.get("remoteProtected") is True
            and receipt.get("publisherAuthorized") is False
            and receipt.get("revision")==1,
            "original source ZIP fields mismatch")
    return sha

def bridge_run():
    token=None
    receipt={"requestId":REQUEST,"result":"FAILED","publisherAuthorized":False}
    try:
        require(os.environ["GITHUB_REPOSITORY"]==REPO
                and os.environ["GITHUB_EVENT_NAME"]=="workflow_run"
                and os.environ["GITHUB_REF"]=="refs/heads/main"
                and os.environ["GITHUB_RUN_ATTEMPT"]=="1","bridge context mismatch")
        event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                         object_pairs_hook=json_unique)
        origin,data,decl=authenticated_completed_source(event)
        zipsha=verify_source_zip(origin,decl,data)
        token,cas=app_cas()
        blob,state=cas.read(REQUEST)
        require(state["requestSha256"]==decl["rawSha256"]
                and state["sourceHeadSha"]==origin["head_sha"]
                and state["sourceRun"]=={"id":origin["id"],"attempt":1},
                "state original source changed")
        if state["terminal"] is None:
            advanced=lifecycle.record_completion(state,state["revision"],"completed-bridge",
               run_id=int(os.environ["GITHUB_RUN_ID"]),attempt=1,
               source_id=origin["id"],outcome="NO_UPDATE",
               target_outcomes={TARGET:"SUCCESS"},original_zip_sha=zipsha)
            written=cas.write(advanced,previous=state,expected_blob=blob)
        else:
            require(state["terminal"]=="NO_UPDATE"
                    and state["completionRun"]=={"id":int(os.environ["GITHUB_RUN_ID"]),"attempt":1},
                    "conflicting terminal source")
            written="ALREADY_TERMINAL"
        _,confirmed=cas.read(REQUEST)
        require(confirmed["terminal"]=="NO_UPDATE" and confirmed["publisherAuthorized"] is False,
                "bridge not durably complete")
        receipt.update(result="NO_UPDATE",sourceRunId=origin["id"],originalZipSha256=zipsha,
                       stateRevision=confirmed["revision"],persisted=written)
    except Exception as exc:
        receipt["reason"]=str(exc)[:340]
    finally:
        if token:writer.revoke_and_prove_401(token)
    Path("issue311-r04r05-event-terminal.json").write_text(json.dumps(receipt,sort_keys=True)+"\n")
    print(json.dumps(receipt,sort_keys=True))
    return 0 if receipt["result"]=="NO_UPDATE" else 1

if __name__=="__main__":
    phase=sys.argv[1] if len(sys.argv)>1 else ""
    raise SystemExit(source() if phase=="source" else bridge_run() if phase=="bridge" else 2)
