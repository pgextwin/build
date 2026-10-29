#!/usr/bin/env python3
"""Independent finite push-triggered watchdog for original R04/R05 request.

Runs in parallel with source, NOT as a workflow_run descendant. If the
completion event is absent past the fixed request deadline it persists a
fail-closed terminal via the approved dedicated App state-only CAS. No cron.
"""
from __future__ import annotations
from datetime import datetime, timezone
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

m=load("live","scripts/issue311-r04r05-generic-live.py")
life=m.lifecycle
store=m.store
writer=m.writer
bridge=m.bridge
REQ=m.REQUEST
EVENT_FILE="issue311-r04r05-watchdog-observation.json"
SOURCE_WORKFLOW="issue311-r04r05-source.yml"
BRIDGE_WORKFLOW="issue311-r04r05-bridge.yml"
MAX_POLL=60
POLL_SECONDS=10

def require(ok,why):
    if not ok:raise ValueError("WATCHDOG_DENY "+why)

def initial_event():
    event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),object_pairs_hook=m.json_unique)
    require(os.environ["GITHUB_EVENT_NAME"]=="push"
            and os.environ["GITHUB_REPOSITORY"]=="pgextwin/build"
            and os.environ["GITHUB_REF"]=="refs/heads/main"
            and os.environ["GITHUB_ACTOR"]=="ShutenOishi"
            and event.get("sender",{}).get("login")=="ShutenOishi"
            and event.get("after")==os.environ["GITHUB_SHA"]
            and event.get("ref")=="refs/heads/main"
            and event.get("created") is False and event.get("deleted") is False,
            "not protected original push")
    original=m.contents_original(event["after"])
    data,decl=m.read_request(original,event["after"])
    require(data["requestId"]==REQ and data["mode"]=="AUDIT_ONLY"
            and data["source"]["centralMainSha"]==event["before"]
            and data["approval"]["publicReleaseAuthorized"] is False
            and data["approval"]["publicationGrants"]==[]
            and data["limits"]["maxWallClockMinutes"] <= 10,
            "scope/immutable request mismatched")
    # Do not extend a deadline from a mutable clock or retry beyond request cap.
    cutoff=life.parse_utc(data["expiresAt"])
    now=datetime.now(timezone.utc)
    require(now<cutoff and (cutoff-now).total_seconds()<=600, "watch outside finite budget")
    return data,event["after"]

def state_get():
    record=bridge.get_json("repos/pgextwin/build/contents/"+
                         store.PREFIX+REQ+".json?ref=issue311-state")
    _,state=store.unpack(record,REQ)
    return state

def listed(workflow,head):
    # Every returned run must be retrieved from the exact repo/workflow, no
    # pagination ambiguity and never use an untrusted PR-hosted URL.
    payload=bridge.get_json("repos/pgextwin/build/actions/workflows/"+
                            workflow+"/runs?head_sha="+head+"&per_page=100")
    runs=payload.get("workflow_runs")
    require(type(runs) is list and type(payload.get("total_count")) is int
            and len(runs)==payload["total_count"] and len(runs)<=100,
            "truncated/nonoriginal Actions listing")
    require(all(x.get("head_sha")==head for x in runs), "foreign SHA listing")
    return runs

def snapshot(head,state):
    require(state["sourceHeadSha"]==head and state["requestId"]==REQ,
            "source state changed")
    origin=state["sourceRun"]
    require(origin is not None, "original source not registered")
    original=bridge.get_json("repos/pgextwin/build/actions/runs/"+str(origin["id"]))
    require(original.get("head_sha")==head
            and original.get("id")==origin["id"]
            and original.get("run_attempt")==origin["attempt"]
            and original.get("path")==m.SOURCE_PATH
            and original.get("event")=="push"
            and original.get("actor",{}).get("login")=="ShutenOishi",
            "original Run metadata mismatch")
    others=listed(BRIDGE_WORKFLOW,head)
    require(all(x.get("event")=="workflow_run" for x in others),
            "non-event bridge Run")
    # An original success is not enough: independently hash the actual source
    # receipt ZIP and verify all 17 protected-main GET outcomes first.
    complete=(original.get("status")=="completed"
              and original.get("conclusion")=="success")
    if complete and m._CASE in ("missing-event-17","skipped-17"):
        raw=m.contents_original(head)
        require(hashlib.sha256(raw).hexdigest()==state["requestSha256"],
                "original request hash drift")
        data=json.loads(raw,object_pairs_hook=m.json_unique)
        m.verify_source_zip(original,{"rawSha256":state["requestSha256"]},data)
        # A genuine skipped child cannot be promoted to source-complete
        # merely because GitHub marks the overall workflow successful.
        if m._CASE=="skipped-17":
            complete=False
    return complete,"MISSING_VERIFIED" if not others else "UNKNOWN",len(others)

def observe():
    report={"requestId":REQ,"result":"QUARANTINED",
            "publisherAuthorized":False,"reason":"watchdog observation unavailable"}
    try:
        data,head=initial_event()
        deadline=life.parse_utc(data["expiresAt"])
        last=None
        for _ in range(MAX_POLL):
            try:
                state=state_get()
                require(state["sourceHeadSha"]==head,"state wrong source")
                if state["terminal"] is not None:
                    report={"requestId":REQ,"result":"ALREADY_TERMINAL",
                            "terminal":state["terminal"],"stateRevision":state["revision"],
                            "publisherAuthorized":False}
                    break
                completed,lookup,count=snapshot(head,state)
                last={"sourceCompleted":completed,"lookup":lookup,"bridgeCount":count}
            except Exception as exc:
                last={"sourceCompleted":None,"lookup":"UNKNOWN",
                      "reason":str(exc)[:160]}
            if datetime.now(timezone.utc)>=deadline:
                report={"requestId":REQ,"result":"NEEDS_TERMINAL",
                        "headSha":head,"deadlineAt":data["expiresAt"],
                        "observation":last,"publisherAuthorized":False}
                break
            time.sleep(min(POLL_SECONDS,max(0,(deadline-datetime.now(timezone.utc)).total_seconds())))
        else:
            report["reason"]="watchdog finite poll budget exhausted"
    except Exception as exc:
        report["reason"]=str(exc)[:290]
    Path(EVENT_FILE).write_text(json.dumps(report,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True))
    return 0 if report["result"] in ("ALREADY_TERMINAL","NEEDS_TERMINAL") else 1

def finalize():
    report=json.loads(Path(EVENT_FILE).read_bytes(),object_pairs_hook=m.json_unique)
    require(report.get("requestId")==REQ
            and report.get("publisherAuthorized") is False,"observation mismatch")
    if report["result"]=="ALREADY_TERMINAL":
        print("R05_WATCHDOG_ALREADY_DURABLE_TERMINAL")
        return 0
    require(report["result"]=="NEEDS_TERMINAL","observation did not reach deadline")
    token=None
    try:
        token,cas=m.app_cas()
        blob,state=cas.read(REQ)
        if state["terminal"] is not None:
            print("R05_WATCHDOG_LISTENER_WON_CAS",state["terminal"])
            return 0
        # Re-check authenticated authoritative GitHub REST after expiry; never
        # trust the earlier observation or a status field from a request.
        try:
            completed,lookup,count=snapshot(report["headSha"],state)
        except Exception:
            completed,lookup=None,"UNKNOWN"
        if datetime.now(timezone.utc)<life.parse_utc(state["expiresAt"]):
            raise ValueError("deadline not reached")
        expired=life.event_deadline(state,state["revision"],"finite-event-deadline",
                    now=datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
                    source_completed=completed,
                    original_source_sha=report["headSha"],
                    completion_lookup=lookup)
        result=cas.write(expired,previous=state,expected_blob=blob)
        _,done=cas.read(REQ)
        require(done==expired,"terminal CAS not durably confirmed")
        print("R05_WATCHDOG_DURABLE",done["terminal"],result)
        return 0
    except store.UnknownWrite:
        # A racing true bridge may have won; only observe, never blind-retry.
        try:
            _,existing=cas.read(REQ)
            if existing["terminal"] is not None:
                print("R05_WATCHDOG_CAS_RACE_EXISTING_TERMINAL",existing["terminal"])
                return 0
        except Exception:
            pass
        raise
    finally:
        if token:writer.revoke_and_prove_401(token)

if __name__=="__main__":
    cmd=sys.argv[1] if len(sys.argv)>1 else ""
    raise SystemExit(observe() if cmd=="observe" else finalize() if cmd=="finalize" else 2)
