#!/usr/bin/env python3
"""R06-06-03: two INDEPENDENT real State App jobs race one immutable QUARANTINED revision.

This is a new, isolated AUDIT_ONLY State checkpoint, not a rerun, fake schedule,
real release, or a claim of naturally lost GitHub events. Both writers verify
the SAME revision1 original Git blob BEFORE their one-shot synchronized PUT.
Exactly one must win, and the loser must receive real GitHub stale-SHA 409/422.
Only a separate job without the App key accepts the original bytes/evidence.
"""
from __future__ import annotations
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj
store=load("parallel_store","scripts/issue311-lifecycle-store.py")
writer=load("parallel_writer","scripts/issue311-writer-runtime.py")
bridge=load("parallel_bridge","scripts/issue311-r05-windows-completion-bridge.py")
life=store.lifecycle

NAME="Issue 311 R06 independent two-runner real State App CAS contention (NONPUBLISHING)"
REQ="r-20261030-r06parallelcasproof12"
REQUEST=".github/execution-requests/"+REQ+".json"
INIT="issue311-r06-parallel-init.json"
OUT="issue311-r06-parallel-{}.json"
READBACK="issue311-r06-parallel-keyless-readback.json"
TARGETS=sorted("pgextwin/"+n for n in (
    "pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user","pg_repack",
    "pg_ivm","pg_qualstats","plpgsql_check","orafce","hypopg","wal2json",
    "pg_partman","pg_stat_monitor","pgtap","pg_variables","pg_store_plans"))

def require(value,reason):
    if not value:raise ValueError("R06_PARALLEL_CAS_DENY "+reason)
def strict(raw):
    return json.loads(raw,object_pairs_hook=store.unique_pairs)
def now():
    return datetime.now(timezone.utc)
def get(path):
    return bridge.get_json("repos/pgextwin/build/"+path)

def approved_request():
    require(os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build"
        and os.environ.get("GITHUB_EVENT_NAME")=="push"
        and os.environ.get("GITHUB_WORKFLOW")==NAME
        and os.environ.get("GITHUB_REF")=="refs/heads/main"
        and os.environ.get("GITHUB_ACTOR")=="ShutenOishi"
        and os.environ.get("GITHUB_RUN_ATTEMPT")=="1",
        "not original protected one-shot human main push")
    event=strict(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    head=os.environ["GITHUB_SHA"]
    before=event.get("before")
    require(event.get("ref")=="refs/heads/main" and event.get("after")==head
        and event.get("created") is False and event.get("deleted") is False
        and event.get("sender",{}).get("login")=="ShutenOishi"
        and event.get("repository",{}).get("full_name")=="pgextwin/build"
        and re.fullmatch("[a-f0-9]{40}",head or "")
        and re.fullmatch("[a-f0-9]{40}",before or ""),
        "original event identity invalid")
    require(subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()==head
        and subprocess.check_output(["git","diff","--name-status",before,head],
                                    text=True).splitlines()==["A\t"+REQUEST],
        "not one-file original protected request")
    branch=get("branches/main")
    require(branch.get("protected") is True,"main not protected")
    commits=get("commits/"+head)
    require(len(commits.get("parents",[]))==1
        and commits["parents"][0]["sha"]==before
        and [(f.get("status"),f.get("filename")) for f in commits.get("files",[])]
            ==[("added",REQUEST)],"untrusted original protected source")
    raw=subprocess.check_output(["git","show","HEAD:"+REQUEST])
    origin=get("contents/"+REQUEST+"?ref="+head)
    require(origin.get("encoding")=="base64"
        and base64.b64decode(origin["content"].replace("\r","").replace("\n",""),validate=True)==raw
        and store.blob_hash(raw)==origin.get("sha"),
        "request Git original byte mismatch")
    req=strict(raw)
    require(type(req) is dict and set(req)=={
        "schemaVersion","kind","requestId","mode","baseMainSha","expiresAt",
        "maxWriters","targetScope","publisherAuthorized","runtimeEnabled",
        "publicReleaseAuthorized"}, "invalid request schema")
    require(req["schemaVersion"]==1
        and req["kind"]=="pgextwin-r06-isolated-parallel-state-cas-proof"
        and req["requestId"]==REQ and req["mode"]=="AUDIT_ONLY"
        and req["baseMainSha"]==before and req["maxWriters"]==2
        and req["targetScope"]==TARGETS
        and req["publisherAuthorized"] is False
        and req["runtimeEnabled"] is False
        and req["publicReleaseAuthorized"] is False,
        "request may not confer publication or change target scope")
    expires=life.parse_utc(req["expiresAt"])
    require(now()<expires<=now()+timedelta(hours=3),
            "original request expired or unbounded")
    return req,hashlib.sha256(raw).hexdigest(),head

def bound_state(req,request_sha,head):
    initial=life.new(REQ,request_sha,head,TARGETS,req["expiresAt"],max_events=10)
    bound=life.bind_source(initial,0,"r06_parallel_original_push",
        run_id=int(os.environ["GITHUB_RUN_ID"]),attempt=1,head_sha=head)
    return initial,bound

def write_proposed(bound,name):
    require(name in ("A","B"),"writer must be A or B")
    def terminal(s):
        s["targets"]={k:"QUARANTINED" for k in s["targetScope"]}
        s["terminal"]="QUARANTINED"
        s["completionRun"]={"id":int(os.environ["GITHUB_RUN_ID"]),"attempt":1}
        s["eventTransport"]="BOUNDED_WATCHDOG"
    return life._apply(bound,1,"r06_parallel_writer_"+name,
        {"op":"isolated_real_concurrent_terminal","writer":name,"publication":False},
        terminal)

def run_init():
    req,request_sha,head=approved_request()
    initial,bound=bound_state(req,request_sha,head)
    token=None
    try:
        token=writer.mint_token(os.environ["STATE_WRITER_PRIVATE_KEY"])
        client=store.CAS(lambda method,path,body:writer.api(method,path,token,body))
        try:
            client.read(REQ)
        except writer.HTTPStatus as exc:
            require(exc.code==404,"replayed or unreadable request")
        else:
            raise ValueError("R06_PARALLEL_CAS_DENY checkpoint already exists/replay")
        client.write(initial)
        blob,current=client.read(REQ)
        require(current==initial,"initial original GET mismatch")
        client.write(bound,previous=current,expected_blob=blob)
        revision1_blob,actual=client.read(REQ)
        require(actual==bound,"bound revision1 original GET mismatch")
        start_epoch=int(time.time())+85
        report={"schemaVersion":1,"requestId":REQ,"result":"REVISION1_ORIGINAL_PREPARED",
            "expectedBlobSha":revision1_blob,"requestSha256":request_sha,
            "sourceHeadSha":head,"startEpoch":start_epoch,"revision":1,
            "publicationAuthorized":False}
        Path(INIT).write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        with open(os.environ["GITHUB_OUTPUT"],"a") as handle:
            handle.write("expected_sha="+revision1_blob+"\n")
            handle.write("start_epoch="+str(start_epoch)+"\n")
    finally:
        if token:writer.revoke_and_prove_401(token)
    return 0

def run_writer(name):
    req,request_sha,head=approved_request()
    _,bound=bound_state(req,request_sha,head)
    expected_sha=os.environ["EXPECTED_SHA"]
    start=int(os.environ["START_EPOCH"])
    require(re.fullmatch("[0-9a-f]{40}",expected_sha or "")
        and 0<start-int(time.time())<=200,
        "preimage clock must be a short bounded synchronization window")
    token=None
    proof={"schemaVersion":1,"writer":name,"requestId":REQ,"result":"DENIED",
           "putCount":0,"publicationAuthorized":False,
           "originalSourceSha":head,"expectedBlobSha":expected_sha}
    try:
        token=writer.mint_token(os.environ["STATE_WRITER_PRIVATE_KEY"])
        client=store.CAS(lambda method,path,body:writer.api(method,path,token,body))
        blob,current=client.read(REQ)
        require(blob==expected_sha and current==bound and current["revision"]==1
                and current["terminal"] is None,"writer not armed on SAME original revision1")
        proof["armedEpoch"]=time.time()
        intended=write_proposed(current,name)
        body={"message":"state(issue311): isolated parallel QUARANTINED writer "+name,
              "branch":store.BRANCH,"sha":expected_sha,
              "content":base64.b64encode(store.canonical(intended)).decode("ascii")}
        while time.time()<start:
            time.sleep(min(0.15,start-time.time()))
        require(time.time()<=start+7,"writer missed synchronized collision window")
        proof["putEpoch"]=time.time()
        proof["putCount"]=1
        try:
            reply=writer.api("PUT",store.endpoint(REQ),token,body)
        except writer.HTTPStatus as exc:
            require(exc.code in (409,422),"unexpected State App HTTP status")
            proof["result"]="STALE_SHA_REJECTED"
            proof["httpStatus"]=exc.code
        else:
            require(reply.get("content",{}).get("sha")==store.blob_hash(store.canonical(intended)),
                    "authoritative winning PUT response sha mismatch")
            proof["result"]="QUARANTINED_WINNER"
            proof["winningBlobSha"]=store.blob_hash(store.canonical(intended))
        original_blob,observed=client.read(REQ)
        require(observed["revision"]==2 and observed["terminal"]=="QUARANTINED"
                and len(observed["targets"])==17
                and set(observed["targets"].values())=={"QUARANTINED"}
                and observed["publisherAuthorized"] is False
                and observed["writeOutcomeUnknown"] is False,
                "not a durable independent QUARANTINED17")
        if proof["result"]=="QUARANTINED_WINNER":
            require(observed==intended and original_blob==proof["winningBlobSha"],
                    "winner original Git bytes altered")
        proof["observedBlobSha"]=original_blob
    except Exception as exc:
        proof["result"]="DENIED"
        proof["reason"]=str(exc)[:300]
    finally:
        if token:
            try:
                writer.revoke_and_prove_401(token)
                proof["sameTokenRevoked401"]=True
            except Exception as exc:
                proof["result"]="DENIED"
                proof["revokeError"]=type(exc).__name__
        Path(OUT.format(name)).write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    print("R06_PARALLEL_WRITER_"+name,json.dumps(proof,sort_keys=True))
    return 0 if proof["result"] in ("QUARANTINED_WINNER","STALE_SHA_REJECTED") and proof.get("sameTokenRevoked401") is True else 1

def run_readback():
    require(not os.environ.get("STATE_WRITER_PRIVATE_KEY"),
            "independent reader must have no State App private key")
    req,request_sha,head=approved_request()
    run_id=int(os.environ["GITHUB_RUN_ID"])
    listing=get("actions/runs/"+str(run_id)+"/artifacts?per_page=100")
    artifacts=listing.get("artifacts",[])
    need={name: [a for a in artifacts if a.get("name")=="issue311-r06-parallel-"+name] for name in ("A","B")}
    require(listing.get("total_count")==len(artifacts)
            and all(len(v)==1 and v[0].get("expired") is False for v in need.values()),
            "original independent writer artifacts missing/ambiguous")
    proofs={}
    for name in ("A","B"):
        artifact=need[name][0]
        entry,zip_sha=bridge.original_zip(artifact,OUT.format(name))
        require(zip_sha==artifact["digest"].removeprefix("sha256:")
                and artifact.get("workflow_run",{}).get("id")==run_id
                and entry.get("writer")==name and entry.get("requestId")==REQ
                and entry.get("putCount")==1
                and entry.get("sameTokenRevoked401") is True
                and entry.get("publicationAuthorized") is False
                and entry.get("originalSourceSha")==head
                and entry.get("result") in ("QUARANTINED_WINNER","STALE_SHA_REJECTED"),
                "untrusted original independent writer proof")
        proofs[name]=entry
    winners=[p for p in proofs.values() if p["result"]=="QUARANTINED_WINNER"]
    losers=[p for p in proofs.values() if p["result"]=="STALE_SHA_REJECTED"]
    require(len(winners)==len(losers)==1
            and losers[0]["httpStatus"] in (409,422)
            and abs(proofs["A"]["putEpoch"]-proofs["B"]["putEpoch"])<7
            and abs(proofs["A"]["armedEpoch"]-proofs["B"]["armedEpoch"])<90
            and all(p["armedEpoch"]<p["putEpoch"] for p in proofs.values()),
            "not two independent competing original PUTs")
    blob,state=store.unpack(get("contents/"+store.PREFIX+REQ+".json?ref="+store.BRANCH),REQ)
    require(blob==winners[0]["winningBlobSha"]==losers[0]["observedBlobSha"]
            and state["revision"]==2 and state["terminal"]=="QUARANTINED"
            and state["requestSha256"]==request_sha
            and state["sourceHeadSha"]==head
            and state["sourceRun"]=={"id":run_id,"attempt":1}
            and state["completionRun"]=={"id":run_id,"attempt":1}
            and state["eventTransport"]=="BOUNDED_WATCHDOG"
            and len(state["targets"])==17
            and set(state["targets"].values())=={"QUARANTINED"}
            and state["publisherAuthorized"] is False
            and state["writeOutcomeUnknown"] is False,
            "independent original Git blob not sole immutable winner")
    try:
        life._apply(state,2,"replayed_loser",
                    {"writer":"late"},lambda s:s.update(terminal="NO_UPDATE"))
    except ValueError:pass
    else:raise AssertionError("replay modified terminal")
    again=store.unpack(get("contents/"+store.PREFIX+REQ+".json?ref="+store.BRANCH),REQ)
    require(again==(blob,state),"late race changed authoritative Git bytes")
    out={"schemaVersion":1,"requestId":REQ,"result":"TWO_INDEPENDENT_REAL_GITHUB_CAS_PUTS_ONE_WINNER_ONE_409",
         "stateBlobSha":blob,"revision":2,"targetCount":17,
         "originalWriterOutcomes":{n:p["result"] for n,p in proofs.items()},
         "loserHttpStatus":losers[0]["httpStatus"],
         "publicationAuthorized":False,"appKeyAvailable":False,"replay":"DENY_NO_PUT"}
    Path(READBACK).write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
    print("R06_PARALLEL_CAS_INDEPENDENT_READBACK",json.dumps(out,sort_keys=True))
    return 0

if __name__=="__main__":
    require(len(sys.argv)==2 and sys.argv[1] in ("init","A","B","readback"),
            "unapproved one-shot operation")
    command=sys.argv[1]
    raise SystemExit(run_init() if command=="init" else
                     run_readback() if command=="readback" else run_writer(command))
