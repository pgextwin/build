#!/usr/bin/env python3
"""Fail-closed one-shot recovery of independently observed failed R06 App CAS.

No successful original is rerun. The dedicated State App writes only the existing
request checkpoint, after first-attempt GitHub REST and original ZIP verification.
A separate job without the App key checks the exact new immutable Git blob.
"""
from __future__ import annotations
import hashlib, importlib.util, json, os, re, subprocess, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def load(n,p):
    spec=importlib.util.spec_from_file_location(n,ROOT/p)
    v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);return v
bridge=load("recover_bridge","scripts/issue311-r05-windows-completion-bridge.py")
store=load("recover_store","scripts/issue311-lifecycle-store.py")
writer=load("recover_writer","scripts/issue311-writer-runtime.py")
life=store.lifecycle
REQ="r-20261030-r06autofiniterecover01"
PATH=".github/execution-requests/"+REQ+".json"
WORKFLOW="Issue 311 R06 failed automatic CAS fail-closed recovery (NONPUBLISHING)"
SOURCE_NAME="Issue 311 17 authentic App-bot local PREPARE originals (NO RELEASE)"
SOURCE_PATH=".github/workflows/issue311-coordinator-fleet-original.yml"
CAS_NAME="Issue 311 R06 real 17-App original durable CAS terminal (NONPUBLISHING)"
CAS_PATH=".github/workflows/issue311-r06-app-fleet-cas-terminal.yml"
OLD_STATE="r-20261030-r06appauto41005515488"
SOURCE=41005515488
FAILED=41005723124
SOURCE_ZIP="c89c540b8db8cda09a2237c4ec4963e3dcbee766f121b8395840a0ff07b079ae"
FAIL_ZIP="3c48b13c91d93c7607e8eb9b19549a58319968c9b384e98c6e7286539b3ee8de"
ORIGINAL_STATE_BLOB="42b10181f69058227fdb364db8f0d3344bf64461"
ORIGINAL_HEAD="394fa3b83df8b2ad163faf08aa8db5dc5071e13d"
ORIGINAL_REQUEST_SHA="3a00769bcedcf54f5c5fc6b8f9f3978328693301cd7b7ef83e4a078f2f237e8a"
PROOF="issue311-r06-failed-cas-recovery.json"
READBACK="issue311-r06-failed-cas-recovery-readback.json"

def require(v,s):
    if not v: raise ValueError("R06_FAILED_CAS_RECOVERY_DENY "+s)
def strict(v): return json.loads(v,object_pairs_hook=store.unique_pairs)
def api(p): return bridge.get_json("repos/pgextwin/build/"+p)
def original_zip(run_id, artifact_name, member, digest):
    listing=api("actions/runs/"+str(run_id)+"/artifacts?per_page=100")
    arr=listing.get("artifacts",[])
    require(listing.get("total_count")==len(arr)==1 and
            arr[0].get("name")==artifact_name and
            arr[0].get("digest")=="sha256:"+digest and
            arr[0].get("expired") is False and
            arr[0].get("workflow_run",{}).get("id")==run_id,
            "missing/changed first-attempt ZIP")
    val,actual=bridge.original_zip(arr[0],member)
    require(actual==digest,"original ZIP bytes differ")
    return val

def request():
    require(os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build"
            and os.environ.get("GITHUB_EVENT_NAME")=="push"
            and os.environ.get("GITHUB_WORKFLOW")==WORKFLOW
            and os.environ.get("GITHUB_REF")=="refs/heads/main"
            and os.environ.get("GITHUB_ACTOR")=="ShutenOishi"
            and os.environ.get("GITHUB_RUN_ATTEMPT")=="1",
            "not original protected human push")
    ev=strict(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    after=os.environ["GITHUB_SHA"];before=ev.get("before")
    require(ev.get("after")==after and ev.get("ref")=="refs/heads/main"
            and ev.get("created") is False and ev.get("deleted") is False
            and ev.get("sender",{}).get("login")=="ShutenOishi"
            and ev.get("repository",{}).get("full_name")=="pgextwin/build"
            and re.fullmatch("[0-9a-f]{40}",before or ""),
            "original event mismatch")
    require(subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()==after
            and subprocess.check_output(["git","diff","--name-status",before,after],
                                        text=True).splitlines()==["A\t"+PATH],
            "not one new protected recovery request")
    live=api("branches/main")
    require(live.get("protected") is True and live.get("commit",{}).get("sha")==after,
            "current branch not protected main")
    raw=subprocess.check_output(["git","show","HEAD:"+PATH])
    ref=api("contents/"+PATH+"?ref="+after)
    import base64
    require(ref.get("encoding")=="base64"
            and base64.b64decode(ref["content"].replace("\n","").replace("\r",""),validate=True)==raw
            and store.blob_hash(raw)==ref["sha"],"request original bytes changed")
    r=strict(raw)
    require(type(r) is dict and set(r)=={
        "schemaVersion","kind","requestId","mode","baseMainSha",
        "expiresAt","stateRequestId","stateBlobSha","sourceRunId","failedCasRunId",
        "sourceHeadSha","sourceZipSha256","failedCasZipSha256",
        "originalRequestSha256","runtimeEnabled","publicReleaseAuthorized"},
        "unexpected request fields")
    require(r["schemaVersion"]==1 and r["kind"]=="pgextwin-r06-failed-cas-recovery"
            and r["requestId"]==REQ and r["mode"]=="AUDIT_ONLY"
            and r["baseMainSha"]==before
            and r["stateRequestId"]==OLD_STATE
            and r["stateBlobSha"]==ORIGINAL_STATE_BLOB
            and r["sourceRunId"]==SOURCE and r["failedCasRunId"]==FAILED
            and r["sourceHeadSha"]==ORIGINAL_HEAD
            and r["sourceZipSha256"]==SOURCE_ZIP
            and r["failedCasZipSha256"]==FAIL_ZIP
            and r["originalRequestSha256"]==ORIGINAL_REQUEST_SHA
            and r["runtimeEnabled"] is False
            and r["publicReleaseAuthorized"] is False
            and datetime.now(timezone.utc)<life.parse_utc(r["expiresAt"])
                <=datetime.now(timezone.utc)+timedelta(hours=3),
            "recovery not strictly pinned/nonpublishing/bounded")
    return r,hashlib.sha256(raw).hexdigest()

def evidence():
    source=api("actions/runs/"+str(SOURCE))
    failed=api("actions/runs/"+str(FAILED))
    require(source.get("name")==SOURCE_NAME and source.get("path")==SOURCE_PATH
            and source.get("event")=="workflow_run"
            and source.get("head_sha")==ORIGINAL_HEAD
            and source.get("status")=="completed" and source.get("conclusion")=="success"
            and source.get("run_attempt")==1,
            "original App fleet evidence mismatch")
    require(failed.get("name")==CAS_NAME and failed.get("path")==CAS_PATH
            and failed.get("event")=="workflow_run"
            and failed.get("head_sha")==ORIGINAL_HEAD
            and failed.get("status")=="completed" and failed.get("conclusion")=="failure"
            and failed.get("run_attempt")==1,
            "not independently confirmed original failed CAS")
    source_proof=original_zip(SOURCE,"issue311-r06-app-fleet-original-terminal",
                              "issue311-r06-app-fleet-original-terminal.json",SOURCE_ZIP)
    require(source_proof.get("result")=="CHILDREN_17_ORIGINAL_ZIP_VERIFIED_CAS_PENDING"
            and source_proof.get("durableCasVerified") is False
            and source_proof.get("publicationAuthorized") is False
            and len(source_proof.get("children",[]))==17,
            "source ZIP cannot be authorized as state terminal")
    failure=original_zip(FAILED,"issue311-r06-app-original-cas-proof",
                         "issue311-r06-app-original-cas-proof.json",FAIL_ZIP)
    require(failure.get("result")=="QUARANTINED"
            and "invalid event transport" in failure.get("reason","")
            and failure.get("publicationAuthorized") is False
            and failure.get("publisherAuthorized") is False
            and failure.get("durableCasVerified") is False,
            "failed attempt must retain exact original failure witness")
    jobs=api("actions/runs/"+str(FAILED)+"/jobs?per_page=100")
    require(jobs.get("total_count")==len(jobs.get("jobs",[]))==3 and
            len([j for j in jobs["jobs"] if
                 j.get("name")=="Verify 17 genuine original child ZIPs then finite build-only App CAS"
                 and j.get("conclusion")=="failure"])==1,
            "not original failure job")
    return {"sourceRunId":SOURCE,"failedCasRunId":FAILED,
            "sourceZipSha256":SOURCE_ZIP,"failedCasZipSha256":FAIL_ZIP,
            "failure":"invalid event transport"}

def transition(state, proof, run_id):
    require(state["requestId"]==OLD_STATE and state["revision"]==1
            and state["requestSha256"]==ORIGINAL_REQUEST_SHA
            and state["sourceHeadSha"]==ORIGINAL_HEAD
            and state["sourceRun"]=={"id":SOURCE,"attempt":1}
            and state["completionRun"] is None and state["terminal"] is None
            and state["eventTransport"] is None
            and len(state["targetScope"])==17
            and all(x=="PENDING" for x in state["targets"].values())
            and state["publisherAuthorized"] is False
            and state["writeOutcomeUnknown"] is False,
            "old state is not exact immutable pending revision1")
    def finish(s):
        s["targets"]={k:"QUARANTINED" for k in s["targetScope"]}
        s["terminal"]="QUARANTINED"
        s["eventTransport"]="BOUNDED_WATCHDOG"
        s["completionRun"]={"id":run_id,"attempt":1}
    return life._apply(state,1,"r06_failed_cas_terminal",
                       {"op":"quarantine-original-failed-cas",**proof},finish)

def persist():
    report={"schemaVersion":1,"requestId":REQ,"result":"QUARANTINED",
            "publicationAuthorized":False,"appKeyAvailable":False}
    token=None
    try:
        r,request_sha=request()
        proof=evidence()
        before=api("contents/"+store.PREFIX+OLD_STATE+".json?ref="+store.BRANCH)
        blob,state=store.unpack(before,OLD_STATE)
        require(blob==ORIGINAL_STATE_BLOB,"old state moved; do not overwrite")
        intended=transition(state,proof,int(os.environ["GITHUB_RUN_ID"]))
        token=writer.mint_token(os.environ.get("STATE_WRITER_PRIVATE_KEY",""))
        cas=store.CAS(lambda method,endpoint,body:writer.api(method,endpoint,token,body))
        live_blob,live_state=cas.read(OLD_STATE)
        require((live_blob,live_state)==(blob,state),"unexpected concurrent CAS revision")
        outcome=cas.write(intended,previous=state,expected_blob=blob)
        end_blob,end_state=cas.read(OLD_STATE)
        require(end_state==intended and end_blob==store.blob_hash(store.canonical(intended)),
                "unconfirmed final original CAS blob")
        report.update(result="QUARANTINED_DURABLE_READBACK_PENDING",
                      stateBlobSha=end_blob,stateRevision=2,
                      oldStateBlobSha=blob,sourceRunId=SOURCE,failedCasRunId=FAILED,
                      targetCount=17,requestSha256=request_sha,writeOutcome=outcome)
    except Exception as exc:
        report["reason"]=str(exc)[:350]
    finally:
        if token:
            try:
                writer.revoke_and_prove_401(token)
                report["sameTokenRevoked401"]=True
            except Exception as exc:
                report["revokeFailure"]=type(exc).__name__
                report["result"]="QUARANTINED"
        Path(PROOF).write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print("R06_FAILED_CAS_RECOVERY",json.dumps(report,sort_keys=True))
    return 0 if report["result"]=="QUARANTINED_DURABLE_READBACK_PENDING" and report.get("sameTokenRevoked401") is True else 1

def readback():
    require(not os.environ.get("STATE_WRITER_PRIVATE_KEY"),"reader has forbidden App key")
    request()
    proof=evidence()
    listing=api("actions/runs/"+os.environ["GITHUB_RUN_ID"]+"/artifacts?per_page=100")
    items=listing.get("artifacts",[])
    matches=[a for a in items if a.get("name")=="issue311-r06-failed-cas-recovery"]
    require(len(matches)==1 and matches[0].get("expired") is False,
            "missing unique original recovery proof")
    result,verified=bridge.original_zip(matches[0],PROOF)
    require(result.get("result")=="QUARANTINED_DURABLE_READBACK_PENDING"
            and result.get("sameTokenRevoked401") is True
            and result.get("sourceRunId")==SOURCE
            and result.get("failedCasRunId")==FAILED
            and result.get("targetCount")==17
            and verified==matches[0]["digest"].removeprefix("sha256:"),
            "independent recovery proof mismatch")
    raw=api("contents/"+store.PREFIX+OLD_STATE+".json?ref="+store.BRANCH)
    blob,state=store.unpack(raw,OLD_STATE)
    require(blob==result["stateBlobSha"]
            and state["revision"]==2 and state["terminal"]=="QUARANTINED"
            and state["eventTransport"]=="BOUNDED_WATCHDOG"
            and state["sourceRun"]=={"id":SOURCE,"attempt":1}
            and state["completionRun"]=={"id":int(os.environ["GITHUB_RUN_ID"]),"attempt":1}
            and len(state["targets"])==17
            and set(state["targets"].values())=={"QUARANTINED"}
            and state["publisherAuthorized"] is False
            and state["writeOutcomeUnknown"] is False,
            "independent read-only original state mismatch")
    try:
        life._apply(state,2,"replay",{"action":"replay"},lambda s:s.update(terminal=None))
    except ValueError: pass
    else:raise AssertionError("terminal replay wrongly accepted")
    summary={"schemaVersion":1,"requestId":OLD_STATE,"result":"ORIGINAL_FAILED_CAS_QUARANTINED_DURABLE",
             "revision":2,"gitBlobSha":blob,"sourceRunId":SOURCE,"failedCasRunId":FAILED,
             "appKeyAvailable":False,"publicationAuthorized":False,"replay":"DENY"}
    Path(READBACK).write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print("R06_FAILED_CAS_INDEPENDENT_READBACK",json.dumps(summary,sort_keys=True))
    return 0

if __name__=="__main__":
    require(sys.argv[1:] in (["persist"],["readback"]),"only approved one-shot recovery/readback")
    raise SystemExit(persist() if sys.argv[1]=="persist" else readback())
