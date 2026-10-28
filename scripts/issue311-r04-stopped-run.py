#!/usr/bin/env python3
"""Issue #311 R04: real failed workflow Run -> distinct Run protected-state recovery.

Nonpublishing, fixed two-request proof only. No dispatch, cron, Publisher, tag,
Release or Catalog. All scoped App tokens are minted and revoked in each job.
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
import time

spec=importlib.util.spec_from_file_location("r04writer", Path(__file__).resolve().parent / "issue311-writer-runtime.py")
writer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(writer)

START_ID="r-20261029-r04stopped01"
RESUME_ID="r-20261029-r04resumed02"
LEDGER="checkpoints/issue311-cross-run-v1.json"
STAGE="READONLY_PROTECTED_MAIN_BOUND"
LEASE_SECONDS=120


def guard(ok, reason):
    writer.require(ok,"R04_STOP_RESUME_DENY: "+reason)


def endpoint():
    return "repos/pgextwin/build/contents/" + LEDGER


def load_request(kind):
    rid = START_ID if kind=="start" else RESUME_ID
    raw=Path(".github/execution-requests/"+rid+".json").read_bytes()
    value=json.loads(raw,object_pairs_hook=writer.unique_pairs)
    expected={"schemaVersion","requestId","kind","mode","baseMainSha",
              "publicReleaseAuthorized"}
    if kind=="resume":
        expected|={"sourceMainSha","sourceRunId","sourceRunAttempt","sourceRequestSha256"}
    guard(type(value) is dict and set(value)==expected,"request schema")
    guard(type(value["schemaVersion"]) is int and value["schemaVersion"]==1
          and value["requestId"]==rid and value["kind"]=="issue311-r04-"+kind+"-proof"
          and value["mode"]=="AUDIT_ONLY" and value["publicReleaseAuthorized"] is False
          and type(value["baseMainSha"]) is str
          and writer.SHA1.fullmatch(value["baseMainSha"]),"unrecognized request")
    if kind=="resume":
        guard(type(value["sourceMainSha"]) is str
              and writer.SHA1.fullmatch(value["sourceMainSha"])
              and type(value["sourceRunId"]) is int and value["sourceRunId"]>0
              and type(value["sourceRunAttempt"]) is int and value["sourceRunAttempt"]==1
              and type(value["sourceRequestSha256"]) is str
              and writer.SHA256.fullmatch(value["sourceRequestSha256"]),
              "unpinned source run")
    return value,hashlib.sha256(raw).hexdigest()


def original_push(kind):
    guard(os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build"
          and os.environ.get("GITHUB_EVENT_NAME")=="push"
          and os.environ.get("GITHUB_REF")=="refs/heads/main"
          and os.environ.get("GITHUB_ACTOR")=="ShutenOishi","source event/actor")
    value,raw_sha=load_request(kind)
    event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                     object_pairs_hook=writer.unique_pairs)
    guard(event.get("ref")=="refs/heads/main" and event.get("created") is False
          and event.get("deleted") is False and
          event.get("repository",{}).get("full_name")=="pgextwin/build"
          and event.get("after")==os.environ["GITHUB_SHA"]
          and event.get("before")==value["baseMainSha"],"not original protected push")
    guard(subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()
          ==event["after"],"checkout mismatch")
    subprocess.run(["git","merge-base","--is-ancestor",
                    event["before"],event["after"]],check=True)
    return value,raw_sha


def validate_state(s):
    guard(type(s) is dict and set(s)=={
        "schemaVersion","scope","requestId","requestSha256",
        "revision","phase","sourceMainSha","sourceRunId","sourceRunAttempt",
        "lease","completedStages","resumedByRunId",
        "writeOutcomeUnknown","publisherAuthorized"},"state schema")
    guard(type(s["schemaVersion"]) is int and s["schemaVersion"]==1
          and s["scope"]=="AUDIT_ONLY_READONLY"
          and s["requestId"]==START_ID
          and type(s["requestSha256"]) is str and writer.SHA256.fullmatch(s["requestSha256"])
          and type(s["sourceMainSha"]) is str and writer.SHA1.fullmatch(s["sourceMainSha"])
          and type(s["sourceRunId"]) is int and s["sourceRunId"]>0
          and type(s["sourceRunAttempt"]) is int and s["sourceRunAttempt"]==1
          and type(s["revision"]) is int and s["revision"] in (1,2)
          and s["phase"] in ("LEASED_RUN_STOPPED","RECOVERED_ANOTHER_RUN")
          and s["writeOutcomeUnknown"] is False
          and s["publisherAuthorized"] is False
          and s["completedStages"]==[STAGE],"unsafe persisted state")
    lease=s["lease"]
    guard(type(lease) is dict and set(lease)=={
        "owner","generation","expiresAt","scope"},"lease schema")
    guard(lease["scope"]=="READONLY"
          and type(lease["owner"]) is str
          and re.fullmatch(r"run-[0-9]+\.1\.(stop|resume)",lease["owner"]),
          "bad lease owner")
    guard(type(lease["generation"]) is int and
          lease["generation"]==s["revision"],"fencing not monotonic")
    expires=datetime.fromisoformat(lease["expiresAt"])
    guard(expires.tzinfo is not None and expires.utcoffset()==timedelta(0),
          "lease expiry not UTC")
    if s["revision"]==1:
        guard(s["phase"]=="LEASED_RUN_STOPPED" and
              s["resumedByRunId"] is None and
              lease["owner"]==f'run-{s["sourceRunId"]}.1.stop',
              "untrusted source checkpoint")
    else:
        guard(s["phase"]=="RECOVERED_ANOTHER_RUN" and
              type(s["resumedByRunId"]) is int
              and s["resumedByRunId"]!=s["sourceRunId"]
              and lease["owner"]==f'run-{s["resumedByRunId"]}.1.resume',
              "not another original Run")
    return s


def read(token):
    payload=writer.api("GET",endpoint()+"?ref="+writer.STATE_BRANCH,token)
    guard(payload.get("encoding")=="base64"
          and writer.SHA1.fullmatch(payload.get("sha","")),"missing contents Git blob")
    raw=base64.b64decode(payload["content"])
    git_blob=b"blob "+str(len(raw)).encode()+b"\0"+raw
    guard(hashlib.sha1(git_blob).hexdigest()==payload["sha"],"blob content mismatch")
    state=json.loads(raw,object_pairs_hook=writer.unique_pairs)
    return payload["sha"],validate_state(state)


def save(token, intended, previous_sha=None):
    validate_state(intended)
    body={"message":"state(issue311): bounded R04 crashed-run recovery proof",
          "branch":writer.STATE_BRANCH,
          "content":base64.b64encode(writer.canonical(intended)).decode()}
    if previous_sha is not None:
        guard(writer.SHA1.fullmatch(previous_sha),"expected SHA missing")
        body["sha"]=previous_sha
    try:
        response=writer.api("PUT",endpoint(),token,body)
        guard(writer.SHA1.fullmatch(response.get("content",{}).get("sha","")),
              "invalid PUT response")
    except writer.HTTPStatus as error:
        if error.code not in (429,500,502,503,504):
            raise
        # Server may have committed despite an error: GET only, never POST retry.
        try:
            _,observed=read(token)
        except Exception as read_error:
            raise writer.UncertainWrite("QUARANTINED: failed authoritative GET") from read_error
        if observed!=intended:
            raise writer.UncertainWrite("QUARANTINED: unknown original write")
        return "ORIGINAL_GET_RECONCILED"
    except Exception as error:
        try:
            _,observed=read(token)
        except Exception as read_error:
            raise writer.UncertainWrite("QUARANTINED: network unknown") from read_error
        if observed!=intended:
            raise writer.UncertainWrite("QUARANTINED: write not confirmed") from error
        return "ORIGINAL_GET_RECONCILED"
    _,observed=read(token)
    guard(observed==intended,"authoritative write verification failed")
    return "ORIGINAL_GET_VERIFIED"


def start():
    _,raw_sha=original_push("start")
    token=writer.mint_token(os.environ.get("STATE_WRITER_PRIVATE_KEY",""))
    error=None
    try:
        try:
            read(token)
        except writer.HTTPStatus as exc:
            guard(exc.code==404,"unexpected checkpoint read response")
        else:
            raise writer.Denied("replay of successfully written stopped-run")
        now=datetime.now(timezone.utc)
        run_id=int(os.environ["GITHUB_RUN_ID"])
        state={"schemaVersion":1,"scope":"AUDIT_ONLY_READONLY",
               "requestId":START_ID,"requestSha256":raw_sha,
               "revision":1,"phase":"LEASED_RUN_STOPPED",
               "sourceMainSha":os.environ["GITHUB_SHA"],"sourceRunId":run_id,
               "sourceRunAttempt":1,
               "lease":{"owner":f"run-{run_id}.1.stop","generation":1,
                        "expiresAt":(now+timedelta(seconds=LEASE_SECONDS)).isoformat(),
                        "scope":"READONLY"},
               "completedStages":[STAGE],"resumedByRunId":None,
               "writeOutcomeUnknown":False,"publisherAuthorized":False}
        proof=save(token,state)
    except BaseException as exc:
        error=exc
    finally:
        writer.revoke_and_prove_401(token)
    if error:
        raise error
    print(json.dumps({"requestId":START_ID,"runId":run_id,"runAttempt":1,
                      "stateRevision":1,"phase":"PERSISTED_BEFORE_STOP",
                      "writerRevoke401":True,"writeProof":proof,
                      "publisherAuthorized":False},sort_keys=True),flush=True)
    # Actual original Actions job MUST fail AFTER persistent App write and revocation.
    # This is a deliberate stopped job, not a simulated green recovery.
    raise SystemExit(137)


def resume():
    declaration,_=original_push("resume")
    token=writer.mint_token(os.environ.get("STATE_WRITER_PRIVATE_KEY",""))
    error=None
    try:
        previous_sha,prior=read(token)
        guard(prior["revision"]==1 and prior["phase"]=="LEASED_RUN_STOPPED"
              and prior["sourceMainSha"]==declaration["sourceMainSha"]
              and prior["sourceRunId"]==declaration["sourceRunId"]
              and prior["sourceRunAttempt"]==declaration["sourceRunAttempt"]
              and prior["requestSha256"]==declaration["sourceRequestSha256"],
              "cannot recover different stopped original")
        this_run=int(os.environ["GITHUB_RUN_ID"])
        guard(this_run!=prior["sourceRunId"],"not a distinct original Run")
        expiry=datetime.fromisoformat(prior["lease"]["expiresAt"])
        seconds=max(0,(expiry-datetime.now(timezone.utc)).total_seconds()+1)
        guard(seconds<=LEASE_SECONDS+2,"unbounded recovery delay")
        if seconds: time.sleep(seconds)
        now=datetime.now(timezone.utc)
        guard(now>=expiry,"live lease still held")
        updated=dict(prior)
        updated.update(revision=2,phase="RECOVERED_ANOTHER_RUN",
                       resumedByRunId=this_run,
                       lease={"owner":f"run-{this_run}.1.resume",
                              "generation":2,
                              "expiresAt":(now+timedelta(seconds=LEASE_SECONDS)).isoformat(),
                              "scope":"READONLY"})
        proof=save(token,updated,previous_sha)
    except BaseException as exc:
        error=exc
    finally:
        writer.revoke_and_prove_401(token)
    if error:
        raise error
    print(json.dumps({"requestId":RESUME_ID,"originalRun":prior["sourceRunId"],
                      "newRun":this_run,"revision":2,"generation":2,
                      "recoveredFromDurableCheckpoint":True,
                      "alreadyCompletedStagesPreserved":updated["completedStages"],
                      "writerRevoke401":True,"writeProof":proof,
                      "publisherAuthorized":False,"result":"NO_UPDATE"},
                     sort_keys=True),flush=True)


def main():
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("phase",choices=("admit-start","admit-resume","start","resume","verify"))
    phase=p.parse_args().phase
    if phase.startswith("admit-"):
        _,digest=original_push(phase.removeprefix("admit-"))
        print("AUDIT_ONLY_ORIGINAL_MAIN_PUSH "+digest)
    elif phase=="start":
        start()
    elif phase=="resume":
        resume()
    else:
        original_push("resume")
        _,state=read(os.environ["GH_TOKEN"])
        guard(state["revision"]==2 and state["phase"]=="RECOVERED_ANOTHER_RUN"
              and state["resumedByRunId"]==int(os.environ["GITHUB_RUN_ID"])
              and state["sourceRunId"]!=state["resumedByRunId"]
              and state["completedStages"]==[STAGE]
              and state["publisherAuthorized"] is False,
              "independent recovery check")
        print(json.dumps({"terminal":"NO_UPDATE","readOnly":True,
                          "sourceRunId":state["sourceRunId"],
                          "recoveredByRunId":state["resumedByRunId"],
                          "fencingGeneration":state["lease"]["generation"],
                          "completedStagePreserved":True,
                          "publisherAuthorized":False},sort_keys=True))


if __name__=="__main__":
    main()
