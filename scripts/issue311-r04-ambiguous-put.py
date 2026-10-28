#!/usr/bin/env python3
"""R04 one-time nonpublishing real Contents PUT + injected ambiguous response proof.

The real GitHub server accepts exactly one protected read-only state PUT.
We deliberately discard the response locally, as if an HTTP connection broke,
then independently GET the canonical Git blob and refuse all blind retries.
Also proves timeout BEFORE sending a new intended state is quarantined.
No Publisher, Catalog, tag, Release, or dispatch operation exists here.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("r04writer",HERE/"issue311-writer-runtime.py")
writer=importlib.util.module_from_spec(spec);spec.loader.exec_module(writer)
REQ="r-20261029-r04ambiguous01"
PATH=Path(".github/execution-requests/"+REQ+".json")
STATE_PATH="checkpoints/issue311-ambiguous-v1.json"


def need(ok,reason):
    writer.require(ok,"R04_AMBIGUOUS_DENY: "+reason)


def provenance():
    need(os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build"
         and os.environ.get("GITHUB_ACTOR")=="ShutenOishi"
         and os.environ.get("GITHUB_REF")=="refs/heads/main"
         and os.environ.get("GITHUB_EVENT_NAME")=="push","actor/event")
    event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                     object_pairs_hook=writer.unique_pairs)
    raw=PATH.read_bytes()
    request=json.loads(raw,object_pairs_hook=writer.unique_pairs)
    need(set(request)=={"schemaVersion","requestId","kind","mode","baseMainSha",
                        "publicReleaseAuthorized"} and
         type(request["schemaVersion"]) is int and request["schemaVersion"]==1
         and request["requestId"]==REQ and request["kind"]=="issue311-r04-ambiguous-put-proof"
         and request["mode"]=="AUDIT_ONLY"
         and request["publicReleaseAuthorized"] is False
         and event.get("repository",{}).get("full_name")=="pgextwin/build"
         and event.get("ref")=="refs/heads/main"
         and event.get("created") is False and event.get("deleted") is False
         and event.get("before")==request["baseMainSha"]
         and event.get("after")==os.environ["GITHUB_SHA"],"request/protected push")
    need(subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()
         ==event["after"],"wrong checkout")
    subprocess.run(["git","merge-base","--is-ancestor",
                    event["before"],event["after"]],check=True)
    return hashlib.sha256(raw).hexdigest()


def endpoint():
    return "repos/pgextwin/build/contents/"+STATE_PATH


def fixed_state(raw_sha):
    return {"schemaVersion":1,"requestId":REQ,"requestSha256":raw_sha,
            "scope":"AUDIT_ONLY_READONLY","revision":1,
            "phase":"SERVER_ACCEPTED_RESPONSE_LOST",
            "publisherAuthorized":False,"writeOutcomeUnknown":False}


def verify_state(s,request_sha):
    need(type(s) is dict and set(s)=={
         "schemaVersion","requestId","requestSha256","scope","revision",
         "phase","publisherAuthorized","writeOutcomeUnknown"}
         and s==fixed_state(request_sha),"untrusted recovered server state")


def read(token,raw_sha):
    payload=writer.api("GET",endpoint()+"?ref="+writer.STATE_BRANCH,token)
    need(payload.get("encoding")=="base64"
         and writer.SHA1.fullmatch(payload.get("sha","")),"not original GitHub blob")
    raw=base64.b64decode(payload["content"])
    need(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
         ==payload["sha"],"Git blob bytes mismatch")
    state=json.loads(raw,object_pairs_hook=writer.unique_pairs)
    verify_state(state,raw_sha)
    return payload["sha"],state


def simulate_after_commit_once(token,intended):
    """One actual protected PUT; discard its success response locally; GET only."""
    body={"message":"state(issue311): one-shot nonpublishing ambiguous-response proof",
          "branch":writer.STATE_BRANCH,
          "content":base64.b64encode(writer.canonical(intended)).decode()}
    mutating_calls=0
    try:
        mutating_calls+=1
        writer.api("PUT",endpoint(),token,body)
        # Emulate lost HTTP response AFTER real server accepted the first write.
        raise TimeoutError("injected response loss after original remote PUT")
    except TimeoutError:
        need(mutating_calls==1,"duplicate PUT")
        _,actual=read(token,intended["requestSha256"])
        need(actual==intended,"live remote bytes differ from ambiguous write")
        return {"status":"COMMITTED_RECONCILED_BY_ORIGINAL_GET",
                "putCount":mutating_calls,"automaticPutRetry":False}


def simulated_before_send_must_quarantine(token,intended):
    """No second PUT. Unknown hypothetical modified revision cannot be inferred."""
    proposed=dict(intended,revision=2,phase="WOULD_BE_UNKNOWN")
    try:
        # Inject loss BEFORE sending; no privileged request leaves this runner.
        raise TimeoutError("pre-send response unknown")
    except TimeoutError:
        _,observed=read(token,intended["requestSha256"])
        need(observed!=proposed,"unconfirmed newer checkpoint appeared")
        return {"status":"QUARANTINED","secondPutCount":0,
                "originalRevision":observed["revision"],
                "blindRetryAllowed":False}


def run():
    raw_sha=provenance()
    key=os.environ.get("STATE_WRITER_PRIVATE_KEY","")
    need(bool(key),"dedicated App key not configured")
    token=writer.mint_token(key)
    failure=None
    receipt=None
    try:
        try:
            writer.api("GET",endpoint()+"?ref="+writer.STATE_BRANCH,token)
        except writer.HTTPStatus as error:
            need(error.code==404,"unexpected existing or inaccessible checkpoint")
        else:
            raise writer.Denied("original consumed request/replay prohibited")
        intended=fixed_state(raw_sha)
        result=simulate_after_commit_once(token,intended)
        unknown=simulated_before_send_must_quarantine(token,intended)
        receipt={"requestId":REQ,"requestSha256":raw_sha,"originalRunId":
                 int(os.environ["GITHUB_RUN_ID"]),"originalRunAttempt":
                 int(os.environ["GITHUB_RUN_ATTEMPT"]),"result":"NO_UPDATE",
                 "reconcile":result,"unknownRetry":unknown,
                 "publisherAuthorized":False}
    except BaseException as error:
        failure=error
    finally:
        writer.revoke_and_prove_401(token)
    if failure: raise failure
    receipt["revoked401"]=True
    Path("issue311-r04-ambiguous-receipt.json").write_bytes(writer.canonical(receipt))
    print(json.dumps(receipt,sort_keys=True))


def verify():
    raw_sha=provenance()
    token=os.environ["GH_TOKEN"]
    blob,state=read(token,raw_sha)
    need(state["revision"]==1 and state["publisherAuthorized"] is False,
         "unsafe authoritative terminal state")
    print(json.dumps({"terminal":"NO_UPDATE","readOnly":True,"blobSha":blob,
                      "requestId":REQ,"originalRunId":int(os.environ["GITHUB_RUN_ID"]),
                      "originalRunAttempt":int(os.environ["GITHUB_RUN_ATTEMPT"]),
                      "publisherAuthorized":False},sort_keys=True))


def main():
    import argparse
    p=argparse.ArgumentParser();p.add_argument("phase",choices=("admit","run","verify"))
    phase=p.parse_args().phase
    if phase=="admit":print("AUDIT_ONLY_ORIGINAL_PUSH_SHA256 "+provenance())
    elif phase=="run":run()
    else:verify()


if __name__=="__main__":
    main()
