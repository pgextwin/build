#!/usr/bin/env python3
"""Independent finite guard for protected R06 PREPARE original and 17-App CAS.

Triggered by the original push, NOT by a completion event, cron or dispatch.
A bounded observer verifies actual GitHub runs and state. At an authenticated
failure or fixed request deadline, the dedicated build-only State App can
quarantine a pending checkpoint or a separately scoped source-watch checkpoint.
No ambiguous App PUT is repeated; no success/release is manufactured.
"""
from __future__ import annotations
import base64, hashlib, importlib.util, json, os, re, subprocess, sys, time, urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
bridge=load("r06_guard_bridge","scripts/issue311-r05-windows-completion-bridge.py")
contract=load("r06_guard_contract","scripts/issue311-request-contract.py")
store=load("r06_guard_store","scripts/issue311-lifecycle-store.py")
writer=load("r06_guard_writer","scripts/issue311-writer-runtime.py")
life=store.lifecycle
NAME="Issue 311 R06 independent finite original App event watchdog (NONPUBLISHING)"
OUT="issue311-r06-unattended-finite-watchdog.json"
PROOF="issue311-r06-unattended-finite-terminal.json"
READBACK="issue311-r06-unattended-finite-readback.json"
CENTRAL="issue311-r06-prepare-scan.yml"
FLEET="issue311-coordinator-fleet-original.yml"
CAS="issue311-r06-app-fleet-cas-terminal.yml"
SOURCE_NAME="Issue 311 R06 PREPARE original fleet scan (NONPUBLISHING)"
FLEET_NAME="Issue 311 17 authentic App-bot local PREPARE originals (NO RELEASE)"
CAS_NAME="Issue 311 R06 real 17-App original durable CAS terminal (NONPUBLISHING)"
MAX_POLL=400
POLL_SECONDS=8

def require(v,reason):
    if not v:raise ValueError("R06_UNATTENDED_GUARD_DENY "+reason)
def strict(raw):
    return json.loads(raw,object_pairs_hook=store.unique_pairs)
# GET-only, bounded transient read recovery. No App token, no state PUT retry.
# A prolonged provider outage still fails closed and never becomes acceptance.
TRANSIENT_READ_HTTP = frozenset((429, 502, 503, 504))
GET_MAX_ATTEMPTS = 3

def api(endpoint):
    path = "repos/pgextwin/build/" + endpoint
    for attempt in range(GET_MAX_ATTEMPTS):
        try:
            return bridge.get_json(path)
        except urllib.error.HTTPError as exc:
            if exc.code not in TRANSIENT_READ_HTTP or attempt + 1 == GET_MAX_ATTEMPTS:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt + 1 == GET_MAX_ATTEMPTS:
                raise
        time.sleep(min(2**attempt, 2))
    raise AssertionError("bounded GET exhausted")
def stamp(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def current():
    return datetime.now(timezone.utc)

def original(*, stage="observe"):
    require(stage in ("observe","finalize","readback"),"invalid recovery stage")
    require(os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build"
        and os.environ.get("GITHUB_WORKFLOW")==NAME
        and os.environ.get("GITHUB_EVENT_NAME")=="push"
        and os.environ.get("GITHUB_REF")=="refs/heads/main"
        and os.environ.get("GITHUB_ACTOR")=="ShutenOishi"
        and os.environ.get("GITHUB_RUN_ATTEMPT")=="1","not approved original protected push")
    e=strict(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    head=os.environ["GITHUB_SHA"]
    before=e.get("before")
    require(e.get("ref")=="refs/heads/main" and e.get("after")==head
            and e.get("created") is False and e.get("deleted") is False
            and e.get("sender",{}).get("login")=="ShutenOishi"
            and e.get("repository",{}).get("full_name")=="pgextwin/build"
            and re.fullmatch("[0-9a-f]{40}",head or "")
            and re.fullmatch("[0-9a-f]{40}",before or ""),"untrusted original event")
    require(subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()==head,
            "original checkout SHA mismatch")
    changed=subprocess.check_output(["git","diff","--name-status",before,head],
                                     text=True).splitlines()
    require(len(changed)==1 and changed[0].startswith("A\t"),"not exactly one new request")
    path=changed[0][2:]
    match=re.fullmatch(r"\.github/execution-requests/(r-20[0-9]{6}-r06prepare[a-z0-9-]{4,40})\.json",path)
    require(match is not None,"non-PREPARE source or forged path")
    raw=subprocess.check_output(["git","show","HEAD:"+path])
    # Revalidation after the deadline must not retroactively invalidate the
    # original, authenticated push. Bind the declaration to the actual first-
    # attempt GitHub Actions Run created_at, never a request-supplied clock.
    run_id=os.environ.get("GITHUB_RUN_ID","")
    require(re.fullmatch(r"[1-9][0-9]{4,}",run_id or ""),"invalid original guard Run")
    original_run=api("actions/runs/"+run_id)
    require(original_run.get("id")==int(run_id)
            and original_run.get("head_sha")==head
            and original_run.get("name")==NAME
            and original_run.get("path")==".github/workflows/issue311-r06-unattended-finite-guard.yml"
            and original_run.get("event")=="push"
            and original_run.get("head_branch")=="main"
            and original_run.get("run_attempt")==1
            and original_run.get("actor",{}).get("login")=="ShutenOishi",
            "original guard Run provenance mismatch")
    started=contract._timestamp(original_run["created_at"])
    require(started<=current()+timedelta(minutes=5),"future original guard created_at")
    declaration=contract.validate_declaration(raw,path,now=started)
    req=strict(raw)
    expiry=life.parse_utc(req["expiresAt"])
    if stage=="observe":
        require(current()<expiry,"expired original cannot start observing")
    require(req.get("requestId")==match.group(1)
            and declaration["mode"]=="PREPARE"
            and req.get("source",{}).get("centralMainSha")==before
            and req.get("source",{}).get("fleetRegistryBlobSha")=="69918265dabb86b11a9406533cbe0ce495137b94"
            and req.get("approval",{}).get("publicReleaseAuthorized") is False
            and req["approval"]["publicationGrants"]==[]
            and req["limits"]["maxParallel"]<=4
            and req["limits"]["maxAttemptsPerStage"]==1
            and req["limits"]["maxWallClockMinutes"]<=45
            and req.get("allowFutureUpdates") is False
            and len(req.get("targets",[]))==17
            and len(set(x["repo"] for x in req["targets"]))==17,
            "unbounded or privileged original PREPARE")
    remote=api("contents/"+path+"?ref="+head)
    require(remote.get("encoding")=="base64"
            and base64.b64decode(remote["content"].replace("\n","").replace("\r",""),
                                 validate=True)==raw
            and store.blob_hash(raw)==remote["sha"],"original request Git bytes altered")
    branch=api("branches/main")
    require(branch.get("protected") is True,"main protection missing")
    # Original first-parent protected merge remains authentic even if another
    # unrelated protected main commit happens during the bounded watch window.
    commit=api("commits/"+head)
    require(len(commit.get("parents",[]))==1
            and commit["parents"][0]["sha"]==before
            and [(f.get("status"),f.get("filename")) for f in commit.get("files",[])]
                ==[("added",path)],"untrusted original main commit")
    merged=api("commits/"+head+"/pulls?per_page=100")
    chosen=[x for x in merged if x.get("merged_at") is not None
            and x.get("merge_commit_sha")==head
            and x.get("base",{}).get("ref")=="main"]
    require(len(chosen)==1 and chosen[0].get("user",{}).get("login")=="ShutenOishi",
            "protected PR origin missing")
    cutoff=min(life.parse_utc(req["expiresAt"]),
               contract._timestamp(req["createdAt"])+timedelta(minutes=req["limits"]["maxWallClockMinutes"]))
    require(cutoff>contract._timestamp(req["createdAt"]),"invalid finite deadline")
    if stage!="observe":
        # Keep the finite recovery path open for the separate no-key readback
        # but never allow unbounded historical re-entry on an old original.
        require(current()<=cutoff+timedelta(minutes=20),
                "finite recovery/readback grace exceeded")
    # Checkpoint identity MUST bind original request bytes and original protected HEAD.
    return {"headSha":head,"requestId":req["requestId"],"requestSha256":hashlib.sha256(raw).hexdigest(),
            "targets":sorted(x["repo"] for x in req["targets"]),
            "deadlineAt":stamp(cutoff),"createdAt":req["createdAt"],
            "watchId":"r-"+req["requestId"][2:10]+"-r06watch"+head[:16]}

def candidates(filename,name,event,head):
    response=api("actions/workflows/"+filename+"/runs?head_sha="+head+"&per_page=100")
    rows=response.get("workflow_runs",[])
    require(response.get("total_count")==len(rows) and len(rows)<=100,
            "truncated / ambiguous original workflow list")
    found=[r for r in rows if r.get("head_sha")==head
           and r.get("name")==name and r.get("path")==".github/workflows/"+filename
           and r.get("event")==event and r.get("head_branch")=="main"
           and r.get("run_attempt")==1
           and r.get("actor",{}).get("login")=="ShutenOishi"]
    require(len(found)<=1,"duplicate first-attempt originals")
    if not found:return None
    live=api("actions/runs/"+str(found[0]["id"]))
    require(live.get("id")==found[0]["id"] and
            all(live.get(k)==found[0].get(k) for k in
                ("head_sha","event","path","name","run_attempt","status","conclusion")),
            "workflow list/GET authentication disagreement")
    return live

def contents_state(request_id):
    try:
        data=api("contents/"+store.PREFIX+request_id+".json?ref="+store.BRANCH)
    except urllib.error.HTTPError as ex:
        if ex.code==404:return None
        raise
    return store.unpack(data,request_id)

def snapshot(origin):
    sha=origin["headSha"]
    central=candidates(CENTRAL,SOURCE_NAME,"push",sha)
    fleet=candidates(FLEET,FLEET_NAME,"workflow_run",sha)
    cas=candidates(CAS,CAS_NAME,"workflow_run",sha)
    source_state_id=("r-"+origin["requestId"][2:10]+"-r06appauto"+str(fleet["id"])) if fleet else None
    checkpoint=contents_state(source_state_id) if source_state_id else None
    # An earlier independent finite quarantine is an immutable veto even if a
    # delayed event later creates a separate coordinator/CAS success report.
    watchdog=contents_state(origin["watchId"])
    watch_quarantined=bool(watchdog and watchdog[1]["terminal"] in ("FAILED","QUARANTINED"))
    # Success is only observed when the *separate* genuine keyless readback
    # succeeded and its actual immutable state is completed, not from event flags.
    good=False
    if cas and cas.get("status")=="completed" and cas.get("conclusion")=="success" and checkpoint:
        blob,state=checkpoint
        jobs=api("actions/runs/"+str(cas["id"])+"/jobs?per_page=100")
        row=[x for x in jobs.get("jobs",[]) if
             x.get("name")=="Separate read-only Git original CAS state, source-kind and replay DENY"]
        good=(len(row)==1 and row[0].get("conclusion")=="success"
              and state.get("revision")==2 and state.get("terminal")=="NO_UPDATE"
              and state.get("completionRun")=={"id":cas["id"],"attempt":1}
              and state.get("sourceRun")=={"id":fleet["id"],"attempt":1}
              and state.get("sourceHeadSha")==sha
              and len(state.get("targets",{}))==17
              and set(state["targets"].values())=={"SUCCESS"}
              and state.get("publisherAuthorized") is False
              and state.get("writeOutcomeUnknown") is False)
    if good and watch_quarantined:
        require(False,"conflicting durable watchdog quarantine vs late CAS success")
    failed=any(x and x.get("status")=="completed"
               and x.get("conclusion") not in ("success",)
               for x in (central,fleet,cas))
    return {"central":central,"fleet":fleet,"cas":cas,
            "stateId":source_state_id,"checkpoint":checkpoint,
            "healthy":good,"authoritativeFailure":failed,
            "watchdog":watchdog}

def observation(origin, snap, result):
    return {"schemaVersion":1,"requestId":origin["requestId"],
            "sourceHeadSha":origin["headSha"],"deadlineAt":origin["deadlineAt"],
            "result":result,"publisherAuthorized":False,
            "centralRunId":snap["central"]["id"] if snap.get("central") else None,
            "fleetRunId":snap["fleet"]["id"] if snap.get("fleet") else None,
            "casRunId":snap["cas"]["id"] if snap.get("cas") else None,
            "stateId":snap.get("stateId"),"appKeyAvailable":False}

def observe():
    report={"result":"UNKNOWN","publisherAuthorized":False}
    try:
        origin=original()
        end=life.parse_utc(origin["deadlineAt"])
        for _ in range(MAX_POLL):
            try:
                s=snapshot(origin)
                if s["healthy"]:
                    report=observation(origin,s,"ORIGINAL_ALREADY_DURABLE_SUCCESS")
                    break
                if s["authoritativeFailure"]:
                    report=observation(origin,s,"NEEDS_FAIL_CLOSED_TERMINAL")
                    break
            except Exception as ex:
                report={"result":"OBSERVATION_UNKNOWN","reason":str(ex)[:180],
                        "requestId":origin["requestId"],"publisherAuthorized":False}
            if current()>=end:
                report=observation(origin,{"central":None,"fleet":None,"cas":None},"NEEDS_FAIL_CLOSED_TERMINAL")
                break
            time.sleep(min(POLL_SECONDS,max(0,(end-current()).total_seconds())))
        else:
            report={"result":"OBSERVATION_UNKNOWN","requestId":origin["requestId"],
                    "reason":"finite bounded poll budget exhausted","publisherAuthorized":False}
    except Exception as exc:
        report["reason"]=str(exc)[:300]
    Path(OUT).write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print("R06_AUTONOMOUS_FINITE_OBSERVER",json.dumps(report,sort_keys=True))
    return 0 if report["result"] in ("ORIGINAL_ALREADY_DURABLE_SUCCESS","NEEDS_FAIL_CLOSED_TERMINAL") else 1

def pending_terminal(state, origin, identifier, run_id):
    life.validate(state)
    require(state["requestId"]==identifier and state["sourceHeadSha"]==origin["headSha"]
            and state["targetScope"]==origin["targets"]
            and state["publisherAuthorized"] is False
            and state["writeOutcomeUnknown"] is False
            and state["terminal"] is None and state["revision"] in (0,1),
            "stale/cross-request/privileged or already terminal state")
    def close(s):
        s["targets"]={r:"QUARANTINED" for r in s["targetScope"]}
        s["terminal"]="QUARANTINED"
        s["eventTransport"]="BOUNDED_WATCHDOG"
        s["completionRun"]={"id":run_id,"attempt":1}
    return life._apply(state,state["revision"],"r06_unattended_finite_quarantine",
                       {"request":origin["requestId"],"deadline":origin["deadlineAt"],
                        "source":"independent_original_push_guard",
                        "status":"NO_SUCCESS_CLAIM"},close)

def verify_existing_fail_closed(state, origin):
    """Never accept a durable terminal belonging to another protected original."""
    life.validate(state)
    require(state["sourceHeadSha"]==origin["headSha"]
            and state["targetScope"]==origin["targets"]
            and set(state["targets"])==set(origin["targets"])
            and state["terminal"] in ("FAILED","QUARANTINED")
            and all(v in life.TERMINALS for v in state["targets"].values())
            and state["publisherAuthorized"] is False
            and state["writeOutcomeUnknown"] is False,
            "cross-original or privileged existing terminal denied")

def finalize():
    report={"result":"QUARANTINED","publisherAuthorized":False}
    token=None
    try:
        recorded=strict(Path(OUT).read_bytes())
        origin=original(stage="finalize")
        require(recorded["requestId"]==origin["requestId"]
                and recorded["sourceHeadSha"]==origin["headSha"]
                and recorded["publisherAuthorized"] is False,
                "observer original identity mismatch")
        snap=snapshot(origin)
        if snap["healthy"]:
            report={"result":"ORIGINAL_ALREADY_DURABLE_SUCCESS","requestId":origin["requestId"],
                    "publisherAuthorized":False,"stateId":snap["stateId"]}
        else:
            require(snap["authoritativeFailure"] or current()>=life.parse_utc(origin["deadlineAt"]),
                    "not failed/expired; cannot terminalize a running source")
            # A coordinator source checkpoint can already exist at rev0/1.
            # Quarantine it rather than creating an unrelated success record.
            # Prefer the coordinator checkpoint identity even when absent: a
            # late workflow_run then cannot create a second success checkpoint.
            identifier=(origin["watchId"] if snap["watchdog"] else
                        snap["stateId"] or origin["watchId"])
            existing=(snap["watchdog"] if snap["watchdog"] else
                      snap["checkpoint"] if snap["checkpoint"] else contents_state(identifier))
            token=writer.mint_token(os.environ.get("STATE_WRITER_PRIVATE_KEY",""))
            cas=store.CAS(lambda method,endpoint,body:writer.api(method,endpoint,token,body))
            if existing is None:
                fresh=life.new(identifier,origin["requestSha256"],origin["headSha"],
                               origin["targets"],origin["deadlineAt"],max_events=100)
                bound=(life.bind_source(fresh,0,"r06_watch_original_source",
                        run_id=(snap["fleet"]["id"] if snap["stateId"] else snap["central"]["id"]),
                        attempt=1,head_sha=origin["headSha"])
                        if (snap["fleet"] if snap["stateId"] else snap["central"]) else fresh)
                # No fake source or event: record a separately identified finite
                # observer checkpoint when no authenticated App source exists.
                saved=cas.write(fresh)
                live_blob,live_state=cas.read(identifier)
                require(live_state==fresh,"initial observer state mismatch")
                if snap["central"]:
                    cas.write(bound,previous=fresh,expected_blob=live_blob)
                existing=cas.read(identifier)
            old_blob,old_state=existing
            if old_state["terminal"] is not None:
                # A NO_UPDATE terminal can only be accepted through the
                # separate authenticated normal-success readback above.
                verify_existing_fail_closed(old_state,origin)
                report={"result":"ALREADY_DURABLE_TERMINAL","stateId":identifier,
                        "stateBlobSha":old_blob,"revision":old_state["revision"],
                        "requestId":origin["requestId"],"publisherAuthorized":False}
            else:
                term=pending_terminal(old_state,origin,identifier,int(os.environ["GITHUB_RUN_ID"]))
                save=cas.write(term,previous=old_state,expected_blob=old_blob)
                final_blob,confirmed=cas.read(identifier)
                require(confirmed==term and final_blob==store.blob_hash(store.canonical(term)),
                        "uncertain App PUT, no retry")
                report={"schemaVersion":1,"requestId":origin["requestId"],
                        "result":"QUARANTINED_DURABLE_READBACK_PENDING",
                        "stateId":identifier,"stateBlobSha":final_blob,
                        "revision":term["revision"],"targetCount":17,
                        "completionRunId":int(os.environ["GITHUB_RUN_ID"]),
                        "sourceHeadSha":origin["headSha"],
                        "writeOutcome":save,"publisherAuthorized":False}
    except Exception as ex:
        report["reason"]=str(ex)[:350]
    finally:
        if token:
            try:
                writer.revoke_and_prove_401(token)
                report["sameTokenRevoked401"]=True
            except Exception as ex:
                report["result"]="QUARANTINED"
                report["revocationError"]=type(ex).__name__
        Path(PROOF).write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print("R06_AUTONOMOUS_FINITE_TERMINAL",json.dumps(report,sort_keys=True))
    return 0 if report["result"] in ("ORIGINAL_ALREADY_DURABLE_SUCCESS","ALREADY_DURABLE_TERMINAL") or (
        report["result"]=="QUARANTINED_DURABLE_READBACK_PENDING"
        and report.get("sameTokenRevoked401") is True) else 1

def readback():
    require(not os.environ.get("STATE_WRITER_PRIVATE_KEY"),"reader has App key")
    origin=original(stage="readback")
    listing=api("actions/runs/"+os.environ["GITHUB_RUN_ID"]+"/artifacts?per_page=100")
    choices=[x for x in listing.get("artifacts",[]) if x.get("name")=="issue311-r06-unattended-finite-terminal"]
    require(len(choices)==1 and choices[0].get("expired") is False,"original proof ZIP absent")
    proof,digest=bridge.original_zip(choices[0],PROOF)
    require(digest==choices[0]["digest"].removeprefix("sha256:")
            and proof.get("requestId")==origin["requestId"]
            and proof.get("publisherAuthorized") is False,"original terminal proof mismatch")
    if proof["result"]=="QUARANTINED_DURABLE_READBACK_PENDING":
        require(proof.get("sameTokenRevoked401") is True,"App token not revoked")
        blob,state=store.unpack(api("contents/"+store.PREFIX+proof["stateId"]+".json?ref="+store.BRANCH),
                                proof["stateId"])
        verify_existing_fail_closed(state,origin)
        require(blob==proof["stateBlobSha"] and
                state["revision"]==proof["revision"] and
                state["terminal"]=="QUARANTINED"
                and state["eventTransport"]=="BOUNDED_WATCHDOG"
                and state["completionRun"]=={"id":int(os.environ["GITHUB_RUN_ID"]),"attempt":1}
                and len(state["targets"])==17
                and set(state["targets"].values())=={"QUARANTINED"}
                and state["publisherAuthorized"] is False,
                "independent finite terminal state mismatch")
        try:life._apply(state,state["revision"],"replay",{"op":"replay"},lambda s:s.update(terminal=None))
        except ValueError:pass
        else:raise AssertionError("terminal replay accepted")
    else:
        require(proof["result"] in ("ORIGINAL_ALREADY_DURABLE_SUCCESS","ALREADY_DURABLE_TERMINAL"),
                "not an authenticated no-write result")
        # Keyless proof is required even for an idempotent no-write result.
        snap=snapshot(origin)
        if proof["result"]=="ORIGINAL_ALREADY_DURABLE_SUCCESS":
            require(snap["healthy"] is True and snap["stateId"]==proof["stateId"],
                    "unverified claimed original success")
        else:
            blob,state=store.unpack(api("contents/"+store.PREFIX+proof["stateId"]+".json?ref="+store.BRANCH),proof["stateId"])
            verify_existing_fail_closed(state,origin)
            require(blob==proof["stateBlobSha"] and state["revision"]==proof["revision"],
                    "unverified existing fail-closed terminal")
    out={"requestId":origin["requestId"],"result":proof["result"],
         "stateId":proof.get("stateId"),"appKeyAvailable":False,
         "publicationAuthorized":False,"independentReadback":True}
    Path(READBACK).write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
    return 0

if __name__=="__main__":
    require(sys.argv[1:] in (["observe"],["finalize"],["readback"]),"unapproved command")
    raise SystemExit({"observe":observe,"finalize":finalize,"readback":readback}[sys.argv[1]]())
