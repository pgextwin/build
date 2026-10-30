#!/usr/bin/env python3
"""Fail-closed late-event, original request deadline and ambiguous App PUT regression.

Offline tests only; no forged schedule, no actual App credential or claims of live
missing-event/timeout acceptance. An independent real original is required later.
"""
from __future__ import annotations
import base64, importlib.util, json, os, urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);return v
guard=load("late_guard","scripts/issue311-r06-unattended-finite-guard.py")
cas=load("late_cas","scripts/issue311-r06-app-fleet-cas-terminal.py")
store=cas.store
life=store.lifecycle
targets=["pgextwin/"+x for x in ("pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user",
        "pg_repack","pg_ivm","pg_qualstats","plpgsql_check","orafce",
        "hypopg","wal2json","pg_partman","pg_stat_monitor","pgtap",
        "pg_variables","pg_store_plans")]
head="a"*40
central_id="r-20261030-r06preparecanarylate01"
watch_id="r-20261030-r06watch"+head[:16]
source={"centralRequestId":central_id,"sourceHeadSha":head}
clock=datetime.now(timezone.utc).replace(microsecond=0)
stamp=lambda t:t.strftime("%Y-%m-%dT%H:%M:%SZ")
request={"requestId":central_id,"mode":"PREPARE","createdAt":stamp(clock-timedelta(minutes=2)),
         "expiresAt":stamp(clock+timedelta(hours=1)),
         "allowFutureUpdates":False,"approval":{"publicReleaseAuthorized":False,"publicationGrants":[]},
         "limits":{"maxAttemptsPerStage":1,"maxWallClockMinutes":30},
         "targets":[{"repo":x} for x in targets]}
def git_contents(value):
    raw=(json.dumps(value,sort_keys=True)+"\n").encode()
    encoded=base64.b64encode(raw).decode("ascii")
    return {"sha":store.blob_hash(raw),"encoding":"base64",
            "content":encoded[:70]+"\n"+encoded[70:]}
source_payload=git_contents(request)
def not_found():
    raise urllib.error.HTTPError("https://api.github.com",404,"not found",None,None)
def absent_get(endpoint):
    if "/execution-requests/" in endpoint:return source_payload
    if "request-lifecycle" in endpoint:return not_found()
    raise AssertionError("unexpected original URL "+endpoint)
with patch.dict(os.environ,{"GITHUB_EVENT_NAME":"workflow_run"}),patch.object(cas.bridge,"get_json",side_effect=absent_get):
    cas.finite_original_veto(source)
# Authenticate old original QUARANTINED state; deny a late success regardless of
# freshly delivered GitHub workflow_run.complete event.
base=life.new(watch_id,"b"*64,head,sorted(targets),stamp(clock+timedelta(hours=1)))
def terminal(state):
    state["targets"]={t:"QUARANTINED" for t in state["targetScope"]}
    state["terminal"]="QUARANTINED"
    state["eventTransport"]="BOUNDED_WATCHDOG"
    state["completionRun"]={"id":41009023539,"attempt":1}
tombstone=life._apply(base,0,"original_finite_watch",{"reason":"deadline"},terminal)
bytes_state=store.canonical(tombstone)
watch_payload={"encoding":"base64","sha":store.blob_hash(bytes_state),
               "content":base64.b64encode(bytes_state).decode("ascii")}
def guarded_get(endpoint):
    if "/execution-requests/" in endpoint:return source_payload
    if "request-lifecycle" in endpoint:return watch_payload
    raise AssertionError("unexpected original URL "+endpoint)
with patch.dict(os.environ,{"GITHUB_EVENT_NAME":"workflow_run"}),patch.object(cas.bridge,"get_json",side_effect=guarded_get):
    try:cas.finite_original_veto(source)
    except ValueError as e:assert "watchdog" in str(e)
    else:raise AssertionError("late completion accepted over durable QUARANTINED")
old=dict(request,createdAt=stamp(clock-timedelta(hours=3)),
         expiresAt=stamp(clock+timedelta(minutes=5)))
with patch.dict(os.environ,{"GITHUB_EVENT_NAME":"workflow_run"}),patch.object(cas.bridge,"get_json",side_effect=lambda endpoint:git_contents(old)):
    try:cas.finite_original_veto(source)
    except ValueError as e:assert "deadline expired" in str(e)
    else:raise AssertionError("expired original accepted")
corrupt=dict(source_payload,sha="0"*40)
with patch.dict(os.environ,{"GITHUB_EVENT_NAME":"workflow_run"}),patch.object(cas.bridge,"get_json",side_effect=lambda endpoint:corrupt):
    try:cas.finite_original_veto(source)
    except ValueError as e:assert "Git blob" in str(e)
    else:raise AssertionError("modified original Git bytes accepted")
# Both outcomes of a lost PUT response require a single PUT, never blind retry.
request_id="r-20261030-r06ambiguouscaslatetest01"
proposed=life.new(request_id,"b"*64,head,sorted(targets),stamp(clock+timedelta(hours=1)))
def run_ambiguous(matched):
    called={"put":0}
    original=None
    def fake(method,endpoint,payload):
        nonlocal_dummy=0
        if method=="PUT":
            called["put"]+=1
            if matched:
                called["saved"]=base64.b64decode(payload["content"])
            else:
                called["saved"]=b"unconfirmed or different committed bytes"
            raise RuntimeError("lost HTTP PUT response")
        if method=="GET":
            raw=called.get("saved")
            if raw is None:raise AssertionError("unexpected read before PUT")
            return {"sha":store.blob_hash(raw),"encoding":"base64",
                    "content":base64.b64encode(raw).decode("ascii")}
        raise AssertionError(method)
    store_cas=store.CAS(fake)
    if matched:
        assert store_cas.write(proposed)=="RECONCILED_BY_ORIGINAL_GET"
    else:
        try:store_cas.write(proposed)
        except store.UnknownWrite:pass
        else:raise AssertionError("ambiguous divergent write falsely accepted")
    assert called["put"]==1,"an ambiguous PUT was retried"
run_ambiguous(True)
run_ambiguous(False)
# Fail-closed state terminal is immutable even when the completion is late.
try:life._apply(tombstone,tombstone["revision"],"late_completed",
                {"source":41009052889},lambda state:state.update(terminal="NO_UPDATE"))
except ValueError:pass
else:raise AssertionError("replay changed terminal to NO_UPDATE")
# An already-finalized old NO_UPDATE is not a valid watchdog terminal witness.
assert '"unverified competing successful terminal denied"' in (ROOT/"scripts/issue311-r06-unattended-finite-guard.py").read_text()
assert "identifier=snap[\"stateId\"] or origin[\"watchId\"]" not in (ROOT/"scripts/issue311-r06-unattended-finite-guard.py").read_text()
print("R06_LATE_EVENT_TOMBSTONE_AMBIGUOUS_PUT_OFFLINE_NEGATIVES_PASS")
