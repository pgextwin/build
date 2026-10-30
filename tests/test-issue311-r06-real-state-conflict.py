#!/usr/bin/env python3
"""Offline policy for a one-shot authentic GitHub State App stale-SHA negative.

Real provider 409 and immutable original ZIP are required later; this mock
only proves no mutation/retry on a stale revision and publication DENY.
"""
import base64, importlib.util, json, os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("r06_conflict",
    ROOT/"scripts/issue311-r06-app-fleet-cas-terminal.py")
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
assert mod.CONFLICT_CANARY=="r-20261030-r06prepareappcasconflict11"
targets=["pgextwin/test"+str(i) for i in range(17)]
rid="r-20261030-r06appauto41011122233"
mod.REQ=rid
head="b"*40
expires=(datetime.now(timezone.utc)+timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
record={}
metrics={"putCalls":0,"lostAcks":0}
calls=[]
def server(method,endpoint,body):
    calls.append(method)
    if method=="GET":
        if not record:raise mod.writer.HTTPStatus(404)
        return {"encoding":"base64","sha":record["sha"],
                "content":base64.b64encode(record["raw"]).decode()}
    assert method=="PUT" and type(body)==dict
    old=record.get("sha")
    if old is not None and body.get("sha")!=old:
        metrics["httpConflictCode"]=409
        raise mod.writer.HTTPStatus(409)
    if old is None:assert "sha" not in body
    raw=base64.b64decode(body["content"])
    record["raw"]=raw
    record["sha"]=mod.store.blob_hash(raw)
    metrics["putCalls"]+=1
    return {"content":{"sha":record["sha"]}}
created=mod.store.CAS(server)
fresh=mod.life.new(rid,"c"*64,head,targets,expires,max_events=100)
assert created.write(fresh)=="ORIGINAL_GET_VERIFIED"
blob,current=created.read(rid)
bound=mod.life.bind_source(current,0,"original-17-App",run_id=41014731356,
                           attempt=1,head_sha=head)
created.write(bound,previous=current,expected_blob=blob)
blob,current=created.read(rid)
def success(state):
    state["targets"]={n:"SUCCESS" for n in state["targetScope"]}
    state["terminal"]="NO_UPDATE"
    state["eventTransport"]="workflow_run.completed"
    state["completionRun"]={"id":41014995197,"attempt":1}
intended=mod.life._apply(current,1,"original-normal-success",
                         {"sourceRun":41014731356},success)
with patch.dict(os.environ,{"GITHUB_RUN_ID":"41014995197"}):
    outcome=mod.controlled_competing_state_terminal(
         created,current,blob,intended,metrics,41014731356)
assert outcome["result"]=="QUARANTINED_VERIFIED_STALE_SHA_CONFLICT"
assert outcome["actualGitHubHttpConflictCode"]==409
assert outcome["actualStalePutNotRetried"] is True
assert metrics["putCalls"]==3 and calls.count("PUT")==4, "one real conflicting PUT only"
a,b=created.read(rid)
assert a==outcome["stateBlobSha"] and b["revision"]==2
assert b["terminal"]=="QUARANTINED" and set(b["targets"].values())=={"QUARANTINED"}
assert b["publisherAuthorized"] is False and b["writeOutcomeUnknown"] is False
try:
    mod.life._apply(b,2,"replay",{"op":"replay"},lambda s:s.update(terminal=None))
except ValueError:pass
else:raise AssertionError("terminal replay accepted")
print("R06_ONE_SHOT_REAL_PROVIDER_STALE_SHA_CONFLICT_NEGATIVE_OFFLINE_CONTRACT_PASS")
