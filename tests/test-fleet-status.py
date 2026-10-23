#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import json
import sys
r=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(r/"scripts"))
spec=importlib.util.spec_from_file_location("fleet_status",r/"scripts/fleet-status.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert m.compact_run(None) is None
a=m.compact_run({"id":2,"html_url":"https://github.com/pgextwin/build/actions/runs/2","status":"completed","conclusion":"failure","head_branch":"auto-candidate/123"})
assert a["conclusion"]=="failure" and a["branch"]=="auto-candidate/123"
state={"generatedAt":"2026-10-09T00:00:00Z","extensions":[{"extension":"test","repository":"pgextwin/test",
"mode":"WATCH","lastWatch":{"conclusion":"failure"},"detectedCandidate":None,
"lastCandidateStatus":"FAILED","lastSuccessfulCandidate":{"packagingCommit":"1"*40}}]}
output=m.render(state)
assert "| test | WATCH | failure |" in output
assert "| FAILED | "+"1"*40+" |" in output
assert "Latest run failures" in output
state["extensions"][0]["repository"]="pgextwin/test"
state["extensions"][0]["candidatePrUrl"]="https://github.com/pgextwin/test/pull/123"
output=m.render(state)
assert "[Review candidate PR](https://github.com/pgextwin/test/pull/123)" in output
assert "No item in this report authorizes merging" in output
state["extensions"][0]["candidatePrUrl"]="https://example.invalid/malicious"
assert "INDETERMINATE (unexpected PR URL)" in m.render(state)

# The update-watch.yml workflow also runs on completed Windows CI.
# A normal skipped workflow_run must never overwrite the true schedule status.
true_scan={"id":101,"event":"schedule","status":"completed","conclusion":"success",
           "head_branch":"main"}
skipped_observer={"id":102,"event":"workflow_run","status":"completed",
                  "conclusion":"skipped","head_branch":"main"}
assert m.scheduled_watch_state([true_scan])[1]=="SUCCESS"
assert m.scheduled_watch_state([])==(None,"UNKNOWN")
assert m.scheduled_watch_state([{**true_scan,"status":"in_progress","conclusion":None}])[1]=="RUNNING"
assert m.scheduled_watch_state([{**true_scan,"conclusion":"failure"}])[1]=="FAILED"
assert m.scheduled_watch_state([{**true_scan,"conclusion":"skipped"}])[1]=="FAILED"
for invalid in ([skipped_observer],[skipped_observer,true_scan],
                [None], "schedule", [{"id":77,"event":"push"}]):
    try:
        m.scheduled_watch_state(invalid)
    except m.WatchError:
        pass
    else:
        raise AssertionError("must deny invalid/mixed observed schedule response")

requests=[]
def fixture_request(url):
    requests.append(url)
    if "/update-watch.yml/runs" in url:
        # The API call itself must use the event=schedule filter. A regression
        # to unfiltered newest-first is denied, never called SUCCESS.
        assert "event=schedule" in url
        return {"workflow_runs":[true_scan]}
    if "/issues?" in url or "/pulls?" in url:
        return []
    if "/windows.yml/runs?" in url:
        return {"workflow_runs":[]}
    raise AssertionError("unexpected network: "+url)

m.request=fixture_request
row=m.one({"repository":"pgextwin/pgtap","mode":"BUILD","scheduleUtc":"0 0 * * *"}, {})
assert row["watchResult"]=="SUCCESS" and row["lastWatch"]["runId"]==101
assert row["lastWatch"]["event"]=="schedule"
assert not row["errors"] and len(requests)==4
# Missing original schedule is explicitly UNKNOWN, not a synthetic success.
def no_schedule(url):
    value=fixture_request(url)
    return {"workflow_runs":[]} if "/update-watch.yml/runs" in url else value
m.request=no_schedule
row=m.one({"repository":"pgextwin/pgtap","mode":"BUILD","scheduleUtc":"0 0 * * *"}, {})
assert row["watchResult"]=="UNKNOWN" and row["lastWatch"] is None
# An API contract violation must not let a skipped workflow_run authorize UPDATE.
def wrong_event(url):
    value=fixture_request(url)
    return {"workflow_runs":[skipped_observer]} if "/update-watch.yml/runs" in url else value
m.request=wrong_event
row=m.one({"repository":"pgextwin/pgtap","mode":"BUILD","scheduleUtc":"0 0 * * *"}, {})
assert row["watchResult"]=="UNKNOWN"
assert any("non-scheduled" in e for e in row["errors"])

print("17-extension original schedule-only hourly status fixtures passed")
