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
           "head_branch":"main","head_sha":"1"*40,"run_attempt":1}
skipped_observer={"id":102,"event":"workflow_run","status":"completed",
                  "conclusion":"skipped","head_branch":"main"}
assert m.scheduled_watch_state([true_scan])[1]=="SUCCESS"
protected={"protected":True,"commit":{"sha":"1"*40}}
assert m.current_main_schedule_state(true_scan,"SUCCESS",protected)==(
    "CURRENT_MAIN_SCHEDULE_SUCCESS","1"*40)
assert m.current_main_schedule_state(None,"UNKNOWN",protected)[0]=="NOT_YET_OBSERVED"
assert m.current_main_schedule_state(true_scan,"SUCCESS",{
    "protected":True,"commit":{"sha":"2"*40}})[0]=="PREVIOUS_MAIN_ONLY"
assert m.current_main_schedule_state({**true_scan,"conclusion":"failure"},"FAILED",protected)[0]==(
    "CURRENT_MAIN_SCHEDULE_FAILED")
assert m.current_main_schedule_state({**true_scan,"status":"in_progress"},
                                     "RUNNING",protected)[0]=="CURRENT_MAIN_SCHEDULE_RUNNING"
assert m.current_main_schedule_state({**true_scan,"run_attempt":2},"SUCCESS",
                                     protected)[0]=="UNVERIFIED_ATTEMPT"
for invalid_run,invalid_branch in (
    (true_scan,{"protected":False,"commit":{"sha":"1"*40}}),
    (true_scan,{"protected":True,"commit":{"sha":"malformed"}}),
    ({**true_scan,"event":"workflow_dispatch"},protected),
    ({**true_scan,"head_branch":"other"},protected)):
    try:
        m.current_main_schedule_state(invalid_run,"SUCCESS",invalid_branch)
    except m.WatchError:
        pass
    else:
        raise AssertionError("must deny forged current protected main or schedule")

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
    if url.endswith("/branches/main"):
        return protected
    if "/issues?" in url or "/pulls?" in url:
        return []
    if "/windows.yml/runs?" in url:
        return {"workflow_runs":[]}
    raise AssertionError("unexpected network: "+url)

m.request=fixture_request
row=m.one({"repository":"pgextwin/pgtap","mode":"BUILD","scheduleUtc":"0 0 * * *"}, {})
assert row["watchResult"]=="SUCCESS" and row["lastWatch"]["runId"]==101
assert row["lastWatch"]["event"]=="schedule"
assert row["currentMainScheduleStatus"]=="CURRENT_MAIN_SCHEDULE_SUCCESS"
assert row["currentProtectedMainSha"]=="1"*40
assert not row["errors"] and len(requests)==5
# Missing original schedule is explicitly UNKNOWN, not a synthetic success.
def no_schedule(url):
    value=fixture_request(url)
    return {"workflow_runs":[]} if "/update-watch.yml/runs" in url else value
m.request=no_schedule
row=m.one({"repository":"pgextwin/pgtap","mode":"BUILD","scheduleUtc":"0 0 * * *"}, {})
assert row["watchResult"]=="UNKNOWN" and row["lastWatch"] is None
assert row["currentMainScheduleStatus"]=="NOT_YET_OBSERVED"
# An API contract violation must not let a skipped workflow_run authorize UPDATE.
def wrong_event(url):
    value=fixture_request(url)
    return {"workflow_runs":[skipped_observer]} if "/update-watch.yml/runs" in url else value
m.request=wrong_event
row=m.one({"repository":"pgextwin/pgtap","mode":"BUILD","scheduleUtc":"0 0 * * *"}, {})
assert row["watchResult"]=="UNKNOWN"
assert any("non-scheduled" in e for e in row["errors"])


# Issue #75: the new native PR CI must outrank historic Dispatch CI. Its root
# success is observational, NEVER independent App15368 or Publisher admission.
candidate_branch="auto-candidate/"+"a"*20
candidate_pr={
    "head":{"ref":candidate_branch,"sha":"3"*40,
            "repo":{"full_name":"pgextwin/pgtap"}},
    "user":{"login":"github-actions[bot]"},
    "body":"<!-- pgextwin-candidate:v1:"+"a"*20+" -->",
    "html_url":"https://github.com/pgextwin/pgtap/pull/78"
}
assert m.candidate_run_url("pgextwin/pgtap",candidate_branch,"pull_request") == (
    "https://api.github.com/repos/pgextwin/pgtap/actions/workflows/windows.yml/"
    "runs?event=pull_request&branch=auto-candidate%2F"+"a"*20+"&per_page=100")
for bad_repo,bad_branch,bad_event in (
    ("other/repo",candidate_branch,"pull_request"),
    ("pgextwin/pgtap","main","workflow_dispatch"),
    ("pgextwin/pgtap","auto-candidate/"+"x"*20,"workflow_dispatch"),
    ("pgextwin/pgtap",candidate_branch,"schedule"),
    ("pgextwin/pgtap",candidate_branch+"&event=schedule","pull_request"),
):
    try:
        m.candidate_run_url(bad_repo,bad_branch,bad_event)
    except m.WatchError:
        pass
    else:
        raise AssertionError("unscoped/injected CI query must fail")

native_run={
    "id":202,"event":"pull_request","path":".github/workflows/windows.yml",
    "name":"Windows CI/CD","head_branch":candidate_branch,"head_sha":"3"*40,
    "head_repository":{"full_name":"pgextwin/pgtap"},
    "run_attempt":1,"status":"completed","conclusion":"success"
}
page={"total_count":1,"workflow_runs":[native_run]}
run,kind=m.native_candidate_ci(page,candidate_pr,"pgextwin/pgtap")
assert run["id"]==202 and kind=="NATIVE_CI_SUCCESS_UNVERIFIED"
assert m.native_candidate_ci({"total_count":0,"workflow_runs":[]},
                             candidate_pr,"pgextwin/pgtap")== (None,"NOT_RUN")
assert m.native_candidate_ci(
    {"total_count":1,"workflow_runs":[{**native_run,"head_sha":"4"*40}]},
    candidate_pr,"pgextwin/pgtap")[1]=="STALE_HEAD_CI"
dispatch_run={**native_run,"id":203,"event":"workflow_dispatch"}
dispatch_page={"total_count":1,"workflow_runs":[dispatch_run]}
assert m.native_candidate_ci(dispatch_page,candidate_pr,"pgextwin/pgtap",
                             event="workflow_dispatch")[1]=="DISPATCH_CI_SUCCESS_UNVERIFIED"
assert m.native_candidate_ci(
    {"total_count":1,"workflow_runs":[{**dispatch_run,"head_sha":"4"*40}]},
    candidate_pr,"pgextwin/pgtap",event="workflow_dispatch")[1]=="STALE_HEAD_CI"
for bad in ({"total_count":1,"workflow_runs":[{**dispatch_run,"run_attempt":2}]},
            {"total_count":1,"workflow_runs":[native_run]},
            {"total_count":2,"workflow_runs":[dispatch_run]}):
    try:
        m.native_candidate_ci(bad,candidate_pr,"pgextwin/pgtap",
                              event="workflow_dispatch")
    except m.WatchError:
        pass
    else:
        raise AssertionError("dispatch fallback must reject bad event, attempt or page")

assert m.native_candidate_ci(
    {"total_count":1,"workflow_runs":[{**native_run,"status":"in_progress",
                                    "conclusion":None}]},
    candidate_pr,"pgextwin/pgtap")[1]=="RUNNING"
assert m.native_candidate_ci(
    {"total_count":1,"workflow_runs":[{**native_run,"conclusion":"failure"}]},
    candidate_pr,"pgextwin/pgtap")[1]=="FAILED_OR_UNVERIFIED"

for bad_page,bad_pr in (
    ({"total_count":1,"workflow_runs":[{**native_run,"head_branch":"main"}]},candidate_pr),
    ({"total_count":2,"workflow_runs":[native_run]},candidate_pr),
    ({"total_count":1,"workflow_runs":[{**native_run,"event":"workflow_dispatch"}]},candidate_pr),
    ({"total_count":1,"workflow_runs":[{**native_run,"run_attempt":2}]},candidate_pr),
    ({"total_count":1,"workflow_runs":[{**native_run,"path":"other.yml"}]},candidate_pr),
    ({"total_count":1,"workflow_runs":[{**native_run,"head_repository":{"full_name":"pgextwin/orafce"}}]},candidate_pr),
    (page,{**candidate_pr,"user":{"login":"outside-user"}}),
    (page,{**candidate_pr,"head":{**candidate_pr["head"],"repo":{"full_name":"outside/fork"}}}),
):
    try:
        m.native_candidate_ci(bad_page,bad_pr,"pgextwin/pgtap")
    except m.WatchError:
        pass
    else:
        raise AssertionError("forged/paginated/forked native candidate must fail closed")

def native_request(url):
    if "/pulls?" in url:
        return [candidate_pr]
    if "windows.yml/runs?event=pull_request" in url:
        assert "&branch=auto-candidate%2F"+"a"*20+"&per_page=100" in url
        return page
    if "windows.yml/runs?event=workflow_dispatch" in url:
        raise AssertionError("active native PR cannot be overridden by old Dispatch")
    return fixture_request(url)
m.request=native_request
row=m.one({"repository":"pgextwin/pgtap","mode":"BUILD","scheduleUtc":"0 0 * * *"}, {})
assert not row["errors"] and row["lastCandidateStatus"]=="NATIVE_CI_SUCCESS_UNVERIFIED"
assert row["candidateCiMode"]=="NATIVE_PULL_REQUEST"
assert row["lastWindowsCi"]["runId"]==202 and row["lastSuccessfulCandidate"] is None
assert row["candidatePrUrl"]=="https://github.com/pgextwin/pgtap/pull/78"

# Explicit dispatch created by GITHUB_TOKEN proposer remains the legitimate
# primary candidate CI when the native PR event is suppressed by GitHub.
def dispatch_fallback_request(url):
    if "/pulls?" in url:
        return [candidate_pr]
    if "windows.yml/runs?event=pull_request" in url:
        return {"total_count":0,"workflow_runs":[]}
    if "windows.yml/runs?event=workflow_dispatch" in url:
        assert "&branch=auto-candidate%2F"+"a"*20+"&per_page=100" in url
        return dispatch_page
    return fixture_request(url)
m.request=dispatch_fallback_request
row=m.one({"repository":"pgextwin/pgtap","mode":"BUILD","scheduleUtc":"0 0 * * *"}, {})
assert not row["errors"] and row["lastWindowsCi"]["runId"]==203
assert row["candidateCiMode"]=="ACTIVE_DISPATCH"
assert row["lastCandidateStatus"]=="DISPATCH_CI_SUCCESS_UNVERIFIED"
assert row["lastSuccessfulCandidate"] is None


print("17-extension genuine protected-current-main schedule and native PR CI status fixtures passed")
