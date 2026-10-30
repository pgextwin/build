#!/usr/bin/env python3
"""R06 independent finite event-loss watchdog; OFFLINE negative policy only."""
import importlib.util, os
from pathlib import Path
from datetime import datetime,timezone,timedelta
from unittest.mock import patch
root=Path(__file__).resolve().parents[1]
p=root/"scripts/issue311-r06-unattended-finite-guard.py"
s=p.read_text()
compile(s,str(p),"exec")
assert "writer.mint_token" in s and "writer.revoke_and_prove_401" in s
assert "life.new" in s and "store.CAS" in s and "BOUNDED_WATCHDOG" in s
assert "MAX_POLL=400" in s and "POLL_SECONDS=8" in s
assert '"PUBLISH_ELIGIBLE"' not in s and "workflow_dispatch" not in s and "/releases" not in s
assert "publisherAuthorized" in s and "writeOutcomeUnknown" in s
spec=importlib.util.spec_from_file_location("r06guard",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
now=datetime.now(timezone.utc)
targets=["pgextwin/"+x for x in ("pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user",
          "pg_repack","pg_ivm","pg_qualstats","plpgsql_check","orafce",
          "hypopg","wal2json","pg_partman","pg_stat_monitor","pgtap",
          "pg_variables","pg_store_plans")]
origin={"headSha":"a"*40,"requestId":"r-20261030-r06preparetestwatch01",
        "requestSha256":"b"*64,"deadlineAt":m.stamp(now+timedelta(minutes=8)),
        "createdAt":m.stamp(now),"targets":sorted(targets),
        "watchId":"r-20261030-r06watchaaaaaaaabbbbbbbb"}
base=m.life.new(origin["watchId"],origin["requestSha256"],origin["headSha"],
                origin["targets"],origin["deadlineAt"])
assert m.pending_terminal(base,origin,origin['watchId'],41019000002)["terminal"]=="QUARANTINED"
bound=m.life.bind_source(base,0,"source",run_id=41019000003,attempt=1,head_sha="a"*40)
term=m.pending_terminal(bound,origin,origin['watchId'],41019000002)
assert term["revision"]==2 and term["eventTransport"]=="BOUNDED_WATCHDOG"
assert len(term["targets"])==17 and set(term["targets"].values())=={"QUARANTINED"}
assert term["publisherAuthorized"] is False and term["writeOutcomeUnknown"] is False
for bad in [
    {**bound,"terminal":"NO_UPDATE"},
    {**bound,"sourceHeadSha":"c"*40},
    {**bound,"publisherAuthorized":True},
    {**bound,"writeOutcomeUnknown":True},
    {**bound,"targetScope":["pgextwin/orafce"]},
]:
    try:m.pending_terminal(bad,origin,origin['watchId'],41019000002)
    except ValueError:pass
    else:raise AssertionError("invalid request/terminal accepted")
try:m.pending_terminal(term,origin,origin['watchId'],41019000002)
except ValueError:pass
else:raise AssertionError("terminal replay accepted")
with patch.dict(os.environ,{
    "GITHUB_REPOSITORY":"pgextwin/build",
    "GITHUB_WORKFLOW":m.NAME,"GITHUB_EVENT_NAME":"pull_request",
    "GITHUB_REF":"refs/heads/main","GITHUB_ACTOR":"ShutenOishi",
    "GITHUB_RUN_ATTEMPT":"1"},clear=True):
    try:m.original()
    except ValueError:pass
    else:raise AssertionError("untrusted original event accepted")
print("ISSUE311_R06_INDEPENDENT_FINITE_WATCHDOG_NEGATIVE_PASS_OFFLINE_ONLY")

# Transient READ-only GitHub GET recovery; must never expand into App write retries.
from urllib.error import HTTPError, URLError
assert m.GET_MAX_ATTEMPTS == 3
assert m.TRANSIENT_READ_HTTP == frozenset((429, 502, 503, 504))
def http_error(code):
    return HTTPError("https://api.github.com/repos/pgextwin/build/branches/main",
                     code, "test", {}, None)
for code in (429, 502, 503, 504):
    with patch.object(m.bridge, "get_json", side_effect=[http_error(code), {"protected": True}]) as get, patch.object(m.time, "sleep") as sleep:
        assert m.api("branches/main") == {"protected": True}
        assert get.call_count == 2 and sleep.call_args_list == [((1,), {})]
for transient in (URLError("transport"), TimeoutError("read timed out"), ConnectionError("connection reset")):
    with patch.object(m.bridge, "get_json", side_effect=[transient, transient, {"ok": True}]) as get, patch.object(m.time, "sleep") as sleep:
        assert m.api("branches/main") == {"ok": True}
        assert get.call_count == 3 and sleep.call_count == 2
for code in (401, 403, 404, 409, 422):
    with patch.object(m.bridge, "get_json", side_effect=http_error(code)) as get, patch.object(m.time, "sleep") as sleep:
        try: m.api("branches/main")
        except HTTPError as exc: assert exc.code == code
        else: raise AssertionError("security/non-transient response was retried or accepted")
        assert get.call_count == 1 and sleep.call_count == 0
with patch.object(m.bridge, "get_json", side_effect=http_error(503)) as get, patch.object(m.time, "sleep") as sleep:
    try: m.api("branches/main")
    except HTTPError as exc: assert exc.code == 503
    else: raise AssertionError("repeated provider failure was treated as success")
    assert get.call_count == 3 and sleep.call_count == 2
print("ISSUE311_R06_BOUNDED_READONLY_GET_TRANSIENT_NEGATIVE_PASS_OFFLINE_ONLY")
