#!/usr/bin/env python3
"""Negative, offline-only tests for genuine failed CAS targeted recovery."""
import importlib.util, os
from pathlib import Path
from unittest.mock import patch
from datetime import datetime,timezone,timedelta
root=Path(__file__).resolve().parents[1]
p=root/"scripts/issue311-r06-failed-cas-recovery.py"
s=p.read_text()
compile(s,str(p),"exec")
assert "writer.mint_token" in s and "writer.revoke_and_prove_401" in s
assert "bridge.original_zip" in s
assert "QUARANTINED" in s and "BOUNDED_WATCHDOG" in s
assert "41005723124" in s and "41005515488" in s
for forbidden in ("PUBLISH_ELIGIBLE","workflow_dispatch","/releases","Publisher", "actions/workflows/"):
    assert forbidden not in s,forbidden
spec=importlib.util.spec_from_file_location("recover",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
exp=(datetime.now(timezone.utc)+timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
base=m.life.new(m.OLD_STATE,m.ORIGINAL_REQUEST_SHA,m.ORIGINAL_HEAD,
                 ["pgextwin/orafce","pgextwin/pgaudit"],exp)
bound=m.life.bind_source(base,0,"r06-app-17-original",
                         run_id=m.SOURCE,attempt=1,head_sha=m.ORIGINAL_HEAD)
# Real target is exactly 17; assemble independent in-memory test without credentials.
targets=["pgextwin/"+x for x in ("pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user",
          "pg_repack","pg_ivm","pg_qualstats","plpgsql_check","orafce",
          "hypopg","wal2json","pg_partman","pg_stat_monitor","pgtap",
          "pg_variables","pg_store_plans")]
base=m.life.new(m.OLD_STATE,m.ORIGINAL_REQUEST_SHA,m.ORIGINAL_HEAD,targets,exp)
bound=m.life.bind_source(base,0,"r06-app-17-original",
                         run_id=m.SOURCE,attempt=1,head_sha=m.ORIGINAL_HEAD)
proof={"sourceRunId":m.SOURCE,"failedCasRunId":m.FAILED,
       "failure":"invalid event transport"}
state=m.transition(bound,proof,41012000111)
assert state["revision"]==2 and state["terminal"]=="QUARANTINED"
assert set(state["targets"].values())=={"QUARANTINED"}
assert state["publisherAuthorized"] is False
try:m.transition(state,proof,41012000112)
except ValueError:pass
else:raise AssertionError("replay from terminal was accepted")
for change in [
 {"requestSha256":"0"*64},{"sourceHeadSha":"0"*40},
 {"sourceRun":{"id":99999,"attempt":1}},
 {"publisherAuthorized":True},{"writeOutcomeUnknown":True},
 {"targets":{**bound["targets"],"pgextwin/orafce":"SUCCESS"}},
]:
 corrupted={**bound,**change}
 try:m.transition(corrupted,proof,41012000111)
 except ValueError:pass
 else:raise AssertionError("corrupt original state accepted "+str(change))
with patch.dict(os.environ,{"GITHUB_REPOSITORY":"pgextwin/build",
 "GITHUB_EVENT_NAME":"pull_request","GITHUB_WORKFLOW":m.WORKFLOW,
 "GITHUB_REF":"refs/heads/main","GITHUB_ACTOR":"ShutenOishi",
 "GITHUB_RUN_ATTEMPT":"1"},clear=True):
 try:m.request()
 except ValueError:pass
 else:raise AssertionError("untrusted PR event accepted")
print("ISSUE311_R06_FAILED_CAS_RECOVERY_NEGATIVE_PASS_OFFLINE_ONLY")
