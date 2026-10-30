#!/usr/bin/env python3
"""R06 original two-runner CAS: pure nonpublishing concurrency contract, no credentials."""
import importlib.util, os, json
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import patch
root=Path(__file__).resolve().parents[1]
p=root/"scripts/issue311-r06-parallel-cas-original.py"
compile(p.read_text(),str(p),"exec")
sp=importlib.util.spec_from_file_location("parallel",p)
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
assert len(m.TARGETS)==17 and len(set(m.TARGETS))==17
assert set(m.TARGETS)==set("pgextwin/"+x for x in (
 "pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user","pg_repack",
 "pg_ivm","pg_qualstats","plpgsql_check","orafce","hypopg","wal2json",
 "pg_partman","pg_stat_monitor","pgtap","pg_variables","pg_store_plans"))
stamp=lambda d:d.strftime("%Y-%m-%dT%H:%M:%SZ")
now=datetime.now(timezone.utc)
req={"expiresAt":stamp(now+timedelta(hours=1))}
with patch.dict(os.environ,{"GITHUB_RUN_ID":"41099912345"},clear=False):
    initial,bound=m.bound_state(req,"b"*64,"c"*40)
    assert initial["revision"]==0 and bound["revision"]==1
    A=m.write_proposed(bound,"A")
    B=m.write_proposed(bound,"B")
    assert A!=B and m.store.canonical(A)!=m.store.canonical(B)
    for result in (A,B):
        assert result["revision"]==2 and result["terminal"]=="QUARANTINED"
        assert result["sourceRun"]=={"id":41099912345,"attempt":1}
        assert result["completionRun"]=={"id":41099912345,"attempt":1}
        assert result["eventTransport"]=="BOUNDED_WATCHDOG"
        assert set(result["targets"].values())=={"QUARANTINED"}
        assert len(result["targets"])==17 and result["publisherAuthorized"] is False
        assert result["writeOutcomeUnknown"] is False
        m.store.require_transition(bound,result)
    for wrong in ("C","","r06"):
        try:m.write_proposed(bound,wrong)
        except ValueError:pass
        else:raise AssertionError("unapproved writer name accepted")
    try:m.write_proposed(A,"B")
    except ValueError:pass
    else:raise AssertionError("terminal revision replay accepted")
    try:m.life._apply(A,2,"late",{"completed":True},lambda z:z.update(terminal="NO_UPDATE"))
    except ValueError:pass
    else:raise AssertionError("NO_UPDATE over terminal accepted")
    corrupt=dict(bound,publisherAuthorized=True)
    try:m.write_proposed(corrupt,"A")
    except ValueError:pass
    else:raise AssertionError("publication in State accepted")
with patch.dict(os.environ,{"GITHUB_EVENT_NAME":"pull_request","GITHUB_REPOSITORY":"pgextwin/build",
 "GITHUB_WORKFLOW":m.NAME,"GITHUB_REF":"refs/heads/main","GITHUB_ACTOR":"ShutenOishi",
 "GITHUB_RUN_ATTEMPT":"1"},clear=True):
    try:m.approved_request()
    except ValueError:pass
    else:raise AssertionError("untrusted original source accepted")
code=p.read_text()
assert '"putCount"]=1' in code and 'writer.api("PUT",store.endpoint(REQ),token,body)' in code
assert "writer.revoke_and_prove_401(token)" in code
for forbidden in ("/releases","PUBLISH_ELIGIBLE","workflow_dispatch","schedule:", "git push --force"):
    assert forbidden not in code,forbidden
print("R06_TWO_INDEPENDENT_CAS_QUARANTINED_ONLY_OFFLINE_NEGATIVES_PASS")
