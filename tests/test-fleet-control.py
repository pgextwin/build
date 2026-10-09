#!/usr/bin/env python3
"""Step 20 central policy fail-closed fixtures."""
import importlib.util
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from update_watch_lib import WatchError
s=importlib.util.spec_from_file_location("fleet_control", ROOT/"scripts/fleet-control.py")
c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
policy=json.loads((ROOT/"metadata/automation-fleet.json").read_text())
items=c.validate(policy)
assert len(items)==9
assert set(items)=={"pgextwin/"+n for n in ["pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user","pg_repack","pg_ivm","pg_qualstats","plpgsql_check"]}
local={"schemaVersion":1,"enabled":True,"releasePolicy":"manual-only","workflow":"windows.yml"}
ext={"name":"plpgsql_check","upstream":{"repository":"okbob/plpgsql_check"}}
watch={"repository":"okbob/plpgsql_check","strategy":"github-releases"}
assert c.decide(policy,"pgextwin/plpgsql_check",ext,watch,"candidate",local)==(True,"BUILD")
assert c.decide(policy,"pgextwin/plpgsql_check",ext,watch,"watch")== (True,"BUILD")
def fails(fn):
    try: fn()
    except WatchError: return
    raise AssertionError("expected fail closed")
fails(lambda:c.decide(policy,"pgextwin/unknown",ext,watch,"watch"))
fails(lambda:c.decide(policy,"pgextwin/plpgsql_check",ext,watch,"candidate",None))
fails(lambda:c.decide(policy,"pgextwin/plpgsql_check",ext,{"repository":watch["repository"],"strategy":"github-tags"},"watch"))
for mode in ("WATCH","OFF"):
    obj=json.loads(json.dumps(policy))
    e=next(x for x in obj["entries"] if x["repository"]=="pgextwin/plpgsql_check")
    e["mode"]=mode;e["candidateEnabled"]=False
    assert c.decide(obj,"pgextwin/plpgsql_check",ext,watch,"candidate",local)==(False,mode)
    assert c.decide(obj,"pgextwin/plpgsql_check",ext,watch,"watch")== (mode!="OFF",mode)
for bad in [
    lambda d:d["entries"].append(d["entries"][0]),
    lambda d:d["entries"][0].update(releasePolicy="automatic"),
    lambda d:d["entries"][0].update(candidateEnabled=True),
    lambda d:d.update(scheduleUtc="0 9 * * *"),
    lambda d:d["entries"][0].update(strategy="nonsense"),
]:
    obj=json.loads(json.dumps(policy));bad(obj);fails(lambda:c.validate(obj))
print("Step 20 fleet policy fixture tests passed")
