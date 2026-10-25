#!/usr/bin/env python3
"""Step 20 central policy fail-closed fixtures."""
import importlib.util
import json
from pathlib import Path
import sys
from publication_policy_fixtures import manual_policy
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from update_watch_lib import WatchError
s=importlib.util.spec_from_file_location("fleet_control", ROOT/"scripts/fleet-control.py")
c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
policy=manual_policy("automation-fleet.json")
items=c.validate(policy)
original={"pgextwin/"+n for n in ["pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user","pg_repack","pg_ivm","pg_qualstats","plpgsql_check"]}
staged={"pgextwin/"+n for n in ["hypopg","wal2json","pg_partman","pg_stat_monitor","orafce"]}
third={"pgextwin/"+n for n in ["pgtap","pg_variables","pg_store_plans"]}
assert 17 <= len(items) <= c.fleet_policy.MAX_REGISTERED_FLEET and (original|staged|third).issubset(items), "historical 17 mandatory; protected future fleet may grow"
assert all(items[r]["mode"]=="BUILD" and items[r]["candidateEnabled"] and items[r]["releasePolicy"]=="manual-only" for r in original), "preserve initial nine BUILD"
assert all(items[r]["mode"]=="BUILD" and items[r]["candidateEnabled"] is True and items[r]["releasePolicy"]=="manual-only" for r in staged|third), "enable centrally bounded candidate-only BUILD lanes; local opt-in remains separate"
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
for repo in staged|third:
    e=items[repo]
    ext2={"name":repo.split("/")[-1],"upstream":{"repository":"test/upstream"}}
    watch2={"repository":"test/upstream","strategy":e["strategy"]}
    assert c.decide(policy,repo,ext2,watch2,"watch")==(True,"BUILD")
    assert c.decide(policy,repo,ext2,watch2,"candidate",local)==(True,"BUILD")
    changed=json.loads(json.dumps(policy))
    entry=next(x for x in changed["entries"] if x["repository"]==repo)
    entry["candidateEnabled"]=False  # BUILD without opt-in must fail closed
    fails(lambda: c.validate(changed))


# Synthetic future membership is accepted by the shared protected policy
# without adding another Python allowlist. This does NOT grant publication.
expanded=json.loads(json.dumps(policy))
new=expanded["entries"][-1].copy()
new["repository"]="pgextwin/future_registered"
expanded["entries"].append(new)
future_items=c.validate(expanded)
assert len(future_items)==len(items)+1
assert "pgextwin/future_registered" in future_items
future_ext={"name":"future_registered","upstream":{"repository":"safeorg/future_registered"}}
future_watch={"repository":"safeorg/future_registered","strategy":new["strategy"]}
assert c.decide(expanded,"pgextwin/future_registered",future_ext,future_watch,
                "candidate",local)==(True,"BUILD")
# Oversized/truncated/duplicate protected membership always fails closed.
overflow=json.loads(json.dumps(policy))
for n in range(129):
    row=overflow["entries"][-1].copy()
    row["repository"]=f"pgextwin/registered_{n:03d}"
    overflow["entries"].append(row)
fails(lambda:c.validate(overflow))
duplicate=json.loads(json.dumps(expanded))
duplicate["entries"].append(new)
fails(lambda:c.validate(duplicate))

for bad in [
    lambda d:d["entries"].append(d["entries"][0]),
    lambda d:d["entries"][0].update(releasePolicy="automatic"),
    lambda d:d["entries"][0].update(candidateEnabled=False),
    lambda d:d.update(scheduleUtc="0 9 * * *"),
    lambda d:d["entries"][0].update(strategy="nonsense"),
]:
    obj=json.loads(json.dumps(policy));bad(obj);fails(lambda:c.validate(obj))
print("Step 20 fleet policy fixture tests passed")
