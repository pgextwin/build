#!/usr/bin/env python3
"""R11 hostile regression for writer scope, ACK boundedness, and 20-repo crosswalk."""
import copy
import importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location("r11_transition",
    Path(__file__).resolve().parents[1]/"scripts/issue311-r11-transition-controls.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def denied(fn):
    try:fn()
    except (ValueError,TypeError,KeyError,AttributeError):return
    raise AssertionError("unsafe transition accepted")
a="a"*40;b="b"*40
l=m.writer_resource("pgextwin/orafce","issues","upstream-watch",a)
n=m.writer_resource("pgextwin/orafce","issues","upstream-watch",b)
assert m.classify_writer_pair(l,n)=="SHARED_FENCE_REQUIRED"
assert m.classify_writer_pair(l,m.writer_resource(
    "pgextwin/build","contents","issue311-state/checkpoints",b))=="DISJOINT_EXACT_RESOURCE"
denied(lambda:m.writer_resource("pgextwin/orafce","contents","../secrets",a))
denied(lambda:m.writer_resource("pgextwin/unknown","issues","upstream-watch",a))
denied(lambda:m.classify_writer_pair(l,{"repository":"pgextwin/orafce"}))
def g(status,blob=None):return {"method":"GET","status":status,"blobSha":blob}
assert m.bounded_unknown_ack_get([g(429),g(503),g(200,a)],a)=="MATCHED_NO_REWRITE"
assert m.bounded_unknown_ack_get([g(429),g(503),g(504)],a)=="QUARANTINE_BOUNDED_UNKNOWN"
assert m.bounded_unknown_ack_get([g(409)],a)=="QUARANTINE_PERMANENT"
assert m.bounded_unknown_ack_get([g(200,b)],a)=="QUARANTINE_CONFLICT"
assert m.bounded_unknown_ack_get([g(404)],a)=="QUARANTINE_PERMANENT"
for seq in ([g(429)]*4,[g(200,a),g(503)],[g(401),g(200,a)],
            [{"method":"PUT","status":200,"blobSha":a}],[g(200,None)]):
    denied(lambda seq=seq:m.bounded_unknown_ack_get(seq,a))
original={"schemaVersion":1,"kind":"ISSUE311_R11_AUTHENTICATED_SCHEDULE_INVENTORY",
          "nonpublishing":True,"runtimeEnabled":False,"publicationAuthorized":False,
          "writerUsed":False,"scheduleRemoved":False,"migrationAccepted":False,
          "legacyScheduleMustRemain":True}
original["extensions"]=[]
for repo in m.EXTENSIONS:
    original["extensions"].append({"repository":"pgextwin/"+repo,
         "mainSha":a,"gitBlobSha":b,"workflow":".github/workflows/update-watch.yml",
         "schedule":{"cron":["30 * * * *","41 * * * *"] if repo=="hypopg"
                     else ["30 * * * *"],"migrationAccepted":False,
                     "pushPreserved":True,"workflowRunPreserved":True,
                     "scheduleDependentAuthorize":True}})
original["central"]=[{"repository":"pgextwin/"+repo,"mainSha":a,
 "migrationAccepted":False,"scheduleWorkflows":[{"path":".github/workflows/watch.yml",
 "gitBlobSha":b,"cron":["0 * * * *"],"migrationAccepted":False}]} for repo in m.CENTRAL]
matrix=m.crosswalk(original)
assert matrix["repositoryCount"]==20 and matrix["scheduleCount"]==20
assert matrix["allRetirementDeniedUntilIndependentProof"] is True
assert all(not row["retirementAuthorized"] for row in matrix["rows"])
assert len(matrix["rows"][m.EXTENSIONS.index("hypopg")]["legacyCron"])==2
for modify in (
    lambda d:d["extensions"].pop(),
    lambda d:d["extensions"][0]["schedule"].update(cron=[]),
    lambda d:d["extensions"][0]["schedule"].update(migrationAccepted=True),
    lambda d:d.update(scheduleRemoved=True),
    lambda d:d["central"][0]["scheduleWorkflows"][0].update(cron=[]),
    lambda d:d["central"][0]["scheduleWorkflows"].append(
        copy.deepcopy(d["central"][0]["scheduleWorkflows"][0])),
):
    x=copy.deepcopy(original);modify(x)
    denied(lambda x=x:m.crosswalk(x))
print("R11_TRANSITION_SCOPE_ACK_SCHEDULE_HOSTILE_PASS")
