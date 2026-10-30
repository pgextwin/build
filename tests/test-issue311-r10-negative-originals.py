#!/usr/bin/env python3
"""Offline hostile guards for R10's negative originals. No network or App key."""
import importlib.util
from pathlib import Path
from unittest.mock import patch

p = Path("scripts/issue311-r10-negative-originals.py")
spec = importlib.util.spec_from_file_location("r10_negative_tested", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def deny(name, callback):
    try:
        callback()
    except (ValueError, KeyError, AssertionError):
        print("R10_NEGATIVE_DENY", name)
        return
    raise AssertionError("R10_NEGATIVE_FALSE_ACCEPT " + name)

def only_source(key):
    source_id, job_id, artifact_id, name, entry, sha = m.PROOFS[key]
    assert isinstance(source_id, int) and isinstance(job_id, int)
    assert isinstance(artifact_id, int) and len(sha) == 64
    assert name and entry.endswith(".json")
for k in m.PROOFS:
    only_source(k)
assert len({v[2] for v in m.PROOFS.values()}) == len(m.PROOFS)
assert len(m.PROOFS) == 6

names = sorted("pgextwin/" + x for x in (
    "pg_bigm", "pg_cron", "pg_hint_plan", "pgaudit", "set_user",
    "pg_repack", "pg_ivm", "pg_qualstats", "plpgsql_check",
    "orafce", "hypopg", "wal2json", "pg_partman",
    "pg_stat_monitor", "pgtap", "pg_variables", "pg_store_plans"))
assert len(names) == 17
case = {"stateRevision": 2, "r10_02Accepted": False,
        "publicationAuthorized": False, "terminal": "QUARANTINED",
        "targets": [{"repository": r, "status": "QUARANTINED",
                     "reasonCode": "SOURCE_FAILED",
                     "safeRestartPoint": "NEW_NONPUBLISHING_REQUEST"} for r in names]}
assert set(m.strict_scope(case)) == set(names)
deny("public release", lambda: m.strict_scope({**case, "publicationAuthorized": True}))
deny("false accepted", lambda: m.strict_scope({**case, "r10_02Accepted": True}))
deny("duplicate target", lambda: m.strict_scope({**case, "targets": case["targets"][:-1] + [case["targets"][0]]}))
deny("missing target", lambda: m.strict_scope({**case, "targets": case["targets"][:-1]}))
deny("not terminal", lambda: m.strict_scope({**case, "terminal": "PENDING"}))

origin = {"runId": 41014241399, "runEvent": "workflow_run",
          "runConclusion": "failure", "zipSha256": m.PROOFS["skip"][-1]}
children = []
for name in names:
    if name == "pgextwin/orafce":
        children.append({"repository": name, "result": "QUARANTINED",
                         "publicationAuthorized": False, "sameTokenRevoked401": True,
                         "reason": "R06_APP_FLEET_DENY child not successful"})
    else:
        children.append({"repository": name, "result": "NO_UPDATE",
                         "publicationAuthorized": False})
receipt = {"result": "QUARANTINED", "runtimeEnabled": False,
           "publicationAuthorized": False, "durableCasVerified": False,
           "sourceKind": "AUTHENTIC_APP_BOT_17_LOCAL_ORIGINAL_NONPUBLISHING",
           "children": children}
def fake_readonly(_): return dict(case, stateBlobSha="a"*40)
def fake_child(item): return {
    "originalChildResult": "NO_UPDATE", "originalRunId": 41000000000,
    "originalAttempt": 1, "originalSourceHeadSha": "a"*40,
    "originalArtifactId": 12900000000, "originalZipSha256": "b"*64,
    "originalEvidenceVerified": True}
with patch.object(m.r10, "readonly_case", side_effect=fake_readonly), \
     patch.object(m, "pinned", return_value=(origin, receipt)), \
     patch.object(m, "verify_child", side_effect=fake_child), \
     patch.object(m, "corroborate_orafce", return_value={"candidateRunId": 41014360341, "originalZipSha256": None}):
    result = m.fleet(m.SOURCE, "skip")
    assert result["stateTerminal"] == "QUARANTINED"
    assert result["joinedOriginalChildren"] == 16
    assert result["unjoinedOriginalChildren"] == 1
    assert sum(x["originalEvidenceVerified"] for x in result["perTarget"]) == 16
    orafce = next(x for x in result["perTarget"] if x["repository"] == "pgextwin/orafce")
    assert orafce["originalRunId"] is None and orafce["originalZipSha256"] is None
    assert result["accepted"] is False and result["complete"] is False
    receipt["children"][0]["repository"] = "pgextwin/forged"
    deny("foreign failed child", lambda: m.fleet(m.SOURCE, "skip"))
    receipt["children"][0]["repository"] = names[0]
    receipt["children"][0]["publicationAuthorized"] = True
    deny("child publishing", lambda: m.fleet(m.SOURCE, "skip"))
    receipt["children"][0]["publicationAuthorized"] = False
    receipt["children"][2]["result"] = "QUARANTINED"
    deny("additional unproven child", lambda: m.fleet(m.SOURCE, "skip"))

assert m.serial({"accepted": False}) == b'{\n  "accepted": false\n}\n'
print("R10_NEGATIVE_OFFLINE_PASS 17 targets, 16 verified/1 absent and fail closed")
