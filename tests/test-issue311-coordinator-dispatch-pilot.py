#!/usr/bin/env python3
"""Offline one-shot real App dispatch policy adversarial fixtures, no credentials."""
import copy
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "pilot", Path("scripts/issue311-coordinator-dispatch-pilot.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
policy = m.identity.read_json(m.identity.POLICY)
request = {
    "schemaVersion": 1, "requestId": m.REQUEST_ID, "mode": "AUDIT_ONLY",
    "appId": 5534389, "installationId": 176718417, "botUserId": 350058024,
    "target": "pgextwin/orafce", "workflow": m.WORKFLOW,
    "workflowRef": "main", "localMainSha": "a" * 40,
    "actorRequestId": m.ACTOR_REQUEST_ID,
    "publicReleaseAuthorized": False, "runtimeEnabled": False,
    "allowSinglePilotDispatch": True, "baseMainSha": m.BASE_SHA
}
assert m.check_request(request, policy)

def denied(value, metadata=policy):
    try:
        m.check_request(value, metadata)
    except (m.Denied, m.identity.Deny):
        return
    raise AssertionError("privileged or forged request was accepted")

for k, v in (
    ("mode", "PUBLISH"), ("appId", 5517840), ("botUserId", 1),
    ("installationId", 176347451), ("target", "pgextwin/build"),
    ("workflowRef", "feature"), ("workflow", "promote.yml"),
    ("publicReleaseAuthorized", True), ("runtimeEnabled", True),
    ("allowSinglePilotDispatch", False), ("localMainSha", "a" * 39),
    ("actorRequestId", "PUBLISH"),
):
    test = copy.deepcopy(request)
    test[k] = v
    denied(test)
test = copy.deepcopy(request)
test["extra"] = "unsafe"
denied(test)
for method, path in (("POST", m.WORK), ("POST", "repos/pgextwin/orafce/releases"),
                     ("DELETE", m.DISPATCH), ("POST", m.DISPATCH + "/again")):
    try:
        m.rest(method, path, "never-real-token")
    except m.Denied:
        continue
    raise AssertionError("allowlist leak")
print("ISSUE311_DISPATCH_PILOT_OFFLINE_DENIES_PASS")
