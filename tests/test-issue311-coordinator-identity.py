#!/usr/bin/env python3
"""Offline negative tests for the nonpublishing one-shot Coordinator identity proof."""
import copy
import importlib.util
from pathlib import Path

file = Path("scripts/issue311-coordinator-identity.py")
spec = importlib.util.spec_from_file_location("issue311_coord_probe", file)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

policy = m.read_json(m.POLICY)
request = m.read_json(m.REQUEST)
assert m.check_policy(policy, request)

def denied(call):
    try:
        call()
    except m.Deny:
        return
    raise AssertionError("unsafe policy unexpectedly admitted")

for key, value in (("runtimeEnabled", True), ("botUserId", 1),
                   ("appId", 5517840), ("installationId", 176347451)):
    test = copy.deepcopy(policy)
    test[key] = value
    denied(lambda t=test: m.check_policy(t, request))
for key, value in (("mode", "PUBLISH"), ("publicReleaseAuthorized", True),
                   ("workflowDispatchAuthorized", True),
                   ("targetRepository", "pgextwin/build")):
    test = copy.deepcopy(request)
    test[key] = value
    denied(lambda t=test: m.check_policy(policy, t))
denied(lambda: m.make_jwt("wrong"))
denied(lambda: m.api("POST",
    "repos/pgextwin/orafce/actions/workflows/issue311-fleet-local-prepare.yml/dispatches",
    "not-a-token"))
denied(lambda: m.event_gate())
print("ISSUE311_COORDINATOR_IDENTITY_OFFLINE_DENIES_PASS")
