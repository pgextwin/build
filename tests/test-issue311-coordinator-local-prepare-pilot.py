#!/usr/bin/env python3
"""Fail-closed coordinator App one-shot PREPARE request fixture tests."""
import copy
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
spec = importlib.util.spec_from_file_location(
    "r06localpilot", Path("scripts/issue311-coordinator-local-prepare-pilot.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
r = {
    "schemaVersion": 1, "requestId": m.REQUEST_ID,
    "localRequestId": m.LOCAL_REQUEST_ID, "mode": "PREPARE",
    "sourceRunId": 12345, "sourceHeadSha": "a" * 40,
    "sourceArtifactId": 67890, "sourceZipSha256": "b" * 64,
    "centralRequestId": "r-20261030-r06preparecoord001",
    "localMainSha": "c" * 40, "target": m.REPO,
    "workflow": m.WORKFLOW, "appId": 5534389,
    "installationId": 176718417, "botUserId": 350058024,
    "runtimeEnabled": False, "publicReleaseAuthorized": False,
    "baseMainSha": "d" * 40,
    "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
}
assert m.check_request(r)
def denied(v):
    try:
        m.check_request(v)
    except (ValueError, m.Denied):
        return
    raise AssertionError("unsafe coordinator source accepted")
for key, val in (
    ("mode", "PUBLISH_ELIGIBLE"), ("target", "pgextwin/build"),
    ("workflow", "promote.yml"), ("botUserId", 1),
    ("runtimeEnabled", True), ("publicReleaseAuthorized", True),
    ("sourceRunId", 0), ("sourceArtifactId", 0),
    ("sourceZipSha256", "d" * 63),
    ("localMainSha", "d" * 39),
    ("expiresAt", (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()),
):
    denied(dict(r, **{key: val}))
denied(dict(r, extra="attacker"))
for method, path in [
    ("POST", "repos/pgextwin/orafce/releases"),
    ("POST", m.TARGET_WORK),
    ("DELETE", m.POST),
    ("POST", "repos/pgextwin/build/actions/workflows/another/dispatches")
]:
    try:
        m.api(method, path, "not-a-token")
    except m.Denied:
        pass
    else:
        raise AssertionError("privileged endpoint accepted")
print("ISSUE311_COORD_LOCAL_PREPARE_POLICY_NEGATIVE_PASS")
