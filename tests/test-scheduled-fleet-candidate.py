#!/usr/bin/env python3
"""Offline hostile fixtures: completed central daily proof cannot mint PUBLISH."""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("scheduled_fleet", ROOT / "scripts/verify-scheduled-fleet-candidate.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

now = datetime.now(timezone.utc).replace(microsecond=0)
iso = lambda dt: dt.isoformat()
old = now - timedelta(minutes=4)
end = now - timedelta(minutes=3)
good_sha = "a" * 40
build_sha = "b" * 40
repo = "pgextwin/pgtap"
branch = lambda sha: {"protected": True, "commit": {"sha": sha}}
run = {
    "id": 12345, "event": "schedule", "path": m.WATCH_PATH,
    "head_branch": "main", "run_attempt": 1, "status": "completed",
    "conclusion": "success", "head_sha": build_sha,
    "created_at": iso(old), "updated_at": iso(end),
    "repository": {"full_name": m.BUILD},
}
rows = [{"repository": r, "mainSha": good_sha, "status": "up-to-date", "updates": []}
        for r in sorted(m.REPOSITORIES)]
for item in rows:
    if item["repository"] == repo:
        item["status"] = "update-available"
        item["updates"] = [{"version": "v1.99", "commit": "c" * 40}]
report = {
    "schemaVersion": 1, "scope": "STABLE_UPSTREAM_GET_ONLY",
    "publication": "DENY", "candidatePrCreated": False, "fleetSize": 17,
    "indeterminate": 0, "generatedAt": iso(end), "updatesDetected": 1,
    "extensions": rows,
}
def check(document=report, event=run, bbranch=None, target=None, repository=repo,
          head=good_sha, pin=m.COHORT_3, live_replay=False,
          source_equivalent=False):
    return m.validate(document, event, bbranch or branch(build_sha),
                      target or branch(good_sha), repository, head, pin, now,
                      live_replay=live_replay,
                      source_equivalent=source_equivalent)

assert check() == "candidate"
# The independent fresh GET-only replay is not the central ZIP; it must
# maintain the same protected-main, 17-row, candidate-only contract.
assert check(live_replay=True) == "candidate"
# Normal schedule-head exact match remains mandatory. Only a distinct fresh
# live replay after an authenticated immutable source-identity comparison may
# tolerate unrelated central main advances. Target main still MUST match.
drift_build = branch("d" * 40)
for replay, identical in ((False, False), (True, False), (False, True)):
    try:
        check(bbranch=drift_build, live_replay=replay, source_equivalent=identical)
    except m.Denied:
        pass
    else:
        raise AssertionError("unproven central SHA drift was authorized")
assert check(bbranch=drift_build, live_replay=True,
             source_equivalent=True) == "candidate"
try:
    check(bbranch=drift_build, target=branch("f" * 40),
          live_replay=True, source_equivalent=True)
except m.Denied:
    pass
else:
    raise AssertionError("stale target main accepted after central replay")

# The two GitHub trees and actual pinned checkout must agree on the same
# exact mode/type/blob per file. Malformed/incomplete/changed trees all DENY.
def pristine_tree():
    return {"sha": "a" * 40, "truncated": False,
            "tree": [{"path": path, "type": "blob", "mode": "100644",
                      "sha": m.git_blob_sha((ROOT / path).read_bytes())}
                     for path in m.REPLAY_SOURCE_PATHS]}

with patch.object(m, "api", return_value=pristine_tree()) as fetch:
    assert m.verify_replay_source_blobs("b" * 40, "d" * 40, "") is True
    assert fetch.call_count == 2
    assert all("/git/trees/" in call.args[0] for call in fetch.call_args_list)
for variant in ("missing", "changed", "symlink", "duplicate", "truncated"):
    item = pristine_tree()
    if variant == "missing":
        item["tree"].pop()
    elif variant == "changed":
        item["tree"][0]["sha"] = "f" * 40
    elif variant == "symlink":
        item["tree"][0]["mode"] = "120000"
    elif variant == "duplicate":
        item["tree"].append(dict(item["tree"][0]))
    else:
        item["truncated"] = True
    with patch.object(m, "api", return_value=item):
        try:
            m.verify_replay_source_blobs("b" * 40, "d" * 40, "")
        except m.Denied:
            pass
        else:
            raise AssertionError("malformed identical-source claim accepted: " + variant)
# Original scheduled-tree mismatch cannot be hidden by a matching current
# tree, and no API response is accepted as authentication by itself.
bad = pristine_tree()
bad["tree"][0]["sha"] = "e" * 40
with patch.object(m, "api", side_effect=[bad, pristine_tree()]):
    try:
        m.verify_replay_source_blobs("b" * 40, "d" * 40, "")
    except m.Denied:
        pass
    else:
        raise AssertionError("original schedule scan source tampering accepted")
none = deepcopy(report)
for entry in none["extensions"]:
    if entry["repository"] == repo:
        entry["status"] = "up-to-date"
        entry["updates"] = []
none["updatesDetected"] = 0
assert check(none) == "none"
assert check(none, live_replay=True) == "none"

denials = []
for name, target, key, value in (
    ("PUBLISH", "report", "publication", "ALLOW"),
    ("unsigned candidate", "report", "candidatePrCreated", True),
    ("partial", "report", "fleetSize", 16),
    ("indeterminate", "report", "indeterminate", 1),
    ("forged date", "report", "generatedAt", iso(now - timedelta(days=2))),
    ("wrong count", "report", "updatesDetected", 4),
    ("failed run", "run", "conclusion", "failure"),
    ("unfinished", "run", "status", "in_progress"),
    ("rerun", "run", "run_attempt", 2),
    ("non-schedule", "run", "event", "workflow_dispatch"),
    ("other source", "run", "path", ".github/workflows/validate.yml"),
    ("wrong build HEAD", "run", "head_sha", "d" * 40),
    ("stale run", "run", "created_at", iso(now - timedelta(days=3))),
):
    r, event = deepcopy(report), deepcopy(run)
    if target == "report":
        r[key] = value
    else:
        event[key] = value
    denials.append((name, lambda a=r, b=event: check(a, b)))

r = deepcopy(report)
r["extensions"].append(deepcopy(r["extensions"][0]))
denials.append(("duplicate rows", lambda: check(r)))
r = deepcopy(report)
r["extensions"][0]["repository"] = "pgextwin/evil"
denials.append(("unknown repo", lambda: check(r)))
r = deepcopy(report)
r["extensions"][0]["status"] = "update-available"
denials.append(("lying status", lambda: check(r)))
r = deepcopy(report)
next(row for row in r["extensions"] if row["repository"] == repo)["mainSha"] = "d" * 40
denials.append(("stale extension main", lambda: check(r)))
denials.append(("unprotected main", lambda: check(target={"protected": False, "commit": {"sha": good_sha}})))
denials.append(("detector branch swap", lambda: check(pin=m.COHORT_14)))
denials.append(("unregistered repository", lambda: check(repository="pgextwin/evil")))
denials.append(("caller SHA drift", lambda: check(head="d" * 40)))
replay_early = deepcopy(report)
replay_early["generatedAt"] = iso(old - timedelta(minutes=10))
denials.append(("replayed fleet result predates central schedule",
                lambda: check(replay_early, live_replay=True)))
replay_future = deepcopy(report)
replay_future["generatedAt"] = iso(now + timedelta(minutes=6))
denials.append(("replayed fleet result lies in future",
                lambda: check(replay_future, live_replay=True)))
replay_bad = deepcopy(report)
replay_bad["extensions"][1]["status"] = "INDETERMINATE"
denials.append(("replayed fleet row indeterminate",
                lambda: check(replay_bad, live_replay=True)))
for name, f in denials:
    try:
        f()
    except (m.Denied, TypeError, ValueError):
        pass
    else:
        raise AssertionError("unsafe daily candidate evidence accepted: " + name)

workflow = (ROOT / ".github/workflows/operator-update-auto.yml").read_text("utf-8")
for item in (
    "github.event_name == 'schedule'",
    "permissions:\n  contents: read", "PGEXTWIN_DETECTOR_SHA:",
    "persist-credentials: false",
):
    assert item in workflow, item
for item in ("contents: write", "issues: write", "actions: write", "pull-requests: write",
             "secrets.", "PUBLISH=ALLOW", "gh release ", "build-extension-attested"):
    assert item not in workflow, item
source = (ROOT / "scripts/verify-scheduled-fleet-candidate.py").read_text("utf-8")
for item in ("def replay_live_fleet(", "FLEET_EVIDENCE=INDEPENDENT_GET_ONLY_REPLAY",
             "live_replay=live_replay", "PUBLISH=DENY"):
    assert item in source, item
assert "contents: write" not in workflow
print("PASS: 17-repo schedule proof and distinct GET-only replay plus",
      len(denials), "hostile cases; no Release token or PUBLISH")

# A failed or missing genuine central run never authorizes a candidate.
# Its original failure is preserved; local hourly preflight is labelled DEFERRED
# (not misreported as a Windows compile failure). A forged/invalid successful
# run still goes through strict validate(), so cannot take this route.
import os
from tempfile import TemporaryDirectory
latest_fail = deepcopy(run)
latest_fail["conclusion"] = "failure"
for records, expected_reason in (([latest_fail], "LATEST_GENUINE_CENTRAL_SCAN_NOT_SUCCESSFUL"),
                                 ([], "NO_GENUINE_CENTRAL_FLEET_SCHEDULE")):
    with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                                 "GITHUB_REF": "refs/heads/main",
                                 "GITHUB_RUN_ATTEMPT": "1"}):
        responses = [branch(build_sha), branch(good_sha), {"workflow_runs": records}]
        if records:
            responses.append(latest_fail)
        with patch.object(m, "api", side_effect=responses):
            try:
                m.run(repo, good_sha, m.COHORT_3, "opaque-token")
            except m.Deferred as e:
                assert str(e) == expected_reason
            else:
                raise AssertionError("failed or missing central schedule created a candidate")
with TemporaryDirectory() as directory:
    output = Path(directory) / "output"
    with patch.dict(os.environ, {"GITHUB_REPOSITORY": repo, "GITHUB_SHA": good_sha,
                                 "PGEXTWIN_DETECTOR_SHA": m.COHORT_3,
                                 "GH_TOKEN": "never-log-secret",
                                 "GITHUB_OUTPUT": str(output)}):
        with patch.object(m, "run", side_effect=m.Deferred("LATEST_GENUINE_CENTRAL_SCAN_NOT_SUCCESSFUL")):
            assert m.main() == 0
    assert output.read_text() == "mode=deferred\\n"
print("PASS: unavailable genuine central schedule is safe deferred, not candidate or publish")
