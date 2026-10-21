#!/usr/bin/env python3
"""Offline hostile fixtures: completed central daily proof cannot mint PUBLISH."""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path

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
          head=good_sha, pin=m.COHORT_3):
    return m.validate(document, event, bbranch or branch(build_sha),
                      target or branch(good_sha), repository, head, pin, now)

assert check() == "candidate"
none = deepcopy(report)
for entry in none["extensions"]:
    if entry["repository"] == repo:
        entry["status"] = "up-to-date"
        entry["updates"] = []
none["updatesDetected"] = 0
assert check(none) == "none"

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
for name, f in denials:
    try:
        f()
    except (m.Denied, TypeError, ValueError):
        pass
    else:
        raise AssertionError("unsafe daily candidate evidence accepted: " + name)

workflow = (ROOT / ".github/workflows/operator-update-auto.yml").read_text("utf-8")
for item in (
    "github.event_name == 'schedule'", "github.event_name == 'workflow_dispatch'",
    "permissions:\n  contents: read", "PGEXTWIN_DETECTOR_SHA:",
    "operator-update-readonly.yml@33853f3a4381bfc2d984fad371e5ba5c768595a5",
    "dry_run: true", "persist-credentials: false",
):
    assert item in workflow, item
for item in ("contents: write", "issues: write", "actions: write", "pull-requests: write",
             "secrets.", "PUBLISH=ALLOW", "gh release ", "build-extension-attested"):
    assert item not in workflow, item
print("PASS: immutable 17-repo daily snapshot candidate-only gate plus",
      len(denials), "hostile cases; no Release token or PUBLISH")
