#!/usr/bin/env python3
"""Offline hostile input checks for Issue #311 R11 active Run inventory."""
import copy
import importlib.util
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts/issue311-r11-overlap-preflight.py"
spec = importlib.util.spec_from_file_location("r11_overlap", path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def denied(func):
    try:
        func()
    except (ValueError, KeyError, TypeError):
        return
    raise AssertionError("R11 hostile input was accepted")

head = "a" * 40
run = {"id":42, "run_attempt":1, "status":"queued", "head_sha":head,
       "event":"schedule", "path":".github/workflows/update-watch.yml",
       "repository":{"full_name":"pgextwin/orafce"},
       "actor":{"login":"github-actions[bot]"},
       "created_at":"2026-10-31T00:00:00Z"}
assert m.validate_run("pgextwin/orafce", run, "queued")["runId"] == 42
for key, value in (("status","completed"), ("head_sha","invalid"),
                   ("event","FAKE_SCHEDULE"), ("path","fake.py")):
    changed = copy.deepcopy(run)
    changed[key] = value
    denied(lambda changed=changed: m.validate_run("pgextwin/orafce", changed, "queued"))
denied(lambda: m.validate_run("pgextwin/build", run, "queued"))

branches = {repo: {"name":"main","protected":True,"commit":{"sha":head}} for repo in m.REPOS}
runs = {repo: {"total_count":0,"workflow_runs":[]} for repo in m.REPOS}
def get(endpoint):
    repo = "pgextwin/" + endpoint.split("repos/pgextwin/")[1].split("/")[0]
    return branches[repo] if endpoint.endswith("/branches/main") else runs[repo]
data = m.snapshot(get)
assert len(data["repositories"]) == 20 and data["activeRunCount"] == 0
assert not data["cronRemovalAuthorized"]
assert m.verify(data,get)["verifiedOriginalRunCount"] == 0
changed = copy.deepcopy(data)
changed["cronRemovalAuthorized"] = True
denied(lambda: m.verify(changed,get))
changed = copy.deepcopy(data)
changed["repositories"] = changed["repositories"][:-1]
denied(lambda: m.verify(changed,get))
runs["pgextwin/build"] = {"total_count":101,"workflow_runs":[]}
denied(lambda: m.snapshot(get))
runs["pgextwin/build"] = {"total_count":0,"workflow_runs":[]}
branches["pgextwin/hypopg"]["protected"] = False
denied(lambda: m.snapshot(get))
print("R11_OVERLAP_READONLY_HOSTILE_TESTS_PASS")
