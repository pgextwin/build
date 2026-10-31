#!/usr/bin/env python3
"""Read-only original GitHub GET of active legacy/new Runs for R11; no cron change."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

EXTENSIONS = (
    "pg_bigm", "pg_cron", "pg_hint_plan", "pgaudit", "set_user", "pg_repack",
    "pg_ivm", "pg_qualstats", "plpgsql_check", "orafce", "hypopg", "wal2json",
    "pg_partman", "pg_stat_monitor", "pgtap", "pg_variables", "pg_store_plans",
)
REPOS = tuple("pgextwin/" + x for x in EXTENSIONS) + (
    "pgextwin/build", "pgextwin/catalog", "pgextwin/website",
)
STATUSES = ("queued", "in_progress", "waiting", "pending", "requested")
SHA40 = re.compile(r"[a-f0-9]{40}\Z")

def need(condition, reason):
    if not condition:
        raise ValueError("R11_OVERLAP_DENY " + reason)

def gh(endpoint):
    reply = subprocess.run(["gh", "api", "--method", "GET", endpoint],
                           capture_output=True, text=True, check=False)
    need(reply.returncode == 0, "authenticated original GET failed: " + endpoint)
    return json.loads(reply.stdout)

def validate_run(repo, run, status):
    need(type(run) is dict and run.get("repository", {}).get("full_name") == repo,
         "cross-repository original")
    need(type(run.get("id")) is int and run["id"] > 0
         and type(run.get("run_attempt")) is int and run["run_attempt"] >= 1,
         "invalid original Run/attempt")
    need(run.get("status") == status and status in STATUSES, "unexpected active status")
    need(type(run.get("head_sha")) is str and SHA40.fullmatch(run["head_sha"]),
         "missing original head SHA")
    need(run.get("event") in ("schedule", "push", "pull_request", "workflow_run",
                              "workflow_dispatch", "repository_dispatch", "check_run"),
         "unsupported event kind")
    need(type(run.get("path")) is str
         and run["path"].startswith(".github/workflows/"), "missing workflow path")
    return {
        "runId": run["id"], "attempt": run["run_attempt"],
        "statusAtCapture": status, "sourceKind": run["event"],
        "workflowPath": run["path"], "headSha": run["head_sha"],
        "actor": run.get("actor", {}).get("login"),
        "createdAt": run.get("created_at"),
    }

def snapshot(fetch):
    report = {
        "schemaVersion": 1, "mode": "READONLY_NONPUBLISHING",
        "scope": "R11_LEGACY_NEW_WRITER_OVERLAP_OBSERVATION_ONLY",
        "captureUtc": datetime.now(timezone.utc).isoformat(),
        "repositories": [], "legacyWriterOverlapProven": False,
        "realHttp409InThisSnapshot": False, "cronRemovalAuthorized": False,
        "r11Acceptance": "PENDING", "r10BlockedApprovalPersistenceAccepted": False,
        "limitations": [
            "POINT_IN_TIME_GET_IS_NOT_DURABLE_WRITER_RACE",
            "NO_CAS_WRITE_OR_TOKEN_REVOKE_IN_THIS_AUDIT",
            "NO_PROOF_OF_MISSING_EVENT_FROM_EMPTY_RUN_SET",
            "BLOCKED_APPROVAL_CHECKPOINT_NOT_CREATED",
        ],
    }
    for repo in REPOS:
        branch = fetch("repos/" + repo + "/branches/main")
        need(branch.get("name") == "main" and branch.get("protected") is True,
             "unprotected main: " + repo)
        head = branch.get("commit", {}).get("sha")
        need(type(head) is str and SHA40.fullmatch(head), "invalid protected SHA")
        active = []
        for status in STATUSES:
            result = fetch("repos/" + repo + "/actions/runs?status=" + status
                           + "&per_page=100")
            runs = result.get("workflow_runs")
            need(type(runs) is list and type(result.get("total_count")) is int
                 and 0 <= result["total_count"] <= 100
                 and len(runs) == result["total_count"],
                 "GET not exhaustive for active Runs: " + repo + "/" + status)
            active.extend(validate_run(repo, item, status) for item in runs)
        ids = [item["runId"] for item in active]
        need(len(ids) == len(set(ids)), "same Run duplicated across active states")
        report["repositories"].append({
            "repository": repo, "protectedMainSha": head,
            "activeRunCount": len(active),
            "runs": sorted(active, key=lambda item: item["runId"]),
        })
    need(len(report["repositories"]) == 20, "20 repo scope incomplete")
    report["activeRunCount"] = sum(x["activeRunCount"] for x in report["repositories"])
    return report

def verify(original, fetch):
    need(original.get("schemaVersion") == 1
         and original.get("mode") == "READONLY_NONPUBLISHING"
         and original.get("scope") == "R11_LEGACY_NEW_WRITER_OVERLAP_OBSERVATION_ONLY"
         and original.get("legacyWriterOverlapProven") is False
         and original.get("realHttp409InThisSnapshot") is False
         and original.get("cronRemovalAuthorized") is False
         and original.get("r11Acceptance") == "PENDING"
         and original.get("r10BlockedApprovalPersistenceAccepted") is False,
         "unearned acceptance or approval")
    rows = original.get("repositories")
    need(type(rows) is list and len(rows) == len(REPOS)
         and [r.get("repository") for r in rows] == list(REPOS),
         "scope changed or incomplete")
    seen = set()
    for row in rows:
        repo = row["repository"]
        need(SHA40.fullmatch(row.get("protectedMainSha", "")), "invalid HEAD")
        runs = row.get("runs")
        need(type(runs) is list and len(runs) == row.get("activeRunCount"),
             "per-repo count mismatch")
        for run in runs:
            run_id = run.get("runId")
            need(type(run_id) is int and (repo, run_id) not in seen,
                 "duplicate / invalid Run")
            seen.add((repo, run_id))
            need(run.get("statusAtCapture") in STATUSES,
                 "snapshot claims non-active run")
            latest = fetch("repos/" + repo + "/actions/runs/" + str(run_id))
            need(latest.get("id") == run_id
                 and latest.get("run_attempt") == run["attempt"]
                 and latest.get("head_sha") == run["headSha"]
                 and latest.get("event") == run["sourceKind"]
                 and latest.get("path") == run["workflowPath"]
                 and latest.get("repository", {}).get("full_name") == repo
                 and latest.get("actor", {}).get("login") == run["actor"],
                 "independent original identity mismatch")
            # An original queued Run may legitimately have since completed.
    need(original.get("activeRunCount") == len(seen), "total count mismatch")
    return {"verifiedOriginalRunCount": len(seen), "independentGet": True,
            "readOnly": True, "cronRemovalAuthorized": False,
            "r11Acceptance": "PENDING"}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="issue311-r11-overlap-snapshot.json")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    need(os.environ.get("GITHUB_REPOSITORY") == "pgextwin/build"
         and os.environ.get("GITHUB_REF") == "refs/heads/main"
         and os.environ.get("GITHUB_EVENT_NAME") == "push"
         and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
         and os.environ.get("GH_TOKEN"), "not original protected main push")
    if args.verify:
        raw = Path(args.output).read_bytes()
        proof = verify(json.loads(raw), gh)
        print("R11_INDEPENDENT_ORIGINAL_GET", json.dumps(proof, sort_keys=True),
              "originalJsonSha256", hashlib.sha256(raw).hexdigest())
    else:
        original = snapshot(gh)
        raw = (json.dumps(original, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":")) + "\n").encode()
        Path(args.output).write_bytes(raw)
        print("R11_PROTECTED_ACTIVE_RUN_SNAPSHOT", len(REPOS), "active",
              original["activeRunCount"], "jsonSha256",
              hashlib.sha256(raw).hexdigest())

if __name__ == "__main__":
    main()
