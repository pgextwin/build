#!/usr/bin/env python3
"""17/future-fleet authenticated READ-ONLY Publisher intake (Issue #75).

Identify *potential* genuine signed candidates, NEVER authorize publication.
A successful Windows CI, successful root Run, or artifact listing alone is not
Sigstore verification, an independent release receipt or Publisher authority.
This script executes GET only, never enters the publisher secret Environment.
"""
from __future__ import annotations
from collections import Counter
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "publisher_intake_scope", ROOT / "publisher-scoped-token.py")
_scope = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_scope)
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
SHA = re.compile(r"^[a-f0-9]{40}$")
MAX_RUNS = 100
# Filter at the GitHub API, not after a schedule-heavy first page.
# Per-hour schedule Runs must never evict the original signed main/push Run.
SOURCE_PUSH_RUNS = "actions/workflows/update-watch.yml/runs?event=push&branch=main&per_page=100"
MAX_ITEMS = 100
SIGNED_JOBS = (
    "Audit real single manifest-only protected candidate main push",
    "Attest original candidate after verified protected main merge (NO PUBLISH)",
    "Verify actual signed ZIP/SPDX/Grype provenance without Publisher rights",
    "Independently reverify signed candidate before future Publisher (NO PUBLISH)",
)
SIGNED_ARTIFACTS = {
    "automatic-signed-candidate-audit-nonpublishing",
    "independent-signed-publisher-preflight-nonpublishing",
}

class Denied(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Denied(reason)

def unique(pairs):
    out = {}
    for k, v in pairs:
        require(k not in out, "duplicate GitHub JSON key")
        out[k] = v
    return out

def github(repo, suffix):
    """Authenticated GET only; no credential or untrusted GitHub URL output."""
    require(type(repo) is str and REPO.fullmatch(repo), "non-fleet repository")
    allowed = (
        suffix == "branches/main"
        or suffix == SOURCE_PUSH_RUNS
        or re.fullmatch(r"actions/runs/[1-9][0-9]*/jobs\?per_page=100", suffix)
        or re.fullmatch(r"actions/runs/[1-9][0-9]*/artifacts\?per_page=100", suffix)
    )
    require(allowed, "non-allowlisted or mutating GitHub resource")
    require(bool(os.environ.get("GH_TOKEN")), "read-only GitHub token unavailable")
    result = subprocess.run(["gh", "api", "--method", "GET",
                             "repos/" + repo + "/" + suffix],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=False, timeout=40)
    require(result.returncode == 0 and len(result.stdout) <= 3*1024*1024,
            "GitHub GET failed or incomplete")
    obj = json.loads(result.stdout, object_pairs_hook=unique)
    require(type(obj) is dict, "unexpected GitHub GET response")
    return obj

def examine(repo, branch, runs, *, read_jobs, read_artifacts):
    """Evaluate the EXACT protected main and original signed push; never PUBLISH."""
    require(type(repo) is str and REPO.fullmatch(repo), "invalid source repository")
    require(type(branch) is dict and branch.get("name") == "main"
            and branch.get("protected") is True
            and type(branch.get("commit")) is dict
            and type(branch["commit"].get("sha")) is str
            and SHA.fullmatch(branch["commit"]["sha"]),
            "unprotected or unknown current main")
    sha = branch["commit"]["sha"]
    require(type(runs) is dict and type(runs.get("workflow_runs")) is list
            and len(runs["workflow_runs"]) <= MAX_RUNS
            and all(type(r) is dict for r in runs["workflow_runs"]),
            "missing/oversized Run inventory")
    matches = [r for r in runs["workflow_runs"] if
               r.get("head_sha") == sha and r.get("event") == "push"
               and r.get("path") == ".github/workflows/update-watch.yml"
               and r.get("head_branch") == "main"]
    row = {"repository": repo, "mainSha": sha, "candidateRunId": None,
           "status": "NO_ORIGINAL_SIGNED_PUSH_ON_CURRENT_MAIN",
           "needsRealSigstoreReverification": True,
           "publisherTokenRequested": False,
           "publicationAuthorized": False}
    if not matches:
        return row
    # A re-run of a successful prior attempt does not create an original
    # signed candidate. Never promote it in place of an attempt-1 success.
    run = matches[0]
    if not (type(run.get("id")) is int and run["id"] > 0
            and type(run.get("run_attempt")) is int
            and run["run_attempt"] == 1
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and (run.get("repository") or {}).get("full_name") == repo):
        row["status"] = "ORIGINAL_PUSH_NOT_SUCCESSFULLY_ATTESTED"
        return row
    run_id = run["id"]
    row["candidateRunId"] = run_id
    jobs = read_jobs(run_id)
    require(type(jobs) is dict and type(jobs.get("total_count")) is int
            and 0 <= jobs["total_count"] < MAX_ITEMS
            and type(jobs.get("jobs")) is list
            and len(jobs["jobs"]) == jobs["total_count"]
            and all(type(j) is dict for j in jobs["jobs"]),
            "incomplete signed job inventory")
    names = [j.get("name") for j in jobs["jobs"]]
    for needed in SIGNED_JOBS:
        hits = [j for j in jobs["jobs"]
                if type(j.get("name")) is str
                and (j["name"] == needed or j["name"].endswith(" / " + needed))]
        if len(hits) != 1 or hits[0].get("status") != "completed" or hits[0].get("conclusion") != "success":
            row["status"] = "SIGNED_JOB_CHAIN_INCOMPLETE"
            return row
    artifacts = read_artifacts(run_id)
    require(type(artifacts) is dict and type(artifacts.get("total_count")) is int
            and 0 <= artifacts["total_count"] < MAX_ITEMS
            and type(artifacts.get("artifacts")) is list
            and len(artifacts["artifacts"]) == artifacts["total_count"]
            and all(type(a) is dict for a in artifacts["artifacts"]),
            "partial/ambiguous signed-artifact inventory")
    artifact_names = [a.get("name") for a in artifacts["artifacts"]]
    if not (all(artifact_names.count(name) == 1 for name in SIGNED_ARTIFACTS)
            and all(a.get("expired") is False and type(a.get("size_in_bytes")) is int
                    and a["size_in_bytes"] > 0 for a in artifacts["artifacts"]
                    if a.get("name") in SIGNED_ARTIFACTS)):
        row["status"] = "SIGNED_AUDIT_ARTIFACTS_INCOMPLETE"
        return row
    # Still NOT publication-ready. Real independent downloads, exact-byte SHA,
    # gh Sigstore, Grype and current policies must be re-evaluated by a
    # separately authorized Publisher before any actual Release.
    row["status"] = "SIGNED_RUN_FOUND_REVERIFICATION_REQUIRED"
    return row

def scan(fleet, *, get):
    require(type(fleet) is dict and type(fleet.get("entries")) is list
            and bool(fleet["entries"]), "missing protected Publisher fleet")
    names = [r.get("repository") for r in fleet["entries"] if type(r) is dict]
    require(len(names) == len(fleet["entries"]) and len(set(names)) == len(names),
            "duplicate/malformed fleet")
    for name in names:
        _scope.valid_fleet(fleet, name, release_policy=fleet.get('releasePolicy'))
    rows = []
    for repo in names:
        try:
            row = examine(
                repo, get(repo,"branches/main"),
                get(repo,SOURCE_PUSH_RUNS),
                read_jobs=lambda run_id, r=repo: get(
                    r, f"actions/runs/{run_id}/jobs?per_page=100"),
                read_artifacts=lambda run_id, r=repo: get(
                    r, f"actions/runs/{run_id}/artifacts?per_page=100"))
        except (Denied, OSError, ValueError, KeyError, TypeError,
                subprocess.TimeoutExpired):
            row = {"repository": repo, "mainSha": None,
                   "candidateRunId": None, "status": "INDETERMINATE",
                   "needsRealSigstoreReverification": True,
                   "publisherTokenRequested": False,
                   "publicationAuthorized": False}
        rows.append(row)
    counts = dict(sorted(Counter(r["status"] for r in rows).items()))
    return {"schemaVersion": 1, "status": "NONPUBLISHING_PUBLISHER_INTAKE",
            "repositoryCount": len(names), "counts": counts, "rows": rows,
            "genuineScheduleVerified": False,
            "verifiedSignedReleaseArtifacts": False,
            "publisherWriteAuthorized": False,
            "publishableReceipt": False, "publicationAuthorized": False}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fleet", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--summary", required=True)
    a = ap.parse_args()
    try:
        require(os.getenv("GITHUB_REPOSITORY") == "pgextwin/build"
                and os.getenv("GITHUB_REF") == "refs/heads/main"
                and os.getenv("GITHUB_EVENT_NAME") in ("schedule", "push"),
                "not a protected central scheduling context")
        fleet = json.loads(Path(a.fleet).read_text("utf-8"),
                           object_pairs_hook=unique)
        result = scan(fleet, get=github)
        result["observationEvent"] = os.environ["GITHUB_EVENT_NAME"]
        Path(a.output).write_text(json.dumps(result, indent=2)+"\n","utf-8")
        lines = ["# Read-only Publisher intake (NO RELEASE)",
                 f"Protected fleet scanned: {result['repositoryCount']}",
                 f"Event: {result['observationEvent']} (does not prove a signed Release)",
                 "PUBLISH_DENY; GO B/G4/G5 NO_GO; no Publisher token accessed.",
                 "Status counts:"]
        lines.extend("- "+k+": "+str(v) for k,v in result["counts"].items())
        Path(a.summary).write_text("\n".join(lines)+"\n","utf-8")
        print(result["status"]+"; "+str(result["counts"])+"; EVENT="+result["observationEvent"]+"; PUBLISH_DENY")
        return 0
    except (Denied, OSError, ValueError, KeyError, TypeError) as exc:
        print("PUBLISHER_INTAKE_DENY: "+str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
