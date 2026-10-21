#!/usr/bin/env python3
"""Read an authentic completed central fleet watch before scheduled candidate creation.

This program never writes a GitHub resource. It can only output mode=candidate
when the daily central BUILD scan reported a specific pinned repository update.
The existing local candidate-update workflow independently resolves and rechecks
the stable upstream commit before creating a draft PR. Never authorizes PUBLISH.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

HOST = "https://api.github.com/repos/"
BUILD = "pgextwin/build"
WATCH_PATH = ".github/workflows/fleet-upstream-watch.yml"
SHA = re.compile(r"^[0-9a-f]{40}$")
COHORT_14 = "16b886b9d06d6f389b369b87ce0c155767697ca0"
COHORT_3 = "acd6eb28be6d750e89b626fa4ccd4403e1265cd6"
OLD = {"pg_bigm", "pg_cron", "pg_hint_plan", "pgaudit", "set_user",
       "pg_repack", "pg_ivm", "pg_qualstats", "plpgsql_check", "hypopg",
       "wal2json", "pg_partman", "pg_stat_monitor", "orafce"}
NEW = {"pgtap", "pg_variables", "pg_store_plans"}
REPOSITORIES = {"pgextwin/" + r for r in OLD | NEW}


class Denied(ValueError):
    pass


def need(condition, explanation):
    if not condition:
        raise Denied(explanation)


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def timestamp(value):
    need(type(value) is str, "timestamp missing")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Denied("invalid timestamp") from None
    need(dt.tzinfo is not None, "timezone required")
    return dt.astimezone(timezone.utc)


def validate(report, run, build_branch, target_branch, repository, head, pin, now):
    need(repository in REPOSITORIES, "unregistered candidate repository")
    expected = COHORT_14 if repository.split("/")[1] in OLD else COHORT_3
    need(pin == expected and SHA.fullmatch(head), "invalid immutable detector cohort")
    for branch, sha in ((build_branch, run.get("head_sha")),
                        (target_branch, head)):
        need(type(branch) is dict and branch.get("protected") is True
             and (branch.get("commit") or {}).get("sha") == sha
             and SHA.fullmatch(sha), "protected exact-main evidence missing")
    need(type(run) is dict and run.get("event") == "schedule"
         and run.get("path") == WATCH_PATH and run.get("head_branch") == "main"
         and run.get("run_attempt") == 1
         and run.get("status") == "completed"
         and run.get("conclusion") == "success"
         and type(run.get("id")) is int and run["id"] > 0
         and (run.get("repository") or {}).get("full_name") == BUILD,
         "untrusted or incomplete central fleet run")
    started = timestamp(run.get("created_at"))
    finished = timestamp(run.get("updated_at"))
    need(started <= finished <= now + timedelta(minutes=5)
         and now - started < timedelta(hours=36), "central run expired or clock invalid")
    need(type(report) is dict and report.get("schemaVersion") == 1
         and report.get("scope") == "STABLE_UPSTREAM_GET_ONLY"
         and report.get("publication") == "DENY"
         and report.get("candidatePrCreated") is False
         and report.get("fleetSize") == 17
         and report.get("indeterminate") == 0,
         "central snapshot is not a successful read-only 17-fleet result")
    produced = timestamp(report.get("generatedAt"))
    need(started - timedelta(minutes=5) <= produced <= finished + timedelta(minutes=5),
         "snapshot timestamp differs from central run")
    entries = report.get("extensions")
    need(type(entries) is list and len(entries) == 17, "incomplete fleet snapshot")
    by_repo = {}
    count = 0
    for row in entries:
        need(type(row) is dict and row.get("repository") in REPOSITORIES
             and row["repository"] not in by_repo, "duplicate/unknown fleet entry")
        need(SHA.fullmatch(str(row.get("mainSha", ""))), "unverifiable extension main")
        updates = row.get("updates")
        need(type(updates) is list, "updates list absent")
        status = row.get("status")
        need(status in {"up-to-date", "update-available"}, "unsupported fleet result")
        need(bool(updates) == (status == "update-available"), "inconsistent candidate status")
        count += int(status == "update-available")
        by_repo[row["repository"]] = row
    need(set(by_repo) == REPOSITORIES and report.get("updatesDetected") == count,
         "partial or inconsistent 17-extension result")
    target = by_repo[repository]
    need(target["mainSha"] == head, "candidate manifest main changed since daily watch")
    return "candidate" if target["status"] == "update-available" else "none"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Denied("redirect from API denied")


def api(url, token):
    need(url.startswith(HOST) and "\n" not in url and "\r" not in url, "untrusted API host")
    request = Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }, method="GET")
    try:
        with build_opener(NoRedirect()).open(request, timeout=20) as response:
            need(response.status == 200, "GitHub HTTP failure")
            need("rel=\"next\"" not in response.headers.get("Link", ""),
                 "GitHub result pagination not resolved")
            raw = response.read(2 * 1024 * 1024 + 1)
            need(len(raw) <= 2 * 1024 * 1024, "GitHub response too large")
            return strict_json(raw.decode("utf-8"))
    except (HTTPError, URLError, OSError, ValueError, UnicodeError):
        raise Denied("authenticated GitHub GET unavailable") from None


def run(repository, head, pin, token):
    need(repository in REPOSITORIES and SHA.fullmatch(head), "invalid caller identity")
    need(os.environ.get("GITHUB_EVENT_NAME") == "schedule"
         and os.environ.get("GITHUB_REF") == "refs/heads/main"
         and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
         "only initial protected-main schedule may create a candidate")
    build_branch = api(HOST + BUILD + "/branches/main", token)
    target_branch = api(HOST + repository + "/branches/main", token)
    runs = api(HOST + BUILD + "/actions/runs?event=schedule&per_page=100", token)
    need(type(runs) is dict and type(runs.get("workflow_runs")) is list
         and len(runs["workflow_runs"]) <= 100, "central run list unavailable")
    matching = [r for r in runs["workflow_runs"] if type(r) is dict
                and r.get("path") == WATCH_PATH]
    need(bool(matching), "central fleet run absent")
    current = matching[0]  # GitHub API returns newest runs first; do not ignore failed latest runs.
    need(type(current.get("id")) is int and current["id"] > 0, "run id missing")
    exact = api(HOST + BUILD + "/actions/runs/" + str(current["id"]), token)
    need(exact.get("id") == current["id"] and exact.get("head_sha") == current.get("head_sha")
         and exact.get("conclusion") == "success" and exact.get("status") == "completed",
         "central run has not successfully completed")
    artifacts = api(HOST + BUILD + "/actions/runs/" + str(exact["id"])
                    + "/artifacts?per_page=100", token)
    need(type(artifacts) is dict and type(artifacts.get("artifacts")) is list
         and artifacts.get("total_count") == len(artifacts["artifacts"]),
         "complete central artifacts unavailable")
    matches = [a for a in artifacts["artifacts"] if type(a) is dict
               and a.get("name") == "fleet-upstream-watch"]
    need(len(matches) == 1 and matches[0].get("expired") is False
         and type(matches[0].get("size_in_bytes")) is int
         and 0 < matches[0]["size_in_bytes"] < 200000,
         "unique bounded unexpired central snapshot unavailable")
    with TemporaryDirectory(prefix="pgextwin-fleet-candidate-") as temp:
        command = ["gh", "run", "download", str(exact["id"]), "--repo", BUILD,
                   "--name", "fleet-upstream-watch", "--dir", temp]
        proc = subprocess.run(command, capture_output=True, text=True, check=False,
                              timeout=90, env=os.environ.copy())
        need(proc.returncode == 0, "central snapshot download denied")
        root = Path(temp)
        need({p.name for p in root.iterdir()} ==
             {"fleet-upstream-watch.json", "fleet-upstream-watch.md"},
             "unexpected files in central artifact")
        raw = (root / "fleet-upstream-watch.json").read_bytes()
        need(len(raw) <= 262144, "oversized fleet JSON")
        report = strict_json(raw.decode("utf-8"))
    mode = validate(report, exact, build_branch, target_branch, repository,
                    head, pin, datetime.now(timezone.utc))
    need(api(HOST + BUILD + "/branches/main", token) == build_branch
         and api(HOST + repository + "/branches/main", token) == target_branch,
         "protected main changed during candidate authorization")
    return mode


def main():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    pin = os.environ.get("PGEXTWIN_DETECTOR_SHA", "")
    token = os.environ.get("GH_TOKEN", "")
    try:
        need(bool(token), "GitHub token missing")
        mode = run(repo, sha, pin, token)
        output = os.environ.get("GITHUB_OUTPUT")
        need(bool(output), "GitHub output not available")
        with open(output, "a", encoding="utf-8") as f:
            f.write("mode=" + mode + "\n")
        print("SCHEDULED_FLEET_CANDIDATE=" + mode + "; PUBLISH=DENY")
        return 0
    except (Denied, OSError, subprocess.TimeoutExpired, TypeError, KeyError, ValueError) as exc:
        print("SCHEDULED_FLEET_CANDIDATE=DENY; " + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
