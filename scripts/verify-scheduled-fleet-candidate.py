#!/usr/bin/env python3
"""Read an authentic completed central fleet watch before scheduled candidate creation.

This program never writes a GitHub resource. It can only output mode=candidate
when the daily central BUILD scan reported a specific pinned repository update.
The existing local candidate-update workflow independently resolves and rechecks
the stable upstream commit before creating a draft PR. Never authorizes PUBLISH.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
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
# Every blob must match across the original scheduled scan, current protected
# build main and the immutable reusable-workflow checkout before live replay.
REPLAY_SOURCE_PATHS = (
    ".github/workflows/fleet-upstream-watch.yml",
    "scripts/fleet-upstream-watch.py",
    "metadata/automation-fleet.json",
)


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


def validate(report, run, build_branch, target_branch, repository, head, pin, now, *,
             live_replay=False, source_equivalent=False):
    need(repository in REPOSITORIES, "unregistered candidate repository")
    expected = COHORT_14 if repository.split("/")[1] in OLD else COHORT_3
    need(pin == expected and SHA.fullmatch(head), "invalid immutable detector cohort")
    current_build = (build_branch.get("commit") or {}).get("sha")
    need(type(current_build) is str and SHA.fullmatch(current_build),
         "current central protected main SHA missing")
    # Never silently accept a stale scheduled scan. Only a new, complete
    # 17-repo live replay from byte-identical immutable scan sources may
    # replace the old schedule-head binding; target main stays exact.
    if current_build != run.get("head_sha"):
        need(live_replay is True and source_equivalent is True,
             "central SHA drift without authenticated immutable live replay")
    for branch, sha in ((build_branch, current_build if live_replay and
                         source_equivalent else run.get("head_sha")),
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
    if live_replay:
        # An independent fresh GET-only fleet rescan is an alternative evidence
        # path, NOT the central artifact bytes. It must complete after the
        # genuine central schedule and while this verifier is running.
        need(finished - timedelta(minutes=5) <= produced <= now + timedelta(minutes=5)
             and now - produced < timedelta(minutes=5),
             "live fleet recheck is stale or predates central schedule")
    else:
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
    need(url.startswith(HOST) and "\n" not in url and "\r" not in url,
         "untrusted API host")

    def request_json(credential):
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if credential:
            headers["Authorization"] = "Bearer " + credential
        request = Request(url, headers=headers, method="GET")
        try:
            with build_opener(NoRedirect()).open(request, timeout=20) as response:
                need(response.status == 200, "GitHub HTTP failure")
                raw = response.read(2 * 1024 * 1024 + 1)
                need(len(raw) <= 2 * 1024 * 1024, "GitHub response too large")
                return strict_json(raw.decode("utf-8"))
        except (HTTPError, URLError, OSError, ValueError, UnicodeError):
            raise Denied("GitHub GET unavailable") from None

    try:
        return request_json(token)
    except Denied:
        # This is a PUBLIC repository. Caller-scoped GITHUB_TOKEN is not
        # authorized to read build's cross-repo Actions endpoints by default.
        # GET public metadata anonymously rather than seeking Actions:read
        # privileges, but only for the exact fixed central build repository.
        # The full protected-main/immutable-run/17-row checks still apply.
        if url.startswith(HOST + BUILD + "/"):
            return request_json(None)
        raise


def git_blob_sha(data):
    """GitHub SHA-1 blob identity for the actual immutable checkout bytes."""
    need(type(data) is bytes, "immutable scan source is not bytes")
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") +
                        bytes([0]) + data).hexdigest()


def verify_replay_source_blobs(scheduled_sha, current_sha, token):
    """Fail closed unless scheduled, current and pinned scanner bytes agree."""
    need(type(scheduled_sha) is str and SHA.fullmatch(scheduled_sha)
         and type(current_sha) is str and SHA.fullmatch(current_sha)
         and scheduled_sha != current_sha,
         "central SHA drift proof has invalid refs")
    root = Path(__file__).resolve().parents[1]
    local = {}
    for path in REPLAY_SOURCE_PATHS:
        source = root / path
        need(source.is_file() and not source.is_symlink(),
             "pinned immutable scan source missing or symlinked")
        local[path] = git_blob_sha(source.read_bytes())
    for commit_sha in (scheduled_sha, current_sha):
        tree = api(HOST + BUILD + "/git/trees/" + commit_sha + "?recursive=1", token)
        need(type(tree) is dict and tree.get("truncated") is False
             and type(tree.get("tree")) is list
             and type(tree.get("sha")) is str and SHA.fullmatch(tree["sha"]),
             "incomplete central Git source inventory")
        rows = [item for item in tree["tree"] if type(item) is dict
                and item.get("path") in REPLAY_SOURCE_PATHS]
        need(len(rows) == len(REPLAY_SOURCE_PATHS)
             and len({item["path"] for item in rows}) == len(REPLAY_SOURCE_PATHS)
             and all(item.get("type") == "blob" and item.get("mode") == "100644"
                     and item.get("sha") == local[item["path"]] for item in rows),
             "scheduled/current fleet scan code or policy differs from pinned immutable source")
    return True


def replay_live_fleet(token):
    """Fallback when a caller GITHUB_TOKEN cannot download build's artifact.

    No cross-repository Actions token, credential widening, workflow dispatch,
    candidate writing or Release privilege is needed. Reuse the same pinned
    17-extension fleet detector and its per-repository protected-main double
    GETs. An indeterminate row (or inaccessible public API) is always DENY.
    """
    import runpy
    root = Path(__file__).resolve().parents[1]
    script_dir = str(root / "scripts")
    sys.path.insert(0, script_dir)
    try:
        scan = runpy.run_path(
            str(root / "scripts" / "fleet-upstream-watch.py"),
            run_name="pgextwin_fleet_candidate_readonly_replay")["scan"]
    finally:
        sys.path.remove(script_dir)
    policy = strict_json(
        (root / "metadata" / "automation-fleet.json").read_text("utf-8"))
    return scan(policy, lambda url: api(url, token))


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
    source_equivalent = False
    if build_branch.get("commit", {}).get("sha") != exact.get("head_sha"):
        # The original successful schedule remains necessary, but its old
        # source cannot authorize fresh work unless the scanner/policy blobs
        # match the pinned immutable reusable workflow and current main.
        source_equivalent = verify_replay_source_blobs(
            exact["head_sha"], build_branch["commit"]["sha"], token)
        report = replay_live_fleet(token)
        live_replay = True
        print("FLEET_EVIDENCE=FRESH_17_REPLAY_WITH_IDENTICAL_IMMUTABLE_SOURCES")
    else:
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
            live_replay = proc.returncode != 0
            if live_replay:
                # A repo-scoped GITHUB_TOKEN cannot be assumed to have Actions:read
                # on pgextwin/build. NEVER treat a failed archive download as
                # proof of a successful candidate; rescan all 17 from protected
                # repository sources and validate that independent evidence.
                report = replay_live_fleet(token)
                print("FLEET_EVIDENCE=INDEPENDENT_GET_ONLY_REPLAY; central artifact not downloaded")
            else:
                root = Path(temp)
                need({p.name for p in root.iterdir()} ==
                     {"fleet-upstream-watch.json", "fleet-upstream-watch.md"},
                     "unexpected files in central artifact")
                raw = (root / "fleet-upstream-watch.json").read_bytes()
                need(len(raw) <= 262144, "oversized fleet JSON")
                report = strict_json(raw.decode("utf-8"))

    mode = validate(report, exact, build_branch, target_branch, repository,
                    head, pin, datetime.now(timezone.utc),
                    live_replay=live_replay, source_equivalent=source_equivalent)
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
