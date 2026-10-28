#!/usr/bin/env python3
"""Read an authentic completed central fleet watch before scheduled candidate creation.

This program never writes a GitHub resource. It can only output mode=candidate
when the hourly central BUILD scan reported a specific pinned repository update.
The existing local candidate-update workflow independently resolves and rechecks
the stable upstream commit before creating a draft PR. Never authorizes PUBLISH.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
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
# These 17 existing trusted repos remain mandatory, not the maximum count.
# No future repository is authorized merely by its name matching a regex.
HISTORICAL_FLOOR = frozenset(REPOSITORIES)
MAX_FLEET = 128
ROOT = Path(__file__).resolve().parents[1]
_fleet_spec = importlib.util.spec_from_file_location(
    "scheduled_shared_fleet_policy", ROOT / "scripts/fleet-policy.py")
fleet_policy = importlib.util.module_from_spec(_fleet_spec)
_fleet_spec.loader.exec_module(fleet_policy)


def protected_fleet(registry=None):
    """Exact immutable-checkout manifest, not live unpinned caller metadata."""
    try:
        policy = registry if registry is not None else fleet_policy.read(
            ROOT / "metadata/automation-fleet.json")
        rows = fleet_policy.members(policy, require_build=True)
    except (fleet_policy.Denied, OSError, ValueError, TypeError, KeyError) as exc:
        raise Denied("untrusted protected central fleet manifest") from exc
    need(HISTORICAL_FLOOR.issubset(rows) and
         len(HISTORICAL_FLOOR) <= len(rows) <= MAX_FLEET,
         "protected fleet lost mandatory history or exceeded audit capacity")
    return frozenset(rows)

# Every blob must match across the original scheduled scan, current protected
# build main and the immutable reusable-workflow checkout before live replay.
REPLAY_SOURCE_PATHS = (
    ".github/workflows/fleet-upstream-watch.yml",
    "scripts/fleet-upstream-watch.py",
    "scripts/fleet-control.py",
    "scripts/fleet-policy.py",
    "scripts/update_watch_lib.py",
    "metadata/automation-fleet.json",
)


class Denied(ValueError):
    pass


class SnapshotMainChanged(Denied):
    """An otherwise authentic snapshot predates the exact caller main."""
    pass


class Deferred(Exception):
    """No candidate decision: the genuine central scheduled evidence is unavailable.

    This is never authorization. The central run retains its own failure status;
    the dependent local workflow may finish as a labelled safe no-op and check
    the next scheduled interval without falsely reporting a Windows failure.
    """
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
             live_replay=False, source_equivalent=False, registry=None,
             workflow_sha=None):
    approved = protected_fleet(registry)
    need(repository in approved, "unregistered candidate repository")
    need(type(head) is str and SHA.fullmatch(head), "invalid candidate main SHA")
    current_build = (build_branch.get("commit") or {}).get("sha")
    need(type(current_build) is str and SHA.fullmatch(current_build),
         "current central protected main SHA missing")
    if repository in HISTORICAL_FLOOR:
        expected = COHORT_14 if repository.split("/")[1] in OLD else COHORT_3
        need(pin == expected, "invalid immutable historical detector cohort")
    else:
        # A newly registered source must invoke this reusable workflow by an
        # immutable central source SHA, surfaced by GitHub job.workflow_sha.
        # The same SHA must be the actual protected current/scheduled build
        # main, never a caller-selected arbitrary repository or workflow ref.
        source_sha = workflow_sha if workflow_sha is not None else os.environ.get(
            "PGEXTWIN_WORKFLOW_SHA")
        need(type(source_sha) is str and SHA.fullmatch(source_sha)
             and pin == source_sha
             and source_sha in (current_build, run.get("head_sha")),
             "future detector lacks exact protected immutable source binding")
    # Never silently accept a stale scheduled scan. Only a new, complete
    # registered-fleet live replay from identical immutable scan sources may
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
         and now - started < timedelta(hours=3), "central run expired or clock invalid")
    need(type(report) is dict and report.get("schemaVersion") == 1
         and report.get("scope") == "STABLE_UPSTREAM_GET_ONLY"
         and report.get("publication") == "DENY"
         and report.get("candidatePrCreated") is False
         and report.get("fleetSize") == len(approved)
         and report.get("indeterminate") == 0,
         "central snapshot does not cover the exact protected fleet")
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
    need(type(entries) is list and len(entries) == len(approved), "incomplete fleet snapshot")
    by_repo = {}
    count = 0
    for row in entries:
        need(type(row) is dict and row.get("repository") in approved
             and row["repository"] not in by_repo, "duplicate/unknown fleet entry")
        need(SHA.fullmatch(str(row.get("mainSha", ""))), "unverifiable extension main")
        updates = row.get("updates")
        need(type(updates) is list, "updates list absent")
        status = row.get("status")
        need(status in {"up-to-date", "update-available"}, "unsupported fleet result")
        need(bool(updates) == (status == "update-available"), "inconsistent candidate status")
        count += int(status == "update-available")
        by_repo[row["repository"]] = row
    need(set(by_repo) == approved and report.get("updatesDetected") == count,
         "partial or inconsistent registered fleet result")
    target = by_repo[repository]
    if target["mainSha"] != head:
        raise SnapshotMainChanged("candidate manifest main changed since daily watch")
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
        # The full protected-main/immutable-run/all-row checks still apply.
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
         and type(current_sha) is str and SHA.fullmatch(current_sha),
         "central source proof has invalid refs")
    root = Path(__file__).resolve().parents[1]
    local = {}
    for path in REPLAY_SOURCE_PATHS:
        source = root / path
        need(source.is_file() and not source.is_symlink(),
             "pinned immutable scan source missing or symlinked")
        local[path] = git_blob_sha(source.read_bytes())
    for commit_sha in dict.fromkeys((scheduled_sha, current_sha)):
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
    registered-fleet detector and its per-repository protected-main double
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



def original_outer_sha256(blob, artifact, report):
    """Actual original Actions archive bytes, not a metadata-only digest."""
    from io import BytesIO
    from zipfile import ZipFile, BadZipFile
    digest = artifact.get("digest") if type(artifact) is dict else None
    need(type(digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", digest),
         "original archive metadata digest absent")
    need(type(blob) is bytes and 0 < len(blob) <= 2 * 1024 * 1024,
         "original archive bytes absent/oversized")
    computed = hashlib.sha256(blob).hexdigest()
    need(computed == digest[7:], "original outer archive digest mismatch")
    try:
        with ZipFile(BytesIO(blob)) as z:
            need(sorted(z.namelist()) ==
                 ["fleet-upstream-watch.json", "fleet-upstream-watch.md"]
                 and all(i.file_size <= 262144 for i in z.infolist()),
                 "untrusted original outer ZIP layout")
            decoded = strict_json(z.read("fleet-upstream-watch.json").decode("utf-8"))
    except (BadZipFile, OSError, RuntimeError, KeyError, UnicodeError, ValueError) as exc:
        raise Denied("invalid original outer ZIP") from exc
    need(decoded == report, "original archive report differs from validated snapshot")
    return computed


def candidate_receipt(mode, central, artifact, report, build_branch,
                      repository, head, source_kind, actual_outer_sha=None):
    """A source-typed preflight record. Never creates Publisher authority."""
    need(mode in ("none", "candidate"), "unaccepted receipt mode")
    need(source_kind in ("ORIGINAL_OUTER_ZIP_VERIFIED",
                         "ORIGINAL_EXTRACTED_UNVERIFIED_OUTER_ZIP",
                         "INDEPENDENT_GET_ONLY_REPLAY"), "invalid receipt source kind")
    need(type(artifact) is dict and type(artifact.get("id")) is int
         and artifact["id"] > 0 and artifact.get("expired") is False
         and type(artifact.get("digest")) is str
         and re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]),
         "central original artifact identity/digest missing")
    if actual_outer_sha is None:
        need(source_kind != "ORIGINAL_OUTER_ZIP_VERIFIED",
             "unverified original ZIP promoted as genuine bytes")
    else:
        need(source_kind == "ORIGINAL_OUTER_ZIP_VERIFIED"
             and actual_outer_sha == artifact["digest"][7:],
             "digest moved across source kinds")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    need(run_id.isdecimal() and int(run_id) > 0
         and os.environ.get("GITHUB_EVENT_NAME") == "schedule"
         and os.environ.get("GITHUB_REF") == "refs/heads/main"
         and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
         "original local schedule identity absent")
    need(central.get("event") == "schedule"
         and central.get("path") == WATCH_PATH
         and central.get("head_branch") == "main"
         and central.get("run_attempt") == 1
         and central.get("status") == "completed"
         and central.get("conclusion") == "success"
         and type(central.get("id")) is int and central["id"] > 0
         and (central.get("repository") or {}).get("full_name") == BUILD,
         "central schedule receipt identity absent")
    need(report.get("fleetSize") == len(protected_fleet())
         and len(report.get("extensions", [])) == len(protected_fleet()),
         "partial fleet receipt denied")
    canonical = json.dumps(report, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":")).encode("utf-8")
    return {
        "schemaVersion": 1, "status": "NONPUBLISHING_PREFLIGHT",
        "sourceKind": source_kind, "repository": repository,
        "localRunId": int(run_id), "localRunAttempt": 1,
        "localProtectedMainSha": head,
        "centralRunId": central["id"], "centralRunAttempt": 1,
        "centralScheduledHeadSha": central["head_sha"],
        "centralProtectedMainSha": build_branch["commit"]["sha"],
        "centralArtifactId": artifact["id"],
        "centralArtifactDigestMetadata": artifact["digest"],
        "originalOuterZipSha256Verified": actual_outer_sha,
        "originalOuterZipByteVerified": actual_outer_sha is not None,
        "reportCanonicalSha256": hashlib.sha256(canonical).hexdigest(),
        "registeredFleetCount": len(protected_fleet()), "decision": mode,
        "publisherSourceKindAuthorized": False, "publicationAuthorized": False,
    }


def run(repository, head, pin, token, receipt_out=None):
    need(repository in protected_fleet() and type(head) is str and SHA.fullmatch(head),
         "unregistered or invalid caller identity")
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
    if not matching:
        raise Deferred("NO_GENUINE_CENTRAL_FLEET_SCHEDULE")
    current = matching[0]  # Never replace a failed newest schedule with an older success.
    need(type(current.get("id")) is int and current["id"] > 0, "run id missing")
    exact = api(HOST + BUILD + "/actions/runs/" + str(current["id"]), token)
    need(exact.get("id") == current["id"] and exact.get("head_sha") == current.get("head_sha"),
         "central run identity mismatch")
    if exact.get("status") != "completed" or exact.get("conclusion") != "success":
        # Real central failures stay visible in their original runs. No fallback
        # to old runs, push smoke, workflow_dispatch or unverified candidates.
        raise Deferred("LATEST_GENUINE_CENTRAL_SCAN_NOT_SUCCESSFUL")
    # A genuinely successful but time-expired central schedule is operational
    # unavailability, not an eligible candidate and not a local CI failure.
    # It must NEVER authorize an old result or silently extend its TTL.
    # Malformed/future clocks or spoofed schedule identity still hard-DENY.
    need(exact.get("event") == "schedule"
         and exact.get("path") == WATCH_PATH
         and exact.get("head_branch") == "main"
         and exact.get("run_attempt") == 1
         and (exact.get("repository") or {}).get("full_name") == BUILD,
         "central schedule identity invalid")
    now = datetime.now(timezone.utc)
    started, finished = timestamp(exact.get("created_at")), timestamp(exact.get("updated_at"))
    need(started <= finished <= now + timedelta(minutes=5),
         "central schedule clock invalid")
    if now - started >= timedelta(hours=3):
        raise Deferred("LATEST_GENUINE_CENTRAL_SCAN_EXPIRED")

    source_equivalent = False
    selected_artifact = None
    actual_outer_sha = None
    if build_branch.get("commit", {}).get("sha") != exact.get("head_sha"):
        # The original successful schedule remains necessary, but its old
        # source cannot authorize fresh work unless the scanner/policy blobs
        # match the pinned immutable reusable workflow and current main.
        source_equivalent = verify_replay_source_blobs(
            exact["head_sha"], build_branch["commit"]["sha"], token)
        report = replay_live_fleet(token)
        live_replay = True
        print("FLEET_EVIDENCE=FRESH_FLEET_REPLAY_WITH_IDENTICAL_IMMUTABLE_SOURCES")
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
        selected_artifact = matches[0]
        with TemporaryDirectory(prefix="pgextwin-fleet-candidate-") as temp:
            command = ["gh", "run", "download", str(exact["id"]), "--repo", BUILD,
                       "--name", "fleet-upstream-watch", "--dir", temp]
            proc = subprocess.run(command, capture_output=True, text=True, check=False,
                                  timeout=90, env=os.environ.copy())
            live_replay = proc.returncode != 0
            if live_replay:
                # A repo-scoped GITHUB_TOKEN cannot be assumed to have Actions:read
                # on pgextwin/build. NEVER treat a failed archive download as
                # proof of a successful candidate; rescan the complete protected fleet from
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
                if receipt_out is not None:
                    # A gh run extraction alone never proves outer ZIP bytes.
                    result = subprocess.run(
                        ["gh", "api", "repos/" + BUILD + "/actions/artifacts/"
                         + str(selected_artifact["id"]) + "/zip"],
                        capture_output=True, text=False, check=False,
                        timeout=90, env=os.environ.copy())
                    if result.returncode == 0:
                        actual_outer_sha = original_outer_sha256(
                            result.stdout, selected_artifact, report)

    try:
        mode = validate(report, exact, build_branch, target_branch, repository,
                        head, pin, datetime.now(timezone.utc),
                        live_replay=live_replay, source_equivalent=source_equivalent)
    except SnapshotMainChanged:
        # A successful archive download can still contain the old packaging
        # main after a protected merge. Never authorize that stale row. Only
        # after the original snapshot passes every other authentication gate,
        # bind the entire scanner/policy closure to scheduled/current/pinned
        # source and perform one distinct fresh complete GET-only replay.
        # A drift during an existing replay remains DENY, not an endless retry.
        if live_replay:
            raise
        source_equivalent = verify_replay_source_blobs(
            exact["head_sha"], build_branch["commit"]["sha"], token)
        report = replay_live_fleet(token)
        live_replay = True
        actual_outer_sha = None
        print("FLEET_EVIDENCE=FRESH_FLEET_REPLAY_AFTER_PROTECTED_TARGET_MAIN_CHANGE; "
              "central artifact target row was not accepted")
        mode = validate(report, exact, build_branch, target_branch, repository,
                        head, pin, datetime.now(timezone.utc),
                        live_replay=live_replay, source_equivalent=source_equivalent)
    need(api(HOST + BUILD + "/branches/main", token) == build_branch
         and api(HOST + repository + "/branches/main", token) == target_branch,
         "protected main changed during candidate authorization")
    if receipt_out is not None:
        if selected_artifact is None:
            found = api(HOST + BUILD + "/actions/runs/" + str(exact["id"])
                        + "/artifacts?per_page=100", token)
            need(type(found) is dict and type(found.get("artifacts")) is list
                 and found.get("total_count") == len(found["artifacts"]),
                 "original artifact inventory incomplete")
            matches = [a for a in found["artifacts"] if type(a) is dict
                       and a.get("name") == "fleet-upstream-watch"]
            need(len(matches) == 1, "original artifact ambiguous")
            selected_artifact = matches[0]
        source_kind = ("INDEPENDENT_GET_ONLY_REPLAY" if live_replay else
                       "ORIGINAL_OUTER_ZIP_VERIFIED" if actual_outer_sha else
                       "ORIGINAL_EXTRACTED_UNVERIFIED_OUTER_ZIP")
        receipt_out.update(candidate_receipt(
            mode, exact, selected_artifact, report, build_branch,
            repository, head, source_kind, actual_outer_sha))
    return mode


def main():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    pin = os.environ.get("PGEXTWIN_DETECTOR_SHA", "")
    token = os.environ.get("GH_TOKEN", "")
    try:
        need(bool(token), "GitHub token missing")
        receipt = {}
        mode = run(repo, sha, pin, token, receipt_out=receipt)
        receipt_path = os.environ.get("PGEXTWIN_RECEIPT_PATH")
        need(bool(receipt_path) and bool(receipt), "immutable receipt path missing")
        Path(receipt_path).write_text(
            json.dumps(receipt, sort_keys=True, indent=2) + "\\n", encoding="utf-8")
        output = os.environ.get("GITHUB_OUTPUT")
        need(bool(output), "GitHub output not available")
        with open(output, "a", encoding="utf-8") as f:
            f.write("mode=" + mode + "\nreceipt_ready=true\n")
        print("SCHEDULED_FLEET_CANDIDATE=" + mode + "; PUBLISH=DENY; "
              "ORIGINAL_CENTRAL_RUN=" + str(receipt["centralRunId"]) +
              "; ORIGINAL_CENTRAL_ARTIFACT_ID=" + str(receipt["centralArtifactId"]) +
              "; SOURCE_KIND=" + receipt["sourceKind"] +
              "; ORIGINAL_OUTER_SHA256_VERIFIED=" +
              str(receipt["originalOuterZipByteVerified"]).lower())
        return 0
    except Deferred as exc:
        # An unavailable upstream schedule is not a candidate or a local code
        # failure. Express the distinction in both workflow outputs and logs.
        output = os.environ.get("GITHUB_OUTPUT")
        need(bool(output), "GitHub output not available")
        with open(output, "a", encoding="utf-8") as f:
            f.write("mode=deferred\n")
        print("SCHEDULED_FLEET_CANDIDATE=DEFERRED; reason=" + str(exc) +
              "; PUBLISH=DENY")
        return 0
    except (Denied, OSError, subprocess.TimeoutExpired, TypeError, KeyError, ValueError) as exc:
        # Only predeclared safe diagnostics; never print exception response
        # bodies, tokens or arbitrary API-provided text to Actions logs.
        reason = str(exc) if isinstance(exc, Denied) else type(exc).__name__
        print("SCHEDULED_FLEET_CANDIDATE=DENY; " + reason,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
