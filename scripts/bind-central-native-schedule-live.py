#!/usr/bin/env python3
"""Bind the latest applicable original central native candidate observation."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import quote
from zipfile import BadZipFile, ZipFile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("central_native_original_binder",
    HERE / "bind-native-candidate-audit.py")
binder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binder)

CENTRAL = "pgextwin/build"
ARTIFACT = "registered-original-native-pr-audits"
WORKFLOW = "recover-native-pr-fleet.yml"
PATH = ".github/workflows/" + WORKFLOW
NAME = "Hourly central recovery of approved original native PR artifacts (NONPUBLISHING)"
JOB = "Independent approved attempt and original ZIP/SPDX/Grype audit (no Release)"
RUNS = "actions/workflows/" + WORKFLOW + "/runs?event=schedule&branch=main"
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"
MAX_BYTES = 4 * 1024 * 1024


class Denied(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise Denied(why)


def utc(value):
    require(type(value) is str and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value),
        "missing or invalid original audit timestamp")
    return datetime.strptime(value, TIMESTAMP).replace(tzinfo=timezone.utc)


def runs_endpoint(merged):
    return RUNS + "&created=" + quote("<=" + merged.strftime(TIMESTAMP), safe="") + "&per_page=100"


def gh(repo, endpoint):
    allow = (endpoint == "branches/main"
             or re.fullmatch(re.escape(RUNS) + r"&created=%3C%3D[0-9TZ%-]+&per_page=100", endpoint)
             or re.fullmatch(r"actions/runs/[1-9][0-9]*(/(jobs|artifacts)\?per_page=100)?", endpoint))
    require(repo == CENTRAL and allow, "unallowlisted central schedule GET")
    p = subprocess.run(["gh", "api", "--method", "GET", "repos/" + repo + "/" + endpoint],
                       capture_output=True, text=True, check=False, timeout=50)
    require(p.returncode == 0 and len(p.stdout) < 3_000_000,
            "authenticated central GitHub GET denied or oversized")
    return json.loads(p.stdout)


def download_original(run, artifact, target):
    endpoint = f"repos/{CENTRAL}/actions/artifacts/{artifact['id']}/zip"
    p = subprocess.run(["gh", "api", "--method", "GET", endpoint],
                       capture_output=True, check=False, timeout=150)
    require(p.returncode == 0 and 0 < len(p.stdout) <= MAX_BYTES,
            "original central schedule artifact download failed")
    require(artifact.get("digest") == "sha256:" + hashlib.sha256(p.stdout).hexdigest(),
            "original central schedule archive digest mismatch")
    try:
        with ZipFile(BytesIO(p.stdout)) as archive:
            members = archive.infolist()
            require(len(members) == 1 and members[0].filename == ARTIFACT + ".json"
                    and 0 < members[0].file_size <= MAX_BYTES,
                    "unsafe or incomplete schedule audit artifact members")
            return json.loads(archive.read(members[0]))
    except (BadZipFile, RuntimeError) as exc:
        raise Denied("invalid original central schedule archive") from exc


def inventory(doc, field, *, limit=99):
    require(type(doc) is dict and type(doc.get("total_count")) is int
            and type(doc.get(field)) is list and doc["total_count"] >= 0
            and len(doc[field]) == min(doc["total_count"], limit)
            and all(type(row) is dict for row in doc[field]),
            "incomplete central audit " + field + " inventory")
    return doc[field]


def read_result(indexed, central_sha, repo, *, api, download, now):
    path = "actions/runs/" + str(indexed["id"])
    run = api(CENTRAL, path)
    require(type(run) is dict and run.get("id") == indexed["id"]
            and run.get("created_at") == indexed["created_at"]
            and run.get("path") == PATH and run.get("name") == NAME
            and run.get("event") == "schedule" and type(run.get("run_attempt")) is int
            and run["run_attempt"] == 1 and run.get("head_sha") == central_sha
            and run.get("head_branch") == "main"
            and (run.get("repository") or {}).get("full_name") == CENTRAL
            and run.get("status") == "completed" and run.get("conclusion") == "success",
            "central recovery Run is unfinished, changed or replayed")
    jobs_doc = api(CENTRAL, path + "/jobs?per_page=100")
    jobs = [job for job in inventory(jobs_doc, "jobs") if job.get("name") == JOB]
    require(jobs_doc["total_count"] < 100 and len(jobs) == 1,
            "missing or ambiguous scheduled original audit job")
    job = jobs[0]
    require(type(job.get("id")) is int and job["id"] > 0
            and job.get("run_id") == run["id"] and job.get("run_attempt") == 1
            and job.get("status") == "completed" and job.get("conclusion") == "success",
            "central schedule original audit job was skipped/failed/foreign")
    started, completed = utc(job.get("started_at")), utc(job.get("completed_at"))
    require(utc(run["created_at"]) <= started <= completed <= now,
            "central audit job was not completed by use time")

    artifacts_doc = api(CENTRAL, path + "/artifacts?per_page=100")
    artifacts = [a for a in inventory(artifacts_doc, "artifacts") if a.get("name") == ARTIFACT]
    require(artifacts_doc["total_count"] < 100 and len(artifacts) == 1,
            "no unique genuine central audit artifact")
    artifact = artifacts[0]
    binder.require_artifact(artifact, ARTIFACT, run["id"])
    uploaded = utc(artifact.get("created_at"))
    require(started <= uploaded <= completed, "central audit upload outside the original job")
    report = download(run, artifact, repo)
    require(type(report) is dict and report.get("schemaVersion") == 2
            and report.get("auditor") == {"repository": CENTRAL, "event": "schedule",
                                         "sourceSha": central_sha, "runId": run["id"], "runAttempt": 1}
            and all(report.get(key) is False for key in
                    ("signedArtifactsVerified", "publicationAuthorized", "publishableReceipt"))
            and type(report.get("results")) is dict,
            "central native audit result schema or provenance differs")
    row = report["results"].get(repo)
    require(type(row) is dict, "exact target original native audit row missing")
    require(row.get("observedAt") is not None,
            "target PR list observation unavailable: " + str(row.get("reason", "")))
    observed = utc(row["observedAt"])
    require(started <= observed <= uploaded, "central target observation outside the original job")
    return observed, row, run, artifact


def recover(repo, before, head, pr, manifest, lifecycle, *, manifest_blob, fetch_ci,
            api=gh, download=download_original):
    """Use only the newest target observation from the candidate PR's lifetime."""
    require(type(repo) is str and REPO.fullmatch(repo) and repo != CENTRAL
            and binder.sha(before) and binder.sha(head) and binder.sha(manifest_blob)
            and type(pr.get("number")) is int and pr["number"] > 0,
            "invalid original native candidate merge context")
    now = datetime.now(timezone.utc)
    opened, merged = utc(pr.get("created_at")), utc(pr.get("merged_at"))
    require(opened < merged <= now, "invalid original candidate PR lifetime")
    main = api(CENTRAL, "branches/main")
    central_sha = (main.get("commit") or {}).get("sha")
    require(main.get("name") == "main" and main.get("protected") is True and binder.sha(central_sha),
            "central audit source is not current protected build/main")

    runs = inventory(api(CENTRAL, runs_endpoint(merged)), "workflow_runs", limit=100)
    require(all(type(run.get("id")) is int and run["id"] > 0
                and run.get("path") == PATH and run.get("event") == "schedule"
                and run.get("head_branch") == "main" for run in runs)
            and len({run["id"] for run in runs}) == len(runs),
            "untrusted or duplicate central recovery Run inventory")
    # The last update bounds the observation for completed runs. Use that
    # bound so Runs finishing out of order cannot hide a later observation.
    relevant = []
    for run in runs:
        if utc(run.get("created_at")) <= merged:
            latest = min(merged, utc(run.get("updated_at"))) if run.get("status") == "completed" else merged
            if latest >= opened:
                relevant.append((latest, run["id"], run))
    newest = None
    for latest, _, indexed in sorted(relevant, reverse=True):
        if newest is not None and latest < newest[0]:
            break
        observed, row, run, artifact = read_result(indexed, central_sha, repo,
                                                    api=api, download=download, now=now)
        if observed < opened or observed > merged:
            continue
        require(observed <= latest and observed < merged,
                "central observation time is ambiguous at the PR merge boundary")
        require(newest is None or observed != newest[0],
                "ambiguous latest target PR observation")
        if newest is None or observed > newest[0]:
            newest = observed, row, run, artifact
    require(newest is not None, "no genuine schedule original native audit during the candidate PR lifetime")
    _, row, run, artifact = newest
    require(row.get("status") == "verified",
            "latest target native audit " + str(row.get("status")) + ": " + str(row.get("reason", "")))
    context, audit = row.get("native"), row.get("candidateAudit")
    require(type(context) is dict and type(audit) is dict
            and row.get("candidatePr") == context.get("candidatePr") == pr["number"]
            and row.get("candidateHeadSha") == context.get("candidateHeadSha") == head
            and row.get("targetMainSha") == before and row.get("manifestBlob") == manifest_blob,
            "central original audit not bound to unchanged PR, HEAD, base and manifest blob")
    ci_id = context.get("candidateRunId")
    require(type(ci_id) is int and ci_id > 0, "invalid original native CI Run ID")
    ci = fetch_ci(ci_id)
    bound = binder.join(context=context, audit=audit, ext=manifest, lifecycle=lifecycle,
                        ci_run=ci, audit_run=run, artifact=artifact, repository=repo,
                        current_main_sha=before, central_row=row)
    return bound, ci


if __name__ == "__main__":
    raise SystemExit("Library only: PUBLISH_DENY")
