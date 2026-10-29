#!/usr/bin/env python3
"""Reusable 17-repository PREPARE-only admission; never a candidate writer.

The trusted central PREPARE source and 17 exact protected mains are verified
from their immutable original bytes. A separate protected local request push
is used for the pilot; no schedule, dispatch, Publisher or token reuse.
"""
from __future__ import annotations
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT  # This program runs from the immutable central build checkout.
sys.path.insert(0, str(BUILD / "scripts"))
SOURCE = BUILD / "scripts/issue311-r06-prepare-scan.py"
SPEC = importlib.util.spec_from_file_location("r06_local_prepare_source", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("R06_LOCAL_DENY missing immutable central verifier")
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)
bridge = prepare.bridge
contract = prepare.contract
store = prepare.store

REPO = os.environ.get("GITHUB_REPOSITORY", "")
REQUEST = ""
REQUEST_PATH = ""
WORKFLOW = "Issue 311 R06 fleet local PREPARE verifier (NONPUBLISHING)"
SOURCE_KIND = "AUTHENTICATED_PREPARE_ORIGINAL_ZIP_LOCAL_READONLY"
OUTPUT = "issue311-r06-fleet-local-prepare-receipt.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")

def need(ok, message):
    if not ok:
        raise ValueError("R06_LOCAL_DENY " + message)

def strict(raw):
    return json.loads(raw, object_pairs_hook=store.unique_pairs)

def utc(value):
    need(isinstance(value, str), "missing UTC timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    need(result.tzinfo is not None and result.utcoffset() == timedelta(0),
         "timestamp must be UTC")
    return result

def remote_branch(repository):
    need(repository in prepare.win.TARGETS, "unapproved extension repo")
    return prepare.win.old.get_json(
        "https://api.github.com/repos/" + repository + "/branches/main", os.environ["GH_TOKEN"])

def authenticate_local():
    global REQUEST, REQUEST_PATH
    need(REPO in prepare.win.TARGETS, "unregistered local repository")
    ev = strict(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    head = os.environ["GITHUB_SHA"]
    before = ev.get("before")
    need(os.environ["GITHUB_REPOSITORY"] == REPO
         and os.environ["GITHUB_WORKFLOW"] == WORKFLOW
         and os.environ["GITHUB_EVENT_NAME"] == "push"
         and os.environ["GITHUB_REF"] == "refs/heads/main"
         and os.environ["GITHUB_ACTOR"] == "ShutenOishi"
         and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
         and ev.get("ref") == "refs/heads/main"
         and ev.get("created") is False and ev.get("deleted") is False
         and ev.get("repository", {}).get("full_name") == REPO
         and ev.get("sender", {}).get("login") == "ShutenOishi"
         and ev.get("after") == head and before != head
         and SHA40.fullmatch(head) is not None
         and isinstance(before, str) and SHA40.fullmatch(before) is not None,
         "not authentic local main push")
    need(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == head,
         "not checked out local event SHA")
    changed = subprocess.check_output(["git", "diff", "--name-status",
                                       before, head], text=True).splitlines()
    need(len(changed) == 1, "local request push has unrelated changes")
    hit = re.fullmatch(
        r"A\\t(\\.github/execution-requests/(r-20\\d{6}-r06local[a-z0-9-]{4,40})\\.json)",
        changed[0])
    need(hit is not None, "only a newly added local PREPARE request is accepted")
    REQUEST_PATH, REQUEST = hit.group(1), hit.group(2)
    raw = subprocess.check_output(["git", "show", "HEAD:" + REQUEST_PATH])
    data = strict(raw)
    need(isinstance(data, dict) and set(data) == {
        "schemaVersion", "kind", "requestId", "mode", "sourceRunId",
        "sourceHeadSha", "sourceArtifactId", "sourceZipSha256", "centralRequestId",
        "targetMainSha", "expiresAt", "publicReleaseAuthorized"}
        and data["schemaVersion"] == 1 and data["kind"] == "pgextwin-local-prepare"
        and data["requestId"] == REQUEST and data["mode"] == "PREPARE"
        and type(data["sourceRunId"]) is int and data["sourceRunId"] > 0
        and type(data["sourceArtifactId"]) is int and data["sourceArtifactId"] > 0
        and SHA40.fullmatch(data["sourceHeadSha"]) is not None
        and re.fullmatch(r"r-20\\d{6}-r06prepare[a-z0-9-]{4,40}",
                         data["centralRequestId"]) is not None
        and SHA64.fullmatch(data["sourceZipSha256"]) is not None
        and data["targetMainSha"] == before
        and data["publicReleaseAuthorized"] is False
        and datetime.now(timezone.utc) < utc(data["expiresAt"])
        and utc(data["expiresAt"]) <= datetime.now(timezone.utc) + timedelta(hours=12),
         "malformed or expired local PREPARE request")
    branch = remote_branch(REPO)
    need(branch.get("name") == "main" and branch.get("protected") is True
         and branch.get("commit", {}).get("sha") == head,
         "local main not protected exact live SHA")
    return data, hashlib.sha256(raw).hexdigest(), before

def authenticate_original(local, base_sha):
    sid = local["sourceRunId"]
    run = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(sid))
    need(run.get("id") == sid and run.get("head_sha") == local["sourceHeadSha"]
         and run.get("name") == prepare.WORKFLOW
         and run.get("path") == prepare.WORKFLOW_PATH
         and run.get("event") == "push" and run.get("head_branch") == "main"
         and run.get("actor", {}).get("login") == "ShutenOishi"
         and run.get("status") == "completed" and run.get("conclusion") == "success"
         and run.get("run_attempt") == 1
         and timedelta(0) <= datetime.now(timezone.utc) - utc(run["created_at"])
                             < timedelta(hours=12),
         "unaccepted original central PREPARE Run")
    central_path = ".github/execution-requests/" + local["centralRequestId"] + ".json"
    record = bridge.get_json("repos/pgextwin/build/contents/" +
                             central_path + "?ref=" + run["head_sha"])
    need(record.get("encoding") == "base64" and isinstance(record.get("content"), str),
         "missing original central request")
    raw = base64.b64decode(record["content"].replace(chr(10), "").replace(chr(13), ""),
                           validate=True)
    need(store.blob_hash(raw) == record.get("sha"), "central request Git blob mismatch")
    declaration = contract.validate_declaration(raw, central_path)
    original_request = strict(raw)
    targets = {t["repo"]: t["mainSha"] for t in original_request["targets"]}
    need(declaration["requestId"] == local["centralRequestId"] and declaration["mode"] == "PREPARE"
         and len(targets) == len(original_request["targets"]) == 17
         and set(targets) == set(prepare.win.TARGETS)
         and targets.get(REPO) == base_sha
         and original_request["approval"]["publicReleaseAuthorized"] is False
         and original_request["approval"]["publicationGrants"] == []
         and original_request["source"]["fleetRegistryBlobSha"] == prepare.FLEET_BLOB
         and original_request["allowFutureUpdates"] is False,
         "central source declaration not exact PREPARE")
    commit = bridge.get_json("repos/pgextwin/build/commits/" + run["head_sha"])
    need(commit.get("parents", [{}])[0].get("sha") ==
         original_request["source"]["centralMainSha"], "not original protected request commit")
    jobs = bridge.get_json(
        "repos/pgextwin/build/actions/runs/" + str(sid) + "/jobs?per_page=100")
    need(jobs.get("total_count") == len(jobs.get("jobs", [])) == 1
         and jobs["jobs"][0].get("run_id") == sid
         and jobs["jobs"][0].get("name") ==
         "Scan immutable one-shot 17 protected upstreams, no candidate"
         and jobs["jobs"][0].get("conclusion") == "success",
         "central source job not original success")
    artifacts = bridge.get_json(
        "repos/pgextwin/build/actions/runs/" + str(sid) + "/artifacts?per_page=100")
    need(artifacts.get("total_count") == len(artifacts.get("artifacts", [])) == 1,
         "partial or paginated original ZIP")
    artifact = artifacts["artifacts"][0]
    need(artifact.get("id") == local["sourceArtifactId"]
         and artifact.get("name") == prepare.ARTIFACT
         and artifact.get("expired") is False
         and artifact.get("workflow_run", {}).get("id") == sid
         and artifact.get("digest") == "sha256:" + local["sourceZipSha256"],
         "not exact original source ZIP")
    original, outer_sha = bridge.original_zip(artifact, prepare.RECEIPT)
    need(outer_sha == local["sourceZipSha256"]
         and original.get("requestId") == local["centralRequestId"]
         and original.get("requestSha256") == declaration["rawSha256"]
         and original.get("sourceHeadSha") == run["head_sha"]
         and original.get("sourceRunId") == sid
         and original.get("sourceRunAttempt") == 1
         and original.get("sourceEvent") == "push"
         and original.get("result") == "SCANNED"
         and original.get("admissionScope") ==
           "PREPARE_REQUEST_ORIGINAL_READONLY_SCAN_NO_WRITER"
         and original.get("publicationAuthorized") is False
         and original.get("targetMainSha") == targets,
         "original ZIP contents are not PREPARE source")
    rows = prepare.inspect_report(original.get("report"), targets)
    need(original.get("perTargetStatus") ==
         {r: x["status"] for r, x in rows.items()}
         and original["report"]["updatesDetected"] ==
         sum(x["status"] == "update-available" for x in rows.values()),
         "forged local statuses")
    for repo, sha in sorted(targets.items()):
        if repo == REPO:  # Only this newly added protected request advances local main.
            continue
        item = remote_branch(repo)
        need(item.get("protected") is True and
             item.get("commit", {}).get("sha") == sha,
             "remote protected main drift " + repo)
    return rows[REPO]["status"], declaration["rawSha256"], outer_sha

def run():
    result = {"schemaVersion": 1, "requestId": REQUEST, "result": "FAILED",
              "candidateAdmissionAuthorized": False,
              "publisherSourceKindAuthorized": False,
              "publicationAuthorized": False, "genuineSchedule": False}
    try:
        local, local_sha, base = authenticate_local()
        result["requestId"] = REQUEST
        status, source_sha, zip_sha = authenticate_original(local, base)
        need(status in ("up-to-date", "update-available"), "indeterminate local candidate")
        result.update(
            result=("NO_UPDATE" if status == "up-to-date" else
                    "UPDATE_PRESENT_NOT_AUTHORIZED"),
            sourceKind=SOURCE_KIND, originalSourceRunId=local["sourceRunId"],
            originalSourceHeadSha=local["sourceHeadSha"],
            originalSourceRequestSha256=source_sha,
            originalSourceArtifactId=local["sourceArtifactId"],
            originalOuterZipSha256Verified=zip_sha,
            localRequestSha256=local_sha, localRunId=int(os.environ["GITHUB_RUN_ID"]),
            localRunAttempt=1, localProtectedRequestParentMainSha=base,
            localProtectedHeadSha=os.environ["GITHUB_SHA"],
            localWorkflowInstalled=True, originalScanReexecuted=False)
    except Exception as exc:
        result["reason"] = str(exc)[:400]
    Path(OUTPUT).write_text(json.dumps(result, sort_keys=True) + chr(10), encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] in ("NO_UPDATE", "UPDATE_PRESENT_NOT_AUTHORIZED") else 1

if __name__ == "__main__":
    raise SystemExit(run() if sys.argv[1:] == ["run"] else 2)
