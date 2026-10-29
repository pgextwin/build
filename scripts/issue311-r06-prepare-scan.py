#!/usr/bin/env python3
"""R06: exact one-shot PREPARE central fleet scan, never schedule or publication.

A protected request main-push captures a fresh 17-repository upstream scan and
binds its original report to the immutable request and actual source run.
PREPARE only establishes evidence for a separate local gate; it never creates a candidate, Release or Publisher write. No schedule/dispatch masquerade.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUEST = "r-20261029-r06preparepilot01"
REQUEST_PATH = ".github/execution-requests/" + REQUEST + ".json"
WORKFLOW = "Issue 311 R06 PREPARE original fleet scan (NONPUBLISHING)"
WORKFLOW_PATH = ".github/workflows/issue311-r06-prepare-scan.yml"
ARTIFACT = "issue311-r06-prepare-original-scan"
RECEIPT = "issue311-r06-prepare-original-scan.json"
FLEET_BLOB = "69918265dabb86b11a9406533cbe0ce495137b94"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


store = load("r06_store", "scripts/issue311-lifecycle-store.py")
contract = load("r06_contract", "scripts/issue311-request-contract.py")
watch = load("r06_watch", "scripts/fleet-upstream-watch.py")
bridge = load("r06_bridge", "scripts/issue311-r05-windows-completion-bridge.py")
win = load("r06_windows", "scripts/issue311-r05-windows-17.py")


def require(ok, message):
    if not ok:
        raise ValueError("R06_SCAN_DENY " + message)


def authenticated_request():
    ev = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                    object_pairs_hook=store.unique_pairs)
    head = os.environ["GITHUB_SHA"]
    require(os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
            and os.environ["GITHUB_WORKFLOW"] == WORKFLOW
            and os.environ["GITHUB_EVENT_NAME"] == "push"
            and os.environ["GITHUB_REF"] == "refs/heads/main"
            and os.environ["GITHUB_ACTOR"] == "ShutenOishi"
            and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
            and ev.get("sender", {}).get("login") == "ShutenOishi"
            and ev.get("after") == head and ev.get("before") != head
            and ev.get("created") is False and ev.get("deleted") is False
            and ev.get("repository", {}).get("full_name") == "pgextwin/build",
            "not a genuine protected original push")
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == head,
            "local checkout not event head")
    raw = subprocess.check_output(["git", "show", "HEAD:" + REQUEST_PATH])
    declaration = contract.validate_declaration(raw, REQUEST_PATH)
    request = json.loads(raw, object_pairs_hook=store.unique_pairs)
    require(declaration["requestId"] == REQUEST
            and declaration["mode"] == "PREPARE"
            and len(declaration["targets"]) == 17
            and set(declaration["targets"]) == set(win.TARGETS)
            and {x["repo"]: x["mainSha"] for x in request["targets"]} == win.TARGETS
            and request["source"]["centralMainSha"] == ev["before"]
            and request["source"]["fleetRegistryBlobSha"] == FLEET_BLOB
            and request["limits"]["maxParallel"] <= 4
            and request["limits"]["maxOperations"] <= 100
            and request["limits"]["maxAttemptsPerStage"] == 1
            and request["limits"]["maxWallClockMinutes"] <= 45
            and request["allowFutureUpdates"] is False
            and request["approval"]["publicReleaseAuthorized"] is False
            and request["approval"]["publicationGrants"] == [],
            "wrong bounded 17-target nonpublishing PREPARE request")
    record = bridge.get_json("repos/pgextwin/build/contents/" + REQUEST_PATH + "?ref=" + head)
    require(record.get("encoding") == "base64"
            and type(record.get("sha")) is str
            and type(record.get("content")) is str, "missing original Contents request")
    remote = base64.b64decode(record["content"].replace("\r", "").replace("\n", ""),
                              validate=True)
    require(remote == raw and store.blob_hash(remote) == record["sha"],
            "request original Git blob mismatch")
    fleet_raw = subprocess.check_output(["git", "show", "HEAD:metadata/automation-fleet.json"])
    require(store.blob_hash(fleet_raw) == FLEET_BLOB,
            "pinned fleet registry changed")
    registry = json.loads(fleet_raw, object_pairs_hook=store.unique_pairs)
    require(set(x["repository"] for x in registry["entries"]) == set(win.TARGETS)
            and len(registry["entries"]) == 17,
            "registry not exact 17")
    branch = bridge.get_json("repos/pgextwin/build/branches/main")
    require(branch.get("name") == "main" and branch.get("protected") is True
            and branch.get("commit", {}).get("sha") == head,
            "central protected main drift")
    return request, declaration, registry


def inspect_report(report, targets):
    require(type(report) is dict
            and report.get("schemaVersion") == 1
            and report.get("scope") == "STABLE_UPSTREAM_GET_ONLY"
            and report.get("publication") == "DENY"
            and report.get("candidatePrCreated") is False
            and report.get("fleetSize") == len(targets) == 17
            and report.get("indeterminate") == 0
            and type(report.get("extensions")) is list
            and len(report["extensions"]) == 17,
            "incomplete/indeterminate/nonreadonly central scan")
    found = {}
    for row in report["extensions"]:
        repo = row.get("repository")
        require(repo in targets and repo not in found
                and row.get("mainSha") == targets[repo]
                and row.get("status") in ("up-to-date", "update-available")
                and isinstance(row.get("updates"), list),
                "untrusted local preflight or duplicate/changed main")
        found[repo] = row
    require(set(found) == set(targets), "partial fleet response")
    return found


def scan():
    receipt = {"schemaVersion": 1, "requestId": REQUEST, "result": "FAILED",
               "publicationAuthorized": False, "reason": "scan unavailable"}
    try:
        request, declaration, registry = authenticated_request()
        report = watch.scan(registry, lambda url: watch.github_get_json(
            url, os.environ["GH_TOKEN"]))
        targetmap = {x["repo"]: x["mainSha"] for x in request["targets"]}
        verified = inspect_report(report, targetmap)
        receipt = {
            "schemaVersion": 1, "requestId": REQUEST,
            "requestSha256": declaration["rawSha256"],
            "sourceHeadSha": os.environ["GITHUB_SHA"],
            "sourceRunId": int(os.environ["GITHUB_RUN_ID"]),
            "sourceRunAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "sourceEvent": "push",
            "registryGitBlobSha": FLEET_BLOB,
            "result": "SCANNED", "fleetSize": 17,
            "targetMainSha": targetmap,
            "perTargetStatus": {repo: row["status"] for repo, row in verified.items()},
            "report": report,
            "publicationAuthorized": False,
            "admissionScope": "PREPARE_REQUEST_ORIGINAL_READONLY_SCAN_NO_WRITER"
        }
    except Exception as exc:
        receipt["reason"] = str(exc)[:380]
    Path(RECEIPT).write_text(json.dumps(receipt, sort_keys=True) + "\n",
                             encoding="utf-8")
    print(json.dumps({"requestId": REQUEST, "result": receipt["result"],
                      "fleetSize": receipt.get("fleetSize", 0),
                      "reason": receipt.get("reason", ""),
                      "publicationAuthorized": False}, sort_keys=True))
    return 0 if receipt["result"] == "SCANNED" else 1


if __name__ == "__main__":
    raise SystemExit(scan() if sys.argv[1:] == ["scan"] else 2)
