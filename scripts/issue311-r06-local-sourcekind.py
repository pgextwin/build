#!/usr/bin/env python3
"""R06 pilot: classify a local candidate from original request-bound ZIP bytes.

This central, strictly read-only pilot is NOT installed in the 17 local
candidate-writer workflows. Never conflates a protected request push with a
schedule event or grants candidate/Publisher authority.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import importlib.util


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recovery = load("r06_kind_recovery", "scripts/issue311-r06-original-recovery.py")
proof = recovery.proof
scan = recovery.scan
bridge = recovery.bridge
store = recovery.store
contract = recovery.contract
REQUEST = "r-20261029-r06sourcepilot01"
REQUEST_PATH = ".github/execution-requests/" + REQUEST + ".json"
WORKFLOW = "Issue 311 R06 original ZIP local source-kind pilot (NONPUBLISHING)"
OUTPUT = "issue311-r06-local-sourcekind-pilot.json"
PILOT = "pgextwin/orafce"
SOURCE_KIND = "AUTHENTICATED_REQUEST_ORIGINAL_ZIP_READONLY"
SOURCE_RUN = recovery.SOURCE_RUN
SOURCE_HEAD = recovery.SOURCE_HEAD
SOURCE_ARTIFACT = recovery.SOURCE_ARTIFACT_ID
SOURCE_ZIP_SHA256 = recovery.SOURCE_ZIP_SHA256


def require(ok, reason):
    if not ok:
        raise ValueError("R06_LOCAL_KIND_DENY " + reason)


def time_utc(value):
    require(type(value) is str, "timestamp missing")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "timestamp timezone missing")
    return result.astimezone(timezone.utc)


def classify(original, verified, repository, target_sha):
    """Pure decision over independently authenticated original source bytes.

    Requires the caller to first perform proof.verify_for_source() and to
    re-download the SAME original ZIP via proof.original_zip(). These immutable
    artifacts are not a self-declared authentication credential.
    """
    require(repository in scan.win.TARGETS
            and re.fullmatch("[0-9a-f]{40}", target_sha or "") is not None
            and target_sha == scan.win.TARGETS[repository],
            "pilot local repository or main SHA drift")
    require(type(verified) is dict and verified.get("result") == "SCANNED_VERIFIED"
            and verified.get("sourceKind") == "AUTHENTICATED_REQUEST_READONLY_SCAN"
            and verified.get("sourceRunId") == SOURCE_RUN
            and verified.get("sourceRunAttempt") == 1
            and verified.get("sourceHeadSha") == SOURCE_HEAD
            and verified.get("originalZipArtifactId") == SOURCE_ARTIFACT
            and verified.get("originalZipSha256") == SOURCE_ZIP_SHA256
            and verified.get("targetCount") == 17
            and verified.get("verifiedTargets") == sorted(scan.win.TARGETS)
            and verified.get("candidateAdmissionAuthorized") is False
            and verified.get("publicationAuthorized") is False
            and verified.get("genuineSchedule") is False,
            "independent original source-kind proof not exact")
    require(type(original) is dict
            and original.get("schemaVersion") == 1
            and original.get("requestId") == scan.REQUEST
            and original.get("requestSha256") == verified.get("requestSha256")
            and original.get("sourceRunId") == SOURCE_RUN
            and original.get("sourceHeadSha") == SOURCE_HEAD
            and original.get("sourceEvent") == "push"
            and original.get("admissionScope") == "AUDIT_ONLY_REQUEST_READONLY_SCAN_NOT_SCHEDULE"
            and original.get("result") == "SCANNED"
            and original.get("publicationAuthorized") is False
            and original.get("targetMainSha") == scan.win.TARGETS,
            "original scan proof metadata mismatch")
    rows = scan.inspect_report(original.get("report"), scan.win.TARGETS)
    updates = sum(row["status"] == "update-available" for row in rows.values())
    require(original["report"].get("updatesDetected") == updates
            and original.get("perTargetStatus") ==
            {repo: row["status"] for repo, row in rows.items()}
            and all(bool(row["updates"]) == (row["status"] == "update-available")
                    for row in rows.values()),
            "inconsistent or forged candidate updates")
    # For AUDIT_ONLY the presence of an upstream update is informational.
    # Never return a writer-usable 'candidate' mode or legacy 'schedule' kind.
    decision = ("NO_UPDATE" if rows[repository]["status"] == "up-to-date"
                else "UPDATE_PRESENT_NOT_AUTHORIZED")
    return {"sourceKind": SOURCE_KIND, "repository": repository,
            "localProtectedMainSha": target_sha, "decision": decision,
            "sourceRequestId": scan.REQUEST, "sourceRunId": SOURCE_RUN,
            "sourceHeadSha": SOURCE_HEAD, "originalZipArtifactId": SOURCE_ARTIFACT,
            "originalOuterZipSha256Verified": SOURCE_ZIP_SHA256,
            "originalOuterZipByteVerified": True,
            "genuineSchedule": False, "candidateAdmissionAuthorized": False,
            "publisherSourceKindAuthorized": False, "publicationAuthorized": False}


def authenticated_pilot():
    ev = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                    object_pairs_hook=store.unique_pairs)
    head = os.environ["GITHUB_SHA"]
    require(os.environ["GITHUB_WORKFLOW"] == WORKFLOW
            and os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
            and os.environ["GITHUB_EVENT_NAME"] == "push"
            and os.environ["GITHUB_REF"] == "refs/heads/main"
            and os.environ["GITHUB_ACTOR"] == "ShutenOishi"
            and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
            and ev.get("after") == head and ev.get("before") != head
            and ev.get("sender", {}).get("login") == "ShutenOishi"
            and ev.get("repository", {}).get("full_name") == "pgextwin/build"
            and ev.get("created") is False and ev.get("deleted") is False,
            "not protected exact one-time push")
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == head,
            "local checkout HEAD mismatch")
    raw = subprocess.check_output(["git", "show", "HEAD:" + REQUEST_PATH])
    declared = contract.validate_declaration(raw, REQUEST_PATH)
    data = json.loads(raw, object_pairs_hook=store.unique_pairs)
    require(declared["requestId"] == REQUEST
            and declared["mode"] == "AUDIT_ONLY"
            and data["source"]["centralMainSha"] == ev["before"]
            and data["source"]["fleetRegistryBlobSha"] == scan.FLEET_BLOB
            and len(data["targets"]) == 17
            and {t["repo"]: t["mainSha"] for t in data["targets"]} == scan.win.TARGETS
            and data["resumeFrom"] == scan.REQUEST
            and data["allowFutureUpdates"] is False
            and data["limits"]["maxAttemptsPerStage"] == 1
            and data["approval"]["publicReleaseAuthorized"] is False
            and data["approval"]["publicationGrants"] == [],
            "nonpublication pilot declaration mismatch")
    remote = bridge.get_json("repos/pgextwin/build/contents/" + REQUEST_PATH
                             + "?ref=" + head)
    require(remote.get("encoding") == "base64", "original request Contents missing")
    raw_remote = base64.b64decode(remote["content"].replace("\n", "").replace("\r", ""),
                                  validate=True)
    require(raw_remote == raw and store.blob_hash(raw) == remote.get("sha"),
            "original request blob mismatch")
    branch = bridge.get_json("repos/pgextwin/build/branches/main")
    require(branch.get("protected") is True
            and branch.get("commit", {}).get("sha") == head,
            "central protected main moved")
    return declared


def run():
    result = {"schemaVersion": 1, "requestId": REQUEST, "result": "FAILED",
              "candidateAdmissionAuthorized": False, "publicationAuthorized": False}
    try:
        declaration = authenticated_pilot()
        source = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(SOURCE_RUN))
        now = datetime.now(timezone.utc)
        require(source.get("id") == SOURCE_RUN
                and source.get("head_sha") == SOURCE_HEAD
                and source.get("name") == scan.WORKFLOW
                and source.get("path") == scan.WORKFLOW_PATH
                and source.get("event") == "push"
                and source.get("head_branch") == "main"
                and source.get("status") == "completed"
                and source.get("conclusion") == "success"
                and source.get("run_attempt") == 1
                and source.get("actor", {}).get("login") == "ShutenOishi"
                and timedelta(0) <= now - time_utc(source.get("created_at")) < timedelta(hours=3)
                and time_utc(source.get("updated_at")) <= now + timedelta(minutes=5),
                "expired or forged original scan source")
        verified = proof.verify_for_source(
            source, transport="PROTECTED_MAIN_PUSH_READONLY_LOCAL_KIND")
        original, zip_sha, artifact_id = proof.original_zip(source)
        require(zip_sha == SOURCE_ZIP_SHA256 and artifact_id == SOURCE_ARTIFACT,
                "re-downloaded original ZIP changed")
        decision = classify(original, verified, PILOT, scan.win.TARGETS[PILOT])
        result = {"schemaVersion": 1, "requestId": REQUEST,
                  "requestSha256": declaration["rawSha256"],
                  "result": decision["decision"], "pilotOnly": True,
                  "localRepositoryWorkflowIntegrated": False,
                  "sourceRunReexecuted": False,
                  "localRunId": int(os.environ["GITHUB_RUN_ID"]),
                  "localRunAttempt": 1, **decision}
        # A second protected-main read prevents a successful receipt after drift.
        branch = bridge.get_json("repos/pgextwin/build/branches/main")
        require(branch.get("protected") is True
                and branch.get("commit", {}).get("sha") == os.environ["GITHUB_SHA"],
                "central main changed before receipt")
    except Exception as exc:
        result = {"schemaVersion": 1, "requestId": REQUEST, "result": "FAILED",
                  "reason": str(exc)[:400], "candidateAdmissionAuthorized": False,
                  "publicationAuthorized": False}
    Path(OUTPUT).write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] in ("NO_UPDATE", "UPDATE_PRESENT_NOT_AUTHORIZED") else 1


if __name__ == "__main__":
    raise SystemExit(run() if sys.argv[1:] == ["run"] else 2)
