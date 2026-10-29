#!/usr/bin/env python3
"""R06: one protected, read-only recovery of an already successful original scan.

The first genuine completed-event verifier failed solely due to a build-only
API helper used for 17 local repositories. Never rerun original source scan.
This recovery is a NEW genuine push, never falsely labelled workflow_run.
No candidate/Publisher/Release side effects and no Writer App credentials.
"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
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


proof = load("r06recheck", "scripts/issue311-r06-request-preflight.py")
scan = proof.scan
contract = proof.contract
bridge = proof.bridge
store = proof.store
RECOVERY = "r-20261029-r06recovery001"
RECOVERY_PATH = ".github/execution-requests/" + RECOVERY + ".json"
RECOVERY_WORKFLOW = "Issue 311 R06 original scan safe scoped GET recovery (NONPUBLISHING)"
SOURCE_RUN = 40809608059
SOURCE_HEAD = "72b8300b0130b9f7d8b26a0d33a9ff4572c28965"
SOURCE_ARTIFACT_ID = 12869343975
SOURCE_ZIP_SHA256 = "7691f86ee80f9b7783d607ced481874b9bcdec7b00fdc6f9f4017f77dd78db3e"
FAILED_VERIFIER_RUN = 40809678473
OUTPUT = "issue311-r06-original-recovered-preflight.json"


def require(ok, message):
    if not ok:
        raise ValueError("R06_RECOVERY_DENY " + message)


def authenticated_recovery():
    ev = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                    object_pairs_hook=store.unique_pairs)
    head = os.environ["GITHUB_SHA"]
    require(os.environ["GITHUB_WORKFLOW"] == RECOVERY_WORKFLOW
            and os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
            and os.environ["GITHUB_EVENT_NAME"] == "push"
            and os.environ["GITHUB_REF"] == "refs/heads/main"
            and os.environ["GITHUB_ACTOR"] == "ShutenOishi"
            and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
            and ev.get("sender", {}).get("login") == "ShutenOishi"
            and ev.get("repository", {}).get("full_name") == "pgextwin/build"
            and ev.get("after") == head and ev.get("ref") == "refs/heads/main"
            and ev.get("created") is False and ev.get("deleted") is False,
            "not protected one-time recovery push")
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == head,
            "local HEAD not authenticated event")
    raw = subprocess.check_output(["git", "show", "HEAD:" + RECOVERY_PATH])
    declaration = contract.validate_declaration(raw, RECOVERY_PATH)
    data = json.loads(raw, object_pairs_hook=store.unique_pairs)
    require(declaration["requestId"] == RECOVERY
            and declaration["mode"] == "AUDIT_ONLY"
            and set(declaration["targets"]) == set(scan.win.TARGETS)
            and len(declaration["targets"]) == 17
            and {t["repo"]: t["mainSha"] for t in data["targets"]} == scan.win.TARGETS
            and data["source"]["centralMainSha"] == ev["before"]
            and data["source"]["fleetRegistryBlobSha"] == scan.FLEET_BLOB
            and data["limits"]["maxAttemptsPerStage"] == 1
            and data["approval"]["publicReleaseAuthorized"] is False
            and data["approval"]["publicationGrants"] == []
            and data["allowFutureUpdates"] is False,
            "unapproved recovery request declaration")
    obj = bridge.get_json("repos/pgextwin/build/contents/" + RECOVERY_PATH +
                          "?ref=" + head)
    require(obj.get("encoding") == "base64", "recovery request Contents missing")
    remote = base64.b64decode(obj["content"].replace("\r", "").replace("\n", ""),
                              validate=True)
    require(remote == raw and store.blob_hash(raw) == obj["sha"],
            "original recovery request bytes mismatch")
    current = bridge.get_json("repos/pgextwin/build/branches/main")
    require(current.get("protected") is True and current.get("name") == "main"
            and current.get("commit", {}).get("sha") == head,
            "recovery protected main changed")
    return declaration


def recover():
    receipt = {"schemaVersion": 1, "requestId": RECOVERY, "result": "FAILED",
               "candidateAdmissionAuthorized": False, "publicationAuthorized": False}
    try:
        declaration = authenticated_recovery()
        source = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(SOURCE_RUN))
        require(source.get("id") == SOURCE_RUN
                and source.get("head_sha") == SOURCE_HEAD
                and source.get("run_attempt") == 1
                and source.get("name") == scan.WORKFLOW
                and source.get("path") == scan.WORKFLOW_PATH
                and source.get("status") == "completed"
                and source.get("conclusion") == "success"
                and source.get("event") == "push"
                and source.get("head_branch") == "main"
                and source.get("actor", {}).get("login") == "ShutenOishi",
                "original successful source changed")
        failed = bridge.get_json("repos/pgextwin/build/actions/runs/" +
                                 str(FAILED_VERIFIER_RUN))
        require(failed.get("id") == FAILED_VERIFIER_RUN
                and failed.get("event") == "workflow_run"
                and failed.get("conclusion") == "failure"
                and failed.get("head_sha") == SOURCE_HEAD,
                "prior denied listener not original failure")
        proof_receipt = proof.verify_for_source(
            source, transport="PROTECTED_MAIN_PUSH_READONLY_RECOVERY")
        require(proof_receipt.get("sourceRunId") == SOURCE_RUN
                and proof_receipt.get("originalZipArtifactId") == SOURCE_ARTIFACT_ID
                and proof_receipt.get("originalZipSha256") == SOURCE_ZIP_SHA256
                and proof_receipt.get("result") == "SCANNED_VERIFIED"
                and proof_receipt.get("candidateAdmissionAuthorized") is False
                and proof_receipt.get("publicationAuthorized") is False,
                "original source ZIP/artifact/policy mismatch")
        receipt = {**proof_receipt, "requestId": RECOVERY,
                   "recoveryRequestSha256": declaration["rawSha256"],
                   "originalRequestId": scan.REQUEST,
                   "originalRequestSha256": proof_receipt["requestSha256"],
                   "failedOriginalVerifierRunId": FAILED_VERIFIER_RUN,
                   "recoveryRunId": int(os.environ["GITHUB_RUN_ID"]),
                   "result": "SCANNED_VERIFIED_RECOVERED",
                   "eventTransport": "PROTECTED_MAIN_PUSH_READONLY_RECOVERY",
                   "candidateAdmissionAuthorized": False, "publicationAuthorized": False}
    except Exception as exc:
        receipt["reason"] = str(exc)[:400]
    Path(OUTPUT).write_text(json.dumps(receipt, sort_keys=True) + "\n",
                            encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["result"] == "SCANNED_VERIFIED_RECOVERED" else 1


if __name__ == "__main__":
    raise SystemExit(recover() if sys.argv[1:] == ["recover"] else 2)
