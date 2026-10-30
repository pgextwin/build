#!/usr/bin/env python3
"""R10-02 key-free, GET-only historical terminal report for Issue 311.

Reads immutable original GitHub Contents checkpoint bytes, original Actions Run
and real artifact ZIPs. It NEVER writes to GitHub, retries PUT/POST, mints an App
token, grants publication rights or replays an Action. An absent receipt stays
explicitly absent, rather than being inferred from a successful checkpoint.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
SOURCE_WORKFLOW = "Issue 311 17 authentic App-bot local PREPARE originals (NO RELEASE)"
SOURCE_PATH = ".github/workflows/issue311-coordinator-fleet-original.yml"
SOURCE_ARTIFACT = "issue311-r06-app-fleet-original-terminal"
SOURCE_ENTRY = SOURCE_ARTIFACT + ".json"
CHILD_ARTIFACT = "issue311-app-local-prepare-original-receipt"
CHILD_ENTRY = "issue311-app-local-prepare-receipt.json"
BOT = "pgextwin-issue311-prepare-coord[bot]"
CASE_IDS = (
    "r-20261030-r06appauto41074138918",
    "r-20261030-r06appauto41014241399",
    "r-20261030-r06appauto41015355922",
    "r-20261029-r05eventgap17b01",
    "r-20261030-r06parallelcasproof12",
    "r-20261030-r06appauto41014731356",
)


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def require(value, why):
    if not value:
        raise ValueError("R10_FINAL_DENY " + why)


def strict(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, "duplicate original JSON key")
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs)


def build(state, blob_sha, run, *, source_artifact=None, children=None):
    """Pure fail-closed join. Missing child data can never become a PASS."""
    require(state.get("schemaVersion") == 1 and state.get("revision") == 2
            and state.get("scope") == "AUDIT_ONLY_READONLY"
            and state.get("publisherAuthorized") is False
            and state.get("writeOutcomeUnknown") is False
            and SHA40.fullmatch(blob_sha or "")
            and state.get("terminal") in ("NO_UPDATE", "QUARANTINED", "FAILED",
                                         "BLOCKED_APPROVAL"), "nonterminal or privileged state")
    scope = state.get("targetScope")
    statuses = state.get("targets")
    require(type(scope) is list and len(scope) == 17 and len(set(scope)) == 17
            and all(type(x) is str and x.startswith("pgextwin/") for x in scope)
            and type(statuses) is dict and set(statuses) == set(scope),
            "17-target immutable scope mismatch")
    source = state.get("sourceRun")
    require(type(source) is dict and type(source.get("id")) is int
            and source.get("attempt") == 1 and run.get("id") == source["id"]
            and run.get("run_attempt") == 1
            and run.get("head_sha") == state.get("sourceHeadSha")
            and run.get("status") == "completed", "source Run/attempt/head mismatch")
    completion = state.get("completionRun")
    require(completion is None or (type(completion) is dict
            and type(completion.get("id")) is int and completion.get("attempt") == 1),
            "unverified completion attempt")
    require(state.get("eventTransport") in ("workflow_run.completed", "BOUNDED_WATCHDOG"),
            "unrecognized event transport")
    success = state["terminal"] == "NO_UPDATE"
    require(all(v == "SUCCESS" for v in statuses.values()) if success else
            all(v in ("FAILED", "QUARANTINED", "BLOCKED_APPROVAL") for v in statuses.values()),
            "terminal contradicts target status")
    if success:
        require(run.get("name") == SOURCE_WORKFLOW and run.get("path") == SOURCE_PATH
                and run.get("conclusion") == "success"
                and run.get("event") == "workflow_run" and run.get("head_branch") == "main"
                and type(children) is dict and set(children) == set(scope),
                "NO_UPDATE needs exact original 17 App children")
        require(source_artifact is not None
                and SHA64.fullmatch(source_artifact.get("zipSha256", "")),
                "NO_UPDATE needs real source archive bytes")
    else:
        require(children is None, "failed terminal cannot borrow healthy child receipts")

    entries = []
    for repo in sorted(scope):
        status = statuses[repo]
        child = children[repo] if success else None
        if success:
            require(child.get("repository") == repo
                    and child.get("attempt") == 1
                    and type(child.get("runId")) is int
                    and type(child.get("artifactId")) is int
                    and SHA40.fullmatch(child.get("headSha", ""))
                    and SHA64.fullmatch(child.get("zipSha256", ""))
                    and child.get("verifiedOriginal") is True
                    and child.get("result") == "NO_UPDATE",
                    "missing/forged original per-target receipt " + repo)
        if success:
            reason, resume, last = ("NO_UPDATE_ORIGINAL_ZIP_VERIFIED",
                                    "STOP_NO_UPDATE", "INDEPENDENT_ORIGINAL_ZIP_READBACK")
        elif status == "BLOCKED_APPROVAL":
            reason, resume, last = ("HUMAN_PUBLISH_APPROVAL_NOT_GRANTED",
                                    "WAIT_FOR_SEPARATE_EXPLICIT_AUTHORIZATION", "STATE_CAS_TERMINAL")
        elif state["eventTransport"] == "BOUNDED_WATCHDOG":
            reason, resume, last = ("BOUNDED_WATCHDOG_TERMINAL_SOURCE_DETAIL_UNRESOLVED",
                                    "NEW_PROTECTED_NONPUBLISHING_REQUEST_AFTER_REVIEW",
                                    "STATE_CAS_TERMINAL")
        else:
            reason, resume, last = ("ORIGINAL_SOURCE_OR_CHILD_FAILURE_DETAIL_UNRESOLVED",
                                    "NEW_PROTECTED_NONPUBLISHING_REQUEST_AFTER_REVIEW",
                                    "STATE_CAS_TERMINAL")
        entries.append({
            "repository": repo, "status": status, "reasonCode": reason,
            "reasonDetail": ("original success receipt verified" if success else
                             "original per-target failure/skip/timeout reason not joined; fail closed"),
            "originalRunId": child["runId"] if child else None,
            "originalAttempt": child["attempt"] if child else None,
            "originalSourceHeadSha": child["headSha"] if child else None,
            "originalArtifactId": child["artifactId"] if child else None,
            "originalZipSha256": child["zipSha256"] if child else None,
            "missingEvidenceReason": None if child else "NO_AUTHENTICATED_PER_TARGET_RECEIPT_JOIN",
            "lastSucceededStage": last, "safeRestartPoint": resume,
        })
    report = {
        "schemaVersion": 1, "scope": "R10_02_NONPUBLISHING_READONLY_REPORT",
        "requestId": state["requestId"], "requestSha256": state["requestSha256"],
        "stateBlobSha": blob_sha, "stateRevision": state["revision"],
        "terminal": state["terminal"], "eventTransport": state["eventTransport"],
        "expiresAt": state["expiresAt"],
        "source": {"runId": source["id"], "attempt": 1,
                   "headSha": state["sourceHeadSha"], "event": run.get("event"),
                   "conclusion": run.get("conclusion"), "workflow": run.get("path")},
        "completion": completion,
        "sourceArtifact": source_artifact,
        "publicationAuthorized": False, "writeOutcomeUnknown": False,
        "replayPolicy": "DENY_TERMINAL_NO_RESEND",
        "lateEventPolicy": "IGNORE_TERMINAL_AND_RECHECK_NEW_REQUEST",
        "unknownWritePolicy": "QUARANTINE_AND_GET_ONLY_NO_RESEND",
        "targets": entries,
        "evidenceCompleteness": "COMPLETE_17_ORIGINAL_ZIP" if success else
                                "INCOMPLETE_TARGET_REASON_AND_ZIP_FAIL_CLOSED",
        "r10_02Accepted": False,
    }
    return report


def readonly_case(request_id):
    require(request_id in CASE_IDS, "unapproved historical request")
    store = module("r10_store", "scripts/issue311-lifecycle-store.py")
    bridge = module("r10_bridge", "scripts/issue311-r05-windows-completion-bridge.py")
    client = module("r10_children", "scripts/issue311-r06-child-join-live.py")
    endpoint = store.endpoint(request_id) + "?ref=" + store.BRANCH
    blob, state = store.unpack(bridge.get_json(endpoint), request_id)
    source_id = state["sourceRun"]["id"]
    run = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(source_id))
    require(run.get("id") == source_id and run.get("run_attempt") == 1,
            "original source GET mismatch")
    source_artifact = None
    children = None
    if state["terminal"] == "NO_UPDATE":
        items = bridge.get_json("repos/pgextwin/build/actions/runs/" +
                                str(source_id) + "/artifacts?per_page=100")
        arts = items.get("artifacts", [])
        require(items.get("total_count") == 1 and len(arts) == 1
                and arts[0].get("name") == SOURCE_ARTIFACT
                and arts[0].get("expired") is False, "missing original source artifact")
        receipt, real_sha = bridge.original_zip(arts[0], SOURCE_ENTRY)
        require(arts[0].get("digest") == "sha256:" + real_sha
                and receipt.get("sourceKind") ==
                    "AUTHENTIC_APP_BOT_17_LOCAL_ORIGINAL_NONPUBLISHING"
                and receipt.get("result") ==
                    "CHILDREN_17_ORIGINAL_ZIP_VERIFIED_CAS_PENDING"
                and receipt.get("runtimeEnabled") is False
                and receipt.get("publicationAuthorized") is False,
                "original archive source-kind mismatch")
        source_artifact = {"artifactId": arts[0]["id"], "zipSha256": real_sha}
        listed = receipt.get("children")
        require(type(listed) is list and len(listed) == 17
                and len({c.get("repository") for c in listed}) == 17,
                "source ZIP lacks 17 unique children")
        children = {}
        for item in listed:
            repo = item["repository"]
            rid = item.get("localRunId")
            aid = item.get("originalReceiptArtifactId")
            digest = item.get("originalReceiptZipSha256Verified")
            require(repo in state["targetScope"]
                    and type(rid) is int and type(aid) is int
                    and type(digest) is str and SHA64.fullmatch(digest),
                    "unbound child original")
            local = client.get(repo, "actions/runs/" + str(rid))
            require(local.get("event") == "workflow_dispatch"
                    and local.get("run_attempt") == 1
                    and local.get("status") == "completed"
                    and local.get("conclusion") == "success"
                    and local.get("actor", {}).get("login") == BOT,
                    "forged local bot Run")
            original, art = client.artifact(
                repo, rid, CHILD_ARTIFACT, CHILD_ENTRY,
                expected_id=aid, expected_digest=digest)
            require(art.get("zipSha256") == digest
                    and original.get("localRunId") == rid
                    and original.get("localRunAttempt") == 1
                    and original.get("result") == "NO_UPDATE"
                    and original.get("runtimeEnabled") is False
                    and original.get("publicationAuthorized") is False
                    and item.get("originalReceiptIndependentlyVerified") is True,
                    "original child receipt cross-join rejected")
            children[repo] = {"repository": repo, "runId": rid, "attempt": 1,
                              "headSha": local["head_sha"], "artifactId": aid,
                              "zipSha256": digest, "result": "NO_UPDATE",
                              "verifiedOriginal": True}
    return build(state, blob, run, source_artifact=source_artifact, children=children)


def serial(obj):
    return (json.dumps(obj, ensure_ascii=True, sort_keys=True,
                       indent=2) + "\n").encode("ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="issue311-r10-final-report.json")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    require(bool(os.getenv("GH_TOKEN")), "authenticated read-only GitHub token missing")
    reports = [readonly_case(r) for r in CASE_IDS]
    aggregate = {"schemaVersion": 1, "nonpublishing": True,
                 "complete": False, "accepted": False, "cases": reports}
    raw = serial(aggregate)
    path = Path(args.output)
    if args.verify:
        require(path.exists() and path.read_bytes() == raw,
                "separate Runner original Git GET/report bytes mismatch")
        print("R10_02_SEPARATE_RUNNER_ORIGINAL_GET_MATCH " + hashlib.sha256(raw).hexdigest())
    else:
        path.write_bytes(raw)
        print("R10_02_KEY_FREE_ORIGINAL_GET_REPORT " + hashlib.sha256(raw).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
