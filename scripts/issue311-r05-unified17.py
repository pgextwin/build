#!/usr/bin/env python3
"""One exact 17-target AUDIT_ONLY request: original Windows receipts + durable App CAS.

The build-only App writes only issue311-state. All target repositories are read
with the ordinary GITHUB_TOKEN; no candidate/signature/Release side effects.
An independently authenticated completion listener owns finalization.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUEST = "r-20261029-r05unified17a01"
REQUEST_PATH = ".github/execution-requests/" + REQUEST + ".json"
PREFIX = "issue311-r05-unified17-"
SOURCE_NAME = "Issue 311 R05 unified 17 App persisted original Windows (NONPUBLISHING)"
SOURCE_PATH = ".github/workflows/issue311-r05-unified17.yml"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


win = load("issue311win17", "scripts/issue311-r05-windows-17.py")
life = load("issue311life", "scripts/issue311-request-lifecycle.py")
store = load("issue311store", "scripts/issue311-lifecycle-store.py")
writer = load("issue311writer", "scripts/issue311-writer-runtime.py")
bridge = load("issue311bridge", "scripts/issue311-r05-windows-completion-bridge.py")

# Reuse the original accepted 17-Windows transport and SHA verification, but
# NEVER reuse its old request or frozen R04 checkpoint as this request's proof.
win.REQUEST = REQUEST
win.REQUEST_PATH = REQUEST_PATH
win.ARTIFACT_PREFIX = PREFIX


def require(valid, message):
    if not valid:
        raise ValueError("R05_UNIFIED_DENY " + message)


def original_request():
    win.real_event()
    raw = win.original_bytes()
    declaration = win.strict_request(raw)
    original = bridge.get_json("repos/pgextwin/build/contents/" + REQUEST_PATH +
                               "?ref=" + os.environ["GITHUB_SHA"])
    require(original.get("encoding") == "base64", "request original Contents unavailable")
    b64 = original["content"].replace("\n", "").replace("\r", "")
    remote = base64.b64decode(b64, validate=True)
    require(store.blob_hash(remote) == original["sha"] and remote == raw,
            "original Git blob differs from REST authenticated original")
    data = json.loads(raw, object_pairs_hook=store.unique_pairs)
    require(data["limits"]["maxAttemptsPerStage"] == 1
            and data["limits"]["maxWallClockMinutes"] <= 45
            and data["approval"]["publicReleaseAuthorized"] is False
            and data["approval"]["publicationGrants"] == []
            and data["allowFutureUpdates"] is False,
            "nonpublishing bounded contract mismatch")
    return declaration, data


def read_original_state(declaration=None):
    payload = bridge.get_json("repos/pgextwin/build/contents/" + store.PREFIX +
                              REQUEST + ".json?ref=" + store.BRANCH)
    blob, state = store.unpack(payload, REQUEST)
    if declaration is None:
        declaration, _ = original_request()
    require(state["requestSha256"] == declaration["rawSha256"]
            and state["sourceHeadSha"] == os.environ["GITHUB_SHA"]
            and state["targetScope"] == sorted(win.TARGETS)
            and state["sourceRun"] == {
                "id": int(os.environ["GITHUB_RUN_ID"]), "attempt": 1}
            and state["revision"] == 1 and state["terminal"] is None
            and state["completionRun"] is None and state["publisherAuthorized"] is False
            and all(value == "PENDING" for value in state["targets"].values()),
            "missing/foreign/noninitial durable App checkpoint")
    return blob, state


def init():
    token = None
    receipt = {"requestId": REQUEST, "result": "FAILED", "publisherAuthorized": False}
    try:
        require(os.environ["GITHUB_WORKFLOW"] == SOURCE_NAME
                and os.environ["GITHUB_RUN_ATTEMPT"] == "1", "source identity")
        declaration, data = original_request()
        state = life.new(REQUEST, declaration["rawSha256"], os.environ["GITHUB_SHA"],
                         sorted(win.TARGETS), data["expiresAt"],
                         max_events=data["limits"]["maxOperations"])
        key = os.environ.get("STATE_WRITER_PRIVATE_KEY", "")
        require(bool(key), "approved dedicated App secret absent")
        token = writer.mint_token(key)
        cas = store.CAS(lambda method, path, payload:
                        writer.api(method, path, token, payload))
        created = cas.write(state)
        blob, old = cas.read(REQUEST)
        bound = life.bind_source(old, old["revision"], "original-source-run",
                                 run_id=int(os.environ["GITHUB_RUN_ID"]),
                                 attempt=1, head_sha=os.environ["GITHUB_SHA"])
        committed = cas.write(bound, previous=old, expected_blob=blob)
        final_blob, final = cas.read(REQUEST)
        require(final == bound, "source state original GET mismatch")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fp:
            fp.write("raw_sha=" + declaration["rawSha256"] + "\n")
        receipt.update(result="SOURCE_BOUND", requestSha256=declaration["rawSha256"],
                       sourceRunId=int(os.environ["GITHUB_RUN_ID"]),
                       sourceSha=os.environ["GITHUB_SHA"], stateGitBlobSha=final_blob,
                       revision=1, persistence=[created, committed])
    except Exception as exc:
        receipt["reason"] = str(exc)[:320]
    finally:
        if token is not None:
            writer.revoke_and_prove_401(token)
    Path("issue311-r05-unified17-init.json").write_text(
        json.dumps(receipt, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["result"] == "SOURCE_BOUND" else 1


def inspect():
    repo = os.environ["REMOTE_REPO"]
    receipt = {"requestId": REQUEST, "repo": repo,
               "runId": int(os.environ["GITHUB_RUN_ID"]),
               "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
               "runnerOS": os.environ["RUNNER_OS"], "result": "FAILED",
               "completionEvent": "WINDOWS_ORIGINAL_REMOTE_GET",
               "publicationAuthorized": False, "requestSha256": os.environ["REQUEST_SHA"]}
    try:
        declaration, _ = original_request()
        require(declaration["rawSha256"] == os.environ["REQUEST_SHA"]
                and repo in win.TARGETS and os.environ["REMOTE_SHA"] == win.TARGETS[repo]
                and os.environ["RUNNER_OS"] == "Windows",
                "Windows target/run/request mismatch")
        state_blob, _ = read_original_state(declaration)
        remote = win.old.get_json("https://api.github.com/repos/" + repo + "/branches/main",
                                  os.environ["GH_TOKEN"])
        require(remote.get("name") == "main" and remote.get("protected") is True
                and remote.get("commit", {}).get("sha") == win.TARGETS[repo],
                "remote protected main no longer at requested SHA")
        receipt.update(result="SUCCESS", targetMainSha=win.TARGETS[repo],
                       remoteProtected=True, stateGitBlobSha=state_blob)
    except Exception as exc:
        receipt["reason"] = str(exc)[:300]
    Path("issue311-r05-win17-target.json").write_text(
        json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["result"] == "SUCCESS" else 1


def aggregate():
    try:
        declaration, _ = original_request()
        blob, _ = read_original_state(declaration)
        win.R04_BLOB = blob
        # Reuse original SHA256 checks for 17 freshly generated ZIP bytes.
        # This stage is read-only; listener subsequently re-fetches every ZIP.
        return win.aggregate()
    except Exception as exc:
        # Even missing dependencies must leave an explicit original failure
        # receipt; never claim NO_UPDATE or silently skip the aggregate.
        terminal = {"requestId": REQUEST, "terminal": "FAILED",
                    "runId": int(os.environ["GITHUB_RUN_ID"]),
                    "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                    "publicReleaseAuthorized": False,
                    "reason": str(exc)[:320]}
        Path("issue311-r05-win17-terminal.json").write_text(
            json.dumps(terminal, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(terminal, sort_keys=True))
        return 1


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    raise SystemExit(init() if action == "init" else
                     inspect() if action == "inspect" else
                     aggregate() if action == "aggregate" else 2)
