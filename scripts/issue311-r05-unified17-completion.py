#!/usr/bin/env python3
"""Verify every original Windows ZIP and atomically finalize the 17-target App state.

Trusted workflow_run.completed listener only. Original artifacts are never
treated as authority without authenticating Run, request Git blob, jobs,
artifact provider digests, all contained receipts, and state CAS.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


source = load("unified", "scripts/issue311-r05-unified17.py")
check = source.bridge
life = source.life
store = source.store
writer = source.writer
contract = load("request_contract", "scripts/issue311-request-contract.py")
REQUEST = source.REQUEST
RECEIPT = "issue311-r05-unified17-completion.json"


def require(valid, reason):
    if not valid:
        raise ValueError("R05_UNIFIED_COMPLETION_DENY " + reason)


def validated_source(event):
    run = event.get("workflow_run", {})
    require(event.get("action") == "completed"
            and event.get("repository", {}).get("full_name") == "pgextwin/build"
            and type(run.get("id")) is int and run["id"] > 0
            and run.get("name") == source.SOURCE_NAME
            and run.get("path") == source.SOURCE_PATH
            and run.get("event") == "push"
            and run.get("head_branch") == "main"
            and run.get("actor", {}).get("login") == "ShutenOishi"
            and run.get("run_attempt") == 1
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and re.fullmatch("[a-f0-9]{40}", run.get("head_sha", "")),
            "foreign/failed/untrusted source event")
    actual = check.get_json("repos/pgextwin/build/actions/runs/" + str(run["id"]))
    for field in ("id", "workflow_id", "run_attempt", "head_sha", "event", "path",
                  "head_branch", "conclusion"):
        require(actual.get(field) == run.get(field), "source REST mismatch " + field)
    require(actual.get("status") == "completed"
            and actual.get("actor", {}).get("login") == "ShutenOishi",
            "original source Run not authenticated")
    record = check.get_json("repos/pgextwin/build/contents/" + source.REQUEST_PATH +
                            "?ref=" + run["head_sha"])
    require(record.get("encoding") == "base64", "request Contents unavailable")
    raw = base64.b64decode(record["content"].replace("\n", "").replace("\r", ""),
                           validate=True)
    require(store.blob_hash(raw) == record["sha"], "request Git blob digest mismatch")
    declaration = contract.validate_declaration(raw, source.REQUEST_PATH)
    data = json.loads(raw, object_pairs_hook=store.unique_pairs)
    require(declaration["requestId"] == REQUEST and declaration["mode"] == "AUDIT_ONLY"
            and declaration["targets"] == tuple(sorted(source.win.TARGETS))
            and {x["repo"]: x["mainSha"] for x in data["targets"]} == source.win.TARGETS
            and data["approval"]["publicReleaseAuthorized"] is False
            and data["approval"]["publicationGrants"] == []
            and data["allowFutureUpdates"] is False,
            "request changed or not exact 17-target AUDIT_ONLY")
    # A protected merge has the prior protected main as first parent.
    commit = check.get_json("repos/pgextwin/build/commits/" + run["head_sha"])
    require(commit.get("parents", [{}])[0].get("sha") == data["source"]["centralMainSha"],
            "source prior protected main commit not bound")
    return run, declaration


def verify_all(source_run, request_sha, state_blob):
    source_id = source_run["id"]
    jobs = check.get_json(
        "repos/pgextwin/build/actions/runs/" + str(source_id) + "/jobs?per_page=100")
    per_job = check.require_jobs(jobs, source_id, source_run["conclusion"])
    artifacts = check.get_json(
        "repos/pgextwin/build/actions/runs/" + str(source_id) + "/artifacts?per_page=100")
    check.REQUEST = REQUEST
    check.ZIP_PREFIX = source.PREFIX
    check.ZIP_TERMINAL = "issue311-r05-win17-terminal"
    check.win17.R04_BLOB = state_blob
    entries = check.parse_artifacts(artifacts, source_id)
    receipt_sha, terminal_sha = check.check_receipts(
        entries, source_id, source_run["run_attempt"], request_sha,
        source.win.TARGETS, per_job)
    return per_job, receipt_sha, terminal_sha


def complete():
    token = None
    receipt = {"schemaVersion": 1, "requestId": REQUEST,
               "result": "FAILED", "publisherAuthorized": False}
    try:
        require(os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
                and os.environ["GITHUB_EVENT_NAME"] == "workflow_run"
                and os.environ["GITHUB_REF"] == "refs/heads/main"
                and os.environ["GITHUB_RUN_ATTEMPT"] == "1",
                "not a trusted main completion listener")
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                           object_pairs_hook=store.unique_pairs)
        original, declaration = validated_source(event)
        key = os.environ.get("STATE_WRITER_PRIVATE_KEY", "")
        require(bool(key), "approved App secret absent")
        token = writer.mint_token(key)
        cas = store.CAS(lambda method, path, payload:
                        writer.api(method, path, token, payload))
        blob, state = cas.read(REQUEST)
        require(state["sourceRun"] == {"id": original["id"], "attempt": 1}
                and state["sourceHeadSha"] == original["head_sha"]
                and state["requestSha256"] == declaration["rawSha256"]
                and state["targetScope"] == sorted(source.win.TARGETS)
                and state["revision"] == 1
                and state["terminal"] is None
                and all(v == "PENDING" for v in state["targets"].values()),
                "not the authentic pending App state")
        per_job, originals, terminal = verify_all(original, declaration["rawSha256"], blob)
        manifest = {"sourceRunId": original["id"],
                    "sourceRunAttempt": original["run_attempt"],
                    "targetZipSha256": originals,
                    "terminalZipSha256": terminal}
        manifest_sha = hashlib.sha256(json.dumps(
            manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        finished = life.record_completion(
            state, state["revision"], "complete-original-17-zip",
            run_id=int(os.environ["GITHUB_RUN_ID"]),
            attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
            source_id=original["id"], outcome="NO_UPDATE",
            target_outcomes={repo: "SUCCESS" for repo in source.win.TARGETS},
            original_zip_sha=manifest_sha)
        result = cas.write(finished, previous=state, expected_blob=blob)
        after_blob, after = cas.read(REQUEST)
        require(after == finished and after["terminal"] == "NO_UPDATE",
                "terminal App CAS original readback mismatch")
        receipt.update(result="NO_UPDATE", sourceRunId=original["id"],
                       completionRunId=int(os.environ["GITHUB_RUN_ID"]),
                       requestSha256=declaration["rawSha256"],
                       originalSourceHead=original["head_sha"],
                       sourceRunAttempt=1, stateRevision=after["revision"],
                       stateGitBlobSha=after_blob, originalReceipts=manifest,
                       originalReceiptManifestSha256=manifest_sha,
                       perTarget={t: "SUCCESS" for t in source.win.TARGETS},
                       persistence=result, eventTransport="workflow_run.completed")
    except Exception as exc:
        receipt["reason"] = str(exc)[:400]
    finally:
        if token is not None:
            writer.revoke_and_prove_401(token)
    Path(RECEIPT).write_text(json.dumps(receipt, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["result"] == "NO_UPDATE" else 1


if __name__ == "__main__":
    raise SystemExit(complete() if sys.argv[1:] == ["complete"] else 2)
