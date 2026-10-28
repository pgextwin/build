#!/usr/bin/env python3
"""Issue 311 R04: pure versioned checkpoint transitions; NO persistence or writer authority.

The caller MUST supply a trustworthy CAS repository/storage adapter and independently
verified original evidence before committing a returned state. This module cannot
create a release, branch, GitHub issue, GitHub Actions event or write any state.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re

SHA256 = re.compile(r"^[0-9a-f]{64}$")
STAGES = ("AUTHENTICATE", "SCAN", "PREFLIGHT", "CANDIDATE", "SIGNED_AUDIT",
          "PUBLICATION_CHECK", "DOWNSTREAM")
TERMINALS = frozenset(("SUCCESS", "NO_UPDATE", "FAILED",
                       "BLOCKED_APPROVAL", "QUARANTINED"))
OUTCOMES = TERMINALS | frozenset(("STEP_OK", "RETRYABLE", "WRITE_OUTCOME_UNKNOWN"))


class Conflict(ValueError):
    pass


def require(valid, reason):
    if not valid:
        raise Conflict(reason)


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def create_state(request_id: str, original_request_sha256: str, targets: list[str],
                 max_attempts: int = 2, max_operations: int = 200) -> dict:
    require(type(request_id) is str and request_id.startswith("r-"), "invalid request ID")
    require(type(original_request_sha256) is str and SHA256.fullmatch(original_request_sha256),
            "invalid original request byte hash")
    require(type(targets) is list and bool(targets) and len(set(targets)) == len(targets),
            "duplicate/missing targets")
    require(type(max_attempts) is int and 1 <= max_attempts <= 3, "invalid retry budget")
    require(type(max_operations) is int and 1 <= max_operations <= 2000, "invalid operation budget")
    return {"schemaVersion": 1, "requestId": request_id,
            "requestSha256": original_request_sha256, "revision": 0,
            "maxAttempts": max_attempts, "maxOperations": max_operations,
            "events": {}, "terminal": False,
            "targets": {repo: {"stage": STAGES[0], "attempts": {}, "inputDigests": {},
                               "outcome": "PENDING", "lastReceiptSha256": None,
                               "reason": None} for repo in targets}}


def advance(state: dict, expected_revision: int, event: dict) -> dict:
    """Return a new state or fail closed. Never mutate the input state."""
    require(type(state) is dict and state.get("schemaVersion") == 1, "invalid state")
    require(type(event) is dict, "event must be object")
    required = {"key", "repo", "stage", "outcome", "inputSha256",
                "receiptSha256", "runId", "runAttempt", "reason"}
    require(set(event) == required, "unexpected/missing event keys")
    require(type(event["key"]) is str and 1 <= len(event["key"]) <= 200,
            "invalid event key")
    require(type(event["repo"]) is str and event["repo"] in state.get("targets", {}),
            "unknown target")
    for field in ("inputSha256", "receiptSha256"):
        require(type(event[field]) is str and SHA256.fullmatch(event[field]),
                "missing immutable original evidence " + field)
    require(type(event["runId"]) is int and event["runId"] > 0,
            "invalid original run ID")
    require(type(event["runAttempt"]) is int and event["runAttempt"] > 0,
            "invalid original run attempt")
    require(type(event["reason"]) is str and 1 <= len(event["reason"]) <= 500,
            "missing bounded reason")
    require(event["outcome"] in OUTCOMES, "invalid outcome")

    # Exact duplicate is idempotent even if the caller has an old CAS revision.
    original = state.get("events", {}).get(event["key"])
    if original is not None:
        require(original == digest(event), "event key collision / tampered replay")
        return copy.deepcopy(state)

    require(type(expected_revision) is int and expected_revision == state.get("revision"),
            "stale CAS revision")
    require(not state.get("terminal"), "request already terminal")
    require(len(state["events"]) < state["maxOperations"], "operation budget exhausted")
    target = state["targets"][event["repo"]]
    require(target["outcome"] == "PENDING", "target already terminal")
    require(event["stage"] == target["stage"], "wrong stage or skipped original proof")

    new = copy.deepcopy(state)
    item = new["targets"][event["repo"]]
    expected_input = item["inputDigests"].get(event["stage"])
    require(expected_input is None or expected_input == event["inputSha256"],
            "same-stage retry input changed without fresh authorization")
    item["inputDigests"][event["stage"]] = event["inputSha256"]
    count = item["attempts"].get(event["stage"], 0) + 1
    require(count <= new["maxAttempts"], "retry budget exhausted")
    item["attempts"][event["stage"]] = count
    item["lastReceiptSha256"] = event["receiptSha256"]
    item["reason"] = event["reason"]

    if event["outcome"] == "WRITE_OUTCOME_UNKNOWN":
        item["outcome"] = "QUARANTINED"  # never blind-write retry after network ambiguity
    elif event["outcome"] == "RETRYABLE":
        if count >= new["maxAttempts"]:
            item["outcome"] = "FAILED"
    elif event["outcome"] == "STEP_OK":
        index = STAGES.index(event["stage"])
        if index == len(STAGES) - 1:
            item["outcome"] = "SUCCESS"
        else:
            item["stage"] = STAGES[index + 1]
    else:
        item["outcome"] = event["outcome"]

    new["events"][event["key"]] = digest(event)
    new["revision"] += 1
    new["terminal"] = all(x["outcome"] in TERMINALS for x in new["targets"].values())
    return new


def summarize(state: dict) -> dict:
    """Display a bounded result, not an authenticated state-storage receipt."""
    return {"requestId": state["requestId"], "revision": state["revision"],
            "terminal": state["terminal"],
            "outcomes": {repo: value["outcome"] for repo, value in state["targets"].items()},
            "persistenceAccepted": False, "publisherAuthorized": False}
