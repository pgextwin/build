#!/usr/bin/env python3
"""R04/R05 generic bounded AUDIT_ONLY request lifecycle (pure; no GitHub authority).

Transitions are intended for a trusted coordinator to persist using the dedicated
App Contents CAS. Caller-provided observations are NOT authenticated by this
library. It neither starts workflows nor authorizes publication.
"""
from __future__ import annotations
import copy
from datetime import datetime, timezone
import hashlib
import json
import re

REQ = re.compile(r"r-[0-9]{8}-[a-z0-9-]{8,56}$")
SHA1 = re.compile(r"[a-f0-9]{40}$")
SHA256 = re.compile(r"[a-f0-9]{64}$")
TARGET = re.compile(r"pgextwin/[a-z0-9_-]+$")
TERMINALS = frozenset(("SUCCESS", "NO_UPDATE", "FAILED", "BLOCKED_APPROVAL", "QUARANTINED"))
OUTCOMES = TERMINALS | {"PENDING"}
MAX_EVENTS = 2000


class Denied(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Denied(message)


def parse_utc(value):
    require(type(value) is str and value.endswith("Z"), "expected UTC deadline")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Denied("invalid UTC deadline") from exc
    require(result.utcoffset().total_seconds() == 0, "non-UTC deadline")
    return result


def new(request_id, request_sha, source_head, targets, expires_at, *, max_events=100):
    require(type(request_id) is str and REQ.fullmatch(request_id), "invalid request ID")
    require(type(request_sha) is str and SHA256.fullmatch(request_sha), "invalid original SHA256")
    require(type(source_head) is str and SHA1.fullmatch(source_head), "invalid source commit")
    require(type(targets) is list and 1 <= len(targets) <= 17
            and all(type(t) is str and TARGET.fullmatch(t) for t in targets)
            and len(set(targets)) == len(targets), "invalid or duplicate target")
    parse_utc(expires_at)
    require(type(max_events) is int and 1 <= max_events <= MAX_EVENTS, "invalid event budget")
    return {
        "schemaVersion": 1, "scope": "AUDIT_ONLY_READONLY",
        "requestId": request_id, "requestSha256": request_sha,
        "sourceHeadSha": source_head, "expiresAt": expires_at,
        "maxEvents": max_events, "revision": 0, "events": {},
        "sourceRun": None, "completionRun": None, "eventTransport": None,
        "targetScope": sorted(targets),
        "targets": {t: "PENDING" for t in targets}, "terminal": None,
        "publisherAuthorized": False, "writeOutcomeUnknown": False
    }


def validate(state):
    require(type(state) is dict and set(state) == {
        "schemaVersion", "scope", "requestId", "requestSha256",
        "sourceHeadSha", "expiresAt", "maxEvents", "revision", "events",
        "sourceRun", "completionRun", "eventTransport", "targetScope", "targets", "terminal",
        "publisherAuthorized", "writeOutcomeUnknown"}, "unknown state fields")
    require(state["schemaVersion"] == 1 and state["scope"] == "AUDIT_ONLY_READONLY"
            and state["publisherAuthorized"] is False and state["writeOutcomeUnknown"] is False,
            "unsafe scope or ambiguous write")
    require(type(state["revision"]) is int and state["revision"] >= 0
            and type(state["maxEvents"]) is int and 1 <= state["maxEvents"] <= MAX_EVENTS,
            "invalid revision/budget")
    require(REQ.fullmatch(state["requestId"]) and SHA256.fullmatch(state["requestSha256"])
            and SHA1.fullmatch(state["sourceHeadSha"]), "invalid immutable identity")
    parse_utc(state["expiresAt"])
    require(type(state["events"]) is dict and len(state["events"]) <= state["maxEvents"]
            and all(type(k) is str and SHA256.fullmatch(v) for k, v in state["events"].items()),
            "invalid event log")
    require(type(state["targetScope"]) is list and 1 <= len(state["targetScope"]) <= 17
            and len(set(state["targetScope"])) == len(state["targetScope"]), "invalid target allowlist")
    require(type(state["targets"]) is dict and set(state["targets"]) == set(state["targetScope"])
            and 1 <= len(state["targets"]) <= 17
            and all(TARGET.fullmatch(k) and v in OUTCOMES for k, v in state["targets"].items()),
            "invalid per-target states")
    for key in ("sourceRun", "completionRun"):
        value = state[key]
        require(value is None or (type(value) is dict and set(value) == {"id", "attempt"}
                and type(value["id"]) is int and value["id"] > 0
                and type(value["attempt"]) is int and 1 <= value["attempt"] <= 3),
                "malformed source/completion run")
    require(state["eventTransport"] in (None, "workflow_run.completed", "BOUNDED_WATCHDOG"),
            "invalid event transport")
    if state["terminal"] is not None:
        require(state["terminal"] in TERMINALS
                and all(v in TERMINALS for v in state["targets"].values()),
                "partial terminal falsely finalized")
    return state


def _apply(state, expected_revision, key, payload, transform):
    validate(state)
    require(type(key) is str and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", key), "bad event key")
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if key in state["events"]:
        require(state["events"][key] == digest, "event key collision/replay altered")
        return copy.deepcopy(state)
    require(type(expected_revision) is int and expected_revision == state["revision"],
            "stale CAS revision")
    require(state["terminal"] is None, "already terminal")
    require(len(state["events"]) < state["maxEvents"], "event budget exhausted")
    result = copy.deepcopy(state)
    transform(result)
    result["events"][key] = digest
    result["revision"] += 1
    validate(result)
    return result


def bind_source(state, revision, key, *, run_id, attempt, head_sha):
    """The caller MUST independently authenticate source REST/actor/main/event."""
    payload = dict(op="source", runId=run_id, attempt=attempt, head=head_sha)
    def action(s):
        require(type(run_id) is int and run_id > 0
                and type(attempt) is int and 1 <= attempt <= 3
                and head_sha == s["sourceHeadSha"] and s["sourceRun"] is None,
                "source run changed or invalid")
        s["sourceRun"] = {"id": run_id, "attempt": attempt}
    return _apply(state, revision, key, payload, action)


def record_completion(state, revision, key, *, run_id, attempt, source_id,
                      outcome, target_outcomes, original_zip_sha):
    """The caller MUST verify original 17 ZIPs + completed-event source independently."""
    payload = dict(op="completion", runId=run_id, attempt=attempt, source=source_id,
                   outcome=outcome, targets=target_outcomes, zip=original_zip_sha)
    def action(s):
        require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0
                and s["sourceRun"] is not None and source_id == s["sourceRun"]["id"],
                "unbound original source")
        require(outcome in ("NO_UPDATE", "FAILED", "QUARANTINED"), "unsupported terminal")
        require(type(target_outcomes) is dict and set(target_outcomes) == set(s["targets"])
                and all(v in TERMINALS for v in target_outcomes.values()),
                "missing or pending target")
        require(type(original_zip_sha) is str and SHA256.fullmatch(original_zip_sha),
                "missing original source artifact proof")
        require(outcome != "NO_UPDATE" or all(v == "SUCCESS" for v in target_outcomes.values()),
                "cannot claim NO_UPDATE on failed child")
        s["targets"] = dict(target_outcomes)
        s["terminal"] = outcome
        s["completionRun"] = {"id": run_id, "attempt": attempt}
        s["eventTransport"] = "workflow_run.completed"
    return _apply(state, revision, key, payload, action)


def event_deadline(state, revision, key, *, now, source_completed,
                   original_source_sha, completion_lookup):
    """Finite fail-closed termination. None/unknown event lookup -> QUARANTINED.

    This does NOT detect missing events by itself. Trusted bounded sidecar must
    authenticate all GitHub REST replies before calling. No silent retries.
    """
    payload = dict(op="deadline", now=now, source=source_completed,
                   sourceSha=original_source_sha, lookup=completion_lookup)
    def action(s):
        require(parse_utc(now) >= parse_utc(s["expiresAt"]), "watch window not expired")
        require(s["sourceRun"] is not None, "cannot infer a source run")
        require(source_completed is None or type(source_completed) is bool, "invalid original run state")
        require(original_source_sha == s["sourceHeadSha"], "source commit changed")
        require(completion_lookup in ("MISSING_VERIFIED", "UNKNOWN", "DELIVERED"),
                "invalid observed lookup")
        require(completion_lookup != "DELIVERED", "delivered event must be verified")
        result = "FAILED" if source_completed is True and completion_lookup == "MISSING_VERIFIED" else "QUARANTINED"
        s["targets"] = {t: (v if v in TERMINALS else result) for t, v in s["targets"].items()}
        s["terminal"] = result
        s["eventTransport"] = "BOUNDED_WATCHDOG"
    return _apply(state, revision, key, payload, action)
