#!/usr/bin/env python3
"""Nonpublishing generic request checkpoint in the approved build-only App state ref.

This adapter receives an API function with a previously authenticated build-only
App installation token. It does NOT mint tokens, authenticate workflow evidence,
dispatch workflows, or grant any publication permission.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lifecycle", ROOT / "scripts" / "issue311-request-lifecycle.py")
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)

BRANCH = "issue311-state"
PREFIX = "checkpoints/request-lifecycle/"
REPOSITORY = "repos/pgextwin/build/contents/"
SHA1 = re.compile(r"[0-9a-f]{40}$")


class Denied(ValueError):
    pass


class UnknownWrite(Denied):
    pass


def require(value, message):
    if not value:
        raise Denied(message)


def unique_pairs(pairs):
    result = {}
    for k,v in pairs:
        require(k not in result, "duplicate JSON field")
        result[k] = v
    return result


def endpoint(request_id):
    require(type(request_id) is str and lifecycle.REQ.fullmatch(request_id),
            "request path outside immutable namespace")
    return REPOSITORY + PREFIX + request_id + ".json"


def canonical(state):
    lifecycle.validate(state)
    return (json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n").encode("ascii")


def blob_hash(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def unpack(payload, request_id):
    require(type(payload) is dict and payload.get("encoding") == "base64"
            and type(payload.get("sha")) is str and SHA1.fullmatch(payload["sha"]),
            "invalid authenticated Contents response")
    try:
        raw = base64.b64decode(payload["content"], validate=True)
        state = json.loads(raw, object_pairs_hook=unique_pairs)
    except (ValueError, KeyError, TypeError) as exc:
        raise Denied("corrupt original checkpoint") from exc
    require(blob_hash(raw) == payload["sha"], "Git blob SHA differs from actual bytes")
    lifecycle.validate(state)
    require(state["requestId"] == request_id, "cross-request replay")
    return payload["sha"], state


def require_transition(previous, proposed):
    lifecycle.validate(proposed)
    if previous is None:
        require(proposed["revision"] == 0 and proposed["events"] == {}
                and proposed["sourceRun"] is None and proposed["terminal"] is None,
                "initial state must not claim received events")
    else:
        lifecycle.validate(previous)
        for key in ("requestId", "requestSha256", "sourceHeadSha", "targetScope",
                    "expiresAt", "maxEvents", "scope", "schemaVersion"):
            require(previous[key] == proposed[key], "immutable request field changed " + key)
        require(proposed["revision"] == previous["revision"] + 1,
                "stale or skipped CAS revision")
        require(set(previous["events"]).issubset(proposed["events"])
                and all(previous["events"][k] == proposed["events"][k]
                        for k in previous["events"])
                and len(proposed["events"]) == len(previous["events"]) + 1,
                "changed/replayed event proof")
        require(previous["terminal"] is None and previous["writeOutcomeUnknown"] is False,
                "terminal/ambiguous state is immutable")
    require(proposed["publisherAuthorized"] is False
            and proposed["writeOutcomeUnknown"] is False, "publication and ambiguity denied")


class CAS:
    """API signature api(method, endpoint, payload_or_None). No hidden retries."""
    def __init__(self, api):
        self.api = api

    def read(self, request_id):
        return unpack(self.api("GET", endpoint(request_id) + "?ref=" + BRANCH, None),
                      request_id)

    def write(self, proposed, *, previous=None, expected_blob=None):
        require_transition(previous, proposed)
        request_id = proposed["requestId"]
        if previous is None:
            require(expected_blob is None, "new checkpoint cannot overwrite existing file")
        else:
            require(type(expected_blob) is str and SHA1.fullmatch(expected_blob),
                    "existing checkpoint requires original Git blob SHA")
            require(previous["requestId"] == request_id, "cross-request CAS")
        body = {"message": "state(issue311): nonpublishing bounded lifecycle " + request_id,
                "branch": BRANCH, "content": base64.b64encode(canonical(proposed)).decode("ascii")}
        if previous is not None:
            body["sha"] = expected_blob
        try:
            response = self.api("PUT", endpoint(request_id), body)
        except Exception as exc:
            # A lost PUT response must never be blindly retried.
            try:
                _, actual = self.read(request_id)
            except Exception as lookup:
                raise UnknownWrite("QUARANTINED: PUT uncertain, GET unavailable") from lookup
            if actual == proposed:
                return "RECONCILED_BY_ORIGINAL_GET"
            raise UnknownWrite("QUARANTINED: PUT uncertain, no exact-byte match") from exc
        require(type(response) is dict
                and SHA1.fullmatch(str(response.get("content", {}).get("sha", ""))),
                "unverifiable PUT response")
        try:
            actual_blob, actual = self.read(request_id)
        except Exception as exc:
            raise UnknownWrite("QUARANTINED: committed state readback unavailable") from exc
        require(actual_blob == response["content"]["sha"] and actual == proposed,
                "postwrite original byte mismatch")
        return "ORIGINAL_GET_VERIFIED"
