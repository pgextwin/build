#!/usr/bin/env python3
"""Issue #311: validate a bounded request DECLARATION, never authorize an actor or Release.

This module is intentionally pure/offline. Original GitHub PR/main-push, actor,
App, required CI and Release proof must be verified by separate trusted code.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = Path(__file__).resolve().parents[1] / "schema" / "issue311-execution-request-v1.schema.json"
REQUEST_DIR = Path(".github/execution-requests")
MAX_RAW_BYTES = 16384
MAX_TTL = timedelta(hours=24)
CLOCK_SKEW = timedelta(minutes=5)


class DeclarationDenied(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise DeclarationDenied(message)


def _unique_pairs(pairs):
    data = {}
    for key, value in pairs:
        require(key not in data, "duplicate JSON key")
        data[key] = value
    return data


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        raise DeclarationDenied("invalid timestamp")
    require(parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0),
            "request timestamp must be UTC")
    return parsed.astimezone(timezone.utc)


def validate_declaration(raw: bytes, path: str, *, now: datetime | None = None) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RAW_BYTES, "invalid raw request size")
    try:
        request = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise DeclarationDenied("invalid JSON") from exc
    require(type(request) is dict, "JSON root must be object")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(request)
    except Exception as exc:
        raise DeclarationDenied("v1 JSON Schema violation: " + str(exc)) from exc

    expected = REQUEST_DIR / (request["requestId"] + ".json")
    require(Path(path).as_posix() == expected.as_posix(), "requestId/path mismatch")
    created, expires = _timestamp(request["createdAt"]), _timestamp(request["expiresAt"])
    actual_now = now or datetime.now(timezone.utc)
    require(actual_now.tzinfo is not None, "trusted clock must be timezone-aware")
    actual_now = actual_now.astimezone(timezone.utc)
    require(created <= actual_now + CLOCK_SKEW, "request is future-dated")
    require(created < expires and expires - created <= MAX_TTL, "unbounded request lifetime")
    require(actual_now < expires, "request expired")

    target_names = [t["repo"] for t in request["targets"]]
    require(len(target_names) == len(set(target_names)), "duplicate target repository")
    grants = request["approval"]["publicationGrants"]
    grant_names = [g["repo"] for g in grants]
    require(len(grant_names) == len(set(grant_names)), "duplicate publication grant")
    require(set(grant_names) <= set(target_names), "publication grant outside target scope")
    require(request["resumeFrom"] != request["requestId"], "self-resume denied")
    if request["mode"] != "PUBLISH_ELIGIBLE":
        require(not grants and request["approval"]["publicReleaseAuthorized"] is False,
                "audit/prepare cannot declare publication")
    else:
        require(set(grant_names) == set(target_names), "missing per-target publication declaration")

    # This result is deliberately INERT. The actual real GitHub actor and
    # source/original-byte provenance are not derived from request JSON.
    return {
        "requestId": request["requestId"],
        "rawSha256": hashlib.sha256(raw).hexdigest(),
        "mode": request["mode"],
        "targets": tuple(target_names),
        "declarationOnly": True,
        "actorAuthenticated": False,
        "publicationAuthorized": False,
        "terminalAfter": expires.isoformat(),
    }
