#!/usr/bin/env python3
"""Issue #311 R04: inert GitHub Contents CAS/lease adapter (NONPUBLISHING).

This is an unconnected module, NOT an Actions credential grant or approved state
writer. A separately audited trusted service may supply an API transport later.
Never use the isolated Publisher/Catalog tokens or interpret this as Release permission.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

STATE_REF = "refs/heads/issue311-state"
REQ_ID = re.compile(r"^r-[0-9]{8}-[a-z0-9-]{8,56}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
LEASE_MAX_SECONDS = 600


class Denied(ValueError):
    pass


class Conflict(Denied):
    pass


class UnknownWriteOutcome(Denied):
    pass


def path_for(request_id):
    if type(request_id) is not str or not REQ_ID.fullmatch(request_id):
        raise Denied("invalid request identifier")
    return "checkpoints/" + request_id + ".json"


def check_state(state, request_id):
    if (type(state) is not dict or state.get("schemaVersion") != 1
            or state.get("requestId") != request_id
            or type(state.get("revision")) is not int or state["revision"] < 0
            or state.get("publisherAuthorized") is not False):
        raise Denied("state provenance/scope mismatch or publication claimed")
    if not SHA256.fullmatch(state.get("requestSha256", "")):
        raise Denied("missing immutable request-byte hash")
    return state


def decode_contents(payload, request_id):
    if not isinstance(payload, dict) or payload.get("encoding") != "base64":
        raise Denied("not original GitHub Contents")
    sha = payload.get("sha")
    if type(sha) is not str or not re.fullmatch("[0-9a-f]{40}", sha):
        raise Denied("missing Git blob SHA")
    try:
        raw = base64.b64decode(payload["content"], validate=False)
        state = json.loads(raw, object_pairs_hook=_unique_keys)
    except (KeyError, ValueError, TypeError) as exc:
        raise Denied("corrupt checkpoint") from exc
    return sha, check_state(state, request_id)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied("duplicate checkpoint JSON key")
        result[key] = value
    return result


def acquire_lease(state, request_id, owner, now, seconds=300):
    """Pure lease transition. Expired lease never grants retry of unknown writes."""
    check_state(state, request_id)
    if not (type(owner) is str and re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", owner)):
        raise Denied("invalid lease owner")
    if not (type(now) is datetime and now.tzinfo is not None):
        raise Denied("trusted aware timestamp required")
    if type(seconds) is not int or not 1 <= seconds <= LEASE_MAX_SECONDS:
        raise Denied("unbounded lease")
    if state.get("terminal") or state.get("writeOutcomeUnknown") is True:
        raise Denied("terminal or privileged outcome ambiguous")
    lease = state.get("lease")
    if lease is not None:
        if not isinstance(lease, dict) or set(lease) != {"owner","expiresAt","generation","scope"}:
            raise Denied("invalid persisted lease")
        if lease.get("scope") != "READONLY" or type(lease.get("generation")) is not int:
            raise Denied("invalid lease scope/generation")
        expires = datetime.fromisoformat(lease["expiresAt"].replace("Z","+00:00"))
        if expires.tzinfo is None:
            raise Denied("untrusted expiry")
        if now < expires and lease["owner"] != owner:
            raise Conflict("lease active under another owner")
    result = copy.deepcopy(state)
    generation = (lease["generation"] if lease is not None else 0) + 1
    result["lease"] = {"owner": owner, "expiresAt": (now + timedelta(seconds=seconds)).isoformat(),
                       "generation": generation, "scope": "READONLY"}
    result["revision"] += 1
    return result


class GithubContentsCAS:
    """Supply API callable(method,endpoint,json_body=None). No implicit token, retry or write."""
    def __init__(self, api):
        self.api = api

    def read(self, request_id):
        path = path_for(request_id)
        response = self.api("GET", "repos/pgextwin/build/contents/" + path +
                            "?ref=" + STATE_REF, None)
        return decode_contents(response, request_id)

    def commit_lease(self, request_id, expected_sha, previous, updated):
        path = path_for(request_id)
        check_state(previous, request_id)
        check_state(updated, request_id)
        if (type(expected_sha) is not str or not re.fullmatch("[0-9a-f]{40}", expected_sha)
                or updated["revision"] != previous["revision"] + 1
                or updated["requestSha256"] != previous["requestSha256"]
                or updated.get("lease", {}).get("scope") != "READONLY"
                or updated.get("writeOutcomeUnknown") is True
                or previous.get("writeOutcomeUnknown") is True
                or previous.get("terminal") or updated.get("terminal")
                or {k: v for k, v in updated.items() if k not in ("lease","revision")}
                   != {k: v for k, v in previous.items() if k not in ("lease","revision")}):
            raise Denied("CAS lease transition would change nonlease state or privilege")
        payload = {"message": "state(issue311): nonpublishing CAS lease " + request_id,
                   "branch": STATE_REF.removeprefix("refs/heads/"),
                   "sha": expected_sha,
                   "content": base64.b64encode((json.dumps(updated, sort_keys=True, separators=(",", ":"))+
                                               "\n").encode()).decode()}
        try:
            response = self.api("PUT", "repos/pgextwin/build/contents/" + path, payload)
        except Conflict:
            raise
        except Exception as exc:
            raise UnknownWriteOutcome("unknown checkpoint write: reconcile authoritative ref") from exc
        if not isinstance(response, dict) or not re.fullmatch(
                "[a-f0-9]{40}", str(response.get("content", {}).get("sha", ""))):
            raise UnknownWriteOutcome("unverifiable checkpoint write response")
        return response["content"]["sha"]


    def reconcile_ambiguous_lease(self, request_id, original_blob_sha, previous, intended):
        """READ-ONLY authoritative recheck after an ambiguous PUT; NEVER retries.

        COMMITTED means the exact intended lease checkpoint is still the state
        currently stored at the independently trusted state ref. UNRESOLVED
        must remain quarantined; CONFLICT means another state was observed.
        It does not prove that the caller owns Actions write scope or permit
        any privileged action based solely on an expired lease.
        """
        check_state(previous, request_id)
        check_state(intended, request_id)
        if (type(original_blob_sha) is not str
                or not re.fullmatch("[0-9a-f]{40}", original_blob_sha)
                or intended.get("revision") != previous["revision"] + 1
                or intended.get("requestSha256") != previous["requestSha256"]
                or intended.get("lease", {}).get("scope") != "READONLY"
                or previous.get("terminal") or intended.get("terminal")
                or previous.get("writeOutcomeUnknown") is True
                or intended.get("writeOutcomeUnknown") is True
                or {k:v for k,v in previous.items() if k not in ("lease", "revision")}
                   != {k:v for k,v in intended.items() if k not in ("lease", "revision")}):
            raise Denied("invalid lease reconciliation transition")
        try:
            current_sha, current = self.read(request_id)
        except Exception as exc:
            raise UnknownWriteOutcome("read-only reconciliation unavailable; QUARANTINE") from exc
        if current == intended and current_sha != original_blob_sha:
            return {"status": "COMMITTED", "blobSha": current_sha,
                    "revision": current["revision"], "readOnly": True}
        if current == previous and current_sha == original_blob_sha:
            return {"status": "UNRESOLVED", "blobSha": current_sha,
                    "revision": current["revision"], "readOnly": True}
        return {"status": "CONFLICT", "blobSha": current_sha,
                "revision": current["revision"], "readOnly": True}
