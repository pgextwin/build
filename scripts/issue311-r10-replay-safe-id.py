#!/usr/bin/env python3
"""R10 one-source/one-target deterministic replay-safe local request IDs.

This helper does not itself authorize a dispatch or update State. The caller
must first authenticate the immutable central PREPARE source and live protected
target HEAD, and record the exact wire payload before one provider POST.
"""
from __future__ import annotations
import hashlib
import re

TARGETS = frozenset({
    "pg_bigm", "pg_cron", "pg_hint_plan", "pgaudit", "set_user",
    "pg_repack", "pg_ivm", "pg_qualstats", "plpgsql_check", "orafce",
    "hypopg", "wal2json", "pg_partman", "pg_stat_monitor", "pgtap",
    "pg_variables", "pg_store_plans",
})
SOURCE = re.compile(r"r-(20[0-9]{6})-r06prepare[a-z0-9-]{4,40}\Z")
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
RID = re.compile(r"r-20[0-9]{6}-r06coordlocal[a-f0-9]{24}\Z")

def derive(central_request_id: str, source_run_id: int,
           source_head_sha: str, source_zip_sha256: str,
           target_repo: str, target_main_sha: str) -> str:
    """Return a content-bound local ID; duplicate original inputs mean replay."""
    match = SOURCE.fullmatch(central_request_id) if type(central_request_id) is str else None
    if (match is None or type(source_run_id) is not int or source_run_id <= 0
        or type(source_head_sha) is not str or SHA40.fullmatch(source_head_sha) is None
        or type(source_zip_sha256) is not str or SHA64.fullmatch(source_zip_sha256) is None
        or type(target_repo) is not str or not target_repo.startswith("pgextwin/")
        or target_repo.split("/",1)[1] not in TARGETS
        or type(target_main_sha) is not str or SHA40.fullmatch(target_main_sha) is None):
        raise ValueError("R10_LOCAL_REQUEST_DENY invalid immutable source/target")
    fields = (central_request_id, str(source_run_id), source_head_sha,
              source_zip_sha256, target_repo, target_main_sha)
    payload = b"pgextwin-r10-local-request-v1\0" + b"\0".join(x.encode("ascii") for x in fields)
    digest = hashlib.sha256(payload).hexdigest()[:24]
    result = "r-" + match.group(1) + "-r06coordlocal" + digest
    assert RID.fullmatch(result)
    return result

def verify(inputs: dict) -> str:
    """Fail closed unless a dispatch contains exactly its six bound fields and derived ID."""
    if type(inputs) is not dict or set(inputs) != {
        "request_id","central_request_id","source_run_id","source_head_sha",
        "source_zip_sha256","target_repo","local_main_sha"
    }:
        raise ValueError("R10_LOCAL_REQUEST_DENY unexpected dispatch keys")
    try:
        run_id = int(inputs["source_run_id"])
    except (ValueError,TypeError,OverflowError):
        raise ValueError("R10_LOCAL_REQUEST_DENY run ID") from None
    if str(run_id) != inputs["source_run_id"]:
        raise ValueError("R10_LOCAL_REQUEST_DENY noncanonical run ID")
    computed = derive(inputs["central_request_id"],run_id,
                      inputs["source_head_sha"],inputs["source_zip_sha256"],
                      inputs["target_repo"],inputs["local_main_sha"])
    if inputs["request_id"] != computed:
        raise ValueError("R10_LOCAL_REQUEST_DENY replay or substituted request")
    return computed
