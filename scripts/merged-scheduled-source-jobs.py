#!/usr/bin/env python3
"""Strict original GitHub signed schedule job inventory, read-only and DENY.

This validates original REST source shapes only, not cryptographic signatures,
actual ZIP bytes, Sigstore issuer, Release authorization or a publisher receipt.
Historical main/push/manual source-kind is NEVER silently upgraded here.
"""
from __future__ import annotations
import re

SHA = re.compile(r"[0-9a-f]{40}\Z")
TARGETS = frozenset({
    "pgextwin/orafce", "pgextwin/pg_ivm",
    "pgextwin/plpgsql_check", "pgextwin/pg_hint_plan"})
CALLER = ".github/workflows/update-watch.yml"
ROOT = "Requalify existing merged candidate with genuine OIDC signature (NO RELEASE) / "
AUTH = ROOT + "Authenticate original local schedule and merged native origin (NO PUBLISH)"
SIGN = ROOT + "New genuine-schedule OIDC signed Windows PG build (NO PUBLISH) / "
AUDITOR_A = ROOT + "First independent original Windows ZIP/SPDX/Grype Sigstore verification (NO PUBLISH)"
AUDITOR_B = ROOT + "SECOND independent re-download and Sigstore original-byte verification (NO PUBLISH)"
JOIN = ROOT + "Require TWO independent source/PG/signature/byte receipts (DENY-only)"
SOURCE = "MERGED_BOT_SCHEDULED_REQUALIFICATION_SIGNED_BUILD"

class Denied(ValueError):
    pass

def need(value, reason):
    if not value:
        raise Denied(reason)

def positive(value):
    return type(value) is int and value > 0

def verify(run, jobs, *, repository, sha, run_id, attempt, majors):
    """Only complete original local scheduled source job inventory is eligible for later verification."""
    need(repository in TARGETS and type(sha) is str and SHA.fullmatch(sha)
         and positive(run_id) and type(attempt) is int and attempt == 1,
         "invalid explicitly authorized merged schedule root identity")
    need(type(majors) is list and bool(majors) and len(majors)<=32
         and majors==sorted(set(majors)) and all(positive(x) for x in majors),
         "maintained PostgreSQL roster invalid or duplicates")
    need(type(run) is dict and type(run.get("id")) is int and run["id"]==run_id
         and type(run.get("run_attempt")) is int and run["run_attempt"]==1
         and (run.get("repository") or {}).get("full_name")==repository
         and run.get("head_sha")==sha and run.get("head_branch")=="main"
         and run.get("event")=="schedule" and run.get("path")==CALLER
         and run.get("status")=="completed" and run.get("conclusion")=="success",
         "not a completed successful ORIGINAL genuine local schedule")
    need(type(jobs) is dict and type(jobs.get("total_count")) is int
         and type(jobs.get("jobs")) is list and jobs["total_count"]==len(jobs["jobs"])
         and 0<jobs["total_count"]<100,
         "partial/paginated or empty authentic local schedule job inventory")
    expected={AUTH,SIGN+"Resolve extension and PostgreSQL matrix",
        AUDITOR_A,AUDITOR_B,JOIN}
    expected.update({SIGN+f"PostgreSQL {m} / Windows x64" for m in majors})
    found={}
    job_ids=set()
    for row in jobs["jobs"]:
        need(type(row) is dict and positive(row.get("id"))
             and row["id"] not in job_ids
             and type(row.get("run_id")) is int and row["run_id"]==run_id
             and type(row.get("run_attempt")) is int and row["run_attempt"]==1
             and row.get("head_sha")==sha and type(row.get("name")) is str,
             "cross-run/head/attempt, duplicate or malformed job")
        job_ids.add(row["id"])
        name=row["name"]
        if name.startswith(SIGN) or name.startswith(ROOT):
            need(name in expected, "extra or substituted signed OIDC job lane")
        if name not in expected:
            continue
        need(name not in found and row.get("status")=="completed"
             and row.get("conclusion")=="success",
             "missing, duplicated, skipped or failed original OIDC job")
        need(row.get("check_run_url") ==
             "https://api.github.com/repos/"+repository+"/check-runs/"+str(row["id"])
             and row.get("html_url") ==
             "https://github.com/"+repository+"/actions/runs/"+str(run_id)+"/job/"+str(row["id"]),
             "original check job URLs mismatch authenticated runtime")
        found[name]=row["id"]
    need(set(found)==expected,
         "no exact successful original schedule signed PG matrix and two independent auditors")
    return {"schemaVersion":1,"sourceKind":SOURCE,"repository":repository,
        "mainSha":sha,"scheduleRun":run_id,"scheduleAttempt":1,
        "maintainedMajors":majors,
        "authenticatedRequiredJobIds":{k:found[k] for k in sorted(found)},
        "signedArtifactsVerified":False,
        "independentSigstoreAudits":0,
        "publicationAuthorized":False,"publisherSourceKindAuthorized":False}
