#!/usr/bin/env python3
"""Bind the deployed signed-candidate job chain to its original main/push.

Only authentic REST run/job snapshots and maintained majors derived from the
protected manifest may be supplied. This shape check verifies no signatures
and issues no publication authority. Original byte/Sigstore checks stay separate.
"""
from __future__ import annotations
import re

SHA = re.compile(r"[0-9a-f]{40}\Z")
REPO = re.compile(r"pgextwin/[a-z][a-z0-9_]*\Z")
AUTH = ("Authenticate main merge and scheduled decision (NONPUBLISHING) / "
        "Authenticate protected candidate merge from real GitHub bytes")
BUILD = "Attest original candidate after verified protected main merge (NO PUBLISH) / "
AUDIT = "Independently verify signed candidate bytes and identity (NO PUBLISH) / "

class Denied(ValueError):
    pass

def need(value, reason):
    if not value:
        raise Denied(reason)

def positive(value):
    return type(value) is int and value > 0

def verify(run, jobs, *, repository, sha, run_id, attempt, majors):
    """Require the actual resolver, full signed matrix and two independent jobs."""
    need(type(repository) is str and REPO.fullmatch(repository)
         and type(sha) is str and SHA.fullmatch(sha)
         and positive(run_id) and type(attempt) is int and attempt == 1,
         "invalid original signed source identity")
    need(type(majors) is list and bool(majors) and len(majors) <= 32
         and all(positive(m) for m in majors)
         and majors == sorted(set(majors)),
         "maintained manifest PostgreSQL matrix missing or ambiguous")
    need(type(run) is dict and run.get("id") == run_id
         and type(run.get("id")) is int
         and run.get("run_attempt") == attempt
         and type(run.get("run_attempt")) is int
         and (run.get("repository") or {}).get("full_name") == repository
         and run.get("head_sha") == sha and run.get("head_branch") == "main"
         and run.get("event") == "push"
         and run.get("path") == ".github/workflows/update-watch.yml"
         and run.get("status") == "completed" and run.get("conclusion") == "success",
         "not an original completed successful signed main/push")
    need(type(jobs) is dict and type(jobs.get("total_count")) is int
         and 0 < jobs["total_count"] < 100 and type(jobs.get("jobs")) is list
         and jobs["total_count"] == len(jobs["jobs"]),
         "incomplete or paginated original signed jobs")
    expected = {AUTH, BUILD + "Resolve extension and PostgreSQL matrix",
        AUDIT + "Verify actual signed ZIP/SPDX/Grype provenance without Publisher rights",
        AUDIT + "Independently reverify signed candidate before future Publisher (NO PUBLISH)"}
    expected |= {BUILD + f"PostgreSQL {m} / Windows x64" for m in majors}
    found = {}
    ids = set()
    for job in jobs["jobs"]:
        need(type(job) is dict and positive(job.get("id"))
             and job["id"] not in ids and positive(job.get("run_id"))
             and job["run_id"] == run_id
             and type(job.get("run_attempt")) is int and job["run_attempt"] == attempt
             and job.get("head_sha") == sha and type(job.get("name")) is str,
             "duplicate or cross-run/head/attempt signed job")
        ids.add(job["id"])
        name = job["name"]
        # A partial or extra signed PG lane must never silently qualify.
        if name.startswith(BUILD):
            need(name in expected, "unexpected signed PostgreSQL matrix lane")
        if name not in expected:
            continue
        need(name not in found and job.get("status") == "completed"
             and job.get("conclusion") == "success",
             "duplicate, failed or skipped required signed job")
        need(job.get("check_run_url") == "https://api.github.com/repos/" + repository
             + "/check-runs/" + str(job["id"])
             and job.get("html_url") == "https://github.com/" + repository
             + "/actions/runs/" + str(run_id) + "/job/" + str(job["id"]),
             "signed job URLs do not bind its original GitHub run/check")
        found[name] = job["id"]
    need(set(found) == expected,
         "missing protected merge, resolver, signed PG matrix or independent audit")
    return tuple(sorted(found.items()))
