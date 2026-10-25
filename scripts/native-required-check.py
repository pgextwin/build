#!/usr/bin/env python3
"""Bind required Windows success to the genuine native PR Run's check suite.

Dispatch and pull_request runs can legitimately share HEAD and check names.
Only the authenticated native Run.check_suite_id selects its required check;
another suite's success is never a substitute. This helper grants no publish.
"""
from __future__ import annotations
import re

SHA=re.compile(r"^[0-9a-f]{40}$")
REPO=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
class Denied(ValueError):pass
def require(ok,why):
    if not ok:raise Denied(why)
def positive(value):return type(value) is int and value>0

def verify(run,checks,*,repository,head):
    """Use separately authenticated Run/checks snapshots; no network or writes."""
    require(type(repository) is str and REPO.fullmatch(repository)
            and type(head) is str and SHA.fullmatch(head),
            "invalid native repository/HEAD")
    require(type(run) is dict and positive(run.get("id"))
            and positive(run.get("check_suite_id"))
            and positive(run.get("run_attempt"))
            and run.get("event")=="pull_request"
            and run.get("name")=="Windows CI/CD"
            and run.get("path")==".github/workflows/windows.yml"
            and run.get("head_sha")==head
            and (run.get("head_repository") or {}).get("full_name")==repository
            and run.get("status")=="completed" and run.get("conclusion")=="success",
            "original successful native Windows Run/check suite not proven")
    require(type(checks) is dict and type(checks.get("total_count")) is int
            and 0<checks["total_count"]<100
            and type(checks.get("check_runs")) is list
            and len(checks["check_runs"])==checks["total_count"]
            and all(type(c) is dict and positive(c.get("id"))
                    for c in checks["check_runs"])
            and len({c["id"] for c in checks["check_runs"]})==len(checks["check_runs"]),
            "incomplete or duplicate required check-run inventory")
    matches=[c for c in checks["check_runs"]
             if c.get("name")=="Windows required summary"
             and type(c.get("check_suite")) is dict
             and type(c["check_suite"].get("id")) is int
             and c["check_suite"]["id"]==run["check_suite_id"]]
    require(len(matches)==1,
            "missing or ambiguous required summary in original native check suite")
    check=matches[0]
    require(check.get("head_sha")==head
            and (check.get("app") or {}).get("id")==15368
            and type((check.get("app") or {}).get("id")) is int
            and check.get("status")=="completed" and check.get("conclusion")=="success",
            "original native suite required App15368 Windows summary not successful")
    require(check.get("details_url")=="https://github.com/"+repository+
                "/actions/runs/"+str(run["id"])+"/job/"+str(check["id"]),
            "required check links to a different original native Run/job")
    return {"runId":run["id"],"runAttempt":run["run_attempt"],
            "checkSuiteId":run["check_suite_id"],"checkRunId":check["id"],
            "headSha":head}
