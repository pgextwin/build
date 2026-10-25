#!/usr/bin/env python3
"""Deterministic, nonpublishing work queue for hourly connected ChatGPT tasks.

Inputs are *untrusted observational snapshots* from fleet-status.py. This
module never grants Release authority or changes GitHub resources. The task
must independently GET exact current evidence before any PR mutation.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path
import re

PR_URL = re.compile(r"^https://github\.com/(pgextwin/[a-z][a-z0-9_]*)/pull/([1-9][0-9]*)$")
STATES = {"NOT_RUN", "RUNNING", "FAILED_OR_UNVERIFIED", "FAILED",
          "VERIFIED", "INDETERMINATE", "NATIVE_CI_SUCCESS_UNVERIFIED",
          "STALE_HEAD_CI", "DISPATCH_CI_SUCCESS_UNVERIFIED"}
WATCH = {"UNKNOWN", "SUCCESS", "RUNNING", "FAILED"}


_policy_spec=importlib.util.spec_from_file_location("shared_fleet_policy",Path(__file__).with_name("fleet-policy.py"))
fleet_policy=importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(fleet_policy)

class Denied(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Denied(reason)


def plan(policy, snapshot):
    """Return reviewable tasks, never an authorization or publication receipt."""
    try:
        by_repo=fleet_policy.members(policy,require_build=False)
    except fleet_policy.Denied as exc:
        raise Denied("invalid protected fleet") from exc
    require(type(snapshot) is dict and type(snapshot.get("schemaVersion")) is int and snapshot.get("schemaVersion") == 1
            and snapshot.get("policyRelease") == policy["releasePolicy"],
            "untrusted fleet status or publication policy")
    rows = snapshot.get("extensions")
    require(type(rows) is list and len(rows) == len(by_repo),
            "incomplete registered-fleet status")
    seen = set()
    actions = []
    for row in rows:
        require(type(row) is dict and row.get("repository") in by_repo
                and row["repository"] not in seen,
                "unknown or duplicate snapshot row")
        repo = row["repository"]
        seen.add(repo)
        entry = by_repo[repo]
        require(row.get("extension") == repo.split("/")[1]
                and row.get("mode") == entry["mode"]
                and type(row.get("errors")) is list
                and all(type(x) is str for x in row["errors"]),
                "snapshot identity/mode/errors mismatch")
        ci = row.get("lastCandidateStatus")
        watch = row.get("watchResult")
        require(ci in STATES and watch in WATCH,
                "unrecognized candidate or watch result")
        url = row.get("candidatePrUrl")
        require(url is None or
                (type(url) is str and (m := PR_URL.fullmatch(url)) is not None
                 and m.group(1) == repo),
                "candidate PR is outside exact repository")
        # A native CI signal is observational only, not independent App15368
        # matrix/artifact/signature verification or automatic merge authority.
        require(ci not in {"NATIVE_CI_SUCCESS_UNVERIFIED", "DISPATCH_CI_SUCCESS_UNVERIFIED", "STALE_HEAD_CI"}
                or url is not None, "native PR CI result without active candidate PR")
        detected = row.get("detectedCandidate")
        require(detected is None or type(detected) is dict,
                "malformed update Issue")
        action, reason = None, None
        if row["errors"] or ci == "INDETERMINATE" or watch == "FAILED":
            action, reason = "INVESTIGATE_EVIDENCE", "unknown or failed observations"
        elif ci in {"FAILED", "FAILED_OR_UNVERIFIED", "STALE_HEAD_CI"}:
            action, reason = "INVESTIGATE_CI", "candidate CI is not verified"
        elif ci == "RUNNING" or watch == "RUNNING":
            continue
        elif url is not None:
            action, reason = "REVIEW_CANDIDATE", "independent exact-head PR/CI audit required"
        elif detected is not None and entry["mode"] == "BUILD" and watch == "SUCCESS":
            action, reason = "VERIFY_UPSTREAM", "Issue is observational; recheck protected-main pins and live upstream full SHA before any PR"
        elif detected is not None:
            action, reason = "INVESTIGATE_EVIDENCE", "watch/BUILD gate not proven"
        if action is not None:
            actions.append({"repository": repo, "action": action,
                            "reason": reason, "candidatePrUrl": url})
    require(seen == set(by_repo), "partial fleet snapshot")
    return {"schemaVersion": 1, "scope": "CHAT_HOURLY_NONPUBLISHING",
            "fleetSize": len(by_repo), "pending": len(actions),
            "releaseAuthorized": False, "formalReleasePermitted": False,
            "actions": sorted(actions, key=lambda x: x["repository"])}
