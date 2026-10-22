#!/usr/bin/env python3
"""Deterministic, nonpublishing work queue for hourly connected ChatGPT tasks.

Inputs are *untrusted observational snapshots* from fleet-status.py. This
module never grants Release authority or changes GitHub resources. The task
must independently GET exact current evidence before any PR mutation.
"""
from __future__ import annotations
import re

PR_URL = re.compile(r"^https://github\.com/(pgextwin/[a-z][a-z0-9_]*)/pull/([1-9][0-9]*)$")
STATES = {"NOT_RUN", "RUNNING", "FAILED_OR_UNVERIFIED", "FAILED",
          "VERIFIED", "INDETERMINATE"}
WATCH = {"UNKNOWN", "SUCCESS", "RUNNING", "FAILED"}


class Denied(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Denied(reason)


def plan(policy, snapshot):
    """Return reviewable tasks, never an authorization or publication receipt."""
    require(type(policy) is dict and policy.get("schemaVersion") == 1
            and policy.get("releasePolicy") == "manual-only",
            "central fleet is not manual-only")
    entries = policy.get("entries")
    require(type(entries) is list and len(entries) == 17,
            "incomplete central 17-extension fleet")
    by_repo = {}
    for entry in entries:
        require(type(entry) is dict and
                type(entry.get("repository")) is str and
                re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*", entry["repository"])
                and entry["repository"] not in by_repo
                and entry.get("releasePolicy") == "manual-only"
                and entry.get("mode") in {"BUILD", "WATCH", "OFF"},
                "unknown, duplicate or non-manual fleet entry")
        by_repo[entry["repository"]] = entry
    require(type(snapshot) is dict and snapshot.get("schemaVersion") == 1
            and snapshot.get("policyRelease") == "manual-only",
            "untrusted fleet status or publication policy")
    rows = snapshot.get("extensions")
    require(type(rows) is list and len(rows) == len(by_repo),
            "incomplete 17-extension status")
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
        detected = row.get("detectedCandidate")
        require(detected is None or type(detected) is dict,
                "malformed update Issue")
        action, reason = None, None
        if row["errors"] or ci == "INDETERMINATE" or watch == "FAILED":
            action, reason = "INVESTIGATE_EVIDENCE", "unknown or failed observations"
        elif ci in {"FAILED", "FAILED_OR_UNVERIFIED"}:
            action, reason = "INVESTIGATE_CI", "candidate CI is not verified"
        elif ci == "RUNNING" or watch == "RUNNING":
            continue
        elif url is not None:
            action, reason = "REVIEW_CANDIDATE", "independent exact-head PR/CI audit required"
        elif detected is not None and entry["mode"] == "BUILD" and watch == "SUCCESS":
            action, reason = "PREPARE_CANDIDATE", "verify upstream SHA and create safe PR"
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
