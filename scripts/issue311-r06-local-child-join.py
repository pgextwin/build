#!/usr/bin/env python3
"""R06-05-02-02 strict same-central-cycle child-Run policy (NONPUBLISHING).

Pure admission boundary, not a receipt authenticator. Production callers MUST
independently GET the original GitHub run, commit, artifact and ZIP bytes and
verify the provider SHA256 before passing these records to this function.
A passing unit test is never a live child-Run or App CAS acceptance.
No GitHub write, workflow dispatch, schedule, Publisher or Release path.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_KIND = "AUTHENTICATED_PREPARE_ORIGINAL_ZIP_LOCAL_READONLY"
LOCAL_WORKFLOW = ".github/workflows/issue311-fleet-local-prepare.yml"
NORMAL = {"NO_UPDATE", "UPDATE_PRESENT_NOT_AUTHORIZED"}
ABNORMAL = {"failure": "FAILED", "skipped": "SKIPPED", "timed_out": "TIMEOUT"}
TERMINALS = NORMAL | {"QUARANTINED"}


class Denied(ValueError):
    """Reject unverified identity, cross-cycle replay, or missing original proof."""


def need(ok, message):
    if not ok:
        raise Denied("R06_SAME_CYCLE_DENY " + message)


def timestamp(value):
    need(isinstance(value, str), "missing UTC time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Denied("R06_SAME_CYCLE_DENY invalid time") from None
    need(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0,
         "non-UTC time")
    return parsed


def validate_child(central, child):
    """Validate one independently authenticated original local run/receipt pair.

    The caller is responsible for independently confirming REST objects and
    compressed ZIP bytes, not copying self-asserted JSON from the request.
    """
    repo = child.get("repo")
    targets = central["targetMainSha"]
    need(repo in targets, "unknown local repo")
    req = child.get("request", {})
    run = child.get("run", {})
    parent = child.get("parentSha")
    need(req.get("schemaVersion") == 1
         and req.get("kind") == "pgextwin-local-prepare"
         and req.get("mode") == "PREPARE"
         and req.get("centralRequestId") == central["requestId"]
         and req.get("sourceRunId") == central["sourceRunId"]
         and req.get("sourceHeadSha") == central["sourceHeadSha"]
         and req.get("sourceArtifactId") == central["sourceArtifactId"]
         and req.get("sourceZipSha256") == central["sourceZipSha256"]
         and req.get("targetMainSha") == targets[repo]
         and req.get("publicReleaseAuthorized") is False,
         "local declaration crosses original central request/cycle")
    need(parent == targets[repo]
         and SHA40.fullmatch(parent or "") is not None,
         "local original protected request parent not central snapshot")
    need(isinstance(run.get("id"), int) and type(run.get("run_attempt")) is int
         and run["run_attempt"] == 1
         and run.get("repository") == repo
         and run.get("path") == LOCAL_WORKFLOW
         and run.get("event") == "push"
         and run.get("head_branch") == "main"
         and run.get("actor") == "ShutenOishi"
         and run.get("status") == "completed"
         and SHA40.fullmatch(run.get("head_sha", "")) is not None
         and run["head_sha"] != parent
         and run.get("protectedMain") is True,
         "not genuine first-attempt protected local main-push run")
    need(timestamp(run["created_at"]) >= timestamp(central["created_at"]),
         "child run predates central original")
    need(timestamp(run["created_at"]) <= timestamp(req["expiresAt"]),
         "child request expired before run")
    need(req.get("publicReleaseAuthorized") is False
         and child.get("publisherAuthorized") is False
         and child.get("publicationRequested") is False,
         "any publication privilege")
    receipt = child.get("receipt")
    conclusion = run.get("conclusion")
    if conclusion == "success" and child.get("completionEventDelivered") is False:
        watch = child.get("watchdog")
        need(isinstance(watch, dict)
             and watch.get("sourceRunId") == run["id"]
             and watch.get("sourceRunAttempt") == 1
             and watch.get("centralRunId") == central["sourceRunId"]
             and watch.get("centralRequestId") == central["requestId"]
             and watch.get("localRequestId") == req.get("requestId")
             and watch.get("status") == "MISSING_EVENT"
             and watch.get("terminal") == "QUARANTINED"
             and watch.get("originalGetVerified") is True
             and watch.get("durableAppCasReadbackVerified") is True
             and watch.get("noReexecute") is True
             and watch.get("publisherAuthorized") is False
             and isinstance(watch.get("watchdogRunId"), int)
             and timestamp(watch["observedAt"]) >= timestamp(req["expiresAt"]),
             "missing completion event has no finite original watchdog")
        return "QUARANTINED"
    if conclusion == "success":
        need(child.get("completionEventDelivered") is True
             and child.get("originalJobConclusion") == "success",
             "child success has no authenticated completion and successful job")
        need(isinstance(receipt, dict)
             and receipt.get("schemaVersion") == 1
             and receipt.get("requestId") == req.get("requestId")
             and receipt.get("result") in NORMAL
             and receipt.get("sourceKind") == SOURCE_KIND
             and receipt.get("originalSourceRunId") == central["sourceRunId"]
             and receipt.get("originalSourceHeadSha") == central["sourceHeadSha"]
             and receipt.get("originalSourceArtifactId") == central["sourceArtifactId"]
             and receipt.get("originalOuterZipSha256Verified") == central["sourceZipSha256"]
             and receipt.get("localRunId") == run["id"]
             and receipt.get("localRunAttempt") == 1
             and receipt.get("localProtectedRequestParentMainSha") == parent
             and receipt.get("localProtectedHeadSha") == run["head_sha"]
             and receipt.get("candidateAdmissionAuthorized") is False
             and receipt.get("publisherSourceKindAuthorized") is False
             and receipt.get("publicationAuthorized") is False
             and receipt.get("genuineSchedule") is False,
             "successful original local ZIP receipt cannot bind to central cycle")
        return receipt["result"]

    need(conclusion in ABNORMAL, "unrecognized local workflow conclusion")
    # A non-success original run does NOT prove a successful local receipt.
    # A missing receipt, failed job or skipped job requires a separately
    # authenticated original finite watchdog, including durable terminal.
    watchdog = child.get("watchdog")
    need(isinstance(watchdog, dict)
         and watchdog.get("sourceRunId") == run["id"]
         and watchdog.get("sourceRunAttempt") == 1
         and watchdog.get("centralRunId") == central["sourceRunId"]
         and watchdog.get("centralRequestId") == central["requestId"]
         and watchdog.get("localRequestId") == req.get("requestId")
         and watchdog.get("status") == ABNORMAL[conclusion]
         and watchdog.get("terminal") == "QUARANTINED"
         and watchdog.get("originalGetVerified") is True
         and watchdog.get("durableAppCasReadbackVerified") is True
         and watchdog.get("noReexecute") is True
         and watchdog.get("publisherAuthorized") is False
         and isinstance(watchdog.get("watchdogRunId"), int)
         and watchdog["watchdogRunId"] > 0
         and timestamp(watchdog["observedAt"]) >= timestamp(run["created_at"]),
         "non-success child missing independent finite original watchdog")
    # A skipped job can have workflow conclusion success: it must never be
    # misclassified as a failed/skipped workflow without original job proof.
    if conclusion == "skipped":
        need(child.get("originalJobConclusion") == "skipped",
             "not actual skipped child job")
    if conclusion == "failure":
        need(child.get("originalJobConclusion") == "failure",
             "not actual failed child job")
    if conclusion == "timed_out":
        need(child.get("originalJobConclusion") == "timed_out",
             "not actual timed-out child job")
    need(receipt is None or
         (receipt.get("result") == "FAILED"
          and receipt.get("publicationAuthorized") is False),
         "failed child supplied success receipt")
    return "QUARANTINED"


def validate_17_original_children(central, children):
    """Return a strictly nonpublishing summary, not an App terminal acceptance."""
    need(isinstance(central, dict)
         and central.get("sourceRunAttempt") == 1
         and central.get("sourceEvent") == "push"
         and central.get("publisherAuthorized") is False
         and SHA40.fullmatch(central.get("sourceHeadSha", "")) is not None
         and SHA64.fullmatch(central.get("sourceZipSha256", "")) is not None
         and isinstance(central.get("sourceRunId"), int)
         and isinstance(central.get("sourceArtifactId"), int)
         and isinstance(central.get("targetMainSha"), dict)
         and len(central["targetMainSha"]) == 17
         and all(x.startswith("pgextwin/") and
                 SHA40.fullmatch(s or "") is not None
                 for x, s in central["targetMainSha"].items()),
         "central original request scope incomplete")
    need(isinstance(children, list) and len(children) == 17, "17 original children required")
    outcomes = {}
    for child in children:
        repo = child.get("repo")
        need(repo not in outcomes, "duplicate local original child")
        outcomes[repo] = validate_child(central, child)
    need(set(outcomes) == set(central["targetMainSha"]), "missing local child repo")
    result = "QUARANTINED" if any(x == "QUARANTINED" for x in outcomes.values()) else "NO_UPDATE"
    return {"result": result, "originalCentralRunId": central["sourceRunId"],
            "originalCentralArtifactId": central["sourceArtifactId"],
            "originalCentralZipSha256": central["sourceZipSha256"],
            "targetCount": 17, "outcomes": outcomes, "publisherAuthorized": False,
            "proofScope": "POLICY_BOUNDARY_ONLY_NOT_LIVE_CAS"}
