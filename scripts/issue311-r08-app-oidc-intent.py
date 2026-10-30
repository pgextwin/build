#!/usr/bin/env python3
"""R08-01: authenticate an original App PREPARE receipt before requesting OIDC.

This is a READ-ONLY signing INTENT, never a signature or Publisher grant.
It must run in the SAME local workflow_dispatch Run after the R06 verifier
succeeded. Later signing/audit jobs must independently bind this intent.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = "pgextwin/orafce"  # R08 pilot only; explicit allowlist, not wildcard
ACTOR = "pgextwin-issue311-prepare-coord[bot]"
ACTOR_ID = 350058024
PATH = ".github/workflows/issue311-request-local-prepare.yml"
WORKFLOW = "Issue 311 App-bot original local PREPARE (NO RELEASE)"
SOURCE_KIND = "APP_BOT_AUTHENTICATED_ORIGINAL_PREPARE_LOCAL_READONLY_V1"
INTENT = "APP_BOT_PREPARE_OIDC_SIGNING_INTENT_ONLY"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
REQUEST = re.compile(r"r-20[0-9]{6}-r06coordlocal[a-z0-9-]{4,40}\Z")
CENTRAL = re.compile(r"r-20[0-9]{6}-r06prepare[a-z0-9-]{4,40}\Z")
INPUTS = frozenset({"request_id", "source_run_id", "source_head_sha",
                    "source_artifact_id", "source_zip_sha256",
                    "central_request_id", "local_main_sha"})
NO_AUTH = ("candidateAdmissionAuthorized", "publisherSourceKindAuthorized",
           "publicationAuthorized", "publicReleaseAuthorized", "runtimeEnabled",
           "genuineSchedule", "originalScanReexecuted", "candidateCreated")


class Denied(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Denied("R08_APP_SIGNING_INTENT_DENY: " + message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def positive_decimal(value):
    return type(value) is str and re.fullmatch(r"[1-9][0-9]*", value) is not None


def validate(receipt, event, run, branch, env):
    """Compare independent original event, job receipt, Run GET and branch GET."""
    need(type(receipt) is dict and type(event) is dict
         and type(run) is dict and type(branch) is dict, "missing evidence objects")
    need(env.get("GITHUB_REPOSITORY") == REPO
         and env.get("GITHUB_WORKFLOW") == WORKFLOW
         and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
         and env.get("GITHUB_REF") == "refs/heads/main"
         and env.get("GITHUB_ACTOR") == ACTOR
         and env.get("GITHUB_RUN_ATTEMPT") == "1"
         and env.get("GITHUB_JOB") == "r08_app_signing_intent"
         and positive_decimal(env.get("GITHUB_RUN_ID"))
         and type(env.get("GITHUB_SHA")) is str
         and SHA40.fullmatch(env["GITHUB_SHA"]), "runner identity/attempt not authorized")
    sha, run_id = env["GITHUB_SHA"], int(env["GITHUB_RUN_ID"])
    need(event.get("repository", {}).get("full_name") == REPO
         and event.get("ref") == "refs/heads/main"
         and event.get("sender", {}).get("login") == ACTOR
         and event.get("sender", {}).get("id") == ACTOR_ID
         and event.get("sender", {}).get("type") == "Bot", "forged event/App sender")
    inputs = event.get("inputs")
    need(type(inputs) is dict and set(inputs) == INPUTS, "extra/missing event inputs")
    need(type(run.get("id")) is int and run["id"] == run_id
         and run.get("run_attempt") == 1
         and run.get("repository", {}).get("full_name") == REPO
         and run.get("head_branch") == "main" and run.get("head_sha") == sha
         and run.get("event") == "workflow_dispatch"
         and run.get("path") == PATH and run.get("name") == WORKFLOW
         and run.get("status") == "in_progress" and run.get("conclusion") is None
         and run.get("actor", {}).get("login") == ACTOR
         and run.get("actor", {}).get("id") == ACTOR_ID
         and run.get("triggering_actor", {}).get("login") == ACTOR,
         "original Run GET does not authenticate exact App workflow/attempt")
    need(branch.get("name") == "main" and branch.get("protected") is True
         and branch.get("commit", {}).get("sha") == sha,
         "protected local main changed before signing intent")
    need(receipt.get("schemaVersion") == 1
         and receipt.get("sourceKind") == SOURCE_KIND
         and receipt.get("result") == "NO_UPDATE"
         and receipt.get("localOriginalEvent") == "workflow_dispatch"
         and receipt.get("actualBotLogin") == ACTOR
         and receipt.get("actualBotUserId") == ACTOR_ID
         and receipt.get("localRunId") == run_id
         and receipt.get("localRunAttempt") == 1
         and receipt.get("localProtectedMainSha") == sha
         and all(receipt.get(key) is False for key in NO_AUTH),
         "same-Run local PREPARE original not safely admitted")
    expected = {
        "request_id": "requestId",
        "source_run_id": "centralSourceRunId",
        "source_head_sha": "centralSourceHeadSha",
        "source_artifact_id": "centralSourceArtifactId",
        "source_zip_sha256": "centralOriginalOuterZipSha256Verified",
        "central_request_id": "centralSourceRequestId",
        "local_main_sha": "localProtectedMainSha",
    }
    for key, field in expected.items():
        actual = receipt.get(field)
        if key in ("source_run_id", "source_artifact_id"):
            need(positive_decimal(inputs[key]) and type(actual) is int
                 and actual == int(inputs[key]), "numeric source mismatch " + key)
        else:
            need(type(inputs[key]) is str and type(actual) is str
                 and inputs[key] == actual, "different original cycle/HEAD " + key)
    need(type(receipt.get("requestId")) is str
         and REQUEST.fullmatch(receipt["requestId"]) is not None
         and CENTRAL.fullmatch(receipt["centralSourceRequestId"]) is not None
         and SHA40.fullmatch(receipt["centralSourceHeadSha"]) is not None
         and SHA64.fullmatch(receipt["centralOriginalOuterZipSha256Verified"]) is not None
         and SHA64.fullmatch(receipt.get("centralSourceRawRequestSha256", "")) is not None,
         "malformed immutable central request/ZIP identity")
    return {
        "schemaVersion": 1, "status": INTENT,
        "sourceKind": "APP_BOT_PREPARE_WORKFLOW_DISPATCH_SIGNED_BUILD_ONLY",
        "repository": REPO, "localProtectedMainSha": sha,
        "localRunId": run_id, "localRunAttempt": 1,
        "localWorkflow": PATH, "localActor": ACTOR, "localActorId": ACTOR_ID,
        "requestId": receipt["requestId"],
        "centralRequestId": receipt["centralSourceRequestId"],
        "centralRunId": receipt["centralSourceRunId"],
        "centralHeadSha": receipt["centralSourceHeadSha"],
        "centralArtifactId": receipt["centralSourceArtifactId"],
        "centralRequestRawSha256": receipt["centralSourceRawRequestSha256"],
        "centralOuterZipSha256": receipt["centralOriginalOuterZipSha256Verified"],
        "signedArtifactsVerified": False, "independentSigstoreAudits": 0,
        "publisherSourceKindAuthorized": False, "publicationAuthorized": False,
        "runtimeEnabled": False,
    }


def read_get(endpoint):
    need(os.environ.get("GH_TOKEN"), "read-only GitHub token unavailable")
    need(endpoint in (f"repos/{REPO}/actions/runs/{os.environ['GITHUB_RUN_ID']}",
                      f"repos/{REPO}/branches/main"), "GET allowlist")
    result = subprocess.run(["gh", "api", "--method", "GET", endpoint],
                            capture_output=True, text=True, timeout=45, check=False)
    need(result.returncode == 0 and 0 < len(result.stdout) < 500_000,
         "authenticated GitHub GET failed (no optimistic fallback)")
    return parse(result.stdout)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--receipt", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    try:
        need(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and os.environ.get("GITHUB_JOB") == "r08_app_signing_intent"
             and positive_decimal(os.environ.get("GITHUB_RUN_ID")), "wrong execution context")
        event = parse(Path(os.environ["GITHUB_EVENT_PATH"]).read_text("utf-8"))
        receipt = parse(Path(args.receipt).read_text("utf-8"))
        run = read_get(f"repos/{REPO}/actions/runs/{os.environ['GITHUB_RUN_ID']}")
        branch = read_get(f"repos/{REPO}/branches/main")
        intent = validate(receipt, event, run, branch, os.environ)
        need(read_get(f"repos/{REPO}/actions/runs/{os.environ['GITHUB_RUN_ID']}") == run,
             "Run changed across authentication GETs")
        Path(args.output).write_text(json.dumps(intent, indent=2, sort_keys=True)+"\n",
                                     encoding="utf-8")
        print("R08_AUTHENTIC_APP_SIGNING_INTENT_ONLY; NEW_OIDC_AND_DUAL_AUDITS_REQUIRED; PUBLISH_DENY")
        return 0
    except (Denied, OSError, TypeError, KeyError, ValueError,
            subprocess.TimeoutExpired) as exc:
        print("R08_APP_SIGNING_INTENT_DENY: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
