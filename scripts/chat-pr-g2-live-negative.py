#!/usr/bin/env python3
"""Issue #75 G2: two genuine GET-only negative snapshots; NEVER a publish receipt.

Trusted build SHA is checked out only by a protected-main, path-only pilot job.
This intentionally cannot accept any real authorization. Missing proof fails closed.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = "pgextwin/plpgsql_check"
BASE = "repos/" + REPO + "/"
CANDIDATE_PR = 29
CANDIDATE_RUN = 38356899464
CANDIDATE_BRANCH = "auto-candidate/29d1c1984a1b44a55107"
CANDIDATE_HEAD = "ea08bc74446c081368866e33ec3106d67daadb2b"
# Merely a read-only prospective lookup, NOT a release request or authorization.
PROSPECTIVE_TAG = "v2.10.15-windows.1"
EXISTING_TAG = "v2.10.14-windows.1"
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


class Denied(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Denied(message)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    require(spec is not None and spec.loader is not None, "pinned build module unavailable")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def preflight(event, env):
    sha = env.get("GITHUB_SHA", "")
    require(SHA_RE.fullmatch(sha) is not None
            and env.get("GITHUB_REPOSITORY") == REPO
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_EVENT_NAME") == "push"
            and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("GITHUB_ACTOR") == "ShutenOishi",
            "protected-main run identity invalid")
    require(type(event) is dict and event.get("ref") == "refs/heads/main"
            and event.get("after") == sha
            and type(event.get("repository")) is dict
            and event["repository"].get("full_name") == REPO
            and type(event.get("sender")) is dict
            and event["sender"].get("login") == env["GITHUB_ACTOR"]
            and event["sender"].get("type") == "User",
            "authenticated event identity mismatch")
    return sha


def snapshot(evidence, admin, adapter, expected_sha):
    """A FULL independent negative-read round. No synthetic approval data."""
    scope = admin.get("installation/repositories?per_page=100")
    require(type(scope) is dict and scope.get("total_count") == 1
            and type(scope.get("repositories")) is list
            and len(scope["repositories"]) == 1
            and type(scope["repositories"][0]) is dict
            and scope["repositories"][0].get("full_name") == REPO,
            "admin installation scope not exactly one pilot repo")

    branch = evidence.get(BASE + "branches/main")
    require(type(branch) is dict and branch.get("name") == "main"
            and branch.get("protected") is True
            and type(branch.get("commit")) is dict
            and branch["commit"].get("sha") == expected_sha,
            "main advanced or protection missing")
    classic = adapter.classic_lib.collect_verified_composite(
        adapter.classic_lib.CompositeReader(admin.token),
        expected_main_sha=expected_sha)
    require(type(classic) is dict
            and classic.get("status") == "VERIFIED_CLASSIC_COMPOSITE_READ_ONLY"
            and classic.get("mainSha") == expected_sha
            and classic.get("snapshotCount") == 2
            and classic.get("independentEffectiveRefZero") is True
            and classic.get("independentPushUnrestricted") is True
            and classic.get("publishableReceipt") is False,
            "effective REST/GraphQL Classic proof denied")
    auth = evidence.get(BASE + "contents/.github/release-authorizations?ref=" + expected_sha,
                        allow_404=True)
    require(auth is None, "real authorization path exists or is not a genuine 404")
    commit = evidence.get(BASE + "commits/" + expected_sha)
    require(type(commit) is dict and commit.get("sha") == expected_sha
            and type(commit.get("files")) is list
            and not any(type(f) is not dict or
                        f.get("filename", "").startswith(".github/release-authorizations/")
                        for f in commit["files"]),
            "actual main commit cannot prove no authorization change")
    candidate = evidence.get(BASE + "pulls/" + str(CANDIDATE_PR))
    require(type(candidate) is dict and candidate.get("number") == CANDIDATE_PR
            and candidate.get("state") == "open" and candidate.get("draft") is True
            and candidate.get("merged") is False
            and type(candidate.get("head")) is dict
            and candidate["head"].get("ref") == CANDIDATE_BRANCH
            and candidate["head"].get("sha") == CANDIDATE_HEAD,
            "candidate PR changed from unmerged Draft at known exact head")
    run = evidence.get(BASE + "actions/runs/" + str(CANDIDATE_RUN))
    require(type(run) is dict and run.get("id") == CANDIDATE_RUN
            and run.get("head_sha") == CANDIDATE_HEAD
            and run.get("head_branch") == CANDIDATE_BRANCH
            and run.get("event") == "workflow_dispatch"
            and run.get("run_attempt") == 1
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and type(run.get("repository")) is dict
            and run["repository"].get("full_name") == REPO,
            "candidate Windows CI run identity invalid")
    checks = evidence.get(BASE + "commits/" + CANDIDATE_HEAD + "/check-runs?per_page=100")
    require(type(checks) is dict and type(checks.get("total_count")) is int
            and type(checks.get("check_runs")) is list
            and checks["total_count"] == len(checks["check_runs"]),
            "candidate exact-head CI check list incomplete")
    required = adapter.classic_lib.rest.REQUIRED_CONTEXTS
    passing = sorted({c.get("name") for c in checks["check_runs"]
                      if type(c) is dict and c.get("name") in required
                      and c.get("head_sha") == CANDIDATE_HEAD
                      and type(c.get("app")) is dict and c["app"].get("id") == 15368
                      and c.get("status") == "completed"
                      and c.get("conclusion") == "success"})
    require(len(passing) <= 8, "CI context mismatch")

    local = adapter.trusted_json_file(evidence, "config/release-promotion.json", expected_sha)
    require(type(local) is dict and local.get("releasePolicy") == "manual-dispatch",
            "pilot publication policy no longer manual-dispatch")
    prospective_ref = evidence.get(BASE + "git/ref/tags/" + PROSPECTIVE_TAG,
                                   allow_404=True)
    prospective_release = evidence.get(BASE + "releases/tags/" + PROSPECTIVE_TAG,
                                       allow_404=True)
    require(prospective_ref is None and prospective_release is None,
            "prospective tag/Release occupied: publication must be DENIED")
    existing_ref = evidence.get(BASE + "git/ref/tags/" + EXISTING_TAG)
    existing_release = evidence.get(BASE + "releases/tags/" + EXISTING_TAG)
    require(type(existing_ref) is dict and existing_ref.get("ref") == "refs/tags/" + EXISTING_TAG
            and type(existing_release) is dict
            and existing_release.get("tag_name") == EXISTING_TAG
            and existing_release.get("draft") is False
            and existing_release.get("published_at") is not None,
            "historical tag/Release status not authenticated")
    end_branch = evidence.get(BASE + "branches/main")
    require(end_branch == branch, "main advanced during a read round")
    return {
        "mainSha": expected_sha,
        "classicStatus": classic["status"],
        "classicMainSha": classic["mainSha"],
        "classicSnapshotCount": classic["snapshotCount"],
        "requiredCheckPolicyCount": len(required),
        "candidatePr": CANDIDATE_PR,
        "candidateHeadSha": CANDIDATE_HEAD,
        "candidateDraft": True,
        "candidateRunId": CANDIDATE_RUN,
        "candidateExactHeadPassingChecks": passing,
        "authorization": "ABSENT_AUTHENTICATED_404",
        "candidateTag": PROSPECTIVE_TAG,
        "candidateTagRef": "ABSENT_AUTHENTICATED_404",
        "candidateRelease": "ABSENT_AUTHENTICATED_404",
        "historicalTag": EXISTING_TAG,
        "historicalRelease": "PUBLISHED_EXISTING_ONLY",
        "releasePolicy": "manual-dispatch",
    }


def verify(adapter, evidence_token, admin_token, event, env):
    sha = preflight(event, env)
    evidence = adapter.PilotReadOnly(evidence_token)
    admin = adapter.PilotReadOnly(admin_token)
    first = snapshot(evidence, admin, adapter, sha)
    second = snapshot(evidence, admin, adapter, sha)
    require(first == second, "independent real snapshots changed (TOCTOU)")
    return {
        "status": "DRY_RUN_G2_NEGATIVE_ONLY",
        "snapshotCount": 2,
        "mainSha": sha,
        "classicSnapshotCountPerRound": 2,
        "requiredCheckPolicyCount": 8,
        "candidatePr": CANDIDATE_PR,
        "candidateHeadSha": CANDIDATE_HEAD,
        "candidateExactHeadPassingCheckCount": len(second["candidateExactHeadPassingChecks"]),
        "authorization": second["authorization"],
        "candidateDraft": second["candidateDraft"],
        "candidateTagRef": second["candidateTagRef"],
        "candidateRelease": second["candidateRelease"],
        "historicalRelease": second["historicalRelease"],
        "releasePolicy": second["releasePolicy"],
        "publishableReceipt": False,
        "mutationsEnabled": False,
        "fullPositiveJit": "BLOCKED_NO_REAL_AUTHORIZATION",
        "futureCandidateSignature": "NOT_VERIFIED_DRAFT",
    }


def main():
    try:
        adapter = load("issue75_g2_adapter", "chat-pr-phase-d-github-readonly.py")
        result = verify(
            adapter, os.environ["EVIDENCE_TOKEN"], os.environ["ADMIN_TOKEN"],
            json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()), os.environ)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        print("DENY: G2 real two-snapshot audit incomplete; "
              "publishableReceipt=false; mutationsEnabled=false")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
