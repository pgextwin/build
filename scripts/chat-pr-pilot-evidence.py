#!/usr/bin/env python3
"""Issue #75 Phase C: read-only plpgsql_check PR-authorization pilot evidence.

NO workflow entrypoint, dispatch, git/tag/Release mutation, token write scope,
publisher call or receipt is provided. This is an independent DRY-RUN collector,
not production authorization. On missing or unavailable GitHub evidence, deny.
"""
from __future__ import annotations
import base64
import binascii
import importlib.util
import json
import os
import re
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

PILOT = "pgextwin/plpgsql_check"
ROOT = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("chat_pr_phase_b", ROOT / "chat-pr-authorization.py")
auth = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(auth)


class Blocked(ValueError):
    """Missing, inconsistent, or nonauthoritative read-only evidence."""


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


class GitHubReadOnly:
    """Authenticated GitHub REST GET only; deliberately has no write methods."""

    def __init__(self, token):
        require(isinstance(token, str) and bool(token), "GitHub read token required")
        self.token = token

    def get(self, path, *, allow_404=False):
        require(type(path) is str and path.startswith("repos/pgextwin/plpgsql_check/"),
                "only the single pilot repository can be read")
        req = Request(
            "https://api.github.com/" + path,
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
            method="GET",
        )
        try:
            with urlopen(req, timeout=20) as response:
                require(response.status == 200, "unexpected GitHub REST response")
                # A truncated GitHub collection can otherwise look like a
                # unique PR, merge, or required CI result. Never trust page 1.
                link = response.headers.get("Link", "")
                require(not re.search(r'\brel\s*=\s*"?next"?', link, re.IGNORECASE),
                        "GitHub pagination requires complete authoritative evidence")
                return json.load(response)
        except HTTPError as exc:
            if allow_404 and exc.code == 404:
                return None
            raise Blocked("GitHub REST read denied HTTP " + str(exc.code)) from exc
        except (URLError, ValueError) as exc:
            raise Blocked("GitHub REST read unavailable") from exc


def required_head_ci(protection, check_runs, sha):
    """Bind protected-main required checks to exact-head successful GitHub Apps.

    Status-context-only checks with no pinned App ID fail closed during pilot:
    they must not count as independently authenticated proof.
    """
    require(type(protection) is dict, "effective branch-protection detail unavailable")
    rules = protection.get("required_status_checks") or {}
    require(rules.get("strict") is True, "latest-head strict CI enforcement missing")
    required = rules.get("checks")
    require(type(required) is list and bool(required), "App-bound required check list absent")
    require(type(check_runs) is dict and type(check_runs.get("check_runs")) is list,
            "exact-head check-run snapshot unavailable")
    checked = []
    for rule in required:
        require(type(rule) is dict and type(rule.get("context")) is str
                and bool(rule["context"]) and type(rule.get("app_id")) is int
                and rule["app_id"] > 0,
                "unbound required status context or App identity")
        # Inspect ALL matching executions. A successful historical attempt must
        # not mask a later failed, cancelled or skipped run on the same SHA.
        # Until a trustworthy latest-check-run selector is implemented, any
        # duplicate required check from the pinned App denies authorization.
        matches = [
            c for c in check_runs["check_runs"]
            if type(c) is dict
            and c.get("name") == rule["context"]
            and (c.get("app") or {}).get("id") == rule["app_id"]
        ]
        require(len(matches) == 1, "required App check missing or ambiguous")
        require(matches[0].get("head_sha") == sha
                and matches[0].get("status") == "completed"
                and matches[0].get("conclusion") == "success",
                "required App check is not successful on exact head")
        require(rule["context"] not in checked, "duplicate required check")
        checked.append(rule["context"])
    require(check_runs.get("total_count") == len(check_runs["check_runs"]),
            "paginated CI snapshot cannot establish complete unique checks")
    return sorted(checked)


def effective_branch_rules(branch, protection):
    require(branch.get("protected") is True, "main is not GitHub-protected")
    require(type(protection) is dict, "branch protection was not independently readable")
    reviews = protection.get("required_pull_request_reviews")
    require(type(reviews) is dict
            and reviews.get("required_approving_review_count") == 0,
            "protected PR-only main without third-party review requirement not proven")
    bypass = reviews.get("bypass_pull_request_allowances") or {}
    require(type(bypass) is dict and not bypass.get("users")
            and not bypass.get("teams") and not bypass.get("apps"),
            "PR bypass actor exists")
    require((protection.get("enforce_admins") or {}).get("enabled") is True,
            "admin protection bypass must be disabled")
    for name in ("allow_force_pushes", "allow_deletions"):
        require((protection.get(name) or {}).get("enabled") is False,
                name + " must be disabled")
    return {"protectedMain": True, "requiredChecksEnforced": True,
            "restrictDirectPush": True}


def inspect_pilot(api, event, *, runtime_repo, runtime_ref, runtime_sha,
                  runtime_actor, allowed_operators):
    """Read GitHub's authoritative snapshots; produce a NONPUBLISHING report.

    Runtime values must ultimately come from GitHub Actions environment on a
    trusted main event, not from a PR body, dispatch input, or user-supplied JSON.
    This collector currently has NO callable publishing workflow.
    """
    require(runtime_repo == PILOT and runtime_ref == "refs/heads/main",
            "outside pilot or main runtime")
    require(auth.full_sha(runtime_sha) and auth.human(runtime_actor)
            and runtime_actor in allowed_operators,
            "untrusted pilot runtime actor/SHA")
    require(type(event) is dict and event.get("ref") == runtime_ref
            and event.get("after") == runtime_sha
            and (event.get("sender") or {}).get("login") == runtime_actor
            and (event.get("sender") or {}).get("type") == "User"
            and (event.get("repository") or {}).get("full_name") == PILOT,
            "event/runtime actor or commit mismatch")
    base = "repos/" + PILOT + "/"
    branch = api.get(base + "branches/main")
    require((branch.get("commit") or {}).get("sha") == runtime_sha,
            "main advanced after authorization commit")
    commit = api.get(base + "commits/" + runtime_sha)
    require(type(commit.get("files")) is list and len(commit["files"]) == 1,
            "squash commit must change exactly one file")
    filename = commit["files"][0].get("filename", "")
    prefix = ".github/release-authorizations/"
    require(filename.startswith(prefix) and filename.endswith(".json"),
            "no single authorization path in merged commit")
    tag = filename[len(prefix):-5]
    require(auth.TAG.fullmatch(tag) is not None, "unsafe authorization tag")
    prs = api.get(base + "commits/" + runtime_sha + "/pulls")
    require(type(prs) is list and len(prs) == 1
            and prs[0].get("merge_commit_sha") == runtime_sha,
            "squash-merge PR linkage missing or ambiguous")
    pr_number = prs[0].get("number")
    require(type(pr_number) is int and pr_number > 0,
            "untrusted authorization PR identifier")
    pr = api.get(base + "pulls/" + str(pr_number))
    require((pr.get("user") or {}).get("type") == "User"
            and (pr.get("merged_by") or {}).get("type") == "User",
            "PR author and merger must be real GitHub users")
    pr_files = api.get(base + "pulls/" + str(pr_number) + "/files?per_page=100")
    require(type(pr_files) is list and len(pr_files) == 1,
            "authorization PR file list ambiguous")
    data = api.get(base + "contents/" + quote(filename, safe="/") +
                   "?ref=" + runtime_sha)
    require(type(data) is dict and data.get("encoding") == "base64"
            and type(data.get("content")) is str, "committed JSON blob unavailable")
    try:
        raw = base64.b64decode("".join(data["content"].split()), validate=True)
        source = raw.decode("utf-8")
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise Blocked("invalid committed authorization bytes") from exc
    require(data.get("sha") == auth.git_blob_sha(raw),
            "GitHub contents blob identity mismatch")
    protection = api.get(base + "branches/main/protection")
    rules = effective_branch_rules(branch, protection)
    head_sha = (pr.get("head") or {}).get("sha", "")
    require(auth.full_sha(head_sha), "authorization PR head absent")
    check_runs = api.get(base + "commits/" + head_sha + "/check-runs?per_page=100")
    required = required_head_ci(protection, check_runs, head_sha)
    try:
        approved = auth.verify_approval(
            source, repository=PILOT, event=event, pr=pr, pr_files=pr_files,
            commit=commit,
            ci={"headSha": head_sha, "allRequiredChecksPassed": True,
                "requiredChecks": required},
            effective_rules=rules, allowed_operators=allowed_operators,
        )
    except auth.Denied as exc:
        raise Blocked("PR approval context denied: " + str(exc)) from exc
    # Read, do not certify, candidate metadata. Full decision/artifact/SBOM/
    # signature verification remains the separate Phase B fleet gate's job.
    candidate_pr = api.get(base + "pulls/" + str(approved["candidatePr"]))
    candidate_run = api.get(base + "actions/runs/" + str(approved["candidateRunId"]))
    decision_run = api.get(base + "actions/runs/" + str(approved["decisionRunId"]))
    require(candidate_pr.get("merged") is True
            and (candidate_pr.get("user") or {}).get("login") == "github-actions[bot]"
            and (candidate_pr.get("head") or {}).get("sha") == approved["candidateHeadSha"],
            "candidate PR identity not independently confirmed")
    require(candidate_run.get("id") == approved["candidateRunId"]
            and candidate_run.get("run_attempt") == 1
            and (candidate_run.get("repository") or {}).get("full_name") == PILOT
            and candidate_run.get("head_branch") ==
                (candidate_pr.get("head") or {}).get("ref")
            and candidate_run.get("event") == "workflow_dispatch"
            and candidate_run.get("status") == "completed"
            and candidate_run.get("conclusion") == "success"
            and candidate_run.get("head_sha") == approved["candidateHeadSha"],
            "candidate Windows run identity, first attempt or exact head unproven")
    require(decision_run.get("id") == approved["decisionRunId"]
            and decision_run.get("run_attempt") == 1
            and (decision_run.get("repository") or {}).get("full_name") == PILOT
            and decision_run.get("status") == "completed"
            and decision_run.get("conclusion") == "success"
            and decision_run.get("head_branch") == "main",
            "candidate decision run identity or first attempt unproven")
    require(api.get(base + "git/ref/tags/" + quote(tag, safe=""),
                    allow_404=True) is None
            and api.get(base + "releases/tags/" + quote(tag, safe=""),
                        allow_404=True) is None,
            "tag or Release already exists")
    return {
        "schemaVersion": 1, "status": "DRY_RUN_CONTEXT_ONLY",
        "publishingEnabled": False, "publishableReceipt": False,
        "repository": PILOT, "mainSha": runtime_sha,
        "authorizationPr": approved["authorizationPr"],
        "authorizationCommit": approved["authorizationCommit"],
        "candidatePr": approved["candidatePr"],
        "candidateRunId": approved["candidateRunId"],
        "decisionRunId": approved["decisionRunId"],
        "requiredChecks": required,
        "candidateArtifactsAndSignatures": "NOT_YET_VERIFIED",
        "centralLocalChatMode": "NOT_VERIFIED",
        "rollback": "retain workflow_dispatch manual-dispatch; no new trigger installed",
    }
