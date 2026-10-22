#!/usr/bin/env python3
"""Authenticated GitHub candidate-merge observer: READ ONLY, never publishes.

Issue #75 Phase 2: independently GET live main commit, bot candidate PR,
App15368 required CI and real PR run. Exact candidate ZIP/SBOM audit and
effective no-bypass branch protection are deliberately NOT inferred here.
A passing observation is not an authorization receipt or a Release request.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SHA = re.compile(r"^[0-9a-f]{40}$")
BRANCH = re.compile(r"^auto-candidate/([0-9a-f]{20})$")
LOGIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
REPOSITORY = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")


class Denied(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Denied(message)


def is_sha(value):
    return type(value) is str and SHA.fullmatch(value) is not None


def one_file(items):
    return (type(items) is list and len(items) == 1
            and type(items[0]) is dict
            and items[0].get("filename") == "config/extension.json"
            and items[0].get("status") == "modified")


def verify_snapshot(*, event, commit, prs, files, branch, checks, runs,
                    repository, actor, expected_sha, roster):
    """Validate separately fetched GitHub REST data, without granting PUBLISH."""
    require(type(roster) is list and len(roster) == 17
            and len(set(roster)) == 17
            and all(type(r) is str and REPOSITORY.fullmatch(r) for r in roster)
            and repository in roster, "not an exact member of protected 17-extension roster")
    require(type(actor) is str and LOGIN.fullmatch(actor)
            and actor.lower() != "github-actions[bot]"
            and actor == "ShutenOishi", "operator not the approved human GitHub identity")
    require(type(event) is dict
            and event.get("ref") == "refs/heads/main"
            and (event.get("repository") or {}).get("full_name") == repository
            and (event.get("sender") or {}).get("login") == actor
            and is_sha(event.get("before")) and is_sha(event.get("after"))
            and event.get("after") == expected_sha
            and event.get("created") is False and event.get("deleted") is False,
            "unauthorized main push event")
    require(type(event.get("commits")) is list
            and len(event["commits"]) == 1
            and event["commits"][0].get("id") == expected_sha,
            "push must have exactly one commit")
    require(type(commit) is dict and commit.get("sha") == expected_sha
            and type(commit.get("parents")) is list and len(commit["parents"]) == 1
            and commit["parents"][0].get("sha") == event["before"]
            and one_file(commit.get("files")),
            "unexpected merged commit SHA, parents or manifest-only change")
    require(type(prs) is list and len(prs) == 1
            and type(prs[0]) is dict, "missing/ambiguous merged PR")
    pr = prs[0]
    require(pr.get("state") == "closed" and pr.get("merged") is True
            and pr.get("draft") is False
            and pr.get("merge_commit_sha") == expected_sha
            and (pr.get("base") or {}).get("ref") == "main"
            and (pr.get("base") or {}).get("repo", {}).get("full_name") == repository
            and (pr.get("head") or {}).get("repo", {}).get("full_name") == repository
            and (pr.get("user") or {}).get("login") == "github-actions[bot]"
            and (pr.get("merged_by") or {}).get("login") == actor
            and type(pr.get("number")) is int and pr["number"] > 0
            and is_sha((pr.get("head") or {}).get("sha"))
            and one_file(files),
            "candidate merge must come from one normal protected bot PR")
    branch_name = (pr.get("head") or {}).get("ref")
    branch_match = BRANCH.fullmatch(branch_name) if type(branch_name) is str else None
    require(branch_match
            and ("<!-- pgextwin-candidate:v1:" + branch_match.group(1) + " -->")
            in (pr.get("body") or ""), "candidate ownership marker mismatch")
    require(files[0].get("sha") == commit["files"][0].get("sha")
            and is_sha(files[0].get("sha")),
            "merged manifest Git blob does not match candidate PR")
    head_sha = pr["head"]["sha"]
    require(type(branch) is dict and branch.get("name") == "main"
            and branch.get("protected") is True
            and (branch.get("commit") or {}).get("sha") == expected_sha,
            "current main SHA changed, or protected main not established")
    required = ((branch.get("protection") or {}).get("required_status_checks") or {}).get("checks")
    require(type(required) is list
            and any(type(row) is dict and row.get("context") == "Windows required summary"
                    and row.get("app_id") == 15368 for row in required),
            "App15368 required Windows context not enforced")
    require(type(checks) is list and len(checks) < 100, "incomplete check-run inventory")
    matches = [c for c in checks
               if type(c) is dict and c.get("name") == "Windows required summary"
               and (c.get("app") or {}).get("id") == 15368
               and c.get("head_sha") == head_sha and c.get("status") == "completed"
               and c.get("conclusion") == "success"]
    require(len(matches) == 1, "exact candidate HEAD App15368 required CI absent or ambiguous")
    require(type(runs) is list and len(runs) < 100, "incomplete Actions run history")
    eligible = [r for r in runs if type(r) is dict
                and r.get("head_sha") == head_sha
                and r.get("event") == "pull_request"
                and r.get("name") == "Windows CI/CD"
                and r.get("status") == "completed"
                and r.get("conclusion") == "success"
                and type(r.get("id")) is int and r["id"] > 0]
    require(len(eligible) == 1, "unique successful exact-head native PR Windows run missing")
    # Explicitly do not promote this to a signed candidate-audit or trusted
    # independent branch rule/attestation proof.
    return {"schemaVersion": 1, "status": "AUTHENTICATED_PR_CI_ONLY",
            "repository": repository, "candidatePr": pr["number"],
            "candidateHeadSha": head_sha, "candidateCiRunId": eligible[0]["id"],
            "mainCommit": expected_sha, "operator": actor,
            "allMaintainedMajorsAudited": False,
            "candidateArtifactAuditVerified": False,
            "effectiveBranchRulesAudited": False,
            "signatureAndProvenanceVerified": False,
            "publicationAuthorized": False, "publishableReceipt": False}


def api(repo, suffix):
    require(type(repo) is str and REPOSITORY.fullmatch(repo), "invalid repository")
    allowed = (
        re.fullmatch(r"commits/[a-f0-9]{40}", suffix)
        or re.fullmatch(r"commits/[a-f0-9]{40}/pulls\?per_page=100", suffix)
        or re.fullmatch(r"pulls/[1-9][0-9]*/files\?per_page=100", suffix)
        or suffix == "branches/main"
        or re.fullmatch(r"commits/[a-f0-9]{40}/check-runs\?per_page=100", suffix)
        or re.fullmatch(r"actions/runs\?head_sha=[a-f0-9]{40}&per_page=100", suffix)
    )
    require(allowed, "GitHub API path not allowlisted")
    result = subprocess.run(
        ["gh", "api", "--method", "GET", "repos/" + repo + "/" + suffix],
        capture_output=True, text=True, check=False, timeout=40)
    require(result.returncode == 0, "authenticated GitHub GET failed closed")
    require(len(result.stdout) < 2 * 1024 * 1024, "GitHub API snapshot too large")
    return json.loads(result.stdout)


def live(event, repository, actor, sha, roster):
    require(os.environ.get("GITHUB_EVENT_NAME") == "push"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_REPOSITORY") == repository
            and os.environ.get("GITHUB_SHA") == sha
            and bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")),
            "not a trusted Actions protected main push runtime")
    commit = api(repository, "commits/" + sha)
    prs = api(repository, "commits/" + sha + "/pulls?per_page=100")
    require(type(prs) is list and len(prs) == 1, "ambiguous associated PR")
    number = prs[0].get("number")
    require(type(number) is int and number > 0, "invalid candidate PR number")
    files = api(repository, "pulls/" + str(number) + "/files?per_page=100")
    branch = api(repository, "branches/main")
    head_sha = (prs[0].get("head") or {}).get("sha")
    require(is_sha(head_sha), "missing candidate HEAD SHA")
    checks = api(repository, "commits/" + head_sha + "/check-runs?per_page=100")
    runs_data = api(repository, "actions/runs?head_sha=" + head_sha + "&per_page=100")
    require(type(runs_data) is dict and type(runs_data.get("total_count")) is int
            and runs_data["total_count"] < 100
            and type(runs_data.get("workflow_runs")) is list,
            "incomplete Actions run pagination")
    require(type(checks) is dict and type(checks.get("total_count")) is int
            and checks["total_count"] < 100
            and type(checks.get("check_runs")) is list,
            "incomplete check-run pagination")
    return verify_snapshot(event=event, commit=commit, prs=prs, files=files,
                           branch=branch, checks=checks["check_runs"],
                           runs=runs_data["workflow_runs"], repository=repository,
                           actor=actor, expected_sha=sha, roster=roster)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--fleet", required=True)
    p.add_argument("--output", required=True)
    a = p.parse_args()
    try:
        fleet = json.loads(Path(a.fleet).read_text("utf-8"))
        require(type(fleet) is dict and fleet.get("releasePolicy") == "manual-only"
                and type(fleet.get("entries")) is list,
                "production release policy unexpectedly changed")
        roster = [entry["repository"] for entry in fleet["entries"]]
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text("utf-8"))
        result = live(event, os.environ["GITHUB_REPOSITORY"],
                      os.environ.get("GITHUB_ACTOR", ""),
                      os.environ["GITHUB_SHA"], roster)
        Path(a.output).write_text(json.dumps(result, indent=2) + "\n", "utf-8")
        print("NONPUBLISHING LIVE CANDIDATE OBSERVER:", result["status"])
        return 0
    except (Denied, OSError, KeyError, ValueError, TypeError,
            subprocess.TimeoutExpired) as e:
        print("AUTOMATIC CANDIDATE MERGE OBSERVER DENY:", str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
