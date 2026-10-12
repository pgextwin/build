#!/usr/bin/env python3
"""Offline-verifiable Chat-authored Release PR attestation preflight.

Phase B: PURE VALIDATION ONLY. No CLI, network access, GitHub writes, or
workflow entrypoint here. A future protected-main workflow MUST fetch the PR,
push commit, effective branch rules and exact-head checks itself before calling
verify_approval(). Never trust these arguments when supplied by a PR.
"""
from __future__ import annotations
import re

SHA = re.compile(r"^[0-9a-f]{40}$")
LOGIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
TAG = re.compile(r"^v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*$")
FIELDS = frozenset({
    "schemaVersion", "type", "repository", "releaseTag", "packagingMainSha",
    "candidatePr", "candidateHeadSha", "candidateRunId", "decisionRunId",
    "operatorLogin", "confirmRelease",
})


class Denied(ValueError):
    """Reject unsafe or insufficiently proven authorization."""


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def human(value):
    return isinstance(value, str) and LOGIN.fullmatch(value) is not None and not value.lower().endswith("bot")


def full_sha(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def positive_int(value):
    return type(value) is int and value > 0


def exact_changed_file(files, path):
    return (type(files) is list and len(files) == 1
            and type(files[0]) is dict and files[0].get("filename") == path
            and files[0].get("status") == "added")


def verify_approval(request, *, repository, event, pr, pr_files, commit,
                    ci, effective_rules, allowed_operators):
    """Validate GitHub API snapshots obtained independently by a trusted runner.

    Returns attested *context*, NOT a promotion receipt. Only an independent
    candidate evidence verifier may combine this with a promotion receipt.
    """
    require(type(request) is dict and set(request) == FIELDS,
            "authorization request must have exact schema keys")
    require(request["schemaVersion"] == 1 and type(request["schemaVersion"]) is int
            and request["type"] == "pgextwin-chat-authorized-release"
            and request["confirmRelease"] == "PUBLISH",
            "explicit typed PUBLISH authorization missing")
    repo = request["repository"]
    tag = request["releaseTag"]
    operator = request["operatorLogin"]
    parent = request["packagingMainSha"]
    require(isinstance(repository, str) and repo == repository
            and repo.startswith("pgextwin/") and len(repo.split("/")) == 2,
            "target repository differs from trusted context")
    require(isinstance(tag, str) and TAG.fullmatch(tag) is not None,
            "invalid or unsafe release tag syntax")
    require(full_sha(parent) and full_sha(request["candidateHeadSha"])
            and all(positive_int(request[k]) for k in (
                "candidatePr", "candidateRunId", "decisionRunId")),
            "incomplete candidate or packaging commit identity")
    require(human(operator) and type(allowed_operators) in (set, frozenset)
            and operator in allowed_operators,
            "no explicit allowed human operator")
    require(type(event) is dict and event.get("ref") == "refs/heads/main"
            and (event.get("repository") or {}).get("full_name") == repo
            and event.get("before") == parent and full_sha(event.get("after"))
            and (event.get("sender") or {}).get("login") == operator,
            "untrusted push/ref/repository/sender/pre-merge commit")
    after = event["after"]
    changes = event.get("commits")
    require(type(changes) is list and len(changes) == 1
            and changes[0].get("id") == after
            and event.get("created") is False and event.get("deleted") is False,
            "push must contain exactly one non-ref-changing commit")
    require(type(commit) is dict and commit.get("sha") == after
            and type(commit.get("parents")) is list
            and len(commit["parents"]) == 1
            and commit["parents"][0].get("sha") == parent,
            "squash commit must be a single parent directly on verified main")
    path = ".github/release-authorizations/" + tag + ".json"
    require(exact_changed_file(commit.get("files"), path),
            "unexpected squash-commit files or change status")
    require(type(pr) is dict and pr.get("merged") is True
            and pr.get("state") == "closed"
            and pr.get("merge_commit_sha") == after
            and (pr.get("base") or {}).get("ref") == "main"
            and (pr.get("base") or {}).get("repo", {}).get("full_name", repo) == repo
            and (pr.get("head") or {}).get("repo", {}).get("full_name", repo) == repo
            and full_sha((pr.get("head") or {}).get("sha"))
            and (pr.get("user") or {}).get("login") == operator
            and (pr.get("merged_by") or {}).get("login") == operator,
            "authorization must be a same-repo PR created and merged by allowed human")
    require(exact_changed_file(pr_files, path),
            "authorization PR must add exactly one typed record")
    require(type(ci) is dict and ci.get("headSha") == pr["head"]["sha"]
            and ci.get("allRequiredChecksPassed") is True
            and type(ci.get("requiredChecks")) is list
            and len(ci["requiredChecks"]) > 0
            and all(isinstance(x, str) and x for x in ci["requiredChecks"]),
            "exact-head required CI proof missing")
    require(type(effective_rules) is dict
            and effective_rules.get("protectedMain") is True
            and effective_rules.get("requiredChecksEnforced") is True
            and effective_rules.get("restrictDirectPush") is True,
            "GitHub-enforced protected PR-only main with required CI not proven")
    # Additional caller obligations: check that tag/release do not exist, the
    # event SHA is still current main, central/local mode is explicit, and all
    # candidate evidence fully matches. This pure helper never publishes.
    return {
        "operator": operator, "repository": repo,
        "releaseTag": tag, "packagingMainSha": parent,
        "authorizationPr": pr.get("number"),
        "authorizationCommit": after,
        "authorizationHeadSha": pr["head"]["sha"],
        "authorizationBaseSha": parent,
        "candidatePr": request["candidatePr"],
        "candidateHeadSha": request["candidateHeadSha"],
        "candidateRunId": request["candidateRunId"],
        "decisionRunId": request["decisionRunId"],
        "event": "push",
    }
