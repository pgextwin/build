#!/usr/bin/env python3
"""Issue #75: fail-closed, nonpublishing policy preflight for automatic Releases.

Only a read-only decision helper. All input dictionaries are UNTRUSTED until
separately fetched and authenticated from GitHub by a future trusted caller.
The existing pinned Signer, candidate verifier, manual Publisher and all
17 production promotion workflows remain untouched by this module.
"""
from __future__ import annotations

import re

SHA = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*$")
HUMAN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
FILES = {"config/extension.json", "config/initial-release-candidate.json"}


class Denied(ValueError):
    """Fail closed, without granting a publishable receipt."""


def require(value, message):
    if not value:
        raise Denied(message)


def same_sha(value):
    return isinstance(value, str) and bool(SHA.fullmatch(value))


def preflight(fleet, event, pr, commit, checks, candidate, decision, audit,
              release, *, permitted_mergers):
    """Validate observational cross-links, returning a NONPUBLISHING work item.

    This does not verify real signatures, effective GitHub protection, Release
    tag absence, candidate ZIP bytes or full upstream SHA/license. It must NOT
    be converted to a Publisher receipt or used as a release authorization.
    """
    require(type(fleet) is dict and fleet.get("schemaVersion") == 1
            and type(fleet.get("schemaVersion")) is int
            and fleet.get("releasePolicy") == "manual-only",
            "existing production manual-only policy changed unexpectedly")
    entries = fleet.get("entries")
    require(type(entries) is list and len(entries) == 17,
            "not the complete production 17-extension roster")
    roster = [v.get("repository") for v in entries if type(v) is dict]
    require(len(roster) == 17 and len(set(roster)) == 17
            and all(isinstance(v, str) and v.startswith("pgextwin/")
                    and v.count("/") == 1 for v in roster),
            "malformed/duplicated roster")
    require(type(permitted_mergers) in (set, frozenset)
            and permitted_mergers
            and all(isinstance(s, str) and HUMAN.fullmatch(s)
                    and not s.lower().endswith("bot") for s in permitted_mergers),
            "no trusted human GitHub merge identity configured")
    require(type(event) is dict and event.get("event") == "push"
            and event.get("ref") == "refs/heads/main"
            and event.get("repository") in roster
            and same_sha(event.get("before")) and same_sha(event.get("after"))
            and event.get("created") is False and event.get("deleted") is False
            and event.get("actor") in permitted_mergers,
            "not an authenticated candidate merge push on main")
    require(type(commit) is dict and commit.get("sha") == event["after"]
            and type(commit.get("parents")) is list
            and len(commit["parents"]) == 1
            and commit["parents"][0] == event["before"],
            "merge must be one protected, single-parent squash commit")
    changed = commit.get("files")
    require(type(changed) is list and len(changed) == 1
            and changed[0].get("path") in FILES
            and changed[0].get("status") in ("added", "modified"),
            "unrelated file change cannot request a Release")
    require(type(pr) is dict and pr.get("merged") is True
            and pr.get("draft") is False
            and pr.get("base") == "main"
            and pr.get("mergeCommit") == event["after"]
            and pr.get("mergedBy") == event["actor"]
            and pr.get("repository") == event["repository"]
            and pr.get("author") == "github-actions[bot]"
            and same_sha(pr.get("headSha"))
            and isinstance(pr.get("number"), int) and type(pr["number"]) is int
            and pr["number"] > 0
            and pr.get("changedFiles") == changed,
            "cannot bind exact bot candidate PR to authentic Chat merge")
    require(type(checks) is dict and checks.get("sha") == pr["headSha"]
            and checks.get("requiredWindows") == "success"
            and checks.get("githubActionsAppId") == 15368
            and checks.get("matrix") == "success"
            and checks.get("allMaintainedMajorsPassed") is True
            and checks.get("protectedMainEnforced") is True,
            "exact-head protected Windows CI not proven")
    branch = pr.get("branch")
    require(isinstance(branch, str)
            and re.fullmatch(r"auto-candidate/[0-9a-f]{20}", branch),
            "unexpected candidate branch")
    require(type(candidate) is dict and candidate.get("branch") == branch
            and candidate.get("headSha") == pr["headSha"]
            and candidate.get("event") == "workflow_dispatch"
            and candidate.get("status") == "completed"
            and candidate.get("conclusion") == "success"
            and type(candidate.get("id")) is int and candidate["id"] > 0,
            "original immutable candidate run incomplete")
    require(type(decision) is dict and decision.get("candidateBranch") == branch
            and decision.get("conclusion") == "success"
            and type(decision.get("id")) is int and decision["id"] > 0,
            "candidate decision run incomplete or mismatched")
    require(type(audit) is dict and audit.get("status") == "VERIFIED"
            and audit.get("candidateRunId") == candidate["id"]
            and audit.get("candidateHeadSha") == pr["headSha"]
            and audit.get("fullMatrix") is True
            and audit.get("sourceIdentityMatched") is True
            and audit.get("licenseMatched") is True,
            "independent candidate artifact and upstream audit missing")
    require(type(release) is dict
            and isinstance(release.get("tag"), str) and TAG.fullmatch(release["tag"])
            and release.get("tagExists") is False
            and release.get("releaseExists") is False
            and release.get("upstreamIsNewer") is True,
            "new signed Release identity not established")

    # A passing dry-run MUST NOT become a release authorization even if the
    # actual caller accidentally treats its observations as a trusted receipt.
    return {"schemaVersion": 1, "status": "ELIGIBLE_FOR_FURTHER_AUTHENTICATED_AUDIT",
            "repository": event["repository"], "candidatePr": pr["number"],
            "candidateHeadSha": pr["headSha"], "candidateRunId": candidate["id"],
            "decisionRunId": decision["id"], "releaseTag": release["tag"],
            "mergeCommit": event["after"],
            "publicationAuthorized": False, "publishableReceipt": False,
            "signedArtifactsVerified": False, "automaticReleaseEnabled": False}
