#!/usr/bin/env python3
"""Issue #75: credential-ready, GET-only Classic protection evidence reader.

No CLI, secret loading, Actions workflow, publication receipt, or write API.
The caller MUST be trusted code running from a protected main revision.
"""
from __future__ import annotations

import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPOSITORY = "pgextwin/plpgsql_check"
BRANCH_PATH = "repos/pgextwin/plpgsql_check/branches/main"
PROTECTION_PATH = BRANCH_PATH + "/protection"
ACTIONS_APP_ID = 15368
REQUIRED_CONTEXTS = frozenset({
    "syntax",
    "windows / Resolve extension and PostgreSQL matrix",
    "windows / PostgreSQL 15 / Windows x64",
    "windows / PostgreSQL 16 / Windows x64",
    "windows / PostgreSQL 17 / Windows x64",
    "windows / PostgreSQL 18 / Windows x64",
    "Regression-test immutable Release preflight",
    "Windows required summary",
})
SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES = 131072


class ProtectionDenied(ValueError):
    """Proof incomplete, access denied, or Classic policy unacceptable."""


def require(ok, why):
    if not ok:
        raise ProtectionDenied(why)


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "duplicate field in authenticated GitHub response")
        out[key] = value
    return out


class ClassicProtectionReader:
    """Read precisely two known REST resources, using a narrowly scoped token.

    The token is never printed, serialized, included in a return value, or
    attached to a diagnostic. This type has no write operations.
    """

    def __init__(self, installation_token):
        require(type(installation_token) is str and bool(installation_token),
                "a scoped installation token is required")
        self._token = installation_token

    def get(self, path):
        require(path in (BRANCH_PATH, PROTECTION_PATH),
                "GitHub read outside the single pilot main branch denied")
        request = Request(
            "https://api.github.com/" + path,
            headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            with urlopen(request, timeout=20) as response:
                require(response.status == 200, "GitHub evidence read was not HTTP 200")
                link = response.headers.get("Link", "")
                require('rel="next"' not in link and "rel=next" not in link,
                        "paginated GitHub evidence cannot prove a complete state")
                payload = response.read(MAX_JSON_BYTES + 1)
                require(len(payload) <= MAX_JSON_BYTES, "oversized GitHub evidence")
        except HTTPError as exc:
            # Never include response body, URL query, exception text, or token.
            raise ProtectionDenied("Classic GitHub API returned HTTP " + str(exc.code)) from None
        except (URLError, OSError, TimeoutError):
            raise ProtectionDenied("Classic GitHub API unavailable") from None
        try:
            value = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
        except (ValueError, UnicodeDecodeError):
            raise ProtectionDenied("invalid or ambiguous GitHub JSON response") from None
        require(type(value) is dict, "GitHub protection evidence is not an object")
        return value


def _boolean_object(protection, name, expected):
    item = protection.get(name)
    require(type(item) is dict and type(item.get("enabled")) is bool
            and item["enabled"] is expected,
            "invalid or missing Classic protection " + name)


def _no_bypass(reviews):
    # GitHub REST documents bypass_pull_request_allowances as an object
    # containing users/teams/apps. Until a real 200 response proves that
    # omission equals an empty list, an omitted key MUST fail closed.
    allowances = reviews.get("bypass_pull_request_allowances")
    require(type(allowances) is dict and
            all(type(allowances.get(k)) is list and not allowances[k]
                for k in ("users", "teams", "apps")),
            "PR bypass actor status absent or nonempty")


def _validate_snapshot(branch, protection, expected_sha, *,
                       required_contexts=REQUIRED_CONTEXTS,
                       repository=REPOSITORY):
    # Policy can be specialized for another reviewed repository without
    # weakening the plpgsql_check eight-context default.
    require(type(expected_sha) is str and SHA.fullmatch(expected_sha) is not None,
            "expected main SHA is not a full hexadecimal object ID")
    require(type(branch) is dict and
            type(branch.get("commit")) is dict and
            branch["commit"].get("sha") == expected_sha and
            branch.get("name") == "main" and branch.get("protected") is True,
            "branch is unprotected, stale or not main")
    require(type(protection) is dict and protection,
            "Classic protection detail is missing")
    checks = protection.get("required_status_checks")
    require(type(checks) is dict and checks.get("strict") is True,
            "required up-to-date status checks (strict) are missing")
    contexts = checks.get("contexts")
    rules = checks.get("checks")
    require(type(contexts) is list and len(contexts) == len(required_contexts)
            and all(type(c) is str for c in contexts)
            and set(contexts) == required_contexts,
            "required status contexts are missing, duplicated or unexpected")
    require(type(rules) is list and len(rules) == len(required_contexts),
            "App-bound required status checks are incomplete")
    verified = set()
    for rule in rules:
        require(type(rule) is dict and type(rule.get("context")) is str
                and type(rule.get("app_id")) is int
                and rule["app_id"] == ACTIONS_APP_ID
                and rule["context"] in required_contexts
                and rule["context"] not in verified,
                "required check has a wrong name, duplicate, or untrusted App")
        verified.add(rule["context"])
    require(verified == required_contexts,
            "App-bound check list differs from expected Classic policy")
    if "enforcement_level" in checks:
        require(checks["enforcement_level"] == "everyone",
                "required checks not enforced on everyone")

    reviews = protection.get("required_pull_request_reviews")
    require(type(reviews) is dict and
            type(reviews.get("required_approving_review_count")) is int and
            reviews["required_approving_review_count"] == 0,
            "PR requirement / zero approving reviews not proven")
    _no_bypass(reviews)
    _boolean_object(protection, "enforce_admins", True)
    _boolean_object(protection, "allow_force_pushes", False)
    _boolean_object(protection, "allow_deletions", False)

    # Null is the documented REST representation of unrestricted push actors.
    # An omitted field or unknown shape is NOT an empty restriction list.
    require("restrictions" in protection, "push actor restrictions are unknown")
    restrictions = protection["restrictions"]
    require(restrictions is None or
            (type(restrictions) is dict and
             all(type(restrictions.get(k)) is list and not restrictions[k]
                 for k in ("users", "teams", "apps"))),
            "push actor restrictions differ from audited policy")

    summary = (branch.get("protection") or {}).get("required_status_checks")
    require(type(summary) is dict and summary.get("enforcement_level") == "everyone",
            "branch summary does not prove required checks for everyone")
    summary_rules = summary.get("checks")
    require(type(summary_rules) is list and len(summary_rules) == len(required_contexts)
            and {r.get("context") for r in summary_rules if type(r) is dict} == required_contexts
            and all(type(r) is dict and type(r.get("app_id")) is int
                    and r["app_id"] == ACTIONS_APP_ID for r in summary_rules),
            "branch summary disagrees on App-bound checks")
    return {
        "schemaVersion": 1,
        "status": "VERIFIED_CLASSIC_READ_ONLY",
        "repository": repository,
        "branch": "main",
        "mainSha": expected_sha,
        "requiredChecks": sorted(required_contexts),
        "requiredChecksAppId": ACTIONS_APP_ID,
        "strict": True,
        "pullRequestRequired": True,
        "requiredApprovals": 0,
        "adminEnforced": True,
        "actorBypass": False,
        "forcePushAllowed": False,
        "deletionAllowed": False,
        "publishableReceipt": False,
    }


def collect_verified_classic(reader, *, expected_main_sha):
    """GET + verify twice; reject changed branch/rules between the two reads.

    This is NOT a transactional lock. The future privileged job must re-read
    and verify just before publication, additionally checking main SHA, tag
    reservation and candidate proofs. Never persist a token or response body.
    """
    snapshots = []
    for _ in range(2):
        branch = reader.get(BRANCH_PATH)
        details = reader.get(PROTECTION_PATH)
        snapshots.append((
            _validate_snapshot(branch, details, expected_main_sha),
            branch, details,
        ))
    require(snapshots[0][1:] == snapshots[1][1:],
            "Classic protection or branch changed during audit")
    return snapshots[1][0]
