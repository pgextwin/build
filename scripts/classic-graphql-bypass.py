#!/usr/bin/env python3
"""Issue #75: pure, fail-closed GraphQL effective-branch bypass zero verifier.

NO I/O, HTTP, token loading, release receipt, fallback, or write operation.
The caller must independently authenticate the GraphQL response with a tightly
scoped installation token and bind it to the same protected main SHA as the
Classic REST proof. This module alone is never a publication authorization.
"""
from __future__ import annotations

import re

_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPO = "pgextwin/plpgsql_check"


class GraphqlBypassDenied(ValueError):
    """The independently sourced effective Classic bypass proof is incomplete."""


def _require(condition, message):
    if not condition:
        raise GraphqlBypassDenied(message)


def validate_effective_ref_bypass_zero(payload, *, expected_main_sha, repository=_REPO):
    """Accept only a complete main-bound GraphQL zero-count connection.

    Expected *read-only query* shape:
      repository(owner: "pgextwin", name: "plpgsql_check") {
        nameWithOwner
        ref(qualifiedName: "refs/heads/main") {
          name prefix target { oid }
          branchProtectionRule {
            id
            bypassPullRequestAllowances(first: 1) {
              totalCount nodes { id } pageInfo { hasNextPage }
            }
          }
        }
      }
    No data from caller-generated fixture may be used as live proof.
    """
    _require(type(repository) is str and bool(repository),
             "expected repository invalid")
    _require(type(expected_main_sha) is str
             and _SHA.fullmatch(expected_main_sha) is not None,
             "expected main SHA invalid")
    _require(type(payload) is dict and "errors" not in payload,
             "GraphQL errors or invalid root")
    data = payload.get("data")
    _require(type(data) is dict, "GraphQL data unavailable")
    repo = data.get("repository")
    _require(type(repo) is dict and repo.get("nameWithOwner") == repository,
             "GraphQL repository identity mismatch")
    ref = repo.get("ref")
    _require(type(ref) is dict and ref.get("name") == "main"
             and ref.get("prefix") == "refs/heads/",
             "GraphQL effective main Ref unavailable")
    target = ref.get("target")
    _require(type(target) is dict and target.get("oid") == expected_main_sha,
             "GraphQL Ref target stale or incorrect")
    rule = ref.get("branchProtectionRule")
    _require(type(rule) is dict and type(rule.get("id")) is str
             and bool(rule["id"]),
             "effective Classic branch rule not visible")
    allowances = rule.get("bypassPullRequestAllowances")
    _require(type(allowances) is dict, "GraphQL bypass connection missing")
    count = allowances.get("totalCount")
    _require(type(count) is int and count == 0,
             "GraphQL bypass allowances nonzero or ambiguous")
    _require(type(allowances.get("nodes")) is list
             and not allowances["nodes"],
             "GraphQL bypass nodes ambiguous")
    page = allowances.get("pageInfo")
    _require(type(page) is dict and page.get("hasNextPage") is False,
             "GraphQL bypass page is incomplete")
    return {
        "schemaVersion": 1,
        "status": "VERIFIED_EFFECTIVE_REF_BYPASS_ZERO",
        "repository": repository,
        "branch": "main",
        "mainSha": expected_main_sha,
        "bypassPullRequestAllowances": 0,
        "publishableReceipt": False,
    }
