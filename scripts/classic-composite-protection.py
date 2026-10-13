#!/usr/bin/env python3
"""Issue #75: strict two-snapshot REST + effective-ref GraphQL Classic proof.

Read-only, single-repository, same-token pilot. A missing *REST* PR bypass
allowance field can be filled ONLY after an independently verified effective
refs/heads/main zero-bypass GraphQL result. Explicit malformed/nonempty REST
values always DENY. Never issue a publication receipt or write request.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_ROOT = Path(__file__).resolve().parent
_MAX = 131072
_QUERY = """query {
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
}"""


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _ROOT / filename)
    if spec is None or spec.loader is None:
        raise CompositeDenied("pinned verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rest = _load("classic_protection_audit_composite", "classic-protection-audit.py")
graphql = _load("classic_graphql_bypass_composite", "classic-graphql-bypass.py")


class CompositeDenied(ValueError):
    """Missing, stale, nonzero, ambiguous or conflicting protection evidence."""


class CompositeReader:
    """One installation token for all REST GETs and GraphQL read-only queries.

    Production client is fully isolated in trusted build checkout. No write
    method, token serialization, arbitrary user-supplied endpoint or logging.
    """

    def __init__(self, installation_token):
        rest.require(type(installation_token) is str and bool(installation_token),
                     "same scoped installation token required")
        self._rest = rest.ClassicProtectionReader(installation_token)
        self._token = installation_token

    def get(self, path):
        return self._rest.get(path)

    def get_graphql(self):
        req = Request(
            "https://api.github.com/graphql",
            data=json.dumps({"query": _QUERY}, separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="POST",  # GraphQL query transport only; NO mutation.
        )
        try:
            with urlopen(req, timeout=20) as response:
                if response.status != 200:
                    raise CompositeDenied("GraphQL was not HTTP 200")
                payload = response.read(_MAX + 1)
                if len(payload) > _MAX:
                    raise CompositeDenied("GraphQL response too large")
        except HTTPError as exc:
            raise CompositeDenied("GraphQL HTTP " + str(exc.code)) from None
        except (URLError, OSError, TimeoutError):
            raise CompositeDenied("GraphQL unavailable") from None
        try:
            value = json.loads(payload.decode("utf-8"), object_pairs_hook=rest._unique_object)
        except (ValueError, UnicodeDecodeError):
            raise CompositeDenied("invalid GraphQL JSON") from None
        if type(value) is not dict:
            raise CompositeDenied("invalid GraphQL root")
        return value


def _verified_rest_snapshot(branch, protection, graphql_response, expected_sha):
    # Verify independent evidence before permitting the sole omission fallback.
    proof = graphql.validate_effective_ref_bypass_zero(
        graphql_response, expected_main_sha=expected_sha)
    if (proof.get("status") != "VERIFIED_EFFECTIVE_REF_BYPASS_ZERO"
            or proof.get("mainSha") != expected_sha
            or proof.get("publishableReceipt") is not False):
        raise CompositeDenied("effective GraphQL zero proof incomplete")

    if type(protection) is not dict:
        raise CompositeDenied("REST protection not object")
    reviews = protection.get("required_pull_request_reviews")
    if type(reviews) is not dict:
        raise CompositeDenied("REST required reviews missing")
    normalized = deepcopy(protection)
    if "bypass_pull_request_allowances" not in reviews:
        # This is the ONLY synthesized field, and it exists solely in the
        # ephemeral verification copy after independently authenticated
        # GraphQL effective-main zero verification. The raw REST is retained.
        normalized["required_pull_request_reviews"]["bypass_pull_request_allowances"] = {
            "users": [], "teams": [], "apps": [],
        }
        source = "GRAPHQL_ZERO_FOR_REST_OMISSION"
    else:
        # No fallback for null, object with missing lists, wrong types or
        # nonempty actors; the unchanged original REST validator denies them.
        source = "REST_EXPLICIT_EMPTY"
    verified = rest._validate_snapshot(branch, normalized, expected_sha)
    return verified, source


def collect_verified_composite(reader, *, expected_main_sha):
    """Two complete REST+GraphQL snapshots: branch, Classic detail, query x 2.

    Caller MUST use CompositeReader(token) with one single-repository App
    installation token on a reviewed protected-main job. A caller-supplied
    fixture alone cannot constitute live proof. Fail closed for any race.
    """
    if type(expected_main_sha) is not str or rest.SHA.fullmatch(expected_main_sha) is None:
        raise CompositeDenied("expected main SHA invalid")
    snapshots = []
    for _ in range(2):
        branch = reader.get(rest.BRANCH_PATH)
        protection = reader.get(rest.PROTECTION_PATH)
        gql_data = reader.get_graphql()
        verified, source = _verified_rest_snapshot(
            branch, protection, gql_data, expected_main_sha)
        snapshots.append((branch, protection, gql_data, verified, source))
    first, second = snapshots
    # Raw, rather than synthesized, protection snapshots must be identical.
    # This also checks effective rule ID and both GraphQL connections unchanged.
    if first[:3] != second[:3] or first[4] != second[4]:
        raise CompositeDenied("REST/GraphQL evidence changed between snapshots")
    result = dict(second[3])
    result.update({
        "schemaVersion": 1,
        "status": "VERIFIED_CLASSIC_COMPOSITE_READ_ONLY",
        "bypassEvidence": second[4],
        "independentEffectiveRefZero": True,
        "snapshotCount": 2,
        "publishableReceipt": False,
    })
    return result
