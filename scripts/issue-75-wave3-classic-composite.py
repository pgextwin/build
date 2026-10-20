#!/usr/bin/env python3
"""Issue #75 Wave3 Classic REST + GraphQL GET/read-only contract.

Reuse the previously tested plpgsql_check two-snapshot composite proof core
with exact Wave3 repo identity and one required App15368 summary check.
No privileged workflow or mint. A synthetic PASS is never live auth/GO.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from urllib.request import Request

_ROOT = Path(__file__).resolve().parent


def load(alias, filename):
    spec = importlib.util.spec_from_file_location(alias, _ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wave3 = load("wave3_scoped_original", "issue-75-wave3-classic-readonly.py")
core = load("pilot_classic_composite_reused", "classic-composite-protection.py")
# We only interpolate a repository slug AFTER exact membership validation.
_PLACEHOLDER = 'name: "plpgsql_check"'
_QUERY = core._QUERY
assert _QUERY.count(_PLACEHOLDER) == 1
MAX_GRAPHQL = 131072


class CompositeReader(wave3.ScopedReader):
    """All 4 allowed REST GETs and a static read-only GraphQL query share token."""

    def __init__(self, token, repository, *, opener=None):
        super().__init__(token, repository, opener=opener)
        self._repository = repository

    def get_graphql(self):
        query = _QUERY.replace(_PLACEHOLDER,
                               'name: "' + self._repository.split("/")[1] + '"')
        wave3.require("mutation" not in query.lower())
        request = Request(
            "https://api.github.com/graphql",
            data=json.dumps({"query": query}, separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "pgextwin-issue75-wave3-classic-readonly",
            }, method="POST")  # GraphQL QUERY only; no mutation.
        try:
            with self._open(request, timeout=20) as response:
                wave3.require(response.status == 200)
                wave3.require(not response.headers.get("Link"))
                raw = response.read(MAX_GRAPHQL + 1)
                wave3.require(0 < len(raw) <= MAX_GRAPHQL)
            obj = json.loads(raw.decode("utf-8"),
                             object_pairs_hook=wave3.rest._unique_object)
            wave3.require(type(obj) is dict)
            return obj
        except Exception:
            raise wave3.Deny("Wave3 authenticated GraphQL read NOT_PROVEN") from None


def collect(reader, *, repository, expected_main_sha):
    """Two full 4-GET plus GraphQL snapshots; no live-identity claim."""
    names = wave3.paths(repository)
    wave3.require(type(expected_main_sha) is str and
                  wave3.rest.SHA.fullmatch(expected_main_sha) is not None)
    snapshots = []
    for _ in range(2):
        identity, branch, classic, rulesets = (reader.get(p) for p in names)
        wave3.require_repo_identity(identity, repository)
        wave3.require(type(rulesets) is list and not rulesets)
        gql = reader.get_graphql()
        result, bypass, pushes = core._verified_rest_snapshot(
            branch, classic, gql, expected_main_sha,
            repository=repository, required_contexts=wave3.EXPECTED_CONTEXTS)
        wave3.require(result["requiredChecks"] == ["Windows required summary"]
                      and result["requiredChecksAppId"] == 15368
                      and result["publishableReceipt"] is False)
        snapshots.append((identity, branch, classic, rulesets, gql,
                          bypass, pushes))
    wave3.require(snapshots[0] == snapshots[1])
    return {
        "schemaVersion": 1,
        "classification": "WAVE3_CLASSIC_REST_GRAPHQL_CONTRACT_ONLY",
        "repository": repository, "repositoryId": wave3.TARGETS[repository],
        "mainSha": expected_main_sha,
        "requiredCheck": "Windows required summary",
        "requiredCheckAppId": 15368,
        "auditorExpectedAppId": wave3.AUDITOR_APP_ID,
        "auditorExpectedInstallationId": wave3.AUDITOR_INSTALLATION_ID,
        "bypassEvidence": snapshots[1][5],
        "pushEvidence": snapshots[1][6],
        "readOnlyQueryAndSnapshotCount": 2,
        "independentAppPrincipalAuthenticated": False,
        "adminReadPermissionAuthenticated": False,
        "signerWriterIsolationProven": False,
        "publicationAuthorized": False, "publishableReceipt": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
    }
