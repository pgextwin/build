#!/usr/bin/env python3
"""Wave3 strictly scoped Classic protection GET-only contract (Issue #75).

Not connected to a privileged workflow. An injected reader/synthetic response
never establishes independent App authentication or publication authorization.
The existing plpgsql_check eight-context policy remains the default in the
reused validator. No credential mint, Signer, mutation or CLI entrypoint.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

_ROOT = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "issue75_original_classic", _ROOT / "classic-protection-audit.py")
rest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rest)

TARGETS = {
    "pgextwin/pgtap": 1425678353,
    "pgextwin/pg_variables": 1425679720,
    "pgextwin/pg_store_plans": 1425680909,
}
EXPECTED_CONTEXTS = frozenset(("Windows required summary",))
AUDITOR_APP_ID = 5295410
AUDITOR_INSTALLATION_ID = 170837728
MAX_RESPONSE = 131072


class Deny(ValueError):
    pass


def require(condition):
    if not condition:
        raise Deny("Wave3 authenticated admin protection evidence NOT_PROVEN")


def paths(repository):
    require(type(repository) is str and repository in TARGETS)
    base = "repos/" + repository
    return (base, base + "/branches/main",
            base + "/branches/main/protection",
            base + "/rulesets?includes_parents=true")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Deny("GitHub redirect denied")


class ScopedReader:
    """One supplied installation token; four allowlisted GET URLs only.

    This reader does not mint or classify the installation token. Owner must
    independently prove App 5295410/installation 170837728 and effective
    Administration:read, Metadata:read and selected repo membership.
    """

    def __init__(self, token, repository, *, opener=None):
        require(type(token) is str and len(token) >= 20)
        self._paths = paths(repository)
        self._token = token
        self._open = opener or build_opener(NoRedirect()).open

    def get(self, path):
        require(type(path) is str and path in self._paths)
        req = Request(
            "https://api.github.com/" + path,
            headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "pgextwin-issue75-wave3-classic-readonly",
            }, method="GET")
        try:
            with self._open(req, timeout=20) as response:
                require(response.status == 200)
                require(not response.headers.get("Link"))
                raw = response.read(MAX_RESPONSE + 1)
                require(0 < len(raw) <= MAX_RESPONSE)
            obj = json.loads(raw.decode("utf-8"),
                             object_pairs_hook=rest._unique_object)
            require(type(obj) in (dict, list))
            return obj
        except Exception:
            # Never echo secrets, opaque URL errors or response bodies.
            raise Deny("Wave3 scoped authenticated GET failed") from None


def require_repo_identity(value, repository):
    """Single pinned identity check shared by REST and GraphQL collectors."""
    paths(repository)
    require(type(value) is dict and type(value.get("id")) is int
            and value["id"] == TARGETS[repository]
            and value.get("full_name") == repository
            and type(value.get("owner")) is dict
            and value["owner"].get("login") == "pgextwin")


def collect(reader, *, repository, expected_main_sha):
    """Two exact raw snapshots; REST omission is a denial, not assumed empty."""
    names = paths(repository)
    require(type(expected_main_sha) is str
            and rest.SHA.fullmatch(expected_main_sha) is not None)
    snaps = []
    for _ in range(2):
        repo, branch, classic, rulesets = (reader.get(p) for p in names)
        require_repo_identity(repo, repository)
        require(type(rulesets) is list and not rulesets)
        result = rest._validate_snapshot(
            branch, classic, expected_main_sha,
            required_contexts=EXPECTED_CONTEXTS, repository=repository)
        require(result.get("publishableReceipt") is False
                and result.get("requiredChecksAppId") == 15368
                and result.get("requiredChecks") == ["Windows required summary"])
        snaps.append((repo, branch, classic, rulesets))
    require(snaps[0] == snaps[1])  # fail closed on SHA/rules/bypass drift
    return {
        "schemaVersion": 1,
        "classification": "WAVE3_CLASSIC_TWO_SNAPSHOT_CONTRACT_ONLY",
        "repository": repository, "repositoryId": TARGETS[repository],
        "mainSha": expected_main_sha,
        "observedRequiredCheck": "Windows required summary",
        "requiredCheckAppId": 15368,
        "auditorExpectedAppId": AUDITOR_APP_ID,
        "auditorExpectedInstallationId": AUDITOR_INSTALLATION_ID,
        "auditorIdentityIndependentlyAuthenticated": False,
        "effectiveRulesAuthenticatedByIndependentApp": False,
        "externalCredentialIsolationProven": False,
        "rulesetsAbsentInSuppliedSnapshots": True,
        "publishableReceipt": False,
        "publicationAuthorized": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
    }
