#!/usr/bin/env python3
"""Issue #75: dormant, private-only auditor App read-token mint/probe/revoke.

NO workflow, CLI, secrets, storage, signer, Writer, Tag, Release or PUBLISH.
Reuses the existing strict private Writer's authenticated bounded GET and
DELETE transport, JWT identity checks, token expiry and revocation pattern.
One separately authorized App JWT must mint one Administration:read token for
ONE pinned Wave3 target, immediately verify real Classic+GraphQL and revoke.
The token mint is a PRIVILEGED action: never call from public Actions/CI.
Offline fixture success NEVER proves that the actual App/key exists.
"""
from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
from urllib.request import Request, build_opener

ROOT = Path(__file__).resolve().parent


def load(alias, file):
    spec = importlib.util.spec_from_file_location(alias, ROOT / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


transport = load("issue75_pinned_writer_get_transport",
                 "issue-75-private-writer-app-probe.py")
auditor = load("issue75_exact_auditor_identity",
               "issue-75-wave3-auditor-app-get-preflight.py")
composite = load("issue75_reused_wave3_composite",
                 "issue-75-wave3-classic-composite.py")

# Explicitly restrict issuer, installation, target and permissions.
ISSUE_PATH = "/app/installations/170837728/access_tokens"
TOKEN_PERMISSIONS = {"administration": "read"}
# Metadata read is mandatory/default on actual GitHub installation tokens.
EFFECTIVE_PERMISSIONS = {"administration": "read", "metadata": "read"}


class Deny(ValueError):
    pass


def require(ok):
    if not ok:
        raise Deny("private auditor identity/scope/verification NOT_PROVEN")


def mint_read_token(app_jwt, repository_id, *, opener=None):
    """The ONLY token-creating HTTP route; no Writer/contents permissions.

    Called only after authenticating the exact App+installation by JWT GET.
    Numeric repository ID must be one of Wave3 and the caller must separately
    bind it to the expected exact repository string.
    """
    require(type(app_jwt) is str and len(app_jwt) >= 20)
    require(type(repository_id) is int
            and repository_id in auditor.wave3.TARGETS.values())
    payload = {"repository_ids": [repository_id],
               "permissions": TOKEN_PERMISSIONS}
    request = Request(
        "https://api.github.com" + ISSUE_PATH,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + app_jwt,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "Content-Type": "application/json",
            "User-Agent": "pgextwin-issue75-auditor-private-token-proof",
        }, method="POST")
    call = opener or build_opener(transport.NoRedirect()).open
    try:
        with call(request, timeout=20) as response:
            require(response.status == 201)
            require(not response.headers.get("Link"))
            raw = response.read(transport.MAX_RESPONSE + 1)
            require(0 < len(raw) <= transport.MAX_RESPONSE)
        result = json.loads(raw.decode("utf-8"),
                            object_pairs_hook=transport.unique)
        require(type(result) is dict)
        return result
    except Exception:
        # If remote minted but reply was lost, there may be an untracked
        # short-lived credential. Stop, quarantine and DO NOT retry blindly.
        raise Deny("auditor mint ambiguous: stop and quarantine, no retry") from None


def audit_token(token, repository, expected_main_sha):
    """One same-token Classic REST+GraphQL proof; never publication authority."""
    reader = composite.CompositeReader(token, repository)
    return composite.collect(reader, repository=repository,
                             expected_main_sha=expected_main_sha)


def probe(app_jwt, *, repository, expected_main_sha, now,
          api=transport.authenticated_call, issue=mint_read_token,
          verify=audit_token):
    """Fail-closed single-target read-only JWT issuance/revocation contract.

    A private owner-approved executor (NOT current public CI) must source an
    authentic App JWT without exposing its private key. The code itself does
    not load or mint JWTs, nor provision secrets or change installations.
    """
    require(type(app_jwt) is str and len(app_jwt) >= 20)
    require(type(repository) is str and repository in auditor.wave3.TARGETS)
    rid = auditor.wave3.TARGETS[repository]
    require(type(expected_main_sha) is str and
            auditor.wave3.rest.SHA.fullmatch(expected_main_sha) is not None)
    require(type(now) is datetime and now.tzinfo is not None)
    now = now.astimezone(timezone.utc)

    try:
        app = api("GET", "/app", app_jwt)
        require(type(app) is dict and
                type(app.get("id")) is int and
                app["id"] == auditor.APP_ID and
                app.get("slug") == auditor.APP_SLUG)
        inst = api("GET", "/app/installations/" +
                   str(auditor.INSTALLATION_ID), app_jwt)
        require(type(inst) is dict and
                type(inst.get("id")) is int and
                inst["id"] == auditor.INSTALLATION_ID and
                type(inst.get("app_id")) is int and
                inst["app_id"] == auditor.APP_ID and
                inst.get("target_type") == "Organization" and
                type(inst.get("account")) is dict and
                inst["account"].get("login") == auditor.OWNER and
                inst.get("suspended_at") is None and
                inst.get("repository_selection") == "selected" and
                type(inst.get("permissions")) is dict and
                inst["permissions"] == auditor.EXPECTED_PERMISSIONS)
    except Exception:
        raise Deny("auditor JWT/App/installation identity NOT_PROVEN") from None

    issued = None
    result = None
    try:
        # No new Writer permission: the only POST creates a scoped READ token.
        issued = issue(app_jwt, rid)
        require(type(issued) is dict)
        token = issued.get("token")
        require(type(token) is str and len(token) >= 20 and
                token != app_jwt)
        require(issued.get("repository_selection") == "selected" and
                type(issued.get("permissions")) is dict and
                issued["permissions"] == EFFECTIVE_PERMISSIONS)
        listed = issued.get("repositories")
        require(type(listed) is list and len(listed) == 1 and
                type(listed[0]) is dict and
                type(listed[0].get("id")) is int and
                listed[0]["id"] == rid and
                listed[0].get("full_name") == repository and
                type(listed[0].get("owner")) is dict and
                listed[0]["owner"].get("login") == auditor.OWNER)
        ttl = transport.read_expiry(issued.get("expires_at"), now)
        visible = api("GET", transport.REPOS_ENDPOINT, token)
        require(type(visible) is dict and
                type(visible.get("total_count")) is int and
                visible["total_count"] == 1 and
                type(visible.get("repositories")) is list and
                len(visible["repositories"]) == 1)
        v = visible["repositories"][0]
        require(type(v) is dict and
                type(v.get("id")) is int and v["id"] == rid and
                v.get("full_name") == repository and
                type(v.get("owner")) is dict and
                v["owner"].get("login") == auditor.OWNER)
        proof = verify(token, repository, expected_main_sha)
        require(type(proof) is dict and
                proof.get("classification") ==
                "WAVE3_CLASSIC_REST_GRAPHQL_CONTRACT_ONLY" and
                proof.get("repository") == repository and
                proof.get("repositoryId") == rid and
                proof.get("mainSha") == expected_main_sha and
                proof.get("requiredCheckAppId") == 15368 and
                proof.get("publicationAuthorized") is False and
                proof.get("publishableReceipt") is False)
        result = {
            "schemaVersion": 1,
            "classification": "PRIVATE_AUDITOR_SCOPED_READ_AND_REVOKE_CONTRACT",
            "auditorAppId": auditor.APP_ID,
            "installationId": auditor.INSTALLATION_ID,
            "targetRepository": repository, "repositoryId": rid,
            "checkedMainSha": expected_main_sha,
            "expiresWithinSeconds": ttl,
            "scope": "ONE_REPOSITORY_ADMINISTRATION_READ_ONLY",
            "reusedClassicCompositeContractObserved": True,
            "credentialCustodyIndependentlyProven": False,
            "publisherPrewriteAuthorized": False,
            "publicationAuthorized": False,
            "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
        }
    except Exception:
        raise Deny("auditor read-token scope/real Classic proof NOT_PROVEN") from None
    finally:
        if type(issued) is dict and type(issued.get("token")) is str:
            try:
                revoked = api("DELETE", transport.TOKEN_ENDPOINT,
                              issued["token"])
                require(type(revoked) is dict and revoked.get("revoked") is True)
            except Exception:
                raise Deny("auditor token revocation UNCONFIRMED; quarantine") from None
    require(result is not None)
    result["scopedTokenRevocation204Observed"] = True
    return result
