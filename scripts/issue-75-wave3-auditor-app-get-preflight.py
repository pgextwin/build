#!/usr/bin/env python3
"""Issue #75: dormant READ-only App auditor issuer/scope preflight.

Reuse the already-tested private Writer's bounded authenticated GitHub GET
transport, but NEVER call its token POST/DELETE or publishing path.
No live credentials in public CI. Only separately owner-authorized isolated
runtime may provide a genuine App JWT and an existing installation token.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def _load(alias, filename):
    spec = importlib.util.spec_from_file_location(alias, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

writer = _load("issue75_writer_existing_get_transport",
               "issue-75-private-writer-app-probe.py")
wave3 = _load("issue75_wave3_existing_ids",
              "issue-75-wave3-classic-readonly.py")

APP_ID = 5295410
INSTALLATION_ID = 170837728
APP_SLUG = "pgextwin-classic-protection-audit"
OWNER = "pgextwin"
PILOT = ("pgextwin/plpgsql_check", 1410581312)
EXPECTED = {**wave3.TARGETS, PILOT[0]: PILOT[1]}
EXPECTED_PERMISSIONS = {"administration": "read", "metadata": "read"}
REPO_PATH = "/installation/repositories?per_page=100&page=1"

class Deny(ValueError):
    pass

def require(value):
    if not value:
        raise Deny("independent auditor App identity or scope NOT_PROVEN")

def preflight(app_jwt, installation_token, *,
              api=writer.authenticated_call):
    """GET /app, GET exact installation, GET token-visible repos.

    This method has zero token-creation/mutation side effects. It cannot
    cryptographically bind an externally supplied installation token to the
    JWT issuer; that needs separately authorized mint+revoke proof.
    A synthetic callback may only establish the acceptance *contract*.
    """
    require(type(app_jwt) is str and len(app_jwt) >= 20
            and type(installation_token) is str
            and len(installation_token) >= 20
            and app_jwt != installation_token)
    try:
        app = api("GET", "/app", app_jwt)
        require(type(app) is dict and type(app.get("id")) is int
                and app["id"] == APP_ID and app.get("slug") == APP_SLUG)
        inst = api("GET", "/app/installations/" + str(INSTALLATION_ID),
                   app_jwt)
        require(type(inst) is dict
                and type(inst.get("id")) is int
                and inst["id"] == INSTALLATION_ID
                and type(inst.get("app_id")) is int
                and inst["app_id"] == APP_ID
                and inst.get("target_type") == "Organization"
                and type(inst.get("account")) is dict
                and inst["account"].get("login") == OWNER
                and inst.get("suspended_at") is None
                and inst.get("repository_selection") == "selected"
                and type(inst.get("permissions")) is dict
                and inst["permissions"] == EXPECTED_PERMISSIONS)
        visible = api("GET", REPO_PATH, installation_token)
        require(type(visible) is dict
                and type(visible.get("total_count")) is int
                and visible["total_count"] == len(EXPECTED)
                and type(visible.get("repositories")) is list
                and len(visible["repositories"]) == len(EXPECTED))
        found = {}
        for item in visible["repositories"]:
            require(type(item) is dict
                    and type(item.get("full_name")) is str
                    and type(item.get("id")) is int
                    and type(item.get("owner")) is dict
                    and item["owner"].get("login") == OWNER
                    and item["full_name"] not in found)
            found[item["full_name"]] = item["id"]
        require(found == EXPECTED)
    except Exception:
        # Never print raw JWT, token, response bodies, API exception or URL.
        raise Deny("independent auditor App identity or scope NOT_PROVEN") from None
    return {
        "schemaVersion": 1,
        "classification": "AUDITOR_APP_AND_TOKEN_SCOPE_GET_CONTRACT_ONLY",
        "expectedAppId": APP_ID,
        "expectedInstallationId": INSTALLATION_ID,
        "expectedRepositoryIds": dict(sorted(EXPECTED.items())),
        "expectedPermissions": EXPECTED_PERMISSIONS.copy(),
        "readOnlyTransport": True,
        "mintOrRevokePerformed": False,
        "externalTokenBoundToJwtIssuer": False,
        "independentHostCredentialIsolationProven": False,
        "wave3EffectiveClassicProtectionProven": False,
        "publicationAuthorized": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
    }
