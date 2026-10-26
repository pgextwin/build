#!/usr/bin/env python3
"""Scoped, short-lived Publisher App token lifecycle (NO RELEASE authorization).

Only import from an isolated, protected build/publisher Environment job. A
token is issued for precisely one trusted fleet repository and revoked even on
validation or caller failure. This module never writes refs, tags or Releases
and never emits a publication receipt; separate release admission is required.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path
from contextlib import contextmanager
from urllib.error import HTTPError
from datetime import datetime, timezone, timedelta
import re
import sys

REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")

_policy_spec=importlib.util.spec_from_file_location("shared_fleet_policy",Path(__file__).with_name("fleet-policy.py"))
fleet_policy=importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(fleet_policy)

class Denied(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Denied(reason)

def valid_fleet(fleet, repository, *, release_policy='manual-only'):
    require(release_policy in (fleet_policy.MANUAL,fleet_policy.AUTOMATIC),
            "unsupported requested Publisher fleet policy")
    try:
        rows=fleet_policy.members(fleet)
    except fleet_policy.Denied as exc:
        raise Denied("invalid Publisher fleet") from exc
    require(type(repository) is str and repository in rows
            and fleet["releasePolicy"]==release_policy,
            "missing or unauthorized Publisher target/mode")


def issuer(api, jwt, key, app, installation):
    """JWT-authenticated App identity; do not accept input IDs alone."""
    require(type(app) is int and app == 5451798 and app != 15368
            and type(installation) is int and installation == 174720074
            and type(key) is str and bool(key), "untrusted dedicated Publisher identity")
    identity = api("GET", "/app", jwt(key, app))
    require(type(identity) is dict
            and identity.get("id") == app
            and identity.get("slug") == "pgextwin-publisher",
            "JWT-authenticated Publisher App identity mismatch")
    installed = api("GET", "/app/installations/" + str(installation), jwt(key, app))
    require(type(installed) is dict and installed.get("id") == installation
            and installed.get("app_id") == app
            and type(installed.get("account")) is dict
            and installed["account"].get("login") == "pgextwin"
            and installed.get("repository_selection") == "all"
            and installed.get("permissions") == {"contents": "write", "metadata": "read"}
            and installed.get("suspended_at") is None,
            "JWT-authenticated Publisher installation mismatch")
    return installed

@contextmanager
def single_repository_token(*, api, jwt, key, app, installation,
                            repository, fleet, now=None,
                            release_policy="manual-only"):
    """Yield token + live scope only within one isolated job; ALWAYS revoke.

    No token is emitted to logs or artifacts. Even a successful scope proof is
    not valid publication approval. API requests and actual write verification
    must be done using the yielded token in the SAME trusted process.
    """
    valid_fleet(fleet, repository, release_policy=release_policy)
    issuer(api, jwt, key, app, installation)
    require(now is None or (type(now) is datetime and now.tzinfo is not None),
            "invalid token observation time")
    token = None
    try:
        minted = api("POST", "/app/installations/" + str(installation) + "/access_tokens",
                     jwt(key, app),
                     {"repositories": [repository.split("/", 1)[1]],
                      "permissions": {"contents": "write", "metadata": "read"}})
        require(type(minted) is dict, "Publisher token issuance failed")
        token = minted.get("token")
        require(type(token) is str and len(token) > 20
                and minted.get("repository_selection") == "selected"
                and minted.get("permissions") == {"contents": "write", "metadata": "read"},
                "Publisher token was not exactly scoped")
        expires = minted.get("expires_at")
        require(type(expires) is str and expires.endswith("Z"),
                "Publisher token expiry missing")
        try:
            expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError as exc:
            raise Denied("Publisher token expiry malformed") from exc
        observed = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
        require(timedelta(seconds=60) < expiry - observed <= timedelta(hours=1),
                "Publisher token expired or overlong")
        scoped = api("GET", "/installation/repositories?per_page=100", token)
        require(type(scoped) is dict and type(scoped.get("total_count")) is int
                and scoped["total_count"] == 1
                and type(scoped.get("repositories")) is list
                and len(scoped["repositories"]) == 1
                and type(scoped["repositories"][0]) is dict
                and scoped["repositories"][0].get("full_name") == repository,
                "Publisher token has missing/expanded repository scope")
        yield token, minted, scoped
    finally:
        if type(token) is str and token:
            # DELETE acceptance alone cannot establish token invalidation.
            # Independently require the SAME scoped token to receive 401 from
            # its former authorized read endpoint. Any 403, transport failure
            # or still-usable token is a hard denial, never an accepted proof.
            # Emit only fixed stage labels and numeric HTTP codes. Never log
            # tokens, credential-bearing URLs, exception bodies or API payloads.
            # Any non-401 response still DENIES; this is diagnostics, not a waiver.
            try:
                api("DELETE", "/installation/token", token)
            except HTTPError as exc:
                print("PUBLISHER_REVOKE_DELETE_HTTP_" + str(exc.code), file=sys.stderr)
                raise
            try:
                api("GET", "/installation/repositories?per_page=100", token)
            except HTTPError as exc:
                if exc.code != 401:
                    print("PUBLISHER_REVOKE_PROBE_HTTP_" + str(exc.code), file=sys.stderr)
                require(exc.code == 401,
                        "Publisher token revocation not independently confirmed")
            else:
                print("PUBLISHER_REVOKE_PROBE_TOKEN_STILL_ACTIVE", file=sys.stderr)
                raise Denied("Publisher token remains usable after revocation")
