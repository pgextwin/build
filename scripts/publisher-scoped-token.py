#!/usr/bin/env python3
"""Scoped, short-lived Publisher App token lifecycle (NO RELEASE authorization).

Only import from an isolated, protected build/publisher Environment job. A
token is issued for precisely one trusted fleet repository and revoked even on
validation or caller failure. This module never writes refs, tags or Releases
and never emits a publication receipt; separate release admission is required.
"""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import re

REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")

class Denied(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Denied(reason)

def valid_fleet(fleet, repository):
    require(type(repository) is str and REPO.fullmatch(repository)
            and type(fleet) is dict and type(fleet.get("schemaVersion")) is int
            and fleet["schemaVersion"] == 1
            and fleet.get("releasePolicy") == "manual-only"
            and type(fleet.get("entries")) is list and bool(fleet["entries"]),
            "Publisher target or protected fleet invalid")
    names = []
    for row in fleet["entries"]:
        require(type(row) is dict and type(row.get("repository")) is str
                and REPO.fullmatch(row["repository"])
                and row.get("mode") == "BUILD"
                and row.get("candidateEnabled") is True
                and row.get("releasePolicy") == "manual-only",
                "Publisher target is not an enabled, manual-only BUILD member")
        names.append(row["repository"])
    require(len(names) == len(set(names)) and repository in names,
            "missing, duplicated or unauthorized Publisher target")

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
                            repository, fleet, now=None):
    """Yield token + live scope only within one isolated job; ALWAYS revoke.

    No token is emitted to logs or artifacts. Even a successful scope proof is
    not valid publication approval. API requests and actual write verification
    must be done using the yielded token in the SAME trusted process.
    """
    valid_fleet(fleet, repository)
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
            # On any error, revocation failures must propagate, never be waived.
            api("DELETE", "/installation/token", token)
