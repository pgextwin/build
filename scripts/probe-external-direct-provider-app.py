#!/usr/bin/env python3
"""Exact external direct-provider App credential proof; NEVER publishes.

Reuse the hardened native Publisher probe's JWT/API primitives, but enforce an
independent App, installation, environment and one-repository scope. A single
unreferenced Git blob proves Contents write without touching refs or Releases.
"""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import re
import sys
import time
from urllib.error import HTTPError

_spec = importlib.util.spec_from_file_location(
    "existing_publisher_probe", Path(__file__).with_name("probe-publisher-app.py"))
_existing = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_existing)

APP_ID = 5609317
INSTALLATION_ID = 178510512
APP_SLUG = "pgextwin-external-direct-publisher"
TARGET_REPO = "pgextwin/catalog"
TARGET_REPO_ID = 1405939279
ENVIRONMENT = "external-direct-provider-publisher"
PERMISSIONS = {"metadata": "read", "contents": "write", "pull_requests": "write"}
SHA = re.compile(r"[0-9a-f]{40}\Z")


class Denied(ValueError):
    pass


def require(ok):
    if not ok:
        raise Denied("external App identity, source, scope or revocation DENY")


def verify(api, jwt, env, *, sleep=time.sleep):
    """All credentials are confined to this job; return only a nonsecret receipt."""
    require(env.get("GITHUB_REPOSITORY") == "pgextwin/build"
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_EVENT_NAME") == "push"
            and env.get("GITHUB_RUN_ATTEMPT") == "1")
    source_sha = env.get("GITHUB_SHA", "")
    require(isinstance(source_sha, str) and SHA.fullmatch(source_sha))
    gh_token = env.get("GITHUB_TOKEN", "")
    require(type(gh_token) is str and bool(gh_token))
    branch = api("GET", "/repos/pgextwin/build/branches/main", gh_token)
    require(type(branch) is dict and branch.get("protected") is True
            and type(branch.get("commit")) is dict
            and branch["commit"].get("sha") == source_sha)

    key = env.pop("EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY", "")
    require(type(key) is str and bool(key))
    app_jwt = jwt(key, APP_ID)
    identity = api("GET", "/app", app_jwt)
    require(type(identity) is dict and identity.get("id") == APP_ID
            and identity.get("slug") == APP_SLUG)
    installation = api("GET", "/app/installations/" + str(INSTALLATION_ID), app_jwt)
    require(type(installation) is dict
            and installation.get("id") == INSTALLATION_ID
            and installation.get("app_id") == APP_ID
            and installation.get("repository_selection") == "selected"
            and installation.get("permissions") == PERMISSIONS
            and installation.get("suspended_at") is None
            and type(installation.get("account")) is dict
            and installation["account"].get("login") == "pgextwin")

    token = None
    try:
        minted = api("POST", "/app/installations/" + str(INSTALLATION_ID)
                     + "/access_tokens", app_jwt,
                     {"repositories": ["catalog"], "permissions": PERMISSIONS})
        require(type(minted) is dict)
        token = minted.get("token")
        require(type(token) is str and len(token) > 20
                and minted.get("repository_selection") == "selected"
                and minted.get("permissions") == PERMISSIONS)
        expires = minted.get("expires_at")
        require(type(expires) is str and expires.endswith("Z"))
        expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        remain = expiry - datetime.now(timezone.utc)
        require(timedelta(seconds=60) < remain <= timedelta(hours=1))

        scoped = api("GET", "/installation/repositories?per_page=100", token)
        require(type(scoped) is dict and scoped.get("total_count") == 1
                and type(scoped.get("repositories")) is list
                and len(scoped["repositories"]) == 1)
        selected = scoped["repositories"][0]
        require(type(selected) is dict and selected.get("full_name") == TARGET_REPO
                and selected.get("id") == TARGET_REPO_ID)

        # Git object is unreferenced: no branch, tag, Release, PR or public feed.
        blob_content = b"pgextwin external-direct-provider credential-only proof; NO PUBLISH\n"
        expected = hashlib.sha1(b"blob " + str(len(blob_content)).encode()
                                + b"\0" + blob_content).hexdigest()
        import base64
        blob = api("POST", "/repos/" + TARGET_REPO + "/git/blobs", token,
                   {"content": base64.b64encode(blob_content).decode(),
                    "encoding": "base64"})
        require(type(blob) is dict and blob.get("sha") == expected)
    finally:
        if type(token) is str and token:
            # Same-token 401 is required. 403, timeout and still-working tokens
            # are never accepted as proof of revocation.
            api("DELETE", "/installation/token", token)
            revoked = False
            for delay in (0, 0.5, 1, 2):
                if delay:
                    sleep(delay)
                try:
                    api("GET", "/installation/repositories?per_page=100", token)
                except HTTPError as exc:
                    if exc.code == 401:
                        revoked = True
                        break
                    raise Denied("App token revocation verification DENY") from None
            require(revoked)
    return {
        "status": "EXTERNAL_APP_CREDENTIAL_PROOF_ONLY_NO_PUBLISH",
        "appId": APP_ID, "installationId": INSTALLATION_ID,
        "environment": ENVIRONMENT, "repository": TARGET_REPO,
        "permissions": PERMISSIONS, "sourceCommit": source_sha,
        "tokenRevokedAnd401Confirmed": True, "publicationAuthorized": False,
        "downloadAuthorized": False, "mirrorAuthorized": False,
    }


if __name__ == "__main__":
    try:
        receipt = verify(_existing.api, _existing.jwt, os.environ)
        print(json.dumps(receipt, sort_keys=True))
    except Exception:
        print("EXTERNAL_APP_CREDENTIAL_PROOF_DENY; no credentials or API error payloads emitted",
              file=sys.stderr)
        raise SystemExit(1)
