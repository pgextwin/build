#!/usr/bin/env python3
"""One-shot, nonpublishing coordinator App identity proof. No workflow dispatch."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

APP_ID = 5534389
INSTALLATION_ID = 176718417
APP_SLUG = "pgextwin-issue311-prepare-coord"
REPO = "pgextwin/build"
TARGET = "pgextwin/orafce"
REQUEST = ".github/execution-requests/r-20261030-r06coordinatoridentity001.json"
POLICY = "metadata/proposals/issue311-prepare-coordinator-app.json"
BASE_SHA = "61c07d35ac4e788500f1daf5570ebbca54ed456f"
EXPECTED_REPOS = {
    "pgextwin/" + name for name in (
        "hypopg", "orafce", "pg_bigm", "pg_cron", "pg_hint_plan", "pg_ivm",
        "pg_partman", "pg_qualstats", "pg_repack", "pg_stat_monitor",
        "pg_store_plans", "pg_variables", "pgaudit", "pgtap",
        "plpgsql_check", "set_user", "wal2json")
}
API = "https://api.github.com/"


class Deny(RuntimeError):
    pass


class HTTPFailure(Deny):
    def __init__(self, status):
        self.status = status
        super().__init__("GitHub API status " + str(status))


def require(condition, reason):
    if not condition:
        raise Deny(reason)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_json(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique_pairs)


def check_policy(policy, request):
    require(policy["schemaVersion"] == 1 and policy["runtimeEnabled"] is False,
            "coordinator runtime must remain disabled")
    require(policy["appId"] == APP_ID and policy["installationId"] == INSTALLATION_ID,
            "unapproved App or installation")
    require(policy["botUserId"] is None and policy["botLogin"] == APP_SLUG + "[bot]",
            "identity not yet authoritatively verified")
    require(set(policy["repositories"]) == EXPECTED_REPOS and
            len(policy["repositories"]) == 17, "selected17 mismatch")
    require(policy["requestedRepositoryPermissions"] == {"actions": "write", "metadata": "read"},
            "unsafe App permission")
    require(policy["privateKeyStorage"]["newSecret"] ==
            "ISSUE311_PREPARE_COORDINATOR_PRIVATE_KEY" and
            policy["privateKeyStorage"]["newEnvironment"] ==
            "issue311-prepare-coordinator", "wrong secret boundary")
    require(request == {"schemaVersion": 1,
                        "requestId": "r-20261030-r06coordinatoridentity001",
                        "mode": "AUDIT_ONLY", "publicReleaseAuthorized": False,
                        "appId": APP_ID, "installationId": INSTALLATION_ID,
                        "targetRepository": TARGET,
                        "workflowDispatchAuthorized": False,
                        "baseMainSha": BASE_SHA}, "unknown or privileged request")
    return True


def event_gate():
    require(os.environ.get("GITHUB_REPOSITORY") == REPO and
            os.environ.get("GITHUB_EVENT_NAME") == "push" and
            os.environ.get("GITHUB_REF") == "refs/heads/main" and
            os.environ.get("GITHUB_ACTOR") == "ShutenOishi" and
            os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
            "untrusted event, actor or rerun")
    event = read_json(os.environ["GITHUB_EVENT_PATH"])
    require(event.get("after") == os.environ.get("GITHUB_SHA") and
            event.get("ref") == "refs/heads/main" and
            event.get("deleted") is False and event.get("created") is False and
            event.get("repository", {}).get("full_name") == REPO,
            "nonoriginal main event")
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(sha == os.environ["GITHUB_SHA"], "checked-out HEAD mismatch")
    subprocess.run(["git", "merge-base", "--is-ancestor", BASE_SHA, sha], check=True)


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def make_jwt(key):
    require(key.startswith(("-----BEGIN RSA PRIVATE KEY-----",
                            "-----BEGIN PRIVATE KEY-----")), "missing RSA PEM key")
    now = int(time.time())
    head = b64url(b'{"alg":"RS256","typ":"JWT"}')
    body = b64url(json.dumps({"iat": now - 45, "exp": now + 480, "iss": str(APP_ID)},
                             separators=(",", ":")).encode())
    unsigned = (head + "." + body).encode()
    fd, filename = tempfile.mkstemp(prefix="issue311-coord-pem-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(key)
        signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", filename],
                                   input=unsigned, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, check=True, timeout=20).stdout
    finally:
        os.unlink(filename)
    return unsigned.decode() + "." + b64url(signature)


def api(method, path, token, body=None):
    # This proof deliberately has no workflow_dispatch, Release, Contents PUT or other target.
    allowed = (
        path == "app" or path == "app/installations/" + str(INSTALLATION_ID) or
        path == "app/installations/" + str(INSTALLATION_ID) + "/access_tokens" or
        path == "installation/repositories?per_page=100" or
        path == "installation/token" or
        path == "users/" + APP_SLUG + "%5Bbot%5D" or
        path == "repos/pgextwin/orafce/actions/workflows/issue311-fleet-local-prepare.yml"
    )
    require(allowed and ".." not in path, "endpoint outside exact read-only identity probe allowlist")
    require((method, path) in {
        ("GET", "app"), ("GET", "app/installations/" + str(INSTALLATION_ID)),
        ("POST", "app/installations/" + str(INSTALLATION_ID) + "/access_tokens"),
        ("GET", "installation/repositories?per_page=100"),
        ("DELETE", "installation/token"),
        ("GET", "users/" + APP_SLUG + "%5Bbot%5D"),
        ("GET", "repos/pgextwin/orafce/actions/workflows/issue311-fleet-local-prepare.yml")
    }, "wrong API method")
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "pgextwin-issue311-coordinator-identity"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(API + path, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            content = response.read()
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as error:
        raise HTTPFailure(error.code) from error


def revoke_401(token):
    api("DELETE", "installation/token", token)
    for attempt in range(10):
        try:
            api("GET", "installation/repositories?per_page=100", token)
        except HTTPFailure as err:
            require(err.status == 401, "revocation did not return 401")
            return True
        if attempt < 9:
            time.sleep(2)
    raise Deny("same token was not revoked in bounded window")


def probe():
    check_policy(read_json(POLICY), read_json(REQUEST))
    event_gate()
    jwt = make_jwt(os.environ.get("ISSUE311_PREPARE_COORDINATOR_PRIVATE_KEY", ""))
    app = api("GET", "app", jwt)
    require(app.get("id") == APP_ID and app.get("slug") == APP_SLUG and
            app.get("owner", {}).get("login") == "pgextwin", "real App identity mismatch")
    perms = app.get("permissions", {})
    require(perms.get("actions") == "write" and perms.get("metadata") == "read" and
            set(perms) <= {"actions", "metadata"}, "App has excess permission")
    installation = api("GET", "app/installations/" + str(INSTALLATION_ID), jwt)
    require(installation.get("id") == INSTALLATION_ID and
            installation.get("app_id") == APP_ID and
            installation.get("account", {}).get("login") == "pgextwin" and
            installation.get("repository_selection") == "selected",
            "real App installation scope mismatch")
    bot = None
    token = None
    try:
        response = api("POST", "app/installations/" + str(INSTALLATION_ID) +
                       "/access_tokens", jwt,
                       {"repositories": ["orafce"], "permissions": {"actions": "write"}})
        token = response.get("token")
        require(type(token) is str and len(token) > 30, "no App token")
        print("::add-mask::" + token, flush=True)
        bot = api("GET", "users/" + APP_SLUG + "%5Bbot%5D", token)
        require(bot.get("login") == APP_SLUG + "[bot]" and
                bot.get("type") == "Bot" and
                type(bot.get("id")) is int and bot["id"] > 0,
                "actual App bot identity mismatch")
        scope = response.get("permissions", {})
        require(scope.get("actions") == "write" and
                set(scope) <= {"actions", "metadata"}, "overbroad installation token")
        repos = api("GET", "installation/repositories?per_page=100", token)
        selected = repos.get("repositories", [])
        require(repos.get("total_count") == 1 and len(selected) == 1 and
                selected[0].get("full_name") == TARGET,
                "per-token repository count not exactly one")
        workflow = api("GET",
                       "repos/pgextwin/orafce/actions/workflows/issue311-fleet-local-prepare.yml",
                       token)
        require(workflow.get("path") == ".github/workflows/issue311-fleet-local-prepare.yml",
                "unexpected local workflow identity")
    finally:
        if token:
            revoke_401(token)
    receipt = {
        "schemaVersion": 1, "mode": "AUDIT_ONLY",
        "publicReleaseAuthorized": False, "runtimeEnabled": False,
        "workflowDispatches": 0, "appId": APP_ID,
        "installationId": INSTALLATION_ID, "botLogin": bot["login"],
        "botUserId": bot["id"], "target": TARGET,
        "scopedRepositoryCount": 1, "scopedPermissions": ["actions:write", "metadata:read"],
        "sameTokenRevoked401": True, "runId": int(os.environ["GITHUB_RUN_ID"]),
        "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "githubSha": os.environ["GITHUB_SHA"],
        "requestSha256": hashlib.sha256(Path(REQUEST).read_bytes()).hexdigest(),
    }
    Path("issue311-coordinator-identity-original.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("ISSUE311_COORDINATOR_ACTUAL_BOT_IDENTITY_ORIGINAL", json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--check-policy"]:
        check_policy(read_json(POLICY), read_json(REQUEST))
        print("ISSUE311_COORDINATOR_INERT_POLICY_PASS")
    elif sys.argv[1:] == ["--probe"]:
        probe()
    else:
        raise SystemExit("usage: --check-policy | --probe")
