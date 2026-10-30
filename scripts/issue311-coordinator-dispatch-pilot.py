#!/usr/bin/env python3
"""R06-06 one-shot real App-bot dispatch of read-only orafce actor pilot."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request

SCRIPT = Path("scripts/issue311-coordinator-identity.py")
spec = importlib.util.spec_from_file_location("issue311_coord_identity", SCRIPT)
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)

TARGET = "pgextwin/orafce"
WORKFLOW = "issue311-coordinator-actor-pilot.yml"
REQUEST_ID = "r-20261030-r06coordactorlaunch001"
ACTOR_REQUEST_ID = "r-20261030-r06coordactorpilot01"
REQUEST = ".github/execution-requests/" + REQUEST_ID + ".json"
BASE_SHA = "4c702df72ca5b9bd7df5411aa9260920518b62f1"
RUNS = "repos/pgextwin/orafce/actions/workflows/" + WORKFLOW + "/runs?event=workflow_dispatch&per_page=30"
WORK = "repos/pgextwin/orafce/actions/workflows/" + WORKFLOW
DISPATCH = WORK + "/dispatches"
BOT = "pgextwin-issue311-prepare-coord[bot]"
BOT_ID = 350058024


class Denied(identity.Deny):
    pass


def require(condition, reason):
    if not condition:
        raise Denied(reason)


def check_request(request, policy):
    require(set(request) == {"schemaVersion", "requestId", "mode", "appId",
                           "installationId", "botUserId", "target",
                           "workflow", "workflowRef", "localMainSha",
                           "actorRequestId", "publicReleaseAuthorized",
                           "runtimeEnabled", "allowSinglePilotDispatch", "baseMainSha"},
            "unrecognized request keys")
    require(request["schemaVersion"] == 1 and request["requestId"] == REQUEST_ID and
            request["mode"] == "AUDIT_ONLY" and request["appId"] == 5534389 and
            request["installationId"] == 176718417 and request["botUserId"] == BOT_ID,
            "unapproved App request")
    require(request["target"] == TARGET and request["workflow"] == WORKFLOW and
            request["workflowRef"] == "main" and request["actorRequestId"] == ACTOR_REQUEST_ID and
            request["baseMainSha"] == BASE_SHA, "unapproved dispatch path")
    require(type(request["localMainSha"]) is str and
            identity.SHA1.fullmatch(request["localMainSha"]) if hasattr(identity, "SHA1")
            else isinstance(request["localMainSha"], str) and
            len(request["localMainSha"]) == 40 and
            all(x in "0123456789abcdef" for x in request["localMainSha"]),
            "invalid pinned local protected main")
    require(request["runtimeEnabled"] is False and
            request["publicReleaseAuthorized"] is False and
            request["allowSinglePilotDispatch"] is True,
            "publication or full runtime cannot be enabled")
    identity.check_policy(policy, identity.read_json(identity.REQUEST))
    require(policy["runtimeEnabled"] is False and policy["botUserId"] == BOT_ID,
            "actual bot identity pin not present")
    return True


def rest(method, endpoint, token, payload=None):
    require((method, endpoint) in {("GET", WORK), ("GET", RUNS), ("POST", DISPATCH)},
            "forbidden endpoint, action or method")
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "pgextwin-issue311-one-shot-actor-pilot"}
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request("https://api.github.com/" + endpoint,
                                 method=method, headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            content = response.read()
            return response.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as err:
        raise identity.HTTPFailure(err.code) from err


def candidates(token, existed, workflow_id, sha):
    status, listing = rest("GET", RUNS, token)
    require(status == 200, "invalid original workflow run list")
    return [x for x in listing.get("workflow_runs", [])
            if x.get("id") not in existed and x.get("workflow_id") == workflow_id and
            x.get("event") == "workflow_dispatch" and x.get("head_sha") == sha and
            x.get("actor", {}).get("login") == BOT and
            x.get("actor", {}).get("id") == BOT_ID and
            x.get("run_attempt") == 1]


def pilot():
    request = identity.read_json(REQUEST)
    policy = identity.read_json(identity.POLICY)
    check_request(request, policy)
    identity.event_gate()  # protected original main, expected human actor, attempt 1
    key = os.environ.get("ISSUE311_PREPARE_COORDINATOR_PRIVATE_KEY", "")
    jwt = identity.make_jwt(key)
    app = identity.api("GET", "app", jwt)
    require(app.get("id") == 5534389 and
            app.get("slug") == "pgextwin-issue311-prepare-coord", "wrong actual App")
    installation = identity.api("GET", "app/installations/176718417", jwt)
    require(installation.get("app_id") == 5534389 and
            installation.get("repository_selection") == "selected" and
            installation.get("account", {}).get("login") == "pgextwin",
            "wrong selected installation")
    result = identity.api("POST", "app/installations/176718417/access_tokens",
                          jwt, {"repositories": ["orafce"],
                                "permissions": {"actions": "write"}})
    token = result.get("token")
    require(type(token) is str and len(token) > 30, "missing scoped token")
    print("::add-mask::" + token, flush=True)
    proof = None
    try:
        require(result.get("permissions", {}).get("actions") == "write" and
                set(result.get("permissions", {})) <= {"actions", "metadata"},
                "overbroad credential")
        repos = identity.api("GET", "installation/repositories?per_page=100", token)
        require(repos.get("total_count") == 1 and
                [x.get("full_name") for x in repos.get("repositories", [])] == [TARGET],
                "token repository restriction failed")
        user = identity.api("GET", "users/pgextwin-issue311-prepare-coord%5Bbot%5D", token)
        require(user.get("id") == BOT_ID and user.get("login") == BOT,
                "real App bot changed")
        status, wf = rest("GET", WORK, token)
        require(status == 200 and
                wf.get("path") == ".github/workflows/" + WORKFLOW and
                wf.get("state") == "active" and type(wf.get("id")) is int,
                "pilot workflow not present or active")
        _, before = rest("GET", RUNS, token)
        existed = {x.get("id") for x in before.get("workflow_runs", [])}
        # Exactly ONE nonpublishing POST. A network-ambiguous result is NOT retried.
        post_error = None
        try:
            status, response = rest("POST", DISPATCH, token,
                                    {"ref": "main", "inputs": {"request_id": ACTOR_REQUEST_ID}})
            require(status in (200, 201, 204), "unexpected dispatch response")
        except (identity.HTTPFailure, urllib.error.URLError, TimeoutError) as exc:
            post_error = type(exc).__name__
            status = None
        match = []
        for attempt in range(18):
            match = candidates(token, existed, wf["id"], request["localMainSha"])
            if match:
                break
            if attempt < 17:
                time.sleep(4)
        require(len(match) == 1, "QUARANTINED: ambiguous or missing original App event")
        source = match[0]
        proof = {"schemaVersion": 1, "requestId": REQUEST_ID, "mode": "AUDIT_ONLY",
                 "appId": 5534389, "installationId": 176718417,
                 "botLogin": BOT, "botUserId": BOT_ID,
                 "scopedTarget": TARGET, "scopedRepositoryCount": 1,
                 "workflow": WORKFLOW, "workflowId": wf["id"],
                 "localMainSha": request["localMainSha"],
                 "originalRunId": source["id"], "originalRunAttempt": 1,
                 "originalActor": source["actor"]["login"],
                 "dispatchPostStatus": status, "dispatchPostError": post_error,
                 "dispatches": 1, "runtimeEnabled": False, "publicReleaseAuthorized": False,
                 "localPrepareExecutedByCentral": False,
                 "requestSha256": hashlib.sha256(Path(REQUEST).read_bytes()).hexdigest()}
    finally:
        identity.revoke_401(token)  # SAME live token 401; must succeed even on failed POST
    require(proof is not None, "missing App dispatch receipt")
    proof["sameTokenRevoked401"] = True
    proof["sourceMainSha"] = os.environ["GITHUB_SHA"]
    proof["sourceRunId"] = int(os.environ["GITHUB_RUN_ID"])
    Path("issue311-coordinator-actor-launch-original.json").write_text(
        json.dumps(proof, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("ISSUE311_COORDINATOR_REAL_APP_DISPATCH_ORIGINAL", json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--check"]:
        check_request(identity.read_json(REQUEST), identity.read_json(identity.POLICY))
        print("ISSUE311_DISPATCH_PILOT_POLICY_PASS")
    elif sys.argv[1:] == ["--pilot"]:
        pilot()
    else:
        raise SystemExit("use --check or --pilot")
