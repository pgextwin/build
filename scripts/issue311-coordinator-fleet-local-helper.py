#!/usr/bin/env python3
"""R06-06 reusable App PREPARE GET/POST/ZIP helper, original pilot policy adapted to exact per-repo scope."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

spec = importlib.util.spec_from_file_location(
    "coordinator_identity", "scripts/issue311-coordinator-identity.py")
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)
REPO = "pgextwin/orafce"
WORKFLOW = "issue311-request-local-prepare.yml"
TARGET_WORK = "repos/" + REPO + "/actions/workflows/" + WORKFLOW
RUNS = TARGET_WORK + "/runs?event=workflow_dispatch&per_page=50"
POST = TARGET_WORK + "/dispatches"
REQUEST_ID = "r-20261030-r06coordlocalpilotlaunch001"
LOCAL_REQUEST_ID = "r-20261030-r06coordlocalpilot01"
REQUEST_PATH = ".github/execution-requests/" + REQUEST_ID + ".json"
RECEIPT = "issue311-coordinator-local-prepare-original.json"
SOURCE_WORKFLOW = "Issue 311 R06 PREPARE original fleet scan (NONPUBLISHING)"
SOURCE_PATH = ".github/workflows/issue311-r06-prepare-scan.yml"
ARTIFACT = "issue311-app-local-prepare-original-receipt"
RECEIPT_IN_ZIP = "issue311-app-local-prepare-receipt.json"
BOT = "pgextwin-issue311-prepare-coord[bot]"
BOT_ID = 350058024
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")

class Denied(identity.Deny):
    pass

def need(x, why):
    if not x:
        raise Denied("R06_COORD_LOCAL_DENY " + why)

def strict(raw):
    return json.loads(raw, object_pairs_hook=identity.unique_pairs)

def check_request(value):
    need(type(value) is dict and set(value) == {
        "schemaVersion", "requestId", "localRequestId", "mode",
        "sourceRunId", "sourceHeadSha", "sourceArtifactId",
        "sourceZipSha256", "centralRequestId", "localMainSha",
        "target", "workflow", "appId", "installationId",
        "botUserId", "runtimeEnabled", "publicReleaseAuthorized",
        "expiresAt", "baseMainSha"}, "invalid request schema")
    need(value["schemaVersion"] == 1 and value["requestId"] == REQUEST_ID
         and value["localRequestId"] == LOCAL_REQUEST_ID
         and value["mode"] == "PREPARE" and value["target"] == REPO
         and value["workflow"] == WORKFLOW, "unapproved source-kind/workflow")
    need(value["appId"] == 5534389 and value["installationId"] == 176718417
         and value["botUserId"] == BOT_ID and value["runtimeEnabled"] is False
         and value["publicReleaseAuthorized"] is False, "wrong App scope or privilege")
    need(type(value["sourceRunId"]) is int and value["sourceRunId"] > 0
         and type(value["sourceArtifactId"]) is int and value["sourceArtifactId"] > 0
         and SHA40.fullmatch(value["sourceHeadSha"]) is not None
         and SHA40.fullmatch(value["localMainSha"]) is not None
         and SHA40.fullmatch(value["baseMainSha"]) is not None
         and SHA64.fullmatch(value["sourceZipSha256"]) is not None
         and re.fullmatch(r"r-20261030-r06prepare[a-z0-9-]{4,40}",
                          value["centralRequestId"]) is not None,
         "source Run/source ZIP/target SHA invalid")
    until = datetime.fromisoformat(value["expiresAt"].replace("Z", "+00:00"))
    need(until.utcoffset() == timedelta(0)
         and datetime.now(timezone.utc) < until
         and until < datetime.now(timezone.utc) + timedelta(hours=8),
         "expired/unbounded pilot request")
    identity.check_policy(identity.read_json(identity.POLICY),
                          identity.read_json(identity.REQUEST))
    return True

def event_check():
    identity.event_gate()
    evt = identity.read_json(os.environ["GITHUB_EVENT_PATH"])
    raw = subprocess.check_output(["git", "show", "HEAD:" + REQUEST_PATH])
    request = strict(raw)
    check_request(request)
    need(evt.get("before") == request["baseMainSha"]
         and evt.get("sender", {}).get("login") == "ShutenOishi",
         "not protected original human request merge")
    changes = subprocess.check_output(
        ["git", "diff", "--name-status", evt["before"], os.environ["GITHUB_SHA"]],
        text=True).splitlines()
    need(changes == ["A\t" + REQUEST_PATH],
         "privileged or unrelated change in launch commit")
    return request, hashlib.sha256(raw).hexdigest()

def api(method, endpoint, token, payload=None):
    allowed = {("GET", TARGET_WORK), ("GET", RUNS), ("POST", POST)}
    need((method, endpoint) in allowed, "forbidden App operation")
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pgextwin-issue311-local-prepare-only"}
    if data:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request("https://api.github.com/" + endpoint,
                                     data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            raw = response.read()
            return response.status, strict(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raise identity.HTTPFailure(exc.code) from exc

def readonly_json(path):
    need(path.startswith("repos/pgextwin/build/actions/runs/")
         or path == "repos/" + REPO + "/branches/main",
         "unsafe pre-dispatch GET")
    token = os.environ.get("GH_TOKEN", "")
    need(bool(token), "missing read-only GITHUB_TOKEN")
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(request, timeout=25) as response:
        return strict(response.read())

def check_source(r):
    run = readonly_json("repos/pgextwin/build/actions/runs/" + str(r["sourceRunId"]))
    need(run.get("name") == SOURCE_WORKFLOW and run.get("path") == SOURCE_PATH
         and run.get("id") == r["sourceRunId"]
         and run.get("head_sha") == r["sourceHeadSha"]
         and run.get("event") == "push" and run.get("head_branch") == "main"
         and run.get("actor", {}).get("login") == "ShutenOishi"
         and run.get("status") == "completed" and run.get("conclusion") == "success"
         and run.get("run_attempt") == 1, "unaccepted central source Run")
    artifacts = readonly_json("repos/pgextwin/build/actions/runs/" +
                              str(r["sourceRunId"]) + "/artifacts?per_page=100")
    found = [a for a in artifacts.get("artifacts", [])
             if a.get("id") == r["sourceArtifactId"]]
    need(len(found) == 1 and found[0].get("expired") is False
         and found[0].get("name") == "issue311-r06-prepare-original-scan"
         and found[0].get("digest") == "sha256:" + r["sourceZipSha256"],
         "not exact original PREPARE ZIP")
    branch = readonly_json("repos/" + REPO + "/branches/main")
    need(branch.get("protected") is True
         and branch.get("commit", {}).get("sha") == r["localMainSha"],
         "drifted or unprotected local main")
    return True

def candidates(token, seen, workflow_id, sha):
    code, data = api("GET", RUNS, token)
    need(code == 200, "missing original App workflow runs")
    return [x for x in data.get("workflow_runs", [])
            if x.get("id") not in seen and x.get("workflow_id") == workflow_id
            and x.get("event") == "workflow_dispatch"
            and x.get("head_sha") == sha
            and x.get("actor", {}).get("login") == BOT
            and x.get("actor", {}).get("id") == BOT_ID
            and x.get("run_attempt") == 1]

class SafeArchiveRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward installation credentials to GitHub's artifact storage CDN."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and not newurl.startswith("https://api.github.com/"):
            redirected.remove_header("Authorization")
        return redirected

def verify_original_child_archive(token, child, source):
    run_id = child["id"]
    get = lambda path: get_app_json(token, path)
    jobs = get("repos/" + REPO + "/actions/runs/" + str(run_id) +
               "/jobs?per_page=100")
    names = {row.get("name"): row.get("conclusion") for row in jobs.get("jobs", [])}
    need(jobs.get("total_count") == len(jobs.get("jobs", [])) == 2
         and names.get("Original protected PREPARE ZIP verification (NO RELEASE)") == "success"
         and names.get("Strict App identity and PREPARE source-kind denial tests") == "skipped",
         "unaccepted original child jobs")
    listing = get("repos/" + REPO + "/actions/runs/" + str(run_id) +
                  "/artifacts?per_page=100")
    entries = listing.get("artifacts", [])
    need(listing.get("total_count") == len(entries) == 1
         and entries[0].get("name") == ARTIFACT
         and entries[0].get("expired") is False
         and entries[0].get("workflow_run", {}).get("id") == run_id,
         "missing/extra child receipt artifacts")
    artifact = entries[0]
    endpoint = "https://api.github.com/repos/" + REPO + "/actions/artifacts/" + str(artifact["id"]) + "/zip"
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    opener = urllib.request.build_opener(SafeArchiveRedirect)
    with opener.open(urllib.request.Request(endpoint, headers=headers), timeout=45) as response:
        raw_zip = response.read(10 * 1024 * 1024 + 1)
    need(len(raw_zip) <= 10 * 1024 * 1024, "oversized local original ZIP")
    digest = hashlib.sha256(raw_zip).hexdigest()
    need(artifact.get("digest") == "sha256:" + digest,
         "local original ZIP byte digest mismatch")
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as archive:
        need(archive.namelist() == [RECEIPT_IN_ZIP], "wrong child ZIP members")
        original = strict(archive.read(RECEIPT_IN_ZIP))
    need(original.get("result") in ("NO_UPDATE", "UPDATE_PRESENT_NOT_AUTHORIZED")
         and original.get("schemaVersion") == 1
         and original.get("sourceKind") ==
             "APP_BOT_AUTHENTICATED_ORIGINAL_PREPARE_LOCAL_READONLY_V1"
         and original.get("requestId") == LOCAL_REQUEST_ID
         and original.get("actualBotLogin") == BOT
         and original.get("actualBotUserId") == BOT_ID
         and original.get("localOriginalEvent") == "workflow_dispatch"
         and original.get("localRunId") == run_id
         and original.get("localRunAttempt") == 1
         and original.get("localProtectedMainSha") == source["localMainSha"]
         and original.get("centralSourceRunId") == source["sourceRunId"]
         and original.get("centralSourceHeadSha") == source["sourceHeadSha"]
         and original.get("centralSourceArtifactId") == source["sourceArtifactId"]
         and original.get("centralSourceRequestId") == source["centralRequestId"]
         and original.get("centralOriginalOuterZipSha256Verified") ==
             source["sourceZipSha256"]
         and original.get("publicationAuthorized") is False
         and original.get("candidateAdmissionAuthorized") is False
         and original.get("publisherSourceKindAuthorized") is False
         and original.get("runtimeEnabled") is False
         and original.get("publicReleaseAuthorized") is False,
         "unaccepted real App local source-kind receipt")
    return digest, original["result"], artifact["id"]

def get_app_json(token, path):
    need(path.startswith("repos/" + REPO + "/actions/runs/")
         and (path.endswith("/jobs?per_page=100") or
              path.endswith("/artifacts?per_page=100")),
         "unapproved child GET")
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(request, timeout=25) as response:
        return strict(response.read())

def pilot():
    terminal = {"schemaVersion": 1, "requestId": REQUEST_ID,
                "mode": "PREPARE", "runtimeEnabled": False,
                "publicReleaseAuthorized": False,
                "publicationAuthorized": False,
                "candidateAdmissionAuthorized": False,
                "publisherSourceKindAuthorized": False,
                "dispatchCount": 0, "result": "QUARANTINED",
                "durableCasVerified": False}
    token = None
    try:
        r, raw_sha = event_check()
        check_source(r)
        terminal["requestSha256"] = raw_sha
        jwt = identity.make_jwt(os.environ.get(
            "ISSUE311_PREPARE_COORDINATOR_PRIVATE_KEY", ""))
        app = identity.api("GET", "app", jwt)
        need(app.get("id") == 5534389
             and app.get("slug") == "pgextwin-issue311-prepare-coord", "wrong App identity")
        issued = identity.api("POST", "app/installations/176718417/access_tokens",
                              jwt, {"repositories": ["orafce"],
                                    "permissions": {"actions": "write"}})
        token = issued.get("token")
        need(type(token) is str and len(token) > 30, "scoped App token missing")
        print("::add-mask::" + token, flush=True)
        scope = identity.api("GET", "installation/repositories?per_page=100", token)
        need(scope.get("total_count") == 1
             and [e.get("full_name") for e in scope.get("repositories", [])] == [REPO],
             "token not exactly one repo")
        need(issued.get("permissions", {}).get("actions") == "write"
             and set(issued.get("permissions", {})) <= {"actions", "metadata"},
             "excess permissions")
        _, wf = api("GET", TARGET_WORK, token)
        need(wf.get("state") == "active"
             and wf.get("path") == ".github/workflows/" + WORKFLOW,
             "uninstalled local PREPARE workflow")
        _, prior = api("GET", RUNS, token)
        seen = {x.get("id") for x in prior.get("workflow_runs", [])}
        inputs = {
            "request_id": LOCAL_REQUEST_ID,
            "source_run_id": str(r["sourceRunId"]),
            "source_head_sha": r["sourceHeadSha"],
            "source_artifact_id": str(r["sourceArtifactId"]),
            "source_zip_sha256": r["sourceZipSha256"],
            "central_request_id": r["centralRequestId"],
            "local_main_sha": r["localMainSha"]
        }
        # Exactly one POST; ambiguous HTTP/network response is never retried.
        terminal["dispatchCount"] = 1
        try:
            status, _ = api("POST", POST, token, {"ref": "main", "inputs": inputs})
            need(status in (200, 201, 204), "non-success dispatch response")
            terminal["dispatchHttpStatus"] = status
        except (identity.HTTPFailure, urllib.error.URLError, TimeoutError) as exc:
            terminal["dispatchErrorClass"] = type(exc).__name__
        found = []
        for _ in range(45):
            found = candidates(token, seen, wf["id"], r["localMainSha"])
            if len(found) == 1 and found[0].get("status") == "completed":
                break
            if len(found) > 1:
                break
            time.sleep(12)
        need(len(found) == 1 and found[0].get("status") == "completed"
             and found[0].get("conclusion") == "success",
             "ambiguous, failed or timed out local original App run")
        child = found[0]
        terminal.update({"localRunId": child["id"], "localRunAttempt": 1,
                         "localActor": BOT, "localActorUserId": BOT_ID,
                         "sourceRunId": r["sourceRunId"],
                         "sourceArtifactId": r["sourceArtifactId"],
                         "sourceZipSha256": r["sourceZipSha256"],
                         "originalLocalMainSha": r["localMainSha"]})
        digest, result, artifact_id = verify_original_child_archive(token, child, r)
        terminal.update({"result": result, "localOriginalArtifactId": artifact_id,
                         "localOriginalOuterZipSha256Verified": digest,
                         "receiptIndependentlyVerified": True})
    except Exception as exc:
        terminal["reason"] = str(exc)[:400]
    finally:
        if token:
            try:
                identity.revoke_401(token)
                terminal["sameTokenRevoked401"] = True
            except Exception as exc:
                terminal["result"] = "QUARANTINED"
                terminal["revokeFailure"] = type(exc).__name__
        Path(RECEIPT).write_text(
            json.dumps(terminal, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print("ISSUE311_COORD_APP_PREPARE_TERMINAL", json.dumps(terminal, sort_keys=True))
    return 0 if terminal["result"] in ("NO_UPDATE", "UPDATE_PRESENT_NOT_AUTHORIZED") and terminal.get("sameTokenRevoked401") is True else 1

if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--check"]:
        print("ISSUE311_COORD_LOCAL_PREPARE_POLICY_CODE_PRESENT")
    elif sys.argv[1:] == ["--pilot"]:
        raise SystemExit(pilot())
    else:
        raise SystemExit(2)
