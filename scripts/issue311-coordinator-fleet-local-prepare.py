#!/usr/bin/env python3
"""R06-06: one authentic central PREPARE completion -> 17 scoped App-bot local originals.

Nonpublishing. No candidate, tag, signature, Release, Catalog or user-token
reuse. Exactly one POST per local target; ambiguous outcomes are quarantined.
Durable CAS is a separate required acceptance gate, never implied here.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
REQUEST_ID = "r-20261030-r06preparecoordfleet02"
REQUEST_PATH = ".github/execution-requests/" + REQUEST_ID + ".json"
SOURCE_NAME = "Issue 311 R06 PREPARE original fleet scan (NONPUBLISHING)"
SOURCE_PATH = ".github/workflows/issue311-r06-prepare-scan.yml"
LISTENER = "Issue 311 17 authentic App-bot local PREPARE originals (NO RELEASE)"
OUT = "issue311-r06-app-fleet-original-terminal.json"
WORKFLOW = "issue311-request-local-prepare.yml"
BOT = "pgextwin-issue311-prepare-coord[bot]"
BOT_ID = 350058024
SHA40 = re.compile(r"^[0-9a-f]{40}$")
LOCAL_IDS = {
    "pg_bigm": "r-20261030-r06coordlocalpgbigm01",
    "pg_cron": "r-20261030-r06coordlocalpgcron01",
    "pg_hint_plan": "r-20261030-r06coordlocalpghintplan01",
    "pgaudit": "r-20261030-r06coordlocalpgaudit01",
    "set_user": "r-20261030-r06coordlocalsetuser01",
    "pg_repack": "r-20261030-r06coordlocalpgrepack01",
    "pg_ivm": "r-20261030-r06coordlocalpgivm01",
    "pg_qualstats": "r-20261030-r06coordlocalpgqualstats01",
    "plpgsql_check": "r-20261030-r06coordlocalplpgsqlcheck01",
    "orafce": "r-20261030-r06coordlocalpilot01",
    "hypopg": "r-20261030-r06coordlocalhypopg01",
    "wal2json": "r-20261030-r06coordlocalwal2json01",
    "pg_partman": "r-20261030-r06coordlocalpgpartman01",
    "pg_stat_monitor": "r-20261030-r06coordlocalpgstatmonitor01",
    "pgtap": "r-20261030-r06coordlocalpgtap01",
    "pg_variables": "r-20261030-r06coordlocalpgvariables01",
    "pg_store_plans": "r-20261030-r06coordlocalpgstoreplans01",
}

def load(key, path):
    spec = importlib.util.spec_from_file_location(key, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

identity = load("r06_coord_fleet_identity", "scripts/issue311-coordinator-identity.py")
prepare = load("r06_coord_fleet_prepare", "scripts/issue311-r06-prepare-scan.py")
bridge = prepare.bridge
store = prepare.store
contract = prepare.contract

def need(condition, why):
    if not condition:
        raise ValueError("R06_APP_FLEET_DENY " + why)

def strict(raw):
    return json.loads(raw, object_pairs_hook=identity.unique_pairs)

def utc(ts):
    value = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    need(value.utcoffset() == timedelta(0), "timestamp not UTC")
    return value

def source_original():
    need(os.environ.get("GITHUB_REPOSITORY") == "pgextwin/build"
         and os.environ.get("GITHUB_EVENT_NAME") == "workflow_run"
         and os.environ.get("GITHUB_REF") == "refs/heads/main"
         and os.environ.get("GITHUB_WORKFLOW") == LISTENER
         and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
         "unexpected workflow event/runner/attempt")
    event = strict(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    run = event.get("workflow_run", {})
    need(event.get("action") == "completed"
         and event.get("repository", {}).get("full_name") == "pgextwin/build"
         and run.get("name") == SOURCE_NAME
         and run.get("path") == SOURCE_PATH
         and run.get("event") == "push"
         and run.get("head_branch") == "main"
         and run.get("run_attempt") == 1
         and run.get("status") == "completed"
         and run.get("conclusion") == "success"
         and run.get("actor", {}).get("login") == "ShutenOishi"
         and type(run.get("id")) is int
         and SHA40.fullmatch(run.get("head_sha", "")),
         "untrusted original scan completion")
    rid = run["id"]
    remote = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(rid))
    for key in ("id", "name", "path", "event", "head_branch", "head_sha",
                "run_attempt", "status", "conclusion"):
        need(remote.get(key) == run.get(key), "Run origin disagreement: " + key)
    need(remote.get("actor", {}).get("login") == "ShutenOishi"
         and datetime.now(timezone.utc) - utc(remote["created_at"]) < timedelta(hours=12),
         "source not recent authorized human push")
    branch = bridge.get_json("repos/pgextwin/build/branches/main")
    need(branch.get("protected") is True
         and branch.get("commit", {}).get("sha") == run["head_sha"],
         "current protected central main drift")
    commit = bridge.get_json("repos/pgextwin/build/commits/" + run["head_sha"])
    need(len(commit.get("parents", [])) == 1, "unexpected request commit parents")
    before = commit["parents"][0]["sha"]
    need(SHA40.fullmatch(before) is not None, "invalid parent SHA")
    record = bridge.get_json("repos/pgextwin/build/contents/" + REQUEST_PATH
                             + "?ref=" + run["head_sha"])
    need(record.get("encoding") == "base64", "source request missing")
    raw = base64.b64decode(record["content"].replace("\n", "").replace("\r", ""), validate=True)
    need(store.blob_hash(raw) == record.get("sha"), "Git blob bytes altered")
    declaration = contract.validate_declaration(raw, REQUEST_PATH)
    request = strict(raw)
    targets = {x["repo"]: x["mainSha"] for x in request["targets"]}
    need(request["requestId"] == REQUEST_ID and declaration["mode"] == "PREPARE"
         and request["source"]["centralMainSha"] == before
         and request["source"]["fleetRegistryBlobSha"] == prepare.FLEET_BLOB
         and set(targets) == set(prepare.win.TARGETS)
         and len(targets) == len(request["targets"]) == len(LOCAL_IDS) == 17
         and request["allowFutureUpdates"] is False
         and request["approval"]["publicReleaseAuthorized"] is False
         and request["approval"]["publicationGrants"] == []
         and request["limits"]["maxParallel"] <= 4
         and request["limits"]["maxAttemptsPerStage"] == 1,
         "not exact 17 source or published source-kind")
    changes = bridge.get_json("repos/pgextwin/build/compare/" + before + "..." + run["head_sha"])
    need([x.get("filename") for x in changes.get("files", [])] == [REQUEST_PATH]
         and changes["files"][0].get("status") == "added",
         "central request is not the only added file")
    jobs = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(rid)
                           + "/jobs?per_page=100")
    need(jobs.get("total_count") == len(jobs.get("jobs", [])) == 1
         and jobs["jobs"][0].get("name") ==
              "Scan immutable one-shot 17 protected upstreams, no candidate"
         and jobs["jobs"][0].get("conclusion") == "success",
         "original source job failed")
    listing = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(rid)
                              + "/artifacts?per_page=100")
    items = listing.get("artifacts", [])
    need(listing.get("total_count") == len(items) == 1
         and items[0].get("expired") is False
         and items[0].get("name") == prepare.ARTIFACT,
         "ambiguous source archive")
    report, source_digest = bridge.original_zip(items[0], prepare.RECEIPT)
    need(items[0].get("digest") == "sha256:" + source_digest
         and report.get("requestId") == REQUEST_ID
         and report.get("requestSha256") == declaration["rawSha256"]
         and report.get("sourceRunId") == rid
         and report.get("sourceHeadSha") == run["head_sha"]
         and report.get("sourceRunAttempt") == 1
         and report.get("sourceEvent") == "push"
         and report.get("result") == "SCANNED"
         and report.get("fleetSize") == 17
         and report.get("publicationAuthorized") is False
         and report.get("targetMainSha") == targets,
         "original central ZIP bytes/source do not match")
    rows = prepare.inspect_report(report.get("report"), targets)
    need(report.get("perTargetStatus") == {r: x["status"] for r, x in rows.items()},
         "17 original statuses do not match")
    # This happens BEFORE any scoped App token is minted.
    for repo, sha in sorted(targets.items()):
        live = prepare.win.old.get_json(
            "https://api.github.com/repos/" + repo + "/branches/main",
            os.environ["GH_TOKEN"])
        need(live.get("name") == "main" and live.get("protected") is True
             and live.get("commit", {}).get("sha") == sha,
             "local main not exact/protected: " + repo)
    return {"sourceRunId": rid, "sourceHeadSha": run["head_sha"],
            "sourceArtifactId": items[0]["id"], "sourceZipSha256": source_digest,
            "centralRequestId": REQUEST_ID, "targets": targets,
            "perTargetStatus": report["perTargetStatus"],
            "requestRawSha256": declaration["rawSha256"]}

def worker(name, source, jwt):
    repo = "pgextwin/" + name
    result = {"repository": repo, "result": "QUARANTINED",
              "dispatchCount": 0, "publicationAuthorized": False}
    # Distinct module globals prevent cross-target mutation under four workers.
    m = load("r06_fleet_helper_" + name, "scripts/issue311-coordinator-fleet-local-helper.py")
    m.REPO = repo
    m.LOCAL_REQUEST_ID = LOCAL_IDS[name]
    m.TARGET_WORK = "repos/" + repo + "/actions/workflows/" + WORKFLOW
    m.RUNS = m.TARGET_WORK + "/runs?event=workflow_dispatch&per_page=50"
    m.POST = m.TARGET_WORK + "/dispatches"
    token = None
    try:
        r = {k: source[k] for k in ("sourceRunId", "sourceHeadSha",
             "sourceArtifactId", "sourceZipSha256", "centralRequestId")}
        r["localMainSha"] = source["targets"][repo]
        m.check_source(r)
        minted = identity.api("POST", "app/installations/176718417/access_tokens",
                              jwt, {"repositories": [name],
                                    "permissions": {"actions": "write"}})
        token = minted.get("token")
        need(type(token) is str and len(token) > 30, "missing one-repo App token")
        print("::add-mask::" + token, flush=True)
        need(minted.get("permissions", {}).get("actions") == "write"
             and set(minted.get("permissions", {})) <= {"actions", "metadata"},
             "excess scope")
        scope = identity.api("GET", "installation/repositories?per_page=100", token)
        need(scope.get("total_count") == 1
             and [x.get("full_name") for x in scope.get("repositories", [])] == [repo],
             "scoped App token reached unexpected repo")
        code, wf = m.api("GET", m.TARGET_WORK, token)
        need(code == 200 and wf.get("state") == "active"
             and wf.get("path") == ".github/workflows/" + WORKFLOW,
             "missing local bot-only PREPARE")
        _, prior = m.api("GET", m.RUNS, token)
        baseline = {x.get("id") for x in prior.get("workflow_runs", [])}
        inputs = {
            "request_id": LOCAL_IDS[name], "source_run_id": str(r["sourceRunId"]),
            "source_head_sha": r["sourceHeadSha"],
            "source_artifact_id": str(r["sourceArtifactId"]),
            "source_zip_sha256": r["sourceZipSha256"],
            "central_request_id": REQUEST_ID, "local_main_sha": r["localMainSha"]}
        # One POST maximum. Timeout/ambiguous HTTP must not trigger another POST.
        result["dispatchCount"] = 1
        try:
            status, _ = m.api("POST", m.POST, token, {"ref": "main", "inputs": inputs})
            result["dispatchHttpStatus"] = status
            need(status in (200, 201, 204), "failed App dispatch")
        except (identity.HTTPFailure, Exception) as exc:
            result["dispatchErrorClass"] = type(exc).__name__
        child = None
        for _ in range(70):
            found = m.candidates(token, baseline, wf["id"], r["localMainSha"])
            need(len(found) <= 1, "ambiguous multiple App originals")
            if len(found) == 1 and found[0].get("status") == "completed":
                child = found[0]
                break
            time.sleep(10)
        need(child is not None and child.get("conclusion") == "success",
             "child original failure, skipped, absent or bounded timeout")
        result.update(localRunId=child["id"], localAttempt=1,
                      appBotUserId=BOT_ID, appBotLogin=BOT)
        digest, kind, aid = m.verify_original_child_archive(token, child, r)
        need(kind in ("NO_UPDATE", "UPDATE_PRESENT_NOT_AUTHORIZED"),
             "invalid original source-kind")
        result.update(result=kind, originalReceiptArtifactId=aid,
                      originalReceiptZipSha256Verified=digest,
                      sourceOriginalZipSha256Verified=r["sourceZipSha256"],
                      originalReceiptIndependentlyVerified=True)
    except Exception as exc:
        result["reason"] = str(exc)[:370]
    finally:
        if token:
            try:
                identity.revoke_401(token)
                result["sameTokenRevoked401"] = True
            except Exception as exc:
                result["result"] = "QUARANTINED"
                result["revokeError"] = type(exc).__name__
    return result

def run():
    terminal = {"schemaVersion": 1, "requestId": REQUEST_ID,
                "sourceKind": "AUTHENTIC_APP_BOT_17_LOCAL_ORIGINAL_NONPUBLISHING",
                "result": "QUARANTINED", "runtimeEnabled": False,
                "publicationAuthorized": False, "publicReleaseAuthorized": False,
                "publisherSourceKindAuthorized": False, "candidateAdmissionAuthorized": False,
                "durableCasVerified": False, "appTokenReuse": False,
                "parallelLimit": 4, "children": []}
    try:
        source = source_original()
        terminal["central"] = {k: v for k, v in source.items() if k != "targets"}
        identity.check_policy(identity.read_json(identity.POLICY),
                              identity.read_json(identity.REQUEST))
        jwt = identity.make_jwt(os.environ.get(
            "ISSUE311_PREPARE_COORDINATOR_PRIVATE_KEY", ""))
        app = identity.api("GET", "app", jwt)
        need(app.get("id") == 5534389
             and app.get("slug") == "pgextwin-issue311-prepare-coord"
             and set(identity.EXPECTED_REPOS) == set(source["targets"]),
             "wrong actual App identity or target fleet")
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(worker, n, source, jwt): n for n in LOCAL_IDS}
            for f in as_completed(futures):
                terminal["children"].append(f.result())
        terminal["children"].sort(key=lambda x: x["repository"])
        accepted = {"NO_UPDATE", "UPDATE_PRESENT_NOT_AUTHORIZED"}
        good = all(c["result"] in accepted
                   and c.get("sameTokenRevoked401") is True
                   and c.get("originalReceiptIndependentlyVerified") is True
                   and c.get("dispatchCount") == 1 for c in terminal["children"])
        need(len(terminal["children"]) == 17
             and {c["repository"] for c in terminal["children"]} ==
                 set(source["targets"]) and good, "incomplete/unrevoked child fleet")
        terminal["result"] = "CHILDREN_17_ORIGINAL_ZIP_VERIFIED_CAS_PENDING"
    except Exception as exc:
        terminal["reason"] = str(exc)[:450]
    Path(OUT).write_text(json.dumps(terminal, sort_keys=True, indent=2) + "\n",
                         encoding="utf-8")
    print("ISSUE311_REAL_APP_FLEET", json.dumps({
        "result": terminal["result"], "children": len(terminal["children"]),
        "quarantined": sum(c["result"] == "QUARANTINED"
                           for c in terminal["children"]),
        "publicationAuthorized": False}, sort_keys=True))
    return 0 if terminal["result"] == "CHILDREN_17_ORIGINAL_ZIP_VERIFIED_CAS_PENDING" else 1

if __name__ == "__main__":
    raise SystemExit(run())
