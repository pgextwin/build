#!/usr/bin/env python3
"""R06-06-03: original 17 real App child ZIPs -> bounded build-only CAS terminal.

The trigger is a separate, exactly one-file protected human main-push, never a
fake schedule, rerun, publication, or workflow_dispatch. No candidate writer.
The real fleet original plus all 17 child bytes must authenticate BEFORE any
dedicated state App token is minted. No retries of ambiguous App PUTs.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
REQ = "r-20261030-r06appcas17terminal001"
REQUEST = ".github/execution-requests/" + REQ + ".json"
WORKFLOW = "Issue 311 R06 real 17-App original durable CAS terminal (NONPUBLISHING)"
SOURCE_NAME = "Issue 311 17 authentic App-bot local PREPARE originals (NO RELEASE)"
SOURCE_PATH = ".github/workflows/issue311-coordinator-fleet-original.yml"
SOURCE_ARTIFACT = "issue311-r06-app-fleet-original-terminal"
SOURCE_ENTRY = SOURCE_ARTIFACT + ".json"
CENTRAL_ARTIFACT = "issue311-r06-prepare-original-scan"
CENTRAL_ENTRY = CENTRAL_ARTIFACT + ".json"
LOCAL_ARTIFACT = "issue311-app-local-prepare-original-receipt"
LOCAL_ENTRY = "issue311-app-local-prepare-receipt.json"
LOCAL_SOURCE_KIND = "APP_BOT_AUTHENTICATED_ORIGINAL_PREPARE_LOCAL_READONLY_V1"
BOT = "pgextwin-issue311-prepare-coord[bot]"
BOT_ID = 350058024
CENTRAL_REQUEST = "r-20261030-r06preparecoordfleet03"
PROOF_PATH = "issue311-r06-app-original-cas-proof.json"
READBACK_PATH = "issue311-r06-app-original-cas-readback.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")

def load(key, path):
    spec = importlib.util.spec_from_file_location(key, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

bridge = load("r06_app_cas_bridge", "scripts/issue311-r05-windows-completion-bridge.py")
store = load("r06_app_cas_store", "scripts/issue311-lifecycle-store.py")
writer = load("r06_app_cas_writer", "scripts/issue311-writer-runtime.py")
childlib = load("r06_app_cas_childlib", "scripts/issue311-r06-child-join-live.py")
life = store.lifecycle

def need(x, reason):
    if not x:
        raise ValueError("R06_APP_CAS_DENY " + reason)

def strict(raw):
    return json.loads(raw, object_pairs_hook=store.unique_pairs)

def now():
    return datetime.now(timezone.utc)

def stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def request_proof():
    need(os.environ.get("GITHUB_REPOSITORY") == "pgextwin/build"
         and os.environ.get("GITHUB_EVENT_NAME") == "push"
         and os.environ.get("GITHUB_REF") == "refs/heads/main"
         and os.environ.get("GITHUB_ACTOR") == "ShutenOishi"
         and os.environ.get("GITHUB_WORKFLOW") == WORKFLOW
         and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
         "not protected human one-shot main push")
    event = strict(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    head = os.environ["GITHUB_SHA"]
    before = event.get("before")
    need(event.get("after") == head and event.get("ref") == "refs/heads/main"
         and event.get("sender", {}).get("login") == "ShutenOishi"
         and event.get("repository", {}).get("full_name") == "pgextwin/build"
         and event.get("created") is False and event.get("deleted") is False
         and SHA40.fullmatch(head) and isinstance(before, str) and SHA40.fullmatch(before),
         "untrusted protected original event")
    need(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == head,
         "checkout does not match event")
    changes = subprocess.check_output(["git", "diff", "--name-status", before, head],
                                       text=True).splitlines()
    need(changes == ["A\t" + REQUEST], "not single newly added CAS request")
    raw = subprocess.check_output(["git", "show", "HEAD:" + REQUEST])
    r = strict(raw)
    need(type(r) is dict and set(r) == {
        "schemaVersion", "requestId", "mode", "centralRequestId",
        "centralRunId", "centralZipSha256", "sourceRunId", "sourceHeadSha",
        "sourceArtifactId", "sourceZipSha256", "baseMainSha", "expiresAt",
        "runtimeEnabled", "publicReleaseAuthorized"},
        "request schema not exact")
    need(r["schemaVersion"] == 1 and r["requestId"] == REQ
         and r["mode"] == "PREPARE" and r["centralRequestId"] == CENTRAL_REQUEST
         and r["runtimeEnabled"] is False and r["publicReleaseAuthorized"] is False
         and r["baseMainSha"] == before
         and SHA40.fullmatch(r["sourceHeadSha"])
         and SHA64.fullmatch(r["sourceZipSha256"])
         and SHA64.fullmatch(r["centralZipSha256"])
         and type(r["centralRunId"]) is int and r["centralRunId"] > 0
         and type(r["sourceRunId"]) is int and r["sourceRunId"] > 0
         and type(r["sourceArtifactId"]) is int and r["sourceArtifactId"] > 0,
         "wrong source-kind, unbounded App writer or stale parent")
    until = life.parse_utc(r["expiresAt"])
    need(now() < until <= now() + timedelta(hours=8),
         "expired/unbounded state request")
    branch = bridge.get_json("repos/pgextwin/build/branches/main")
    need(branch.get("protected") is True
         and branch.get("commit", {}).get("sha") == head,
         "not live protected main")
    return r, hashlib.sha256(raw).hexdigest(), head

def original_source(r):
    # Authenticated source was a genuine workflow_run of the distinct central
    # nonpublishing source. This is NOT the protected trigger being fabricated.
    sid = r["sourceRunId"]
    run = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(sid))
    need(run.get("id") == sid and run.get("name") == SOURCE_NAME
         and run.get("path") == SOURCE_PATH
         and run.get("event") == "workflow_run"
         and run.get("head_branch") == "main"
         and run.get("status") == "completed" and run.get("conclusion") == "success"
         and run.get("run_attempt") == 1 and run.get("head_sha") == r["sourceHeadSha"],
         "untrusted original App fleet run")
    jobs = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(sid)
                           + "/jobs?per_page=100")
    needed = "Verify source original bytes then scope and join 17 genuine App bot receipts"
    need(jobs.get("total_count") == len(jobs.get("jobs", [])) == 2
         and len([j for j in jobs["jobs"] if j.get("name") == needed
                  and j.get("conclusion") == "success"]) == 1,
         "source exact original verification job missing")
    artifacts = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(sid)
                                + "/artifacts?per_page=100")
    arr = artifacts.get("artifacts", [])
    need(artifacts.get("total_count") == len(arr) == 1
         and arr[0].get("id") == r["sourceArtifactId"]
         and arr[0].get("name") == SOURCE_ARTIFACT
         and arr[0].get("expired") is False
         and arr[0].get("digest") == "sha256:" + r["sourceZipSha256"],
         "not unique immutable original App source archive")
    original, outer = bridge.original_zip(arr[0], SOURCE_ENTRY)
    need(outer == r["sourceZipSha256"] and original.get("schemaVersion") == 1
         and original.get("requestId") == CENTRAL_REQUEST
         and original.get("sourceKind") == "AUTHENTIC_APP_BOT_17_LOCAL_ORIGINAL_NONPUBLISHING"
         and original.get("result") == "CHILDREN_17_ORIGINAL_ZIP_VERIFIED_CAS_PENDING"
         and original.get("durableCasVerified") is False
         and original.get("runtimeEnabled") is False
         and original.get("publicationAuthorized") is False
         and original.get("publicReleaseAuthorized") is False
         and original.get("publisherSourceKindAuthorized") is False
         and original.get("candidateAdmissionAuthorized") is False
         and original.get("parallelLimit") == 4,
         "source not proven 17 nonpublishing App children")
    central = original.get("central", {})
    need(central.get("sourceRunId") == r["centralRunId"]
         and central.get("centralRequestId") == CENTRAL_REQUEST
         and central.get("sourceZipSha256") == r["centralZipSha256"]
         and central.get("sourceHeadSha") == r["sourceHeadSha"],
         "central original source binding mismatch")
    # The request pinned central is re-fetched as genuine original provider ZIP.
    centarts = bridge.get_json("repos/pgextwin/build/actions/runs/"
        + str(r["centralRunId"]) + "/artifacts?per_page=100")
    cent = centarts.get("artifacts", [])
    need(centarts.get("total_count") == len(cent) == 1
         and cent[0].get("name") == CENTRAL_ARTIFACT
         and cent[0].get("digest") == "sha256:" + r["centralZipSha256"]
         and cent[0].get("expired") is False, "central archive changed")
    proof, digest = bridge.original_zip(cent[0], CENTRAL_ENTRY)
    need(digest == r["centralZipSha256"] and proof.get("requestId") == CENTRAL_REQUEST
         and proof.get("sourceRunId") == r["centralRunId"]
         and proof.get("sourceHeadSha") == r["sourceHeadSha"]
         and proof.get("result") == "SCANNED"
         and proof.get("fleetSize") == 17
         and proof.get("publicationAuthorized") is False
         and len(proof.get("targetMainSha", {})) == 17,
         "central original bytes are not exact")
    children = original.get("children")
    need(type(children) is list and len(children) == 17
         and len({x.get("repository") for x in children}) == 17
         and set(x.get("repository") for x in children) == set(proof["targetMainSha"]),
         "duplicate/incomplete child outcomes")
    return original, proof

def strict_child_receipt(receipt, item, central, target_sha):
    need(receipt.get("schemaVersion") == 1
         and receipt.get("sourceKind") == LOCAL_SOURCE_KIND
         and receipt.get("result") == "NO_UPDATE"
         and receipt.get("requestId", "").startswith("r-20261030-r06coordlocal")
         and receipt.get("actualBotLogin") == BOT
         and receipt.get("actualBotUserId") == BOT_ID
         and receipt.get("localOriginalEvent") == "workflow_dispatch"
         and receipt.get("localRunId") == item["localRunId"]
         and receipt.get("localRunAttempt") == 1
         and receipt.get("localProtectedMainSha") == target_sha
         and receipt.get("centralSourceRunId") == central["sourceRunId"]
         and receipt.get("centralSourceHeadSha") == central["sourceHeadSha"]
         and receipt.get("centralSourceRequestId") == CENTRAL_REQUEST
         and receipt.get("centralOriginalOuterZipSha256Verified") == central["sourceZipSha256"]
         and receipt.get("publicationAuthorized") is False
         and receipt.get("publicReleaseAuthorized") is False
         and receipt.get("candidateCreated") is False
         and receipt.get("genuineSchedule") is False
         and receipt.get("originalScanReexecuted") is False
         and receipt.get("publisherSourceKindAuthorized") is False
         and receipt.get("runtimeEnabled") is False,
         "source-kind, run or release assertion rejected")
    return True

def child_originals(terminal, central):
    results = {}
    local_ids = set()
    for item in sorted(terminal["children"], key=lambda x:x["repository"]):
        repo = item["repository"]
        rid = item.get("localRunId")
        need(type(rid) is int and rid > 0
             and item.get("result") == "NO_UPDATE"
             and item.get("appBotLogin") == BOT
             and item.get("appBotUserId") == BOT_ID
             and item.get("sameTokenRevoked401") is True
             and item.get("dispatchCount") == 1
             and item.get("originalReceiptIndependentlyVerified") is True
             and item.get("publicationAuthorized") is False
             and SHA64.fullmatch(item.get("originalReceiptZipSha256Verified", "")),
             "unaccepted 17-App local terminal child")
        # The child is an original, completed App bot workflow_dispatch.
        run = childlib.get(repo, "actions/runs/" + str(rid))
        need(run.get("id") == rid and run.get("event") == "workflow_dispatch"
             and run.get("head_branch") == "main"
             and run.get("head_sha") == central["targetMainSha"][repo]
             and run.get("actor", {}).get("login") == BOT
             and run.get("actor", {}).get("id") == BOT_ID
             and run.get("run_attempt") == 1
             and run.get("status") == "completed"
             and run.get("conclusion") == "success",
             "not authenticated exact App bot original "+repo)
        receipt, artifact = childlib.artifact(
            repo, rid, LOCAL_ARTIFACT, LOCAL_ENTRY,
            expected_id=item["originalReceiptArtifactId"],
            expected_digest=item["originalReceiptZipSha256Verified"])
        strict_child_receipt(receipt, item, central, central["targetMainSha"][repo])
        need(receipt["requestId"] not in local_ids, "local request replay")
        local_ids.add(receipt["requestId"])
        results[repo] = {"runId": rid, "zipSha256": artifact["zipSha256"],
                         "sourceKind": LOCAL_SOURCE_KIND, "result": "NO_UPDATE"}
    need(len(results) == 17, "incomplete independent 17 child original ZIPs")
    return results

def terminal_replay_denials(state, central, children):
    checks = {}
    def denied(name, action):
        try:
            action()
        except (ValueError, KeyError):
            checks[name] = "DENY"
            return
        raise AssertionError("R06_APP_CAS_FALSE_ACCEPT " + name)
    denied("afterTerminalReplay", lambda: life._apply(
        state, state["revision"], "r06_app_original_replay",
        {"op": "replay", "sourceKind": "FAKE_SCHEDULE"},
        lambda d:d.update(terminal=None)))
    example = next(x for x in children)
    mutated = {"schemaVersion": 1, "sourceKind": "FAKE_SCHEDULE"}
    denied("fakeSourceKind", lambda: strict_child_receipt(
        mutated, {"localRunId":children[example]["runId"]}, central,
        central["targetMainSha"][example]))
    denied("crossRequestStateRead", lambda: store.unpack(
        {"encoding": "base64", "sha":"0"*40, "content": ""}, "r-20261030-otherrequest0001"))
    return checks

def persist():
    result = {"schemaVersion": 1, "requestId": REQ, "result": "QUARANTINED",
              "publicationAuthorized": False, "publisherAuthorized": False,
              "runtimeEnabled": False, "durableCasVerified": False}
    token = None
    try:
        r, rawsha, head = request_proof()
        orig, central = original_source(r)
        actual = child_originals(orig, {
            **orig["central"], "targetMainSha": central["targetMainSha"]})
        need(len(actual) == 17 and all(x["result"] == "NO_UPDATE" for x in actual.values()),
             "no full original 17 NO_UPDATE acceptance")
        initial = life.new(REQ, rawsha, r["sourceHeadSha"], sorted(actual),
                           r["expiresAt"], max_events=100)
        token = writer.mint_token(os.environ.get("STATE_WRITER_PRIVATE_KEY", ""))
        created = store.CAS(lambda method,endpoint,body:
                            writer.api(method,endpoint,token,body))
        save0 = created.write(initial)
        blob, current = created.read(REQ)
        need(current == initial, "revision0 GET mismatch")
        bound = life.bind_source(current, current["revision"], "r06-app-17-original",
                                 run_id=r["sourceRunId"], attempt=1,
                                 head_sha=r["sourceHeadSha"])
        save1 = created.write(bound, previous=current, expected_blob=blob)
        blob, current = created.read(REQ)
        need(current == bound, "revision1 GET mismatch")
        payload = {"originalSourceRunId": r["sourceRunId"], "centralRunId":r["centralRunId"],
                   "sourceZipSha256":r["sourceZipSha256"],
                   "centralZipSha256":r["centralZipSha256"],
                   "children":actual, "completionRunId":int(os.environ["GITHUB_RUN_ID"]),
                   "trigger":"original_protected_main_push_not_schedule"}
        def finish(state):
            state["targets"] = {repo:"SUCCESS" for repo in sorted(actual)}
            state["terminal"] = "NO_UPDATE"
            state["completionRun"] = {"id":int(os.environ["GITHUB_RUN_ID"]), "attempt":1}
            state["eventTransport"] = "BOUNDED_WATCHDOG"
        term = life._apply(current, current["revision"], "r06-real-app-17-terminal", payload, finish)
        save2 = created.write(term, previous=current, expected_blob=blob)
        blob, stored = created.read(REQ)
        need(stored == term and blob == store.blob_hash(store.canonical(term))
             and stored["revision"] == 2 and stored["terminal"] == "NO_UPDATE"
             and all(x == "SUCCESS" for x in stored["targets"].values())
             and stored["publisherAuthorized"] is False, "durable original GET differs")
        checks = terminal_replay_denials(stored, {
            **orig["central"], "targetMainSha":central["targetMainSha"]}, actual)
        blobagain, again = created.read(REQ)
        need(blobagain == blob and again == stored, "replay changed CAS original")
        result.update(result="NO_UPDATE_17_APP_CAS_DURABLE_READBACK_PENDING",
                      durableCasVerified=True, originalSourceRunId=r["sourceRunId"],
                      originalSourceZipSha256=r["sourceZipSha256"],
                      centralRunId=r["centralRunId"], centralZipSha256=r["centralZipSha256"],
                      requestSha256=rawsha, sourceHeadSha=r["sourceHeadSha"],
                      stateBlobSha=blob, stateRevision=2, targetCount=17,
                      childProofSha256=hashlib.sha256(writer.canonical(actual)).hexdigest(),
                      appPersistence=[save0,save1,save2], negatives=checks,
                      completionRunId=int(os.environ["GITHUB_RUN_ID"]))
    except Exception as exc:
        result["reason"] = str(exc)[:380]
    finally:
        if token:
            try:
                writer.revoke_and_prove_401(token)
                result["sameStateTokenRevoked401"] = True
            except Exception as exc:
                result["result"] = "QUARANTINED"
                result["revokeFailure"] = type(exc).__name__
        Path(PROOF_PATH).write_text(json.dumps(result, sort_keys=True, indent=2)+"\n")
        print("ISSUE311_APP_CAS_TERMINAL", json.dumps({
            "result":result["result"], "targetCount":result.get("targetCount",0),
            "publisherAuthorized": False, "reason":result.get("reason", "")},
            sort_keys=True))
    return 0 if result["result"] == "NO_UPDATE_17_APP_CAS_DURABLE_READBACK_PENDING" and result.get("sameStateTokenRevoked401") is True else 1

def readback():
    need(not os.environ.get("STATE_WRITER_PRIVATE_KEY"),
         "independent reader must not have App private key")
    r, rawsha, head = request_proof()
    original, central = original_source(r)
    proof, art = childlib.artifact(
        "pgextwin/build", int(os.environ["GITHUB_RUN_ID"]),
        "issue311-r06-app-original-cas-proof", PROOF_PATH)
    need(proof.get("result") == "NO_UPDATE_17_APP_CAS_DURABLE_READBACK_PENDING"
         and proof.get("sameStateTokenRevoked401") is True
         and proof.get("originalSourceRunId") == r["sourceRunId"]
         and proof.get("originalSourceZipSha256") == r["sourceZipSha256"]
         and proof.get("centralRunId") == r["centralRunId"]
         and proof.get("centralZipSha256") == r["centralZipSha256"]
         and proof.get("requestSha256") == rawsha
         and proof.get("targetCount") == 17
         and proof.get("durableCasVerified") is True,
         "original App writer proof mismatch")
    contents = bridge.get_json("repos/pgextwin/build/contents/"
        + store.PREFIX + REQ + ".json?ref=" + store.BRANCH)
    blob, state = store.unpack(contents, REQ)
    need(blob == proof["stateBlobSha"]
         and state["revision"] == proof["stateRevision"] == 2
         and state["terminal"] == "NO_UPDATE"
         and state["eventTransport"] == "BOUNDED_WATCHDOG"
         and state["sourceRun"] == {"id":r["sourceRunId"],"attempt":1}
         and state["completionRun"] == {"id":int(os.environ["GITHUB_RUN_ID"]),"attempt":1}
         and state["requestSha256"] == rawsha
         and state["sourceHeadSha"] == r["sourceHeadSha"]
         and len(state["targetScope"]) == 17
         and all(x == "SUCCESS" for x in state["targets"].values())
         and state["publisherAuthorized"] is False
         and state["writeOutcomeUnknown"] is False,
         "independent original durable App checkpoint differs")
    checks = terminal_replay_denials(
        state, {**original["central"], "targetMainSha": central["targetMainSha"]},
        {repo:{"runId":0} for repo in state["targets"]})
    again = bridge.get_json("repos/pgextwin/build/contents/"
        + store.PREFIX + REQ + ".json?ref=" + store.BRANCH)
    need(store.unpack(again, REQ) == (blob,state), "read-only replay mutated CAS")
    out = {"requestId":REQ, "result":"ORIGINAL_17_GET_CAS_READBACK_DENIAL_PASS",
           "stateBlobSha":blob, "revision":2, "targetCount":17,
           "appKeyAvailable":False, "publicationAuthorized":False,
           "sourceArtifactSha256":r["sourceZipSha256"],
           "terminalArtifact":art, "replay":"DENY_NO_PUT", "negativeDenials":checks}
    Path(READBACK_PATH).write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
    print("ISSUE311_APP_CAS_INDEPENDENT_READBACK",out["result"])
    return 0

if __name__ == "__main__":
    need(len(sys.argv) == 2 and sys.argv[1] in ("persist","readback"),
         "unapproved operation")
    raise SystemExit(persist() if sys.argv[1] == "persist" else readback())
