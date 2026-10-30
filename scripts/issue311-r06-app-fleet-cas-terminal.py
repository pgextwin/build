#!/usr/bin/env python3
"""R06-06-03: original 17 real App child ZIPs -> bounded build-only CAS terminal.

The trigger is a separate, exactly one-file protected human main-push, never a
fake schedule, rerun, publication, or workflow_dispatch. No candidate writer.
The real fleet original plus all 17 child bytes must authenticate BEFORE any
dedicated state App token is minted. No retries of ambiguous App PUTs.
"""
from __future__ import annotations

import copy
import base64
import urllib.error
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
ACK_LOSS_CANARY = "r-20261030-r06prepareappackloss10"
CONFLICT_CANARY = "r-20261030-r06prepareappcasconflict11"
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

def automatic_request_proof():
    """Bind the new state request to a genuine completed upstream workflow_run.

    No request-file PR, dispatch, stale replay or privileged event payload is
    trusted. Every binding is reconstructed through authenticated REST/ZIP GET.
    """
    global REQ, CENTRAL_REQUEST
    need(os.environ.get("GITHUB_REPOSITORY") == "pgextwin/build"
         and os.environ.get("GITHUB_EVENT_NAME") == "workflow_run"
         and os.environ.get("GITHUB_REF") == "refs/heads/main"
         and os.environ.get("GITHUB_WORKFLOW") == WORKFLOW
         and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
         "untrusted automatic CAS event")
    ev = strict(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    trigger = ev.get("workflow_run", {})
    need(ev.get("action") == "completed"
         and ev.get("repository", {}).get("full_name") == "pgextwin/build"
         and trigger.get("name") == SOURCE_NAME
         and trigger.get("path") == SOURCE_PATH
         and trigger.get("event") == "workflow_run"
         and trigger.get("head_branch") == "main"
         and trigger.get("run_attempt") == 1
         and trigger.get("status") == "completed"
         and trigger.get("conclusion") == "success"
         and trigger.get("actor", {}).get("login") == "ShutenOishi"
         and type(trigger.get("id")) is int and trigger["id"] > 0
         and SHA40.fullmatch(trigger.get("head_sha", "")),
         "no original completed successful App fleet")
    source = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(trigger["id"]))
    need(source.get("id") == trigger["id"] and source.get("name") == SOURCE_NAME
         and source.get("path") == SOURCE_PATH
         and source.get("event") == "workflow_run"
         and source.get("head_branch") == "main"
         and source.get("head_sha") == trigger["head_sha"]
         and source.get("status") == "completed"
         and source.get("conclusion") == "success"
         and source.get("run_attempt") == 1
         and source.get("actor", {}).get("login") == "ShutenOishi",
         "workflow_run event does not match independent REST")
    completed = life.parse_utc(source["updated_at"].replace("+00:00", "Z")
                               .split(".")[0] + "Z" if not source["updated_at"].endswith("Z")
                               else source["updated_at"])
    need(completed <= now() + timedelta(minutes=5)
         and now() <= completed + timedelta(minutes=45),
         "stale or future completed App source")
    main = os.environ["GITHUB_SHA"]
    need(SHA40.fullmatch(main)
         and subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == main
         and subprocess.run(["git", "merge-base", "--is-ancestor",
                             source["head_sha"], main], check=False).returncode == 0,
         "listener checkout must descend from authentic original source")
    branch = bridge.get_json("repos/pgextwin/build/branches/main")
    need(branch.get("protected") is True and branch.get("commit", {}).get("sha") == main,
         "listener no longer at protected main")
    listing = bridge.get_json("repos/pgextwin/build/actions/runs/"
                              + str(source["id"]) + "/artifacts?per_page=100")
    arr = listing.get("artifacts", [])
    need(listing.get("total_count") == len(arr) == 1
         and arr[0].get("name") == SOURCE_ARTIFACT
         and arr[0].get("expired") is False
         and arr[0].get("workflow_run", {}).get("id") == source["id"]
         and arr[0].get("digest", "").startswith("sha256:"),
         "upstream original archive not unique")
    original, digest = bridge.original_zip(arr[0], SOURCE_ENTRY)
    need(digest == arr[0]["digest"].removeprefix("sha256:")
         and original.get("schemaVersion") == 1
         and original.get("sourceKind") == "AUTHENTIC_APP_BOT_17_LOCAL_ORIGINAL_NONPUBLISHING"
         and original.get("result") == "CHILDREN_17_ORIGINAL_ZIP_VERIFIED_CAS_PENDING"
         and original.get("durableCasVerified") is False
         and original.get("runtimeEnabled") is False
         and original.get("publicReleaseAuthorized") is False
         and original.get("publicationAuthorized") is False
         and original.get("publisherSourceKindAuthorized") is False
         and original.get("candidateAdmissionAuthorized") is False
         and len(original.get("children", [])) == 17,
         "automatic source contract forbids publication or incomplete fleet")
    central = original.get("central", {})
    CENTRAL_REQUEST = original.get("requestId")
    need(type(CENTRAL_REQUEST) is str
         and re.fullmatch(r"r-20[0-9]{6}-r06prepare[a-z0-9-]{4,40}", CENTRAL_REQUEST)
         and type(central.get("sourceRunId")) is int and central["sourceRunId"] > 0
         and central.get("sourceHeadSha") == source["head_sha"]
         and SHA64.fullmatch(central.get("sourceZipSha256", "")),
         "unbounded or mismatched central original source")
    date = source["run_started_at"][:10].replace("-", "")
    need(re.fullmatch(r"20[0-9]{6}", date), "invalid original source run date")
    REQ = "r-" + date + "-r06appauto" + str(source["id"])
    expires = stamp(now() + timedelta(hours=2))
    r = {"schemaVersion":1,"requestId":REQ,"mode":"PREPARE",
         "centralRequestId":CENTRAL_REQUEST,
         "centralRunId":central["sourceRunId"],
         "centralZipSha256":central["sourceZipSha256"],
         "sourceRunId":source["id"],"sourceHeadSha":source["head_sha"],
         "sourceArtifactId":arr[0]["id"],
         "sourceZipSha256":digest,
         "expiresAt":expires,"runtimeEnabled":False,
         "publicReleaseAuthorized":False}
    # Bind immutable identity; two calls in the same Actions Run must agree.
    # The expiry must be deterministic across the writer and independent reader.
    r["expiresAt"] = stamp(completed + timedelta(hours=2))
    need(now() < life.parse_utc(r["expiresAt"]), "automatic deadline already expired")
    request_sha = hashlib.sha256(writer.canonical(r)).hexdigest()
    return r, request_sha, main


def request_proof():
    if os.environ.get('GITHUB_EVENT_NAME') == 'workflow_run':
        return automatic_request_proof()
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

def finite_original_veto(r):
    """An original protected PREPARE deadline and State watchdog veto are mandatory.

    Called immediately before each App CAS write, not from independent reader.
    A late delivered workflow_run cannot turn a bounded QUARANTINED original into
    another request's NO_UPDATE. Original Git Contents bytes are independently
    authenticated, never trusted from workflow event claims.
    """
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_run":
        return
    path = ".github/execution-requests/" + r["centralRequestId"] + ".json"
    remote = bridge.get_json("repos/pgextwin/build/contents/" + path
                             + "?ref=" + r["sourceHeadSha"])
    need(remote.get("encoding") == "base64", "original central request not Git Contents")
    raw = base64.b64decode(remote["content"].replace("\r", "").replace("\n", ""),
                           validate=True)
    need(store.blob_hash(raw) == remote.get("sha"), "central request Git blob differs")
    original = strict(raw)
    need(original.get("requestId") == r["centralRequestId"]
         and original.get("mode") == "PREPARE"
         and original.get("allowFutureUpdates") is False
         and original.get("approval", {}).get("publicReleaseAuthorized") is False
         and original.get("approval", {}).get("publicationGrants") == []
         and len(original.get("targets", [])) == 17
         and original.get("limits", {}).get("maxAttemptsPerStage") == 1,
         "nonpublishing bounded central declaration mismatch")
    created = life.parse_utc(original["createdAt"])
    deadline = min(life.parse_utc(original["expiresAt"]),
                   created + timedelta(minutes=original["limits"]["maxWallClockMinutes"]))
    need(now() < deadline, "original finite deadline expired; deny late completion")
    watch_id = ("r-" + r["centralRequestId"][2:10]
                + "-r06watch" + r["sourceHeadSha"][:16])
    try:
        receipt = bridge.get_json("repos/pgextwin/build/contents/"
                 + store.PREFIX + watch_id + ".json?ref=" + store.BRANCH)
    except urllib.error.HTTPError as error:
        need(error.code == 404, "unknown original watchdog GET outcome")
    else:
        blob, state = store.unpack(receipt, watch_id)
        need(state["sourceHeadSha"] == r["sourceHeadSha"]
             and state["publisherAuthorized"] is False, "cross-source finite veto")
        raise ValueError("R06_APP_CAS_DENY durable finite watchdog already exists; "
                         "never claim NO_UPDATE after quarantine")



def app_cas_api_with_one_shot_ack_loss(method, endpoint, body, token, central_request_id, metrics):
    """Exactly one real State App PUT, then controlled loss of only its ACK.

    This is an injected transport-response loss AFTER the server HTTP call
    returns; it is not evidence of a spontaneous GitHub network incident.
    The existing store.CAS performs an authenticated original GET and never
    retransmits the ambiguous PUT. The fixture is allowlisted to one new,
    protected, immutable, nonpublishing central PREPARE request.
    """
    fault = False
    if method == "PUT" and central_request_id == ACK_LOSS_CANARY:
        need(type(body) is dict and type(body.get("content")) is str,
             "one-shot live App PUT missing intended canonical payload")
        proposed = strict(base64.b64decode(body["content"], validate=True))
        fault = (proposed.get("revision") == 2
                 and proposed.get("terminal") == "NO_UPDATE"
                 and proposed.get("publisherAuthorized") is False
                 and len(proposed.get("targets", {})) == 17
                 and set(proposed["targets"].values()) == {"SUCCESS"})
        if fault:
            need(metrics["lostAcks"] == 0, "ambiguous live terminal PUT was retried")
    response = writer.api(method, endpoint, token, body)
    if method == "PUT":
        metrics["putCalls"] += 1
        if fault:
            metrics["lostAcks"] += 1
            raise TimeoutError("controlled ACK loss AFTER actual nonpublishing App PUT")
    return response


def controlled_competing_state_terminal(created, current, old_blob, intended,
                                        metrics, source_run_id):
    """Two genuinely submitted GitHub Contents PUTs against one original SHA.

    The competing fail-closed revision2 is written to the *same isolated new
    request* with the dedicated State App and original server-readback. Then
    the original intended NO_UPDATE rev2 submits its single stale-sha PUT to
    GitHub, expecting a real HTTP 409 or 422. CAS MUST read the competing
    QUARANTINED bytes and fail closed, never retry or claim NO_UPDATE.
    This is a controlled sequential stale-SHA collision, NOT independent
    simultaneous writers or a spontaneous provider network incident.
    """
    need(current.get("revision") == 1 and current.get("terminal") is None
         and intended.get("revision") == 2 and intended.get("terminal") == "NO_UPDATE"
         and len(current.get("targets", {})) == 17
         and len(intended.get("targets", {})) == 17
         and current.get("publisherAuthorized") is False,
         "one-shot live conflict original State shape invalid")
    def quarantine(state):
        state["targets"] = {name: "QUARANTINED" for name in state["targetScope"]}
        state["terminal"] = "QUARANTINED"
        state["completionRun"] = {"id": int(os.environ["GITHUB_RUN_ID"]), "attempt": 1}
        state["eventTransport"] = "BOUNDED_WATCHDOG"
    competitor = life._apply(current, 1, "r06-original-real-stale-cas-conflict",
          {"originalSourceRunId":source_run_id, "source":"controlled_nonpublishing_real_put",
           "concurrentWriterClaim":False}, quarantine)
    saved = created.write(competitor, previous=current, expected_blob=old_blob)
    need(saved in ("ORIGINAL_GET_VERIFIED","RECONCILED_BY_ORIGINAL_GET"),
         "competing real State App PUT lacked exact original GET")
    competitor_blob, live = created.read(REQ)
    need(live == competitor and competitor_blob == store.blob_hash(store.canonical(competitor)),
         "competing real State App server bytes do not match")
    try:
        created.write(intended, previous=current, expected_blob=old_blob)
    except store.UnknownWrite:
        # This exact HTTP error code is captured from the actual GitHub REST
        # transport, not synthesized by the test or interpreted from a mock.
        need(metrics.get("httpConflictCode") in (409, 422),
             "no observed actual GitHub stale-SHA conflict response")
        rechecked_blob, rechecked = created.read(REQ)
        need(rechecked_blob == competitor_blob and rechecked == competitor
             and rechecked["revision"] == 2 and rechecked["terminal"] == "QUARANTINED"
             and set(rechecked["targets"].values()) == {"QUARANTINED"}
             and rechecked["publisherAuthorized"] is False
             and rechecked["writeOutcomeUnknown"] is False,
             "stale competing State App PUT did not fail closed immutably")
        return {"result":"QUARANTINED_VERIFIED_STALE_SHA_CONFLICT",
                "actualGitHubHttpConflictCode":metrics["httpConflictCode"],
                "competingPutReadback":saved, "stateBlobSha":rechecked_blob,
                "stateRevision":2, "targetCount":17,
                "actualStalePutNotRetried":True}
    raise ValueError("R06_APP_CAS_UNSAFE stale SHA unexpectedly overwrote terminal")

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
        finite_original_veto(r)
        initial = life.new(REQ, rawsha, r["sourceHeadSha"], sorted(actual),
                           r["expiresAt"], max_events=100)
        token = writer.mint_token(os.environ.get("STATE_WRITER_PRIVATE_KEY", ""))
        put_metrics = {"putCalls": 0, "lostAcks": 0}
        def canary_transport(method, endpoint, body):
            try:
                return app_cas_api_with_one_shot_ack_loss(
                    method,endpoint,body,token,r["centralRequestId"],put_metrics)
            except writer.HTTPStatus as ex:
                if r["centralRequestId"] == CONFLICT_CANARY and method == "PUT":
                    put_metrics["httpConflictCode"] = ex.code
                raise
        created = store.CAS(canary_transport)
        finite_original_veto(r)
        save0 = created.write(initial)
        blob, current = created.read(REQ)
        need(current == initial, "revision0 GET mismatch")
        bound = life.bind_source(current, current["revision"], "r06-app-17-original",
                                 run_id=r["sourceRunId"], attempt=1,
                                 head_sha=r["sourceHeadSha"])
        finite_original_veto(r)
        save1 = created.write(bound, previous=current, expected_blob=blob)
        blob, current = created.read(REQ)
        need(current == bound, "revision1 GET mismatch")
        payload = {"originalSourceRunId": r["sourceRunId"], "centralRunId":r["centralRunId"],
                   "sourceZipSha256":r["sourceZipSha256"],
                   "centralZipSha256":r["centralZipSha256"],
                   "children":actual, "completionRunId":int(os.environ["GITHUB_RUN_ID"]),
                   "trigger":("genuine_workflow_run_completed" if os.environ["GITHUB_EVENT_NAME"] == "workflow_run" else "original_protected_main_push_not_schedule")}
        def finish(state):
            state["targets"] = {repo:"SUCCESS" for repo in sorted(actual)}
            state["terminal"] = "NO_UPDATE"
            state["completionRun"] = {"id":int(os.environ["GITHUB_RUN_ID"]), "attempt":1}
            state["eventTransport"] = ("workflow_run.completed" if os.environ["GITHUB_EVENT_NAME"] == "workflow_run" else "BOUNDED_WATCHDOG")
        term = life._apply(current, current["revision"], "r06-real-app-17-terminal", payload, finish)
        finite_original_veto(r)
        if r["centralRequestId"] == CONFLICT_CANARY:
            fail_closed = controlled_competing_state_terminal(
                created,current,blob,term,put_metrics,r["sourceRunId"])
            result.update(fail_closed)
            result["centralRunId"] = r["centralRunId"]
            result["originalSourceRunId"] = r["sourceRunId"]
            result["sourceHeadSha"] = r["sourceHeadSha"]
            result["appPutMetrics"] = put_metrics
            result["durableCasVerified"] = True
            # Fail this original CAS workflow deliberately; the separate,
            # already-running original-push watchdog independently checks
            # the durable QUARANTINED17 and no-key replay denial.
            raise ValueError("R06_REAL_GITHUB_CONFLICT_EXPECTED quarantine; never accept NO_UPDATE")
        save2 = created.write(term, previous=current, expected_blob=blob)
        if r["centralRequestId"] == ACK_LOSS_CANARY:
            need(save2 == "RECONCILED_BY_ORIGINAL_GET"
                 and put_metrics == {"putCalls": 3, "lostAcks": 1},
                 "live ACK-loss canary did not reconcile exactly one final PUT")
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
                      controlledAfterActualPutAckLoss=(r["centralRequestId"] == ACK_LOSS_CANARY),
                      appPutMetrics=put_metrics,
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
    if r["centralRequestId"] == ACK_LOSS_CANARY:
        need(proof.get("controlledAfterActualPutAckLoss") is True
             and proof.get("appPutMetrics") == {"putCalls": 3, "lostAcks": 1}
             and proof.get("appPersistence", [None])[-1] == "RECONCILED_BY_ORIGINAL_GET",
             "keyless reader rejects unverified real PUT ACK-loss reconcile")
    contents = bridge.get_json("repos/pgextwin/build/contents/"
        + store.PREFIX + REQ + ".json?ref=" + store.BRANCH)
    blob, state = store.unpack(contents, REQ)
    need(blob == proof["stateBlobSha"]
         and state["revision"] == proof["stateRevision"] == 2
         and state["terminal"] == "NO_UPDATE"
         and state["eventTransport"] == ("workflow_run.completed" if os.environ["GITHUB_EVENT_NAME"] == "workflow_run" else "BOUNDED_WATCHDOG")
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
