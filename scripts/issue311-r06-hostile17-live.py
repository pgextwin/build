#!/usr/bin/env python3
"""R06-05-02 bounded original-source hostile ZIP + durable replay probe.

NONPUBLISHING. Genuine original central artifact bytes are read, never changed.
Mutations exist only in memory, and terminal state lives only in the existing
build-scoped issue311-state App namespace. Controlled faults are not provider outages.
"""
from __future__ import annotations
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
# The existing fleet watcher imports its shared sibling as an ordinary module.
# Match the verified script execution path when this probe is imported by tests.
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
REQ = "r-20261029-r06hostile17g01"
PATH = ".github/execution-requests/" + REQ + ".json"
SOURCE_NAME = "Issue 311 R06 real central ZIP hostile 17 source (NONPUBLISHING)"
SOURCE_PATH = ".github/workflows/issue311-r06-hostile17-source.yml"
SOURCE_ARTIFACT = "issue311-r06-hostile17-original"
SOURCE_RECEIPT = "issue311-r06-hostile17-original.json"
FINAL_RECEIPT = "issue311-r06-hostile17-durable-replay.json"
ORIGINAL_RUN = 40852118886
ORIGINAL_HEAD = "49575a2d11a591fbf456c0c4d790cd0346ef2fe7"
ORIGINAL_ARTIFACT = 12886559374
ORIGINAL_DIGEST = "b81a14c98b7fcc403970b7bde40028799a99938bef595a8ea1400154b35e5262"
RECEIPT_ENTRY = "issue311-r06-prepare-original-scan.json"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


contract = load("r06_h_contract", "scripts/issue311-request-contract.py")
store = load("r06_h_store", "scripts/issue311-lifecycle-store.py")
life = store.lifecycle
writer = load("r06_h_writer", "scripts/issue311-writer-runtime.py")
bridge = load("r06_h_bridge", "scripts/issue311-r05-windows-completion-bridge.py")
scan = load("r06_h_scan", "scripts/issue311-r06-prepare-scan.py")


def need(ok, why):
    if not ok:
        raise ValueError("R06_HOSTILE_DENY " + why)


def contents(path, ref):
    record = bridge.get_json("repos/pgextwin/build/contents/" + path + "?ref=" + ref)
    need(record.get("encoding") == "base64", "missing original contents")
    raw = base64.b64decode(record["content"].replace("\r", "").replace("\n", ""), validate=True)
    need(store.blob_hash(raw) == record.get("sha"), "Git blob original mismatch")
    return raw


def original_central():
    run = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(ORIGINAL_RUN))
    need(run.get("id") == ORIGINAL_RUN and run.get("head_sha") == ORIGINAL_HEAD
         and run.get("run_attempt") == 1 and run.get("event") == "push"
         and run.get("path") == scan.WORKFLOW_PATH
         and run.get("actor", {}).get("login") == "ShutenOishi"
         and run.get("status") == "completed" and run.get("conclusion") == "success",
         "central original run identity/conclusion")
    artifacts = bridge.get_json("repos/pgextwin/build/actions/runs/" +
                                str(ORIGINAL_RUN) + "/artifacts?per_page=100")
    listed = artifacts.get("artifacts", [])
    need(artifacts.get("total_count") == len(listed) == 1, "ambiguous central original artifacts")
    a = listed[0]
    need(a.get("id") == ORIGINAL_ARTIFACT and a.get("name") == scan.ARTIFACT
         and a.get("digest") == "sha256:" + ORIGINAL_DIGEST
         and a.get("expired") is False
         and a.get("workflow_run", {}).get("id") == ORIGINAL_RUN,
         "central provider digest/identity/expiration")
    raw = bridge.get_bytes("repos/pgextwin/build/actions/artifacts/" +
                           str(ORIGINAL_ARTIFACT) + "/zip")
    need(hashlib.sha256(raw).hexdigest() == ORIGINAL_DIGEST, "real central ZIP byte digest")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        need(z.namelist() == [RECEIPT_ENTRY], "unexpected original ZIP entries")
        proof = json.loads(z.read(RECEIPT_ENTRY), object_pairs_hook=store.unique_pairs)
    need(proof.get("result") == "SCANNED" and proof.get("sourceRunId") == ORIGINAL_RUN
         and proof.get("sourceRunAttempt") == 1 and proof.get("sourceHeadSha") == ORIGINAL_HEAD
         and proof.get("sourceEvent") == "push" and proof.get("fleetSize") == 17
         and proof.get("publisherAuthorized") is False
         and len(proof.get("targetMainSha", {})) == 17
         and set(proof["targetMainSha"]) == set(scan.win.TARGETS),
         "central receipt identity/17/scope")
    scan.inspect_report(proof["report"], proof["targetMainSha"])
    orig_path = ".github/execution-requests/" + proof["requestId"] + ".json"
    orig_raw = contents(orig_path, ORIGINAL_HEAD)
    need(hashlib.sha256(orig_raw).hexdigest() == proof["requestSha256"],
         "central original immutable request mismatch")
    return raw, proof, orig_raw, orig_path


def controlled_denials(raw, proof, orig_raw, orig_path):
    """Only in-memory attacker mutations. Every DENY must actually raise."""
    def denied(check, label):
        try:
            check()
        except (ValueError, KeyError, zipfile.BadZipFile, RuntimeError):
            return label
        raise AssertionError("R06_HOSTILE_BAD_ACCEPT " + label)

    def verify_outer(outer):
        need(hashlib.sha256(outer).hexdigest() == ORIGINAL_DIGEST,
             "untrusted artifact byte digest")
        with zipfile.ZipFile(io.BytesIO(outer)) as z:
            need(z.namelist() == [RECEIPT_ENTRY], "untrusted ZIP entries")
            return json.loads(z.read(RECEIPT_ENTRY), object_pairs_hook=store.unique_pairs)

    tainted = bytearray(raw)
    tainted[len(tainted) // 2] ^= 1
    checks = {"tamperedOriginalZip": denied(lambda: verify_outer(bytes(tainted)), "tamper")}
    partial = copy.deepcopy(proof)
    partial["report"]["extensions"].pop()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(RECEIPT_ENTRY, json.dumps(partial, sort_keys=True))
    checks["missingTargetOuterDigest"] = denied(lambda: verify_outer(out.getvalue()), "partialSha")
    checks["missingTargetSchema"] = denied(
        lambda: scan.inspect_report(partial["report"], partial["targetMainSha"]), "partial17")
    request = json.loads(orig_raw, object_pairs_hook=store.unique_pairs)
    later = life.parse_utc(request["expiresAt"]) + timedelta(seconds=1)
    checks["expiredOriginalRequest"] = denied(
        lambda: contract.validate_declaration(orig_raw, orig_path, now=later), "expired")
    need(len(checks) == 4, "missing controlled negatives")
    return checks, datetime.now(timezone.utc) > life.parse_utc(request["expiresAt"])


def real_request_context():
    ev = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                    object_pairs_hook=store.unique_pairs)
    head = os.environ["GITHUB_SHA"]
    need(os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
         and os.environ["GITHUB_EVENT_NAME"] == "push"
         and os.environ["GITHUB_REF"] == "refs/heads/main"
         and os.environ["GITHUB_WORKFLOW"] == SOURCE_NAME
         and os.environ["GITHUB_ACTOR"] == "ShutenOishi"
         and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
         and ev.get("before") != head and ev.get("after") == head
         and ev.get("sender", {}).get("login") == "ShutenOishi"
         and ev.get("created") is False and ev.get("deleted") is False,
         "not an authenticated original request push")
    need(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == head,
         "checkout not exact original SHA")
    changes = subprocess.check_output(
        ["git", "diff", "--name-status", ev["before"], head], text=True).splitlines()
    need(changes == ["A\t" + PATH], "not a request-only protected addition")
    main = bridge.get_json("repos/pgextwin/build/branches/main")
    need(main.get("protected") is True and main.get("commit", {}).get("sha") == head,
         "not current protected main")
    raw = subprocess.check_output(["git", "show", "HEAD:" + PATH])
    need(raw == contents(PATH, head), "request HEAD/original Contents mismatch")
    d = contract.validate_declaration(raw, PATH)
    req = json.loads(raw, object_pairs_hook=store.unique_pairs)
    expected = set(scan.win.TARGETS)
    need(d["requestId"] == REQ and d["mode"] == "AUDIT_ONLY"
         and set(d["targets"]) == expected and len(d["targets"]) == 17
         and req["source"]["centralMainSha"] == ev["before"]
         and req["source"]["fleetRegistryBlobSha"] == scan.FLEET_BLOB
         and req["approval"]["publicReleaseAuthorized"] is False
         and req["approval"]["publicationGrants"] == []
         and req["allowFutureUpdates"] is False
         and req["limits"]["maxAttemptsPerStage"] == 1
         and req["limits"]["maxWallClockMinutes"] <= 10,
         "not this scoped nonpublishing request")
    wanted = {x["repo"]: x["mainSha"] for x in req["targets"]}
    need(len(wanted) == 17 and set(wanted) == expected, "duplicate local targets")
    for repo, sha in sorted(wanted.items()):
        remote = scan.win.old.get_json("https://api.github.com/repos/" +
                                       repo + "/branches/main", os.environ["GH_TOKEN"])
        need(remote.get("protected") is True and remote.get("name") == "main"
             and remote.get("commit", {}).get("sha") == sha,
             "remote protected main drift " + repo)
    return head, d, req


def app():
    key = os.environ.get("STATE_WRITER_PRIVATE_KEY")
    need(bool(key), "existing build-scoped App missing")
    token = writer.mint_token(key)
    return token, store.CAS(lambda method, path, body: writer.api(method, path, token, body))


def source():
    result = {"requestId": REQ, "result": "FAILED", "publisherAuthorized": False}
    token = None
    try:
        head, declaration, req = real_request_context()
        raw, proof, original_request, original_path = original_central()
        checks, actual_expired = controlled_denials(raw, proof, original_request, original_path)
        start = life.new(REQ, declaration["rawSha256"], head,
                         sorted(x["repo"] for x in req["targets"]), req["expiresAt"],
                         max_events=req["limits"]["maxOperations"])
        token, cas = app()
        initial = cas.write(start)  # create-only: original replay cannot overwrite
        blob, loaded = cas.read(REQ)
        bound = life.bind_source(loaded, loaded["revision"], "r06-verified-original-source",
                                 run_id=int(os.environ["GITHUB_RUN_ID"]), attempt=1, head_sha=head)
        persistent = cas.write(bound, previous=loaded, expected_blob=blob)
        _, confirm = cas.read(REQ)
        need(confirm == bound, "original state revision1 readback")
        result.update(result="CONTROLLED_DENY_VERIFIED", sourceHeadSha=head,
                      sourceRunId=int(os.environ["GITHUB_RUN_ID"]), sourceAttempt=1,
                      requestSha256=declaration["rawSha256"], targetCount=17,
                      centralRunId=ORIGINAL_RUN, centralArtifactId=ORIGINAL_ARTIFACT,
                      centralZipSha256=ORIGINAL_DIGEST, originalCurrentlyExpired=actual_expired,
                      expiryCheck="CONTROLLED_EXPIRED_CLOCK_DENY",
                      negativeDenials=checks, stateRevision=1,
                      persistence=[initial, persistent])
    except Exception as exc:
        result["reason"] = str(exc)[:400]
    finally:
        if token:
            writer.revoke_and_prove_401(token)
    Path(SOURCE_RECEIPT).write_text(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] == "CONTROLLED_DENY_VERIFIED" else 1


def verified_source_event():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                       object_pairs_hook=store.unique_pairs)
    source = event.get("workflow_run", {})
    need(os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
         and os.environ["GITHUB_EVENT_NAME"] == "workflow_run"
         and os.environ["GITHUB_REF"] == "refs/heads/main"
         and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
         and event.get("action") == "completed"
         and event.get("repository", {}).get("full_name") == "pgextwin/build"
         and source.get("name") == SOURCE_NAME and source.get("path") == SOURCE_PATH
         and source.get("event") == "push" and source.get("head_branch") == "main"
         and source.get("actor", {}).get("login") == "ShutenOishi"
         and source.get("status") == "completed" and source.get("conclusion") == "success"
         and source.get("run_attempt") == 1, "event source not verified")
    original = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(source["id"]))
    for k in ("id", "head_sha", "run_attempt", "path", "event", "conclusion", "workflow_id"):
        need(original.get(k) == source.get(k), "independent original mismatch " + k)
    need(original.get("actor", {}).get("login") == "ShutenOishi"
         and original.get("status") == "completed", "source actor/status")
    request_raw = contents(PATH, original["head_sha"])
    declaration = contract.validate_declaration(request_raw, PATH)
    need(declaration["requestId"] == REQ, "wrong original request")
    return original, declaration


def complete(original_override=None, declaration_override=None):
    report = {"requestId": REQ, "result": "FAILED", "publisherAuthorized": False}
    token = None
    try:
        if original_override is None:
            original, decl = verified_source_event()
        else:
            original, decl = original_override, declaration_override
        artifacts = bridge.get_json("repos/pgextwin/build/actions/runs/" +
                                    str(original["id"]) + "/artifacts?per_page=100")
        listed = artifacts.get("artifacts", [])
        need(artifacts.get("total_count") == len(listed) == 1, "source ZIP absent/duplicate")
        art = listed[0]
        need(art.get("name") == SOURCE_ARTIFACT and art.get("expired") is False
             and art.get("workflow_run", {}).get("id") == original["id"],
             "original source ZIP metadata")
        proof, digest = bridge.original_zip(art, SOURCE_RECEIPT)
        need(proof.get("result") == "CONTROLLED_DENY_VERIFIED"
             and proof.get("requestId") == REQ
             and proof.get("sourceHeadSha") == original["head_sha"]
             and proof.get("sourceRunId") == original["id"]
             and proof.get("sourceAttempt") == 1
             and proof.get("requestSha256") == decl["rawSha256"]
             and proof.get("targetCount") == 17
             and proof.get("centralRunId") == ORIGINAL_RUN
             and proof.get("centralArtifactId") == ORIGINAL_ARTIFACT
             and proof.get("centralZipSha256") == ORIGINAL_DIGEST
             and proof.get("publicationAuthorized") is False
             and set(proof.get("negativeDenials", {})) == {
                 "tamperedOriginalZip", "missingTargetOuterDigest",
                 "missingTargetSchema", "expiredOriginalRequest"},
             "original source hostile proof not complete")
        token, cas = app()
        blob, state = cas.read(REQ)
        need(state["revision"] == 1 and state["terminal"] is None
             and state["sourceRun"] == {"id": original["id"], "attempt": 1}
             and state["requestSha256"] == decl["rawSha256"]
             and len(state["targets"]) == 17 and all(v == "PENDING" for v in state["targets"].values()),
             "initial durable state not bound to original source")
        ended = life.record_completion(
            state, state["revision"], "r06-controlled-hostile-terminal",
            run_id=int(os.environ["GITHUB_RUN_ID"]), attempt=1, source_id=original["id"],
            outcome="QUARANTINED",
            target_outcomes={x: "QUARANTINED" for x in state["targets"]},
            original_zip_sha=digest)
        persistence = cas.write(ended, previous=state, expected_blob=blob)
        end_blob, confirmed = cas.read(REQ)
        need(confirmed == ended and confirmed["revision"] == 2
             and confirmed["terminal"] == "QUARANTINED"
             and confirmed["publisherAuthorized"] is False,
             "terminal App state not durable")
        # Attempt the replay only against a genuinely persisted terminal checkpoint;
        # the pure transition must DENY before any second network PUT.
        blocked = False
        try:
            life.record_completion(confirmed, confirmed["revision"], "r06-duplicate-event",
                                   run_id=int(os.environ["GITHUB_RUN_ID"]), attempt=1,
                                   source_id=original["id"], outcome="NO_UPDATE",
                                   target_outcomes={x: "SUCCESS" for x in confirmed["targets"]},
                                   original_zip_sha=digest)
        except life.Denied:
            blocked = True
        need(blocked and cas.read(REQ)[1] == confirmed,
             "durable terminal replay accepted/altered")
        report.update(result="CONTROLLED_HOSTILE_TERMINAL", targetCount=17,
                      originalSourceRunId=original["id"], originalSourceZipSha256=digest,
                      completionRunId=int(os.environ["GITHUB_RUN_ID"]),
                      stateGitBlobSha=end_blob, stateRevision=2,
                      replay="DENY_NO_SECOND_PUT", targetOutcome="QUARANTINED",
                      persistence=persistence, originalCentralZipSha256=ORIGINAL_DIGEST)
        print("R06_DURABLE_CONTROLLED_HOSTILE_17_QUARANTINED_REPLAY_DENY", persistence)
    except Exception as exc:
        report["reason"] = str(exc)[:400]
    finally:
        if token:
            writer.revoke_and_prove_401(token)
    Path(FINAL_RECEIPT).write_text(json.dumps(report, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "CONTROLLED_HOSTILE_TERMINAL" else 1



RECOVERY_REQ = "r-20261029-r06recovery17h01"
RECOVERY_PATH = ".github/execution-requests/" + RECOVERY_REQ + ".json"
RECOVERY_NAME = "Issue 311 R06 original failed listener recovery source (NONPUBLISHING)"
RECOVERY_WORKFLOW = ".github/workflows/issue311-r06-hostile17-recovery-source.yml"
RECOVERY_ARTIFACT = "issue311-r06-hostile17-recovery-original"
RECOVERY_RECEIPT = "issue311-r06-hostile17-recovery-original.json"
FAILED_LISTENER = 40876850679
SOURCE_ORIGINAL = 40876766677
SOURCE_ORIGINAL_HEAD = "7cefe10b6ac3d70e2fd0c8378cae2bc763c064c0"


def original_failed_listener():
    run = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(FAILED_LISTENER))
    need(run.get("id") == FAILED_LISTENER and run.get("event") == "workflow_run"
         and run.get("status") == "completed" and run.get("conclusion") == "failure"
         and run.get("run_attempt") == 1 and run.get("head_sha") == SOURCE_ORIGINAL_HEAD,
         "old original failed listener not preserved")
    return run


def verified_old_source():
    run = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(SOURCE_ORIGINAL))
    need(run.get("id") == SOURCE_ORIGINAL and run.get("head_sha") == SOURCE_ORIGINAL_HEAD
         and run.get("path") == SOURCE_PATH and run.get("event") == "push"
         and run.get("actor", {}).get("login") == "ShutenOishi"
         and run.get("run_attempt") == 1
         and run.get("status") == "completed" and run.get("conclusion") == "success",
         "old successful source not original")
    original_raw = contents(PATH, SOURCE_ORIGINAL_HEAD)
    decl = contract.validate_declaration(original_raw, PATH)
    need(decl["requestId"] == REQ and decl["mode"] == "AUDIT_ONLY",
         "original request expired/mismatched")
    return run, decl


def recover_source():
    receipt = {"requestId": RECOVERY_REQ, "result": "FAILED", "publisherAuthorized": False}
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                           object_pairs_hook=store.unique_pairs)
        head = os.environ["GITHUB_SHA"]
        need(os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
             and os.environ["GITHUB_WORKFLOW"] == RECOVERY_NAME
             and os.environ["GITHUB_EVENT_NAME"] == "push"
             and os.environ["GITHUB_REF"] == "refs/heads/main"
             and os.environ["GITHUB_ACTOR"] == "ShutenOishi"
             and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
             and event.get("after") == head and event.get("before") != head
             and event.get("sender", {}).get("login") == "ShutenOishi"
             and event.get("created") is False and event.get("deleted") is False,
             "not genuine protected recovery request")
        need(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == head,
             "recovery checkout not original")
        changed = subprocess.check_output(
            ["git", "diff", "--name-status", event["before"], head],
            text=True).splitlines()
        need(changed == ["A\t" + RECOVERY_PATH], "recovery not request-only")
        main = bridge.get_json("repos/pgextwin/build/branches/main")
        need(main.get("protected") is True and main.get("commit", {}).get("sha") == head,
             "recovery main not exact protected")
        raw = subprocess.check_output(["git", "show", "HEAD:" + RECOVERY_PATH])
        need(raw == contents(RECOVERY_PATH, head), "recovery original Git bytes")
        declaration = contract.validate_declaration(raw, RECOVERY_PATH)
        req = json.loads(raw, object_pairs_hook=store.unique_pairs)
        need(declaration["requestId"] == RECOVERY_REQ
             and declaration["mode"] == "AUDIT_ONLY"
             and set(declaration["targets"]) == set(scan.win.TARGETS)
             and len(declaration["targets"]) == 17
             and req["source"]["centralMainSha"] == event["before"]
             and req["source"]["fleetRegistryBlobSha"] == scan.FLEET_BLOB
             and req["approval"]["publicReleaseAuthorized"] is False
             and req["approval"]["publicationGrants"] == []
             and req["allowFutureUpdates"] is False,
             "recovery declaration privilege/target mismatch")
        old, old_decl = verified_old_source()
        original_failed_listener()
        old_state = bridge.get_json("repos/pgextwin/build/contents/" +
            store.PREFIX + REQ + ".json?ref=issue311-state")
        _, state = store.unpack(old_state, REQ)
        need(state["sourceRun"] == {"id": SOURCE_ORIGINAL, "attempt": 1}
             and state["revision"] == 1 and state["terminal"] is None
             and state["requestSha256"] == old_decl["rawSha256"]
             and len(state["targets"]) == 17
             and all(v == "PENDING" for v in state["targets"].values()),
             "old durable source checkpoint already changed")
        receipt.update(result="RECOVERY_ORIGINAL_VERIFIED",
                       recoveryRunId=int(os.environ["GITHUB_RUN_ID"]),
                       recoveryHeadSha=head, recoveryRequestSha256=declaration["rawSha256"],
                       originalSourceRunId=SOURCE_ORIGINAL,
                       originalSourceHeadSha=SOURCE_ORIGINAL_HEAD,
                       oldListenerRunId=FAILED_LISTENER,
                       originalStateRevision=1, targetCount=17)
    except Exception as exc:
        receipt["reason"] = str(exc)[:400]
    Path(RECOVERY_RECEIPT).write_text(json.dumps(receipt, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["result"] == "RECOVERY_ORIGINAL_VERIFIED" else 1


def recover_complete():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                       object_pairs_hook=store.unique_pairs)
    run = event.get("workflow_run", {})
    need(os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
         and os.environ["GITHUB_EVENT_NAME"] == "workflow_run"
         and os.environ["GITHUB_REF"] == "refs/heads/main"
         and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
         and event.get("action") == "completed"
         and event.get("repository", {}).get("full_name") == "pgextwin/build"
         and run.get("name") == RECOVERY_NAME
         and run.get("path") == RECOVERY_WORKFLOW
         and run.get("event") == "push" and run.get("head_branch") == "main"
         and run.get("actor", {}).get("login") == "ShutenOishi"
         and run.get("run_attempt") == 1
         and run.get("status") == "completed" and run.get("conclusion") == "success",
         "recovery completion event not genuine")
    current = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(run["id"]))
    for k in ("id", "head_sha", "run_attempt", "path", "event", "conclusion", "workflow_id"):
        need(current.get(k) == run.get(k), "recovery REST/event mismatch " + k)
    raw = contents(RECOVERY_PATH, run["head_sha"])
    declaration = contract.validate_declaration(raw, RECOVERY_PATH)
    need(declaration["requestId"] == RECOVERY_REQ, "recovery request invalid")
    source_artifacts = bridge.get_json("repos/pgextwin/build/actions/runs/" +
                                      str(run["id"]) + "/artifacts?per_page=100")
    entries = source_artifacts.get("artifacts", [])
    need(source_artifacts.get("total_count") == len(entries) == 1
         and entries[0].get("name") == RECOVERY_ARTIFACT
         and entries[0].get("expired") is False
         and entries[0].get("workflow_run", {}).get("id") == run["id"],
         "recovery original ZIP not unique")
    proof, _digest = bridge.original_zip(entries[0], RECOVERY_RECEIPT)
    need(proof.get("result") == "RECOVERY_ORIGINAL_VERIFIED"
         and proof.get("requestId") == RECOVERY_REQ
         and proof.get("recoveryRunId") == run["id"]
         and proof.get("recoveryHeadSha") == run["head_sha"]
         and proof.get("recoveryRequestSha256") == declaration["rawSha256"]
         and proof.get("oldListenerRunId") == FAILED_LISTENER
         and proof.get("originalSourceRunId") == SOURCE_ORIGINAL
         and proof.get("originalStateRevision") == 1
         and proof.get("targetCount") == 17
         and proof.get("publisherAuthorized") is False,
         "recovery original ZIP failed independent comparison")
    original_failed_listener()
    source, source_decl = verified_old_source()
    return complete(original_override=source, declaration_override=source_decl)


if __name__ == "__main__":
    raise SystemExit(source() if sys.argv[1:] == ["source"]
                     else complete() if sys.argv[1:] == ["complete"]
                     else recover_source() if sys.argv[1:] == ["recover-source"]
                     else recover_complete() if sys.argv[1:] == ["recover-complete"] else 2)
