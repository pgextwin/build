#!/usr/bin/env python3
"""Immutable R10 negative original-byte join. GET-only; never uses App keys or writers."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

bridge = load("r10_negative_bridge", "scripts/issue311-r05-windows-completion-bridge.py")
client = load("r10_negative_children", "scripts/issue311-r06-child-join-live.py")
r10 = load("r10_negative_base", "scripts/issue311-r10-final-readonly-report.py")
SHA40 = r10.SHA40
SHA64 = r10.SHA64
BOT = r10.BOT
# Fixed from original first-attempt runs. These are real outer ZIP byte digests.
PROOFS = {
 "skip": (41014241399, 123926825986, 12959091676, "issue311-r06-app-fleet-original-terminal", "issue311-r06-app-fleet-original-terminal.json", "c62a8cd9c186d6eb69e012b5cc519ed0924a8e95f84f8b91b6d6f6f552709b9c"),
 "timeout": (41015355922, 123930349900, 12958899431, "issue311-r06-app-fleet-original-terminal", "issue311-r06-app-fleet-original-terminal.json", "a7920088b30517893c14fccbef4db7573dc8691fb8a6fcb43b33300b255583d0"),
 "race_a": (41032550321, 123985615959, 12965809030, "issue311-r06-parallel-A", "issue311-r06-parallel-A.json", "6d5eb77f29057533dab3d644e96eb2a4cc3e59a80563cac27f41569338ee81ca"),
 "race_b": (41032550321, 123985616098, 12965908472, "issue311-r06-parallel-B", "issue311-r06-parallel-B.json", "aeb8df3dcc638f2233b0349cdbb4ff6ec724db31887cb42940d0fc73ea798b8c"),
 "race_readback": (41032550321, 123986204379, 12966393631, "issue311-r06-parallel-keyless-readback", "issue311-r06-parallel-keyless-readback.json", "374721c538e498d287f8bc1621a4b69faef3aebccb6e9b70cd21fa47d7e3c0ce"),
 "event_source": (40864238327, 123414820570, 12893455362, "issue311-r04r05-original-source", "issue311-r04r05-original.json", "f2dbaafd1803a4536e134d99e60d9fd79d83daeb581997d2e53eed3b87a62d3b"),
}
SOURCE = "r-20261030-r06appauto41014241399"
TIMEOUT = "r-20261030-r06appauto41015355922"
RACE = "r-20261030-r06parallelcasproof12"
EVENT = "r-20261029-r05eventgap17b01"

def need(condition, reason):
    if not condition:
        raise ValueError("R10_NEGATIVE_DENY " + reason)

def strict_scope(case):
    targets = case["targets"]
    need(len(targets) == 17 and len({x["repository"] for x in targets}) == 17
         and case["stateRevision"] == 2 and case["r10_02Accepted"] is False
         and case["publicationAuthorized"] is False
         and case["terminal"] in ("QUARANTINED", "FAILED"), "original state/target scope")
    return {x["repository"]: x for x in targets}

def pinned(key):
    run_id, job_id, artifact_id, art_name, filename, digest = PROOFS[key]
    run = bridge.get_json(f"repos/pgextwin/build/actions/runs/{run_id}")
    need(run.get("id") == run_id and run.get("run_attempt") == 1
         and run.get("status") == "completed"
         and SHA40.fullmatch(run.get("head_sha", "")), "first-attempt source Run " + key)
    jobs = bridge.get_json(f"repos/pgextwin/build/actions/runs/{run_id}/attempts/1/jobs?per_page=100")
    need(jobs.get("total_count") == len(jobs.get("jobs", [])) <= 100
         and len([j for j in jobs["jobs"] if j.get("id") == job_id
                  and j.get("run_id") == run_id and j.get("status") == "completed"]) == 1,
         "original job mismatch " + key)
    listing = bridge.get_json(f"repos/pgextwin/build/actions/runs/{run_id}/artifacts?per_page=100")
    arts = listing.get("artifacts", [])
    need(listing.get("total_count") == len(arts) <= 100, "incomplete original artifacts")
    hits = [a for a in arts if a.get("id") == artifact_id and a.get("name") == art_name]
    need(len(hits) == 1 and hits[0].get("expired") is False
         and hits[0].get("workflow_run", {}).get("id") == run_id
         and hits[0].get("digest") == "sha256:" + digest, "original artifact mismatch " + key)
    receipt, actual = bridge.original_zip(hits[0], filename)
    need(actual == digest, "actual original outer ZIP mismatch " + key)
    return {"runId": run_id, "attempt": 1, "headSha": run["head_sha"],
            "runEvent": run["event"], "runConclusion": run["conclusion"],
            "jobId": job_id, "artifactId": artifact_id, "zipSha256": actual,
            "originalEntry": filename}, receipt

def verify_child(item):
    repo = item["repository"]
    rid, aid, sha = (item.get("localRunId"), item.get("originalReceiptArtifactId"),
                     item.get("originalReceiptZipSha256Verified"))
    need(type(rid) is int and type(aid) is int and SHA64.fullmatch(sha or "")
         and item.get("result") == "NO_UPDATE"
         and item.get("localAttempt") == 1
         and item.get("originalReceiptIndependentlyVerified") is True
         and item.get("sameTokenRevoked401") is True
         and item.get("appBotLogin") == BOT
         and item.get("publicationAuthorized") is False,
         "child receipt binding absent " + repo)
    run = client.get(repo, "actions/runs/" + str(rid))
    need(run.get("id") == rid and run.get("run_attempt") == 1
         and run.get("status") == "completed" and run.get("conclusion") == "success"
         and run.get("event") == "workflow_dispatch"
         and run.get("actor", {}).get("login") == BOT
         and SHA40.fullmatch(run.get("head_sha", "")), "original child Run mismatch " + repo)
    receipt, art = client.artifact(repo, rid, r10.CHILD_ARTIFACT, r10.CHILD_ENTRY,
                                 expected_id=aid, expected_digest=sha)
    need(receipt.get("localRunId") == rid
         and receipt.get("localRunAttempt") == 1
         and receipt.get("result") == "NO_UPDATE"
         and receipt.get("publicationAuthorized") is False
         and receipt.get("runtimeEnabled") is False
         and art["zipSha256"] == sha, "original child ZIP or receipt mismatch " + repo)
    return {"originalChildResult": "NO_UPDATE", "originalRunId": rid,
            "originalAttempt": 1, "originalSourceHeadSha": run["head_sha"],
            "originalArtifactId": aid, "originalZipSha256": sha,
            "originalEvidenceVerified": True}

def fleet(case_id, key):
    scope = strict_scope(r10.readonly_case(case_id))
    origin, receipt = pinned(key)
    need(origin["runEvent"] == "workflow_run" and origin["runConclusion"] == "failure"
         and receipt.get("result") == "QUARANTINED"
         and receipt.get("runtimeEnabled") is False
         and receipt.get("publicationAuthorized") is False
         and receipt.get("durableCasVerified") is False
         and receipt.get("sourceKind") == "AUTHENTIC_APP_BOT_17_LOCAL_ORIGINAL_NONPUBLISHING"
         and len(receipt.get("children", [])) == 17, "false accepted failed App fleet")
    items = {x["repository"]: x for x in receipt["children"]}
    need(set(items) == set(scope)
         and all(x.get("publicationAuthorized") is False for x in items.values()), "wrong failed fleet scope")
    missing = items["pgextwin/orafce"]
    need(missing.get("result") == "QUARANTINED"
         and "originalReceiptArtifactId" not in missing
         and "localRunId" not in missing
         and "originalReceiptZipSha256Verified" not in missing
         and missing.get("sameTokenRevoked401") is True
         and isinstance(missing.get("reason"), str), "orafce missing original falsely filled")
    normals = [x for repo, x in sorted(items.items()) if repo != "pgextwin/orafce"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        checked = dict(zip([x["repository"] for x in normals], pool.map(verify_child, normals)))
    rows = []
    for repo in sorted(scope):
        bound = scope[repo]
        row = {"repository": repo, "stateTerminal": "QUARANTINED",
               "stateStatus": bound["status"], "reasonCode": bound["reasonCode"],
               "sourceEvidence": origin, "safeRestartPoint": bound["safeRestartPoint"]}
        if repo in checked:
            row.update(checked[repo], missingEvidenceReason=None,
                       lastSucceededStage="INDEPENDENT_ORIGINAL_CHILD_ZIP_REHASH")
        else:
            row.update(originalChildResult="QUARANTINED",
                       originalRunId=None, originalAttempt=None, originalSourceHeadSha=None,
                       originalArtifactId=None, originalZipSha256=None,
                       originalEvidenceVerified=False,
                       failureReasonOriginal=missing["reason"],
                       missingEvidenceReason="ORAFCE_CHILD_ORIGINAL_RUN_AND_ZIP_ABSENT",
                       lastSucceededStage="APP_FLEET_SOURCE_FAILED_TERMINAL_ZIP_VERIFIED")
        rows.append(row)
    need(len(checked) == 16 and len(rows) == 17, "16+1 original count mismatch")
    return {"requestId": case_id, "kind": "CONTROLLED_" + key.upper(),
            "stateBlobSha": r10.readonly_case(case_id)["stateBlobSha"],
            "stateTerminal": "QUARANTINED", "sourceOriginal": origin,
            "perTarget": rows, "joinedOriginalChildren": 16, "unjoinedOriginalChildren": 1,
            "complete": False, "accepted": False}

def race():
    scope = strict_scope(r10.readonly_case(RACE))
    a, pa = pinned("race_a")
    b, pb = pinned("race_b")
    z, pz = pinned("race_readback")
    need(a["runId"] == b["runId"] == z["runId"] == 41032550321
         and a["runConclusion"] == b["runConclusion"] == z["runConclusion"] == "success"
         and pa.get("writer") == "A" and pb.get("writer") == "B"
         and pa.get("result") == "STALE_SHA_REJECTED" and pa.get("httpStatus") == 409
         and pb.get("result") == "QUARANTINED_WINNER"
         and pa.get("putCount") == pb.get("putCount") == 1
         and pa.get("sameTokenRevoked401") is True
         and pb.get("sameTokenRevoked401") is True
         and pa.get("publicationAuthorized") is False
         and pb.get("publicationAuthorized") is False
         and pa["expectedBlobSha"] == pb["expectedBlobSha"]
         and pa["observedBlobSha"] == pb["observedBlobSha"] == pz["stateBlobSha"]
         and pb["winningBlobSha"] == pz["stateBlobSha"]
         and pz.get("originalWriterOutcomes") ==
             {"A": "STALE_SHA_REJECTED", "B": "QUARANTINED_WINNER"}
         and pz.get("loserHttpStatus") == 409 and pz.get("revision") == 2
         and pz.get("targetCount") == 17 and pz.get("appKeyAvailable") is False
         and pz.get("replay") == "DENY_NO_PUT"
         and pz.get("publicationAuthorized") is False,
         "CAS original race false acceptance")
    rows = [{"repository": repo, "stateStatus": original["status"],
             "reasonCode": "SHARED_STATE_SINGLE_WINNER_CAS409",
             "originalChildRunId": None, "originalChildArtifactId": None,
             "originalChildZipSha256": None,
             "missingEvidenceReason": "NO_PER_TARGET_CHILD_RECEIPT_IN_CAS_CONTROL",
             "lastSucceededStage": "INDEPENDENT_KEYLESS_STATE_READBACK",
             "safeRestartPoint": original["safeRestartPoint"]} for repo, original in sorted(scope.items())]
    return {"requestId": RACE, "kind": "REAL_PARALLEL_CAS", "stateTerminal": "QUARANTINED",
            "stateBlobSha": pz["stateBlobSha"],
            "sourceOriginals": {"A": a, "B": b, "readback": z},
            "loserHttpStatus": 409, "writerPutCount": {"A": 1, "B": 1},
            "sameTokenRevoked401": True, "perTarget": rows,
            "complete": False, "accepted": False}

def event_gap():
    scope = strict_scope(r10.readonly_case(EVENT))
    origin, receipt = pinned("event_source")
    need(origin["runConclusion"] == "success"
         and receipt.get("requestId") == EVENT
         and receipt.get("sourceRunId") == origin["runId"]
         and receipt.get("runAttempt") == 1
         and receipt.get("sourceSha") == origin["headSha"]
         and receipt.get("remoteProtected") is True
         and receipt.get("publisherAuthorized") is False
         and receipt.get("result") == "SUCCESS"
         and set(receipt.get("perTarget", {})) == set(scope),
         "original event-gap source mismatch")
    rows = [{"repository": repo, "stateStatus": state["status"],
             "sourceProtectedMainSha": receipt["perTarget"][repo],
             "reasonCode": "CONTROLLED_MISSING_EVENT_BOUNDED_WATCHDOG",
             "originalChildRunId": None, "originalChildArtifactId": None,
             "originalChildZipSha256": None,
             "missingEvidenceReason": "SOURCE_ONLY_NO_CHILD_EVENT_RECEIPT",
             "lastSucceededStage": "SOURCE_ORIGINAL_PROTECTED_GET",
             "safeRestartPoint": state["safeRestartPoint"]} for repo, state in sorted(scope.items())]
    return {"requestId": EVENT, "kind": "CONTROLLED_MISSING_EVENT",
            "sourceOriginal": origin, "stateTerminal": "FAILED",
            "perTarget": rows, "complete": False, "accepted": False}

def serial(obj):
    return (json.dumps(obj, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode("ascii")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="issue311-r10-negative-originals.json")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    need(bool(os.environ.get("GH_TOKEN")), "read-only GitHub token required")
    report = {"schemaVersion": 1, "nonpublishing": True, "complete": False,
              "accepted": False, "writerUsed": False, "appKeyUsed": False,
              "cases": [fleet(SOURCE, "skip"), fleet(TIMEOUT, "timeout"), race(), event_gap()]}
    raw = serial(report)
    path = Path(args.output)
    if args.verify:
        need(path.exists() and path.read_bytes() == raw,
             "separate runner original-byte report disagrees")
    else:
        path.write_bytes(raw)
    print("R10_NEGATIVE_ORIGINAL_INDEPENDENT_MATCH " + hashlib.sha256(raw).hexdigest())
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
