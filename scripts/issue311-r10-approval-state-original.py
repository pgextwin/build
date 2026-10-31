#!/usr/bin/env python3
"""R10-02 authenticated GET-only State approval-evidence inventory; no writer."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = "pgextwin/build"
STATE_REF = "issue311-state"
DIR = "checkpoints/request-lifecycle"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"r-[0-9]{8}-[a-z0-9-]{8,56}\Z")
TERMINALS = {None, "NO_UPDATE", "QUARANTINED", "FAILED", "BLOCKED_APPROVAL", "SUCCESS"}

def need(ok, why):
    if not ok:
        raise ValueError("R10_APPROVAL_ORIGINAL_DENY " + why)

def blob_sha(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

def unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)

def inspect(name, sha, raw):
    need(type(name) is str and name.endswith(".json") and ID.fullmatch(name[:-5]), "bad original filename")
    need(SHA40.fullmatch(sha or "") and blob_sha(raw) == sha, "Git blob/bytes mismatch")
    state = unique_json(raw)
    need(type(state) is dict and state.get("schemaVersion") == 1
         and state.get("scope") == "AUDIT_ONLY_READONLY"
         and state.get("requestId") == name[:-5]
         and SHA64.fullmatch(state.get("requestSha256") or "")
         and SHA40.fullmatch(state.get("sourceHeadSha") or "")
         and type(state.get("revision")) is int and state["revision"] >= 0
         and state.get("publisherAuthorized") is False
         and state.get("writeOutcomeUnknown") is False
         and state.get("terminal") in TERMINALS,
         "unsafe/invalid State")
    targets, outcomes = state.get("targetScope"), state.get("targets")
    need(type(targets) is list and 1 <= len(targets) <= 17
         and len(set(targets)) == len(targets)
         and all(type(t) is str and t.startswith("pgextwin/") for t in targets)
         and type(outcomes) is dict and set(outcomes) == set(targets),
         "missing/duplicate target")
    blocked = [t for t in targets if outcomes[t] == "BLOCKED_APPROVAL"]
    need(not blocked or state["terminal"] == "BLOCKED_APPROVAL", "blocked target with wrong terminal")
    need(state["terminal"] != "BLOCKED_APPROVAL" or bool(blocked), "terminal without blocked target")
    for key in ("sourceRun", "completionRun"):
        run = state.get(key)
        need(run is None or (type(run) is dict and type(run.get("id")) is int
             and run["id"] > 0 and type(run.get("attempt")) is int
             and 1 <= run["attempt"] <= 3), "invalid original Run locator")
    return {"requestId": name[:-5], "blobSha": sha, "revision": state["revision"],
            "terminal": state["terminal"], "targetCount": len(targets),
            "blockedTargetCount": len(blocked), "sourceRun": state.get("sourceRun"),
            "sourceHeadSha": state["sourceHeadSha"],
            "humanApprovalEvidenceVerified": False, "realApprovalCasReceiptVerified": False,
            "r10_02Accepted": False}

def snapshot(commit, listing, reader):
    need(SHA40.fullmatch(commit or ""), "invalid State ref")
    need(type(listing) is list and len(listing) >= 29, "historical 29 checkpoint scope incomplete")
    seen = set()
    entries = []
    for item in sorted(listing, key=lambda v: v.get("name", "")):
        name = item.get("name")
        need(item.get("type") == "file" and name not in seen
             and item.get("path") == DIR + "/" + name, "missing/duplicate/nested original")
        seen.add(name)
        entries.append(inspect(name, item.get("sha"), reader(item, commit)))
    count = sum(int(row["blockedTargetCount"] > 0) for row in entries)
    return {"schemaVersion": 1, "mode": "AUTHENTICATED_GET_ONLY_NONPUBLISHING",
            "scope": "R10_02_ACTUAL_APPROVAL_EVIDENCE_GAP",
            "stateRef": STATE_REF, "stateCommitSha": commit,
            "checkpointCount": len(entries), "blockedApprovalCheckpointCount": count,
            "blockedApprovalTargetCount": sum(row["blockedTargetCount"] for row in entries),
            "gap": "NO_ACTUAL_BLOCKED_APPROVAL" if count == 0 else
                   "BLOCKED_STATE_HUMAN_APPROVAL_AND_ORIGINAL_CAS_STILL_UNVERIFIED",
            "r10_02Accepted": False, "publicationAuthorized": False,
            "writerUsed": False, "cronChanged": False, "checkpoints": entries}

def gh(path):
    return unique_json(subprocess.check_output(["gh", "api", path], timeout=90))

def reader(item, commit):
    record = gh("repos/" + REPO + "/contents/" + item["path"] + "?ref=" + commit)
    need(record.get("sha") == item["sha"] and record.get("path") == item["path"]
         and record.get("encoding") == "base64", "Contents GET mismatch")
    raw = base64.b64decode(record["content"], validate=False)
    need(len(raw) == record.get("size"), "State original length mismatch")
    return raw

def observe():
    ref = "repos/" + REPO + "/git/ref/heads/" + STATE_REF
    commit = gh(ref)["object"]["sha"]
    items = gh("repos/" + REPO + "/contents/" + DIR + "?ref=" + commit)
    proof = snapshot(commit, items, reader)
    need(gh(ref)["object"]["sha"] == commit, "State changed during snapshot")
    return proof

def serial(doc):
    return (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")

def main():
    need(os.environ.get("GITHUB_REPOSITORY") == REPO
         and os.environ.get("GITHUB_REF") == "refs/heads/main"
         and os.environ.get("GITHUB_EVENT_NAME") == "push"
         and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
         and bool(os.environ.get("GH_TOKEN")), "not authenticated original push")
    output = Path("issue311-r10-approval-original-state.json")
    raw = serial(observe())
    if "--verify" in sys.argv[1:]:
        need(output.read_bytes() == raw, "separate Runner original State mismatch")
    else:
        need(not output.exists(), "never overwrite receipt")
        output.write_bytes(raw)
    data = unique_json(raw)
    print("R10_APPROVAL_STATE_ORIGINAL", data["stateCommitSha"],
          "checkpoints", data["checkpointCount"],
          "blocked", data["blockedApprovalCheckpointCount"],
          "JSON_SHA256", hashlib.sha256(raw).hexdigest(), "R10_02_PENDING")

if __name__ == "__main__":
    main()
