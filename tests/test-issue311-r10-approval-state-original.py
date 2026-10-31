#!/usr/bin/env python3
"""R10 genuine approval evidence-gap hostile fixtures; no network or App key."""
import copy
import importlib.util
import json
from pathlib import Path

p = Path(__file__).resolve().parents[1] / "scripts/issue311-r10-approval-state-original.py"
spec = importlib.util.spec_from_file_location("r10approval", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
name = "r-20261031-r10approvalinventory01.json"
s = {"schemaVersion": 1, "scope": "AUDIT_ONLY_READONLY",
     "requestId": name[:-5], "requestSha256": "b"*64,
     "sourceHeadSha": "a"*40, "revision": 2,
     "publisherAuthorized": False, "writeOutcomeUnknown": False,
     "terminal": "QUARANTINED",
     "targetScope": ["pgextwin/orafce"],
     "targets": {"pgextwin/orafce": "QUARANTINED"},
     "sourceRun": {"id": 42, "attempt": 1}, "completionRun": None}

def raw(obj):
    return (json.dumps(obj, sort_keys=True) + "\n").encode()

def deny(fn):
    try:
        fn()
    except (ValueError, KeyError, TypeError):
        return
    raise AssertionError("R10_FALSE_APPROVAL_ACCEPTED")

original = raw(s)
assert m.inspect(name, m.blob_sha(original), original)["blockedTargetCount"] == 0
blocked = copy.deepcopy(s)
blocked["targets"]["pgextwin/orafce"] = "BLOCKED_APPROVAL"
deny(lambda: m.inspect(name, m.blob_sha(raw(blocked)), raw(blocked)))
blocked["terminal"] = "BLOCKED_APPROVAL"
record = m.inspect(name, m.blob_sha(raw(blocked)), raw(blocked))
assert record["blockedTargetCount"] == 1
assert record["humanApprovalEvidenceVerified"] is False
assert record["r10_02Accepted"] is False
for key, value in (("publisherAuthorized", True), ("writeOutcomeUnknown", True),
                   ("sourceHeadSha", "forged"), ("scope", "PUBLISH_ELIGIBLE"),
                   ("revision", -1)):
    bad = copy.deepcopy(s)
    bad[key] = value
    deny(lambda bad=bad: m.inspect(name, m.blob_sha(raw(bad)), raw(bad)))
deny(lambda: m.inspect(name, "f"*40, original))
deny(lambda: m.inspect("forged.json", m.blob_sha(original), original))
listing, content = [], {}
for index in range(29):
    entry = copy.deepcopy(s)
    filename = f"r-20261031-r10original{index:03d}.json"
    entry["requestId"] = filename[:-5]
    value = raw(entry)
    path = m.DIR + "/" + filename
    listing.append({"name": filename, "path": path, "type": "file",
                    "sha": m.blob_sha(value)})
    content[path] = value
proof = m.snapshot("a"*40, listing, lambda item, commit: content[item["path"]])
assert proof["checkpointCount"] == 29 and proof["blockedApprovalCheckpointCount"] == 0
assert proof["gap"] == "NO_ACTUAL_BLOCKED_APPROVAL"
assert proof["r10_02Accepted"] is False and proof["writerUsed"] is False
deny(lambda: m.snapshot("a"*40, listing[:-1], lambda item, commit: content[item["path"]]))
bad_list = copy.deepcopy(listing)
bad_list[0]["path"] = "forged/path.json"
deny(lambda: m.snapshot("a"*40, bad_list, lambda item, commit: content[item["path"]]))
print("R10_02_ORIGINAL_STATE_HOSTILE_POLICY_PASS")
