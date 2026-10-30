#!/usr/bin/env python3
"""Fail-closed restoration of the SHA-pinned, nonpublishing R10 negative original report.

Only reads local Git evidence. No network, App token, writer, release or dispatch.
"""
from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "docs/audit/issue311-r10-negative-originals-20261031.json.gz.b64"
GZIP_SHA256 = "f15cd41a976b79bc2df3e6eb81f472a043e8cde0c88728c53c620b237dc2a05b"
RAW_SHA256 = "fa1464b9e4fb9234f66a279e6e6360f610b5a933e37483c1a3b70c9f14c10910"
RAW_LENGTH = 72255
ARCHIVE_LENGTH = 7433
CASE_ORDER = ("CONTROLLED_SKIP", "CONTROLLED_TIMEOUT", "REAL_PARALLEL_CAS", "CONTROLLED_MISSING_EVENT")

def need(value, reason):
    if not value:
        raise ValueError("R10_NEGATIVE_ARCHIVE_DENY " + reason)

def unique(pairs):
    d = {}
    for k,v in pairs:
        need(k not in d, "duplicate JSON field")
        d[k] = v
    return d

def restore(encoded=None):
    if encoded is None:
        encoded = ARCHIVE.read_bytes()
    need(type(encoded) is bytes and len(encoded) == ARCHIVE_LENGTH and
         encoded.endswith(b"\n") and encoded.count(b"\n") == 1,
         "invalid bounded Git archive")
    packed = base64.b64decode(encoded[:-1], validate=True)
    need(hashlib.sha256(packed).hexdigest() == GZIP_SHA256,
         "compressed exact byte digest mismatch")
    raw = gzip.decompress(packed)
    need(len(raw) == RAW_LENGTH and hashlib.sha256(raw).hexdigest() == RAW_SHA256,
         "restored original byte digest mismatch")
    report = json.loads(raw, object_pairs_hook=unique)
    need(report.get("schemaVersion") == 1 and report.get("nonpublishing") is True
         and report.get("complete") is False and report.get("accepted") is False
         and report.get("writerUsed") is False and report.get("appKeyUsed") is False,
         "nonpublishing incomplete original guards changed")
    cases = report.get("cases")
    need(type(cases) is list and len(cases) == 4
         and tuple(c.get("kind") for c in cases) == CASE_ORDER,
         "original four-case identity changed")
    for c in cases:
        t = c.get("perTarget")
        need(c.get("complete") is False and c.get("accepted") is False
             and c.get("stateTerminal") in ("QUARANTINED", "FAILED")
             and type(t) is list and len(t) == 17
             and len(set(x.get("repository") for x in t)) == 17,
             "original 17 terminal targets changed")
    for c in cases[:2]:
        targets = c["perTarget"]
        ok = [t for t in targets if t.get("originalEvidenceVerified") is True]
        absent = [t for t in targets if t.get("originalEvidenceVerified") is False]
        need(c.get("joinedOriginalChildren") == 16
             and c.get("unjoinedOriginalChildren") == 1
             and len(ok) == 16 and len(absent) == 1
             and all(t.get("originalRunId") and t.get("originalArtifactId") and
                     len(t.get("originalZipSha256", "")) == 64 and
                     t.get("missingEvidenceReason") is None for t in ok)
             and absent[0].get("repository") == "pgextwin/orafce"
             and absent[0].get("originalRunId") is None
             and absent[0].get("originalArtifactId") is None
             and absent[0].get("originalZipSha256") is None
             and absent[0].get("missingEvidenceReason") ==
                 "NO_DISPATCH_INPUT_BINDING_OR_ORIGINAL_CHILD_ZIP"
             and absent[0].get("corroboratedOriginalRun", {}).get("artifactCount") == 0,
             "partial failed original falsely accepted")
    race = cases[2]
    need(race.get("loserHttpStatus") == 409
         and race.get("writerPutCount") == {"A": 1, "B": 1}
         and race.get("sameTokenRevoked401") is True
         and all(x.get("originalChildZipSha256") is None for x in race["perTarget"]),
         "original real CAS state or single-PUT limit changed")
    event = cases[3]
    need(event["stateTerminal"] == "FAILED"
         and all(x.get("originalChildZipSha256") is None for x in event["perTarget"]),
         "event gap missing receipts falsely accepted")
    return raw

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--restore")
    ap.add_argument("--verify")
    args = ap.parse_args()
    need(not (args.restore and args.verify), "choose one action")
    raw = restore()
    if args.verify:
        need(Path(args.verify).read_bytes() == raw,
             "separate original report bytes mismatch")
    if args.restore:
        target = Path(args.restore)
        need(not target.exists(), "cannot overwrite original bytes")
        target.write_bytes(raw)
    print("R10_NEGATIVE_PROTECTED_ORIGINAL_MATCH " + RAW_SHA256)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
