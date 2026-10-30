#!/usr/bin/env python3
"""Restore and verify the lossless R10-02 original report retained in protected Git.

No network access, App key, workflow dispatch, writer, or publish authority.
The archive is immutable evidence of what was observed on 2026-10-31,
not an acceptance declaration or an authorization to release.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "docs" / "audit" / "issue311-r10-original-report-20261031.json.gz.b64"
REPORT_SHA256 = "615d32b8493ee292daea971d456d08fc74ff9b309690762ff05cd9c97f089688"
GZIP_SHA256 = "67556af5d455eff262e5a719c86fe017c40b365c9effbec8716e90c8a79d3793"
RAW_LENGTH = 76647
CASES = (
    "r-20261030-r06appauto41074138918",
    "r-20261030-r06appauto41014241399",
    "r-20261030-r06appauto41015355922",
    "r-20261029-r05eventgap17b01",
    "r-20261030-r06parallelcasproof12",
    "r-20261030-r06appauto41014731356",
)


def need(ok, reason):
    if not ok:
        raise ValueError("R10_PROTECTED_ARCHIVE_DENY " + reason)


def unique(pairs):
    obj = {}
    for key, value in pairs:
        need(key not in obj, "duplicate JSON field")
        obj[key] = value
    return obj


def restore(encoded=None):
    if encoded is None:
        encoded = ARCHIVE.read_bytes()
    need(type(encoded) is bytes and 0 < len(encoded) <= 12000
         and encoded.endswith(b"\n") and encoded.count(b"\n") == 1,
         "invalid bounded Git archive")
    packed = base64.b64decode(encoded[:-1], validate=True)
    need(hashlib.sha256(packed).hexdigest() == GZIP_SHA256, "compressed byte SHA mismatch")
    raw = gzip.decompress(packed)
    need(len(raw) == RAW_LENGTH and hashlib.sha256(raw).hexdigest() == REPORT_SHA256,
         "original report SHA/length mismatch")
    report = json.loads(raw, object_pairs_hook=unique)
    need(report.get("schemaVersion") == 1 and report.get("nonpublishing") is True
         and report.get("accepted") is False and report.get("complete") is False
         and type(report.get("cases")) is list and len(report["cases"]) == 6
         and tuple(c.get("requestId") for c in report["cases"]) == CASES,
         "original incomplete six-case scope changed")
    for case in report["cases"]:
        targets = case.get("targets")
        need(case.get("r10_02Accepted") is False
             and case.get("publicationAuthorized") is False
             and type(targets) is list and len(targets) == 17
             and len({t.get("repository") for t in targets}) == 17,
             "original nonpublishing targets or guards changed")
        if case.get("terminal") == "NO_UPDATE":
            need(case.get("evidenceCompleteness") == "COMPLETE_17_ORIGINAL_ZIP"
                 and all(t.get("originalZipSha256") for t in targets),
                 "normal original receipt changed")
        else:
            need(case.get("evidenceCompleteness") == "INCOMPLETE_TARGET_REASON_AND_ZIP_FAIL_CLOSED"
                 and all(t.get("missingEvidenceReason") for t in targets),
                 "unjoined negative original was falsely accepted")
    return raw


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", help="compare existing independently recomputed original report")
    parser.add_argument("--restore", help="restore exact archived report to a file")
    args = parser.parse_args()
    need(not (args.verify and args.restore), "choose one mode")
    raw = restore()
    if args.verify:
        need(Path(args.verify).read_bytes() == raw, "original authenticated Git GET differs from protected report")
    if args.restore:
        path = Path(args.restore)
        need(not path.exists(), "never overwrite existing evidence")
        path.write_bytes(raw)
    print("R10_PROTECTED_ORIGINAL_REPORT_MATCH " + REPORT_SHA256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
