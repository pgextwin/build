#!/usr/bin/env python3
"""Independent original-source/ZIP/Sigstore audit for Issue #112 (no publication).

This script NEVER issues download admission, a Release, or Publisher authority.
The auditor does not execute or import the candidate ZIP builder.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile


SOURCE_REPO = "rjuju/pg_track_settings"
SOURCE_SHA = "36a23f3c6d684c40140da1a24b1c3ee0e707b77a"
CATALOG_SHA = "c87161a39c0c18ad849082f41e75e7fc40cf6a92"
MAJORS = ("14", "15", "16", "17", "18")
KIND = "PGEXTWIN_OWNED_SOURCE_ONLY_PRIVATE_PILOT_NOT_CYBERTEC_ORIGINAL"
SCHEMA = "pgextwin-issue112-track-owned-source-pilot/v1"
WORKFLOW = ".github/workflows/issue112-track-owned-source-signed.yml"
FLAGS = ("cybertecProducerAttestation", "independentSignatureVerified",
         "downloadAuthorized", "mirrorAuthorized", "releaseAuthorized",
         "publisherAuthorized")


class Denied(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Denied("SIGNED_SOURCE_DENY: " + reason)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def read_exact_source(source):
    source = Path(source)
    need(source.is_dir() and not source.is_symlink(), "invalid source")
    p = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                       text=True, capture_output=True, timeout=15, check=False)
    need(p.returncode == 0 and p.stdout.strip() == SOURCE_SHA,
         "wrong immutable upstream checkout")
    status = subprocess.run(["git", "-C", str(source), "status", "--porcelain",
                             "--untracked-files=no"], text=True, capture_output=True,
                            timeout=15, check=False)
    need(status.returncode == 0 and not status.stdout.strip(), "modified source checkout")
    sql = sorted(p.name for p in source.iterdir()
                 if p.is_file() and not p.is_symlink()
                 and p.name.startswith("pg_track_settings--")
                 and p.name.endswith(".sql"))
    need(len(sql) == 12 and len(set(sql)) == 12, "unexpected SQL inventory")
    names = ["LICENSE", "pg_track_settings.control", *sql]
    need(len(names) == 14, "unexpected source inventory")
    files = {}
    for name in names:
        path = source / name
        need(path.is_file() and not path.is_symlink()
             and 0 < path.stat().st_size < 100_000, "unsafe source member")
        files[name] = path.read_bytes()
    need(b"Copyright (c) 2015-2023, Julien Rouhaud" in files["LICENSE"]
         and b"provided that the above copyright notice" in files["LICENSE"],
         "missing upstream copyright and redistribution notice")
    need(b"default_version = '2.1.2'" in files["pg_track_settings.control"],
         "wrong source version")
    return files


def inspect_local(dist, files):
    dist = Path(dist)
    expected_files = {f"pg_track_settings-source-pg{pg}.zip" for pg in MAJORS}
    need(dist.is_dir() and not dist.is_symlink(), "invalid artifact folder")
    actual_files = {p.name for p in dist.iterdir() if p.is_file()}
    need(actual_files == expected_files, "missing or unexpected candidate ZIP")
    digests = {}
    expected_members = sorted(["LICENSE", "SOURCE-INPUTS.json"] +
                              ["share/extension/" + n for n in files if n != "LICENSE"])
    expected_hashes = {n: sha256(raw) for n, raw in sorted(files.items())}
    for pg in MAJORS:
        name = f"pg_track_settings-source-pg{pg}.zip"
        p = dist / name
        need(not p.is_symlink() and 0 < p.stat().st_size < 2_000_000,
             "invalid archive size or link")
        raw = p.read_bytes()
        try:
            with zipfile.ZipFile(p) as z:
                items = z.infolist()
                need([i.filename for i in items] == expected_members
                     and len(items) == 15 and len(set(i.filename for i in items)) == 15,
                     "ZIP member allowlist mismatch")
                need(all(i.file_size < 100_000 and i.compress_type == zipfile.ZIP_DEFLATED
                         and (i.external_attr >> 16) == 0o100644 for i in items),
                     "unexpected ZIP attributes")
                need(z.testzip() is None, "ZIP CRC mismatch")
                for source_name, value in files.items():
                    member = "LICENSE" if source_name == "LICENSE" else (
                        "share/extension/" + source_name)
                    need(z.read(member) == value, "source member byte mismatch")
                meta = json.loads(z.read("SOURCE-INPUTS.json"))
        except (OSError, zipfile.BadZipFile, KeyError, UnicodeError) as e:
            raise Denied("SIGNED_SOURCE_DENY: malformed ZIP") from e
        need(type(meta) is dict and set(meta) == {
            "schemaVersion", "status", "kind", "upstreamRepository", "upstreamCommit",
            "upstreamVersion", "postgresqlMajor", "sourceFileSha256",
            "rightsNoticeIncluded", *FLAGS}, "unexpected source metadata fields")
        need(meta["schemaVersion"] == SCHEMA and meta["kind"] == KIND
             and meta["status"] == "CANDIDATE_ONLY"
             and meta["upstreamRepository"] == SOURCE_REPO
             and meta["upstreamCommit"] == SOURCE_SHA
             and meta["upstreamVersion"] == "2.1.2"
             and meta["postgresqlMajor"] == pg
             and meta["rightsNoticeIncluded"] is True
             and meta["sourceFileSha256"] == expected_hashes
             and all(meta[k] is False for k in FLAGS),
             "metadata/source/deny flags mismatch")
        digests[name] = sha256(raw)
    need(len(set(digests.values())) == 5, "PG-specific candidate collision")
    return digests


def verify_attestation(dist, repo, sha, digests):
    need(repo == "pgextwin/build" and len(sha) == 40 and
         all(c in "0123456789abcdef" for c in sha), "invalid signed source identity")
    for name in sorted(digests):
        cmd = ["gh", "attestation", "verify", str(Path(dist) / name),
               "--repo", repo,
               "--signer-workflow", repo + "/" + WORKFLOW,
               "--source-digest", sha, "--source-ref", "refs/heads/main",
               "--predicate-type", "https://slsa.dev/provenance/v1",
               "--format", "json"]
        cp = subprocess.run(cmd, text=True, capture_output=True,
                            timeout=180, check=False)
        need(cp.returncode == 0 and 0 < len(cp.stdout) < 4_000_000,
             "cryptographic attestation verification failed")
        proof = json.loads(cp.stdout)
        need(type(proof) is list and len(proof) == 1 and
             type(proof[0]) is dict and "verificationResult" in proof[0],
             "ambiguous Sigstore verification result")


def audit(args):
    need(os.environ.get("GITHUB_EVENT_NAME") == "push" and
         os.environ.get("GITHUB_REF") == "refs/heads/main" and
         os.environ.get("GITHUB_REPOSITORY") == "pgextwin/build" and
         os.environ.get("GITHUB_RUN_ATTEMPT") == "1" and
         os.environ.get("GITHUB_SHA") == args.sha and
         os.environ.get("GITHUB_RUN_ID") == args.run_id and
         args.auditor in ("first", "second"), "not original protected-main audit")
    files = read_exact_source(args.source)
    digests = inspect_local(args.dist, files)
    verify_attestation(args.dist, "pgextwin/build", args.sha, digests)
    receipt = {"status": "SIGNED_SOURCE_NONPUBLISHING",
               "sourceKind": "PGEXTWIN_TRACK_OWNED_SOURCE_MAIN_PUSH",
               "repository": "pgextwin/build", "mainSha": args.sha,
               "runId": args.run_id, "runAttempt": 1, "event": "push",
               "auditor": args.auditor, "upstreamSha": SOURCE_SHA,
               "catalogSha": CATALOG_SHA, "zipSha256": digests,
               "publicGetAuthorized": False, "releaseAuthorized": False,
               "publisherAuthorized": False, "PUBLISH": "DENY"}
    Path(args.output).write_text(json.dumps(receipt, sort_keys=True) + "\n",
                                 encoding="utf-8")


def join(args):
    first, second = (json.loads(Path(path).read_text("utf-8"))
                     for path in (args.first, args.second))
    need(first.get("auditor") == "first" and second.get("auditor") == "second",
         "auditor identity collision")
    for receipt in (first, second):
        need(receipt.get("status") == "SIGNED_SOURCE_NONPUBLISHING"
             and receipt.get("mainSha") == args.sha
             and receipt.get("runId") == args.run_id
             and receipt.get("repository") == "pgextwin/build"
             and receipt.get("runAttempt") == 1 and receipt.get("event") == "push"
             and receipt.get("PUBLISH") == "DENY"
             and receipt.get("publicGetAuthorized") is False
             and receipt.get("releaseAuthorized") is False
             and receipt.get("publisherAuthorized") is False,
             "not a qualifying original nonpublishing audit")
    keys = set(first) - {"auditor"}
    need(keys == set(second) - {"auditor"}
         and all(first[k] == second[k] for k in keys)
         and set(first["zipSha256"]) ==
         {f"pg_track_settings-source-pg{pg}.zip" for pg in MAJORS},
         "independent auditor evidence disagreement")
    print(json.dumps({"status": "SIGNED_NONPUBLISHING_DUAL_VERIFIED",
                      "runId": args.run_id, "mainSha": args.sha,
                      "packageCount": 5, "PUBLISH": "DENY"}, sort_keys=True))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("audit")
    for key in ("source", "dist", "sha", "run-id", "auditor", "output"):
        a.add_argument("--" + key, required=True)
    j = sub.add_parser("join")
    for key in ("first", "second", "sha", "run-id"):
        j.add_argument("--" + key, required=True)
    args = p.parse_args()
    if args.command == "audit":
        audit(args)
    else:
        join(args)


if __name__ == "__main__":
    main()
