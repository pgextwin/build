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


SOURCE_REPO = "cybertec-postgresql/pg_permissions"
SOURCE_SHA = "3360447e0668fed2b9db6a0ae1d086533781f9bd"
CATALOG_SHA = "7f18abe7d72795d0880c78300099abd5e96e12f8"
MAJORS = ("14", "15", "16", "17", "18")
KIND = "PGEXTWIN_OWNED_SQL_SOURCE_NOT_CYBERTEC_ORIGINAL"
SCHEMA = "pgextwin-issue112-pg-permissions-owned-source-private/v1"
WORKFLOW = ".github/workflows/issue112-permissions-owned-source-signed.yml"
FLAGS = ("cybertecOriginalZip", "cybertecProducerAttestationVerified",
         "independentSourceSignatureVerified", "windowsRuntimeFromThisZipVerified",
         "downloadAuthorized", "mirrorAuthorized", "releaseAuthorized",
         "publisherAuthorized")


class Denied(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Denied("SIGNED_SOURCE_DENY: " + reason)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate JSON field")
        out[key] = value
    return out


PINS = {
    "LICENSE": "1fd282a61d03946e180a0b82a7c82d553e175db8",
    "pg_permissions--1.0--1.1.sql": "ecacee96ce0dc1c13cb35bf3aafb31f67a8486e6",
    "pg_permissions--1.0.sql": "555465bd0c1853b69f8c0d3f953528b0c8535dfb",
    "pg_permissions--1.1--1.2.sql": "2a70e2f76419483816c436fadfea8dbf3f3f5a94",
    "pg_permissions--1.1.sql": "e8cef904e8c12957708697fbdf38f9a5fa8d8e3a",
    "pg_permissions--1.2.sql": "f6b43975bf7b90c9be2a38d3f7c8d4d5f8908c6f",
    "pg_permissions--1.3--1.4.sql": "5700c17d30c84d1b284e1a48fe33d6d92e8a5336",
    "pg_permissions--1.3.sql": "2ca444b8dc619b1a08530b71ed7855771d266231",
    "pg_permissions.control": "18ec7b614454c98b3c33b1d8e7af84167fb6e624",
}


def read_exact_source(source):
    source = Path(source)
    need(source.is_dir() and not source.is_symlink(), "invalid immutable source checkout")
    rev = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                         text=True, capture_output=True, timeout=15, check=False)
    need(rev.returncode == 0 and rev.stdout.strip() == SOURCE_SHA, "wrong upstream commit")
    tree = subprocess.run(["git", "-C", str(source), "ls-tree", "HEAD", "--",
                           *sorted(PINS)], text=True, capture_output=True,
                          timeout=15, check=False)
    need(tree.returncode == 0, "unreadable source tree")
    tree_ids = {}
    for line in tree.stdout.splitlines():
        try:
            spec, name = line.split("\t", 1)
            mode, kind, oid = spec.split()
        except ValueError as exc:
            raise Denied("SIGNED_SOURCE_DENY: invalid Git tree") from exc
        need(mode == "100644" and kind == "blob" and name not in tree_ids,
             "untrusted Git source member")
        tree_ids[name] = oid
    need(tree_ids == PINS, "wrong source blob identity")
    worktree = subprocess.run(["git", "-C", str(source), "status", "--porcelain",
                               "--untracked-files=no"], text=True, capture_output=True,
                              timeout=15, check=False)
    need(worktree.returncode == 0 and not worktree.stdout.strip(),
         "modified immutable source checkout")
    found = {p.name for p in source.iterdir() if p.is_file() and
             (p.name in ("LICENSE", "pg_permissions.control") or
              (p.name.startswith("pg_permissions--") and p.name.endswith(".sql")))}
    need(found == set(PINS), "unexpected installable member")
    files = {}
    for name in sorted(PINS):
        path = source / name
        need(path.is_file() and not path.is_symlink() and
             0 < path.stat().st_size < 2_000_000, "unsafe source member")
        raw = path.read_bytes()
        oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        need(oid == PINS[name], "source bytes differ from immutable blob")
        files[name] = raw
    need(b"Copyright (c) 2018-2023, CYBERTEC" in files["LICENSE"] and
         b"provided that the above copyright notice" in files["LICENSE"],
         "missing complete original license")
    need(b"default_version = '1.4'" in files["pg_permissions.control"],
         "SQL extension version mismatch")
    return files


def inspect_local(dist, files):
    dist = Path(dist)
    need(dist.is_dir() and not dist.is_symlink(), "invalid audit artifact directory")
    expected_names = {f"pg_permissions-source-pg{pg}.{suffix}" for pg in MAJORS
                      for suffix in ("zip", "spdx.json")}
    need({p.name for p in dist.iterdir()} == expected_names,
         "missing or unexpected ZIP/SPDX artifact")
    members_expected = sorted(["LICENSE", "SOURCE-INPUTS.json"] +
                              ["share/extension/" + n for n in files if n != "LICENSE"])
    need(len(members_expected) == 10, "wrong source archive allowlist")
    hashes = {n: sha256(v) for n, v in sorted(files.items())}
    all_digests = {}
    for pg in MAJORS:
        name = f"pg_permissions-source-pg{pg}.zip"
        zpath = dist / name
        spdx_name = f"pg_permissions-source-pg{pg}.spdx.json"
        spath = dist / spdx_name
        need(zpath.is_file() and not zpath.is_symlink() and
             spath.is_file() and not spath.is_symlink() and
             0 < zpath.stat().st_size < 2_000_000 and
             0 < spath.stat().st_size < 2_000_000,
             "oversized, missing, or symlinked signed artifact")
        raw = zpath.read_bytes()
        try:
            with zipfile.ZipFile(zpath, "r") as z:
                infos = z.infolist()
                need([i.filename for i in infos] == members_expected and
                     len(infos) == 10 and len({i.filename for i in infos}) == 10,
                     "unexpected ZIP members")
                need(all(i.file_size < 2_000_000 and i.compress_type == zipfile.ZIP_DEFLATED
                         and (i.external_attr >> 16) == 0o100644 for i in infos),
                     "ZIP metadata mismatch")
                need(z.testzip() is None, "ZIP CRC failure")
                for n, value in files.items():
                    member = "LICENSE" if n == "LICENSE" else "share/extension/" + n
                    need(z.read(member) == value, "original source byte mismatch")
                receipt = json.loads(z.read("SOURCE-INPUTS.json"),
                                     object_pairs_hook=unique_pairs)
                contents = {n: z.read(n) for n in members_expected}
            spdx = json.loads(spath.read_text(encoding="utf-8"),
                              object_pairs_hook=unique_pairs)
        except (OSError, zipfile.BadZipFile, KeyError, UnicodeError, ValueError) as exc:
            raise Denied("SIGNED_SOURCE_DENY: malformed ZIP or SPDX") from exc
        need(type(receipt) is dict and set(receipt) ==
             {"schemaVersion", "status", "kind", "upstreamRepository", "upstreamCommit",
              "upstreamPackageVersion", "sqlExtensionDefaultVersion", "postgresqlMajor",
              "sourceFileSha256", "fullUpstreamLicenseIncluded", *FLAGS},
             "source receipt fields mismatch")
        need(receipt["schemaVersion"] == SCHEMA and receipt["status"] == "CANDIDATE_ONLY" and
             receipt["kind"] == KIND and receipt["upstreamRepository"] == SOURCE_REPO and
             receipt["upstreamCommit"] == SOURCE_SHA and
             receipt["upstreamPackageVersion"] == "1.4.1" and
             receipt["sqlExtensionDefaultVersion"] == "1.4" and
             receipt["postgresqlMajor"] == pg and
             receipt["sourceFileSha256"] == hashes and
             receipt["fullUpstreamLicenseIncluded"] is True and
             all(receipt[f] is False for f in FLAGS),
             "source receipt or authorization altered")
        need(spdx.get("spdxVersion") == "SPDX-2.3" and
             spdx.get("dataLicense") == "CC0-1.0" and
             spdx.get("name") == "pgextwin-private-pg_permissions-1.4.1-pg" + pg and
             spdx.get("documentNamespace") ==
             "https://spdx.org/spdxdocs/pgextwin-issue112-private-" + sha256(raw),
             "SPDX source package identity mismatch")
        packages = spdx.get("packages")
        need(type(packages) is list and len(packages) == 1 and
             packages[0].get("downloadLocation") == "NOASSERTION" and
             packages[0].get("filesAnalyzed") is True and
             packages[0].get("sourceInfo") == "Exact pinned source commit " + SOURCE_SHA and
             packages[0].get("checksums") ==
             [{"algorithm": "SHA256", "checksumValue": sha256(raw)}],
             "SPDX package fingerprint mismatch")
        items = spdx.get("files")
        need(type(items) is list and len(items) == 10 and
             {f.get("fileName") for f in items} ==
             {"./" + n for n in members_expected}, "SPDX file list mismatch")
        for f in items:
            n = f["fileName"][2:]
            need(f.get("checksums") ==
                 [{"algorithm": "SHA1", "checksumValue": hashlib.sha1(contents[n]).hexdigest()},
                  {"algorithm": "SHA256", "checksumValue": sha256(contents[n])}] and
                 f.get("licenseConcluded") == "NOASSERTION",
                 "SPDX individual member fingerprint mismatch")
        all_digests[name] = sha256(raw)
        all_digests[spdx_name] = sha256(spath.read_bytes())
    need(len({all_digests[f"pg_permissions-source-pg{pg}.zip"] for pg in MAJORS}) == 5,
         "PG-major-specific ZIP digests collided")
    return all_digests


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
               "sourceKind": "PGEXTWIN_PERMISSIONS_OWNED_SOURCE_MAIN_PUSH",
               "repository": "pgextwin/build", "mainSha": args.sha,
               "runId": args.run_id, "runAttempt": 1, "event": "push",
               "auditor": args.auditor, "upstreamSha": SOURCE_SHA,
               "catalogSha": CATALOG_SHA, "artifactSha256": digests,
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
         and set(first["artifactSha256"]) ==
         {f"pg_permissions-source-pg{pg}.{suffix}" for pg in MAJORS
          for suffix in ("zip", "spdx.json")},
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
