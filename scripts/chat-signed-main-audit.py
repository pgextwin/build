#!/usr/bin/env python3
"""Independent real-byte/Sigstore audits for genuine owner-comment main source.

A distinct, NONPUBLISHING source type. No push/schedule impersonation, Release,
Publisher App, or publication authorization. Two isolated audit jobs must agree.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from zipfile import ZipFile, BadZipFile

ROOT = Path(__file__).resolve().parent


def module(label, name):
    spec = importlib.util.spec_from_file_location(label, ROOT / name)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


ident = module("owner_main_ident", "fleet-release-identity.py")
pin = module("owner_main_pin", "issue-75-attempt-pin-migration-offline.py")
vuln = module("owner_main_grype", "automatic-grype-publisher-policy.py")
SOURCE_KIND = "OWNER_ISSUE_COMMENT_MAIN_SIGNING"
CALLER = ".github/workflows/chat-signed-main.yml"
# Exact approved builder digest for this genuine owner source only.  Legacy
# workflow_dispatch/manual provenance pins remain separate and unchanged.
# Change only with protected source workflow pin, required CI, and original
# postmerge proof. No wildcard or fallback signer is authorized.
OWNER_SIGNER_SHA = "95418c3b16a843854e931bd4089a4f5827ffe211"


class Denied(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Denied(why)


def read(path):
    return json.loads(Path(path).read_text("utf-8"))


def verify(z, kind, repo, sha):
    cmd = ["gh", "attestation", "verify", str(z), "--repo", repo,
           "--signer-workflow", "pgextwin/build/" + pin.offline.SIGNER_PATH,
           "--signer-digest", OWNER_SIGNER_SHA, "--source-digest", sha,
           "--source-ref", "refs/heads/main", "--predicate-type", kind,
           "--format", "json"]
    cp = subprocess.run(cmd, text=True, capture_output=True, timeout=180, check=False)
    need(cp.returncode == 0 and 0 < len(cp.stdout) < 4_000_000,
         "real GitHub Sigstore verification failed")
    result = json.loads(cp.stdout)
    need(type(result) is list and len(result) == 1
         and type(result[0]) is dict
         and "verificationResult" in result[0],
         "ambiguous signed proof")
    return {"verificationResult": result[0]["verificationResult"]}


def audit(folder, intent, manifest, lifecycle, *, repo, sha, run_id, auditor):
    need(auditor in ("first", "second") and type(intent) is dict
         and intent.get("sourceKind") == SOURCE_KIND
         and intent.get("repository") == repo
         and intent.get("mainSha") == sha and intent.get("runId") == run_id
         and intent.get("runAttempt") == 1
         and intent.get("sourceEvent") == "issue_comment"
         and intent.get("signingEligible") is True
         and intent.get("publisherEligible") is False
         and intent.get("publicationAuthorized") is False,
         "untrusted nonpublishing source intent")
    need(type(manifest) is dict and manifest.get("name") == repo.split("/")[-1],
         "wrong manifest")
    majors = ident.maintained_majors(manifest, lifecycle)
    sources = ident.sources(manifest)
    expected = ident.expected_assets(manifest, majors) - {"SHA256SUMS.txt"}
    files = {f.name for f in folder.iterdir() if f.is_file()}
    need(files == expected, "missing/extra signed artifact bytes")
    digests = {}
    for major in majors:
        stem = ident.asset_stem(manifest, major)
        z, s, g = (folder / (stem + ext) for ext in
                   (".zip", ".spdx.json", ".vulnerabilities.json"))
        for f in (z, s, g):
            need(f.is_file() and 0 < f.stat().st_size < 1024**3,
                 "signed byte missing or oversize")
            digests[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
        try:
            with ZipFile(z) as archive:
                need(archive.testzip() is None, "invalid ZIP CRC")
                info = [f for f in archive.infolist() if f.filename == "PACKAGE-INFO.json"]
                need(len(info) == 1 and info[0].file_size < 256_000, "ambiguous package")
                pkg = json.loads(archive.read(info[0]).decode("utf-8-sig"))
        except (BadZipFile, UnicodeError, KeyError, OSError, ValueError):
            raise Denied("invalid ZIP/PACKAGE-INFO")
        wf = pkg.get("workflowRun") or {}
        upstream = pkg.get("upstream")
        origin = pkg.get("source") or {}
        build = pkg.get("buildInfrastructure") or {}
        package = pkg.get("package") or {}
        need(pkg.get("buildMode") == "release-attested"
             and package.get("name") == manifest["name"]
             and package.get("platform") == "windows"
             and package.get("architecture") == "x64"
             and (pkg.get("postgresql") or {}).get("major") == major
             and upstream == {"repository": manifest["upstream"]["repository"],
                              "ref": sources[major]["ref"],
                              "version": sources[major]["version"],
                              "commit": sources[major]["commit"]}
             and origin.get("packagingRepository") == repo
             and origin.get("packagingCommit") == sha
             and build.get("repository") == "pgextwin/build"
             and build.get("workflow") == pin.offline.SIGNER_PATH
             and build.get("commit") == OWNER_SIGNER_SHA
             and wf.get("id") == run_id and wf.get("attempt") == 1
             and wf.get("event") == "issue_comment"
             and wf.get("ref") == "refs/heads/main"
             and wf.get("url") == f"https://github.com/{repo}/actions/runs/{run_id}",
             "package source/manifest/run/signer mismatch")
        sbom, grype = read(s), read(g)
        need(type(sbom) is dict and sbom.get("spdxVersion") == "SPDX-2.3"
             and type(grype) is dict and type(grype.get("matches")) is list,
             "missing SPDX/Grype evidence")
        vuln.review(grype, asset_stem=stem)
        for kind in (pin.SLSA, pin.SPDX):
            proof = verify(z, kind, repo, sha)
            pin.proof_statement(proof, kind, repo=repo, sha=sha,
                                signer_sha=OWNER_SIGNER_SHA, run_id=run_id,
                                attempt=1, event="issue_comment",
                                config_path=CALLER, zip_name=z.name,
                                zip_digest=digests[z.name], sbom=sbom)
    return {"schemaVersion": 1, "status": "VERIFIED_OWNER_MAIN_SIGNED_NONPUBLISHING",
            "sourceKind": SOURCE_KIND, "repository": repo, "mainSha": sha,
            "runId": run_id, "runAttempt": 1,
            "commentId": intent["commentId"], "auditor": auditor,
            "majors": majors, "SHA256": digests,
            "publisherEligible": False, "publicationAuthorized": False,
            "PUBLISH": "DENY"}


def join(first, second):
    need(type(first) is dict and type(second) is dict
         and first.get("auditor") == "first" and second.get("auditor") == "second",
         "two independently named receipts required")
    expected = {k: v for k, v in first.items() if k != "auditor"}
    observed = {k: v for k, v in second.items() if k != "auditor"}
    need(expected == observed
         and expected.get("status") == "VERIFIED_OWNER_MAIN_SIGNED_NONPUBLISHING"
         and expected.get("sourceKind") == SOURCE_KIND
         and expected.get("publisherEligible") is False
         and expected.get("publicationAuthorized") is False
         and expected.get("PUBLISH") == "DENY"
         and type(expected.get("SHA256")) is dict and bool(expected["SHA256"]),
         "independent real-byte and identity receipts differ")
    return {**expected, "status": "DUAL_VERIFIED_OWNER_MAIN_SIGNED_NONPUBLISHING",
            "auditors": ["first", "second"]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=("audit", "join"))
    for a in ("intent", "manifest", "lifecycle", "dist", "auditor", "first", "second", "output"):
        p.add_argument("--" + a)
    args = p.parse_args()
    try:
        if args.mode == "join":
            outcome = join(read(args.first), read(args.second))
        else:
            env = os.environ
            need(env.get("GITHUB_EVENT_NAME") == "issue_comment"
                 and env.get("GITHUB_REF") == "refs/heads/main"
                 and env.get("GITHUB_RUN_ATTEMPT") == "1"
                 and re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*",
                                  env.get("GITHUB_REPOSITORY", "")),
                 "wrong authentic audit context")
            outcome = audit(Path(args.dist), read(args.intent), read(args.manifest),
                            read(args.lifecycle), repo=env["GITHUB_REPOSITORY"],
                            sha=env["GITHUB_SHA"], run_id=int(env["GITHUB_RUN_ID"]),
                            auditor=args.auditor)
        Path(args.output).write_text(json.dumps(outcome, sort_keys=True) + "\n", "utf-8")
        print(outcome["status"] + "; PUBLISH_DENY")
        return 0
    except (Denied, ident.Denied, pin.Deny, vuln.Denied,
            OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        print("OWNER_SIGNED_SOURCE_AUDIT_DENIED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
