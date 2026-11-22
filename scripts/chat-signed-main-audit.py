#!/usr/bin/env python3
"""Independent real-byte/Sigstore audit for genuine owner-comment main source.

A distinct, NONPUBLISHING source type. No push/schedule impersonation, Release,
Publisher App, or publication authorization.
"""
from __future__ import annotations

import argparse
import base64
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
CENTRAL_REPOSITORY = "pgextwin/build"
SOURCE_WORKFLOW = ".github/workflows/chat-signed-main-source.yml"
AUDIT_JOB = "Independent original Sigstore/ZIP/SPDX/Grype audit (NO PUBLISH)"
AUDIT_ARTIFACT = "chat-owner-sigstore-nonpublishing"
AUDIT_FILE = "chat-owner-audit.json"


class Denied(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Denied(why)


def read(path):
    return json.loads(Path(path).read_text("utf-8"))


def signer_sha_from_workflow(raw):
    import yaml

    class WorkflowLoader(yaml.BaseLoader):
        def construct_mapping(self, node, deep=False):
            mapping = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                need(type(key) is str and key != "<<" and key not in mapping,
                     "ambiguous key in central owner-source workflow")
                mapping[key] = self.construct_object(value_node, deep=deep)
            return mapping

    try:
        workflow = yaml.load(raw, Loader=WorkflowLoader)
        uses = workflow["jobs"]["signed_windows"]["uses"]
    except (yaml.YAMLError, TypeError, KeyError) as exc:
        raise Denied("invalid central owner-source workflow") from exc
    signer = f"{CENTRAL_REPOSITORY}/{pin.offline.SIGNER_PATH}"
    match = re.fullmatch(re.escape(signer) + r"@([0-9a-f]{40})", uses) if type(uses) is str else None
    need(match is not None, "central owner-source workflow must pin the exact builder digest")
    return match.group(1)


def signer_sha_at(central_sha):
    """Read the inner uses from the authenticated central commit, ignoring working-tree edits."""
    need(type(central_sha) is str and ident.SHA.fullmatch(central_sha),
         "missing immutable central workflow commit")
    result = subprocess.run(
        ["git", "-C", str(ROOT.parent), "--no-replace-objects",
         "show", f"{central_sha}:{SOURCE_WORKFLOW}"],
        capture_output=True, timeout=15, check=False)
    need(result.returncode == 0, "central owner-source workflow blob unavailable")
    return signer_sha_from_workflow(result.stdout)


def protected_admission(get):
    """Fetch mutable policy at a protected main snapshot independently of the signer pin."""
    branch = get("branches/main")
    sha = (branch.get("commit") or {}).get("sha")
    need(branch.get("name") == "main" and branch.get("protected") is True
         and type(sha) is str and ident.SHA.fullmatch(sha),
         "central PostgreSQL admission is not from protected main")
    data = get(f"contents/{ident.ADMISSION_PATH}?ref={sha}")
    need(data.get("type") == "file" and data.get("encoding") == "base64"
         and type(data.get("content")) is str, "central PostgreSQL admission data unavailable")
    return ident.parse_admission(base64.b64decode(data["content"].replace("\n", ""), validate=True))


def central_get(route):
    result = subprocess.run(
        ["gh", "api", "--method", "GET", f"repos/{CENTRAL_REPOSITORY}/{route}"],
        capture_output=True, timeout=30, check=False)
    need(result.returncode == 0, "central PostgreSQL admission lookup failed")
    return json.loads(result.stdout)


def verify(z, kind, repo, sha, signer_sha):
    cmd = ["gh", "attestation", "verify", str(z), "--repo", repo,
           "--signer-workflow", f"{CENTRAL_REPOSITORY}/{pin.offline.SIGNER_PATH}",
           "--signer-digest", signer_sha, "--source-digest", sha,
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


def audit(folder, intent, manifest, lifecycle, *, repo, sha, run_id, signer_sha, admission=None):
    need(type(intent) is dict
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
    majors = ident.maintained_majors(manifest, lifecycle, admission=admission)
    sources = ident.sources(manifest, admission=admission)
    expected = ident.expected_assets(manifest, majors, admission=admission) - {"SHA256SUMS.txt"}
    files = {f.name for f in folder.iterdir() if f.is_file()}
    need(files == expected, "missing/extra signed artifact bytes")
    digests = {}
    blocking_findings = 0
    for major in majors:
        stem = ident.asset_stem(manifest, major, admission=admission)
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
             and build.get("repository") == CENTRAL_REPOSITORY
             and build.get("workflow") == pin.offline.SIGNER_PATH
             and build.get("commit") == signer_sha
             and wf.get("id") == run_id and wf.get("attempt") == 1
             and wf.get("event") == "issue_comment"
             and wf.get("ref") == "refs/heads/main"
             and wf.get("url") == f"https://github.com/{repo}/actions/runs/{run_id}",
             "package source/manifest/run/signer mismatch")
        sbom, grype = read(s), read(g)
        need(type(sbom) is dict and sbom.get("spdxVersion") == "SPDX-2.3"
             and type(grype) is dict and type(grype.get("matches")) is list,
             "missing SPDX/Grype evidence")
        blocking_findings += vuln.review(grype, asset_stem=stem)["blockingFindingCount"]
        for kind in (pin.SLSA, pin.SPDX):
            proof = verify(z, kind, repo, sha, signer_sha)
            pin.proof_statement(proof, kind, repo=repo, sha=sha,
                                signer_sha=signer_sha, run_id=run_id,
                                attempt=1, event="issue_comment",
                                config_path=CALLER, zip_name=z.name,
                                zip_digest=digests[z.name], sbom=sbom)
    return {"schemaVersion": 2, "status": "VERIFIED_OWNER_MAIN_SIGNED_NONPUBLISHING",
            "sourceKind": SOURCE_KIND, "repository": repo, "mainSha": sha,
            "runId": run_id, "runAttempt": 1,
            "commentId": intent["commentId"],
            "majors": majors, "SHA256": digests,
            "publisherEligible": False, "publicationAuthorized": False,
            "PUBLISH": "DENY"}, blocking_findings


def main():
    p = argparse.ArgumentParser()
    for a in ("intent", "manifest", "lifecycle", "dist", "output", "workflow-sha"):
        p.add_argument("--" + a, required=True)
    args = p.parse_args()
    try:
        env = os.environ
        need(env.get("GITHUB_EVENT_NAME") == "issue_comment"
             and env.get("GITHUB_REF") == "refs/heads/main"
             and env.get("GITHUB_RUN_ATTEMPT") == "1"
             and re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*",
                              env.get("GITHUB_REPOSITORY", "")),
             "wrong authentic audit context")
        outcome, blocking_findings = audit(
            Path(args.dist), read(args.intent), read(args.manifest),
            read(args.lifecycle), repo=env["GITHUB_REPOSITORY"],
            sha=env["GITHUB_SHA"], run_id=int(env["GITHUB_RUN_ID"]),
            signer_sha=signer_sha_at(args.workflow_sha), admission=protected_admission(central_get))
        print(f"Grype blocking findings across audited majors: {blocking_findings}")
        Path(args.output).write_text(json.dumps(outcome, sort_keys=True) + "\n", "utf-8")
        print(outcome["status"] + "; PUBLISH_DENY")
        return 0
    except (Denied, ident.Denied, pin.Deny, vuln.Denied,
            OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        print("OWNER_SIGNED_SOURCE_AUDIT_DENIED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
