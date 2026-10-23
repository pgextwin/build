#!/usr/bin/env python3
"""Real signed BUILD-only audit after a protected candidate main push.

Independent GitHub Actions run + actual ZIP/SPDX/Grype bytes and cryptographic
gh attestation verify. It deliberately CANNOT authorize or publish a Release.
No network writes, tag, Release or new principal. Issue #75, 17-extension shared.
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

def load(label, filename):
    spec = importlib.util.spec_from_file_location(label, ROOT / filename)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

ident = load("signed_candidate_identity", "fleet-release-identity.py")
pin = load("signed_candidate_certificate", "issue-75-attempt-pin-migration-offline.py")
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
CALLER = ".github/workflows/update-watch.yml"
SIGNED = "VERIFIED_SIGNED_CANDIDATE_NONPUBLISHING"

class Denied(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Denied(reason)

def json_object(raw):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, "duplicate signed JSON field")
            obj[key] = value
        return obj
    return json.loads(raw, object_pairs_hook=unique)

def run_readonly(*args):
    require(args and (args[0:2] == ("gh", "attestation")
            or args[0:3] == ("gh", "api", "--method")),
            "only attestation and GET commands allowed")
    if args[:3] == ("gh", "api", "--method"):
        require(len(args) == 5 and args[3] == "GET"
                and re.fullmatch(r"repos/pgextwin/[a-z][a-z0-9_]*/actions/runs/[1-9][0-9]*", args[4]),
                "non-readonly or non-run GitHub API resource")
    else:
        require(len(args) >= 4 and args[2] == "verify",
                "only gh attestation verify allowed")
    cp = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False)
    require(cp.returncode == 0 and 0 < len(cp.stdout) < 4 * 1024 * 1024,
            "authentic GitHub GET or cryptographic verification failed")
    return json_object(cp.stdout)

def stable_run(run, *, repo, sha, run_id, attempt):
    require(type(run) is dict and run.get("repository", {}).get("full_name") == repo
            and type(run.get("id")) is int and run["id"] == run_id
            and type(run.get("run_attempt")) is int and run["run_attempt"] == attempt
            and run.get("head_sha") == sha and run.get("head_branch") == "main"
            and run.get("event") == "push" and run.get("path") == CALLER
            and run.get("status") == "in_progress" and run.get("conclusion") is None,
            "signed candidate must belong to one still-active main/push Run")

def audit(folder, manifest, lifecycle, intent, first_run, second_run, *, repo,
          sha, run_id, attempt, verify):
    require(type(repo) is str and REPO.fullmatch(repo)
            and type(sha) is str and SHA.fullmatch(sha)
            and type(run_id) is int and run_id > 0
            and type(attempt) is int and attempt > 0
            and type(manifest) is dict and manifest.get("name") == repo.split("/")[1],
            "invalid protected main candidate identity")
    require(first_run == second_run, "Actions Run changed during signed audit")
    stable_run(first_run, repo=repo, sha=sha, run_id=run_id, attempt=attempt)
    require(type(intent) is dict and type(intent.get("schemaVersion")) is int
            and intent["schemaVersion"] == 1
            and intent.get("status") == "ELIGIBLE_FOR_FURTHER_SIGNED_BUILD_AUDIT_NONPUBLISHING"
            and intent.get("repository") == repo
            and intent.get("mainMergeSha") == sha
            and all(intent.get(key) is False for key in
                    ("signedArtifactsVerified", "publishableReceipt",
                     "publicationAuthorized", "automaticReleaseEnabled")),
            "original bound candidate is missing or claims unsafe permission")
    try:
        majors = ident.maintained_majors(manifest, lifecycle)
        pins = ident.sources(manifest)
        names = ident.expected_assets(manifest, majors) - {"SHA256SUMS.txt"}
    except (ident.Denied, TypeError, KeyError, ValueError) as exc:
        raise Denied("untrusted PG source matrix") from exc
    require(intent.get("maintainedMajors") == majors
            and intent.get("releaseTagStem") == ident.tag_stem(manifest)
            and isinstance(folder, Path) and folder.is_dir()
            and {p.name for p in folder.iterdir() if p.is_file()} == names,
            "signed files or original maintained PG matrix incomplete")
    hashes = {}
    for major in majors:
        stem = ident.asset_stem(manifest, major)
        z, s, g = (folder / (stem + ext) for ext in
                   (".zip", ".spdx.json", ".vulnerabilities.json"))
        for p in (z, s, g):
            require(p.is_file() and 0 < p.stat().st_size < 1024 * 1024 * 1024,
                    "missing or oversized signed artifact")
            hashes[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
        try:
            with ZipFile(z) as archive:
                info = [i for i in archive.infolist() if i.filename == "PACKAGE-INFO.json"]
                require(len(info) == 1 and info[0].file_size <= 256_000,
                        "ambiguous PACKAGE-INFO")
                pkg = json_object(archive.read(info[0]).decode("utf-8-sig"))
        except (BadZipFile, UnicodeError, KeyError, OSError) as exc:
            raise Denied("corrupt signed ZIP") from exc
        source = pins[major]
        wf = pkg.get("workflowRun", {})
        build = pkg.get("buildInfrastructure", {})
        origin = pkg.get("source", {})
        upstream = pkg.get("upstream", {})
        require(pkg.get("buildMode") == "release-attested"
                and pkg.get("package", {}).get("name") == manifest["name"]
                and pkg["package"].get("platform") == "windows"
                and pkg["package"].get("architecture") == "x64"
                and type(pkg.get("postgresql", {}).get("major")) is int
                and pkg["postgresql"]["major"] == major
                and upstream == {"repository": manifest["upstream"]["repository"],
                                 "ref": source["ref"], "version": source["version"],
                                 "commit": source["commit"]}
                and origin.get("packagingRepository") == repo
                and origin.get("packagingCommit") == sha
                and build.get("repository") == "pgextwin/build"
                and build.get("workflow") == pin.offline.SIGNER_PATH
                and build.get("commit") == pin.SIGNER_SHA
                and type(wf.get("id")) is int and wf["id"] == run_id
                and type(wf.get("attempt")) is int and wf["attempt"] == attempt
                and wf.get("url") == f"https://github.com/{repo}/actions/runs/{run_id}"
                and wf.get("event") == "push" and wf.get("ref") == "refs/heads/main",
                "ZIP source/PG/Signer/Run/attempt binding invalid")
        sbom = json_object(s.read_text("utf-8-sig"))
        grype = json_object(g.read_text("utf-8-sig"))
        require(type(sbom) is dict and sbom.get("spdxVersion") == "SPDX-2.3"
                and type(grype) is dict and type(grype.get("matches")) is list,
                "missing independently downloaded SBOM or Grype report")
        for kind in (pin.SLSA, pin.SPDX):
            verified = verify(z, kind, repo, sha)
            require(type(verified) is list and len(verified) == 1
                    and type(verified[0]) is dict
                    and set(verified[0]) in
                        ({"verificationResult"}, {"attestation", "verificationResult"}),
                    "ambiguous cryptographic verification envelope")
            item = verified[0]
            if "attestation" in item:
                require(type(item["attestation"]) is dict and bool(item["attestation"]),
                        "missing signed attestation bundle")
            try:
                pin.proof_statement(
                    {"verificationResult": item["verificationResult"]},
                    kind, repo=repo, sha=sha, signer_sha=pin.SIGNER_SHA,
                    run_id=run_id, attempt=attempt, event="push",
                    config_path=CALLER, zip_name=z.name,
                    zip_digest=hashes[z.name], sbom=sbom)
            except (pin.Deny, KeyError, TypeError) as exc:
                raise Denied("cryptographic proof binding failed") from exc
            require(hashlib.sha256(z.read_bytes()).hexdigest() == hashes[z.name]
                    and hashlib.sha256(s.read_bytes()).hexdigest() == hashes[s.name],
                    "signed files changed while verifying")
    require({p.name: hashlib.sha256(p.read_bytes()).hexdigest()
             for p in folder.iterdir() if p.is_file()} == hashes,
            "signed artifact bytes changed during verification")
    return {"schemaVersion": 1, "status": SIGNED,
            "repository": repo, "mainMergeSha": sha,
            "candidatePr": intent.get("candidatePr"),
            "runId": run_id, "runAttempt": attempt,
            "maintainedMajors": majors,
            "zipSha256ByMajor": {str(m): hashes[ident.asset_stem(manifest, m) + ".zip"]
                                for m in majors},
            "spdxSha256ByMajor": {str(m): hashes[ident.asset_stem(manifest, m) + ".spdx.json"]
                                 for m in majors},
            "grypeSha256ByMajor": {str(m): hashes[ident.asset_stem(manifest, m) + ".vulnerabilities.json"]
                                  for m in majors},
            "cryptographicVerification": "REAL_GH_ATTESTATION_VERIFY",
            "signedArtifactsVerified": True,
            "publishableReceipt": False, "publicationAuthorized": False,
            "automaticReleaseEnabled": False}

def main():
    a = argparse.ArgumentParser()
    for name in ("dist", "manifest", "lifecycle", "intent", "output"):
        a.add_argument("--" + name, required=True)
    args = a.parse_args()
    try:
        repo, sha = os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_SHA", "")
        require(os.environ.get("GITHUB_EVENT_NAME") == "push"
                and os.environ.get("GITHUB_REF") == "refs/heads/main"
                and os.environ.get("GH_TOKEN") and REPO.fullmatch(repo)
                and SHA.fullmatch(sha), "not a read-only trusted protected main-push runtime")
        run_id, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
        def github_run():
            return run_readonly("gh", "api", "--method", "GET",
                                f"repos/{repo}/actions/runs/{run_id}")
        def real_verify(z, kind, trusted_repo, trusted_sha):
            return run_readonly("gh", "attestation", "verify", str(z),
                                "--repo", trusted_repo,
                                "--signer-workflow", "pgextwin/build/" + pin.offline.SIGNER_PATH,
                                "--signer-digest", pin.SIGNER_SHA,
                                "--source-digest", trusted_sha,
                                "--source-ref", "refs/heads/main",
                                "--predicate-type", kind, "--format", "json")
        first = github_run()
        result = audit(Path(args.dist), json_object(Path(args.manifest).read_text("utf-8")),
                       json_object(Path(args.lifecycle).read_text("utf-8")),
                       json_object(Path(args.intent).read_text("utf-8")),
                       first, github_run(), repo=repo, sha=sha,
                       run_id=run_id, attempt=attempt, verify=real_verify)
        # Check current exact root Run once more after real signature operations.
        stable_run(github_run(), repo=repo, sha=sha, run_id=run_id, attempt=attempt)
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n", "utf-8")
        print("VERIFIED_REAL_SIGNED_CANDIDATE_BUILD_ONLY; PUBLISH DENY")
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired,
            pin.Deny, ident.Denied) as exc:
        print("SIGNED CANDIDATE AUDIT DENY:", str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
