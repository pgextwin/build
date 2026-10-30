#!/usr/bin/env python3
"""R08 real signed BUILD-only audit after genuine protected App original.

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
vulnerability_policy = load("signed_candidate_grype_policy", "automatic-grype-publisher-policy.py")
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
CALLER = ".github/workflows/issue311-request-local-prepare.yml"
SIGNED = "VERIFIED_APP_PREPARE_OIDC_NONPUBLISHING"

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
            and run.get("event") == "workflow_dispatch" and run.get("path") == CALLER
            and run.get("actor", {}).get("login") == "pgextwin-issue311-prepare-coord[bot]"
            and run.get("actor", {}).get("id") == 350058024
            and run.get("triggering_actor", {}).get("login") == "pgextwin-issue311-prepare-coord[bot]"
            and run.get("status") == "in_progress" and run.get("conclusion") is None,
            "signed candidate must belong to original local App workflow_dispatch Run")

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
    require(type(intent) is dict and intent.get("schemaVersion") == 1
            and intent.get("status") == "APP_BOT_PREPARE_OIDC_SIGNING_INTENT_ONLY"
            and intent.get("sourceKind") == "APP_BOT_PREPARE_WORKFLOW_DISPATCH_SIGNED_BUILD_ONLY"
            and intent.get("repository") == repo
            and intent.get("localProtectedMainSha") == sha
            and intent.get("localRunId") == run_id
            and intent.get("localRunAttempt") == attempt == 1
            and intent.get("localWorkflow") == CALLER
            and intent.get("localActor") == "pgextwin-issue311-prepare-coord[bot]"
            and intent.get("localActorId") == 350058024
            and type(intent.get("requestId")) is str
            and re.fullmatch(r"r-20[0-9]{6}-r06coordlocal[a-z0-9-]{4,40}", intent["requestId"])
            and type(intent.get("centralRequestId")) is str
            and re.fullmatch(r"r-20[0-9]{6}-r06prepare[a-z0-9-]{4,40}", intent["centralRequestId"])
            and type(intent.get("centralRunId")) is int and intent["centralRunId"] > 0
            and type(intent.get("centralArtifactId")) is int and intent["centralArtifactId"] > 0
            and type(intent.get("centralHeadSha")) is str and SHA.fullmatch(intent["centralHeadSha"])
            and all(type(intent.get(k)) is str and re.fullmatch(r"[0-9a-f]{64}", intent[k])
                    for k in ("centralRequestRawSha256", "centralOuterZipSha256"))
            and intent.get("signedArtifactsVerified") is False
            and intent.get("independentSigstoreAudits") == 0
            and all(intent.get(k) is False for k in
                    ("publisherSourceKindAuthorized", "publicationAuthorized", "runtimeEnabled")),
            "App intent missing original Run/central cycle or claims authority")
    try:
        majors = ident.maintained_majors(manifest, lifecycle)
        pins = ident.sources(manifest)
        names = ident.expected_assets(manifest, majors) - {"SHA256SUMS.txt"}
    except (ident.Denied, TypeError, KeyError, ValueError) as exc:
        raise Denied("untrusted PG source matrix") from exc
    require(isinstance(folder, Path) and folder.is_dir()
            and {p.name for p in folder.iterdir() if p.is_file()} == names,
            "signed files or original maintained PG matrix incomplete")
    hashes = {}
    vulnerability_results = {}
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
                and wf.get("event") == "workflow_dispatch" and wf.get("ref") == "refs/heads/main",
                "ZIP source/PG/Signer/Run/attempt binding invalid")
        sbom = json_object(s.read_text("utf-8-sig"))
        grype = json_object(g.read_text("utf-8-sig"))
        require(type(sbom) is dict and sbom.get("spdxVersion") == "SPDX-2.3"
                and type(grype) is dict and type(grype.get("matches")) is list,
                "missing independently downloaded SBOM or Grype report")
        try:
            vulnerability_results[str(major)] = vulnerability_policy.review(grype, asset_stem=stem)
        except vulnerability_policy.Denied as exc:
            raise Denied("untrusted unfiltered Grype evidence") from exc
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
                    run_id=run_id, attempt=attempt, event="workflow_dispatch",
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
            "sourceKind": "APP_BOT_PREPARE_WORKFLOW_DISPATCH_SIGNED_BUILD_ONLY",
            "repository": repo, "mainMergeSha": sha,
            "requestId": intent["requestId"],
            "centralRequestId": intent["centralRequestId"],
            "centralRunId": intent["centralRunId"],
            "centralArtifactId": intent["centralArtifactId"],
            "centralHeadSha": intent["centralHeadSha"],
            "centralRequestRawSha256": intent["centralRequestRawSha256"],
            "centralOuterZipSha256": intent["centralOuterZipSha256"],
            "localWorkflow": CALLER,
            "localActor": intent["localActor"],
            "localActorId": intent["localActorId"],
            "auditorJob": os.environ.get("GITHUB_JOB"),
            "runId": run_id, "runAttempt": attempt,
            "maintainedMajors": majors,
            "zipSha256ByMajor": {str(m): hashes[ident.asset_stem(manifest, m) + ".zip"]
                                for m in majors},
            "spdxSha256ByMajor": {str(m): hashes[ident.asset_stem(manifest, m) + ".spdx.json"]
                                 for m in majors},
            "grypeSha256ByMajor": {str(m): hashes[ident.asset_stem(manifest, m) + ".vulnerabilities.json"]
                                  for m in majors},
            "grypePolicyByMajor": vulnerability_results,
            "cryptographicVerification": "REAL_GH_ATTESTATION_VERIFY",
            "signedArtifactsVerified": True,
            "publishableReceipt": False, "publicationAuthorized": False,
            "publisherSourceKindAuthorized": False,
            "automaticReleaseEnabled": False}

def main():
    a = argparse.ArgumentParser()
    for name in ("dist", "manifest", "lifecycle", "intent", "output"):
        a.add_argument("--" + name, required=True)
    args = a.parse_args()
    try:
        repo, sha = os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_SHA", "")
        require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and os.environ.get("GITHUB_REF") == "refs/heads/main"
                and os.environ.get("GH_TOKEN") and REPO.fullmatch(repo)
                 and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
                 and os.environ.get("GITHUB_JOB") in ("r08_signed_audit_first", "r08_signed_audit_second")
                and SHA.fullmatch(sha), "not a genuine read-only protected main-schedule runtime")
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
        print("VERIFIED_REAL_APP_PREPARE_OIDC_BUILD_ONLY; PUBLISH_DENY")
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired,
            pin.Deny, ident.Denied) as exc:
        print("SIGNED CANDIDATE AUDIT DENY:", str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
