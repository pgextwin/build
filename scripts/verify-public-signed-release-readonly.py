#!/usr/bin/env python3
"""Issue #75: ONE existing public Release, read-only positive Sigstore proof.

No publication receipt or trigger. Runs only for the explicitly pinned,
already published plpgsql_check release in a minimally privileged PR check.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile, BadZipFile

ROOT = Path(__file__).resolve().parents[1]
REPO = "pgextwin/plpgsql_check"
TAG = "v2.10.14-windows.1"
RELEASE_ID = 409572202
TAG_SHA = "37cb5ee00f556fd6b57e439a5e19cd210125a571"
UPSTREAM_SHA = "ccdbcce9de51f01e1138c270aeb9fe4e26c6e911"
SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"
PROVENANCE = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document/v2.3"
MAJORS = (14, 15, 16, 17, 18)
STEM = "plpgsql_check-v2.10.14-pg{}-windows-x64"


class Deny(ValueError):
    pass


class Unavailable(Deny):
    pass


def ensure(condition, reason):
    if not condition:
        raise Deny(reason)


def unique(pairs):
    obj = {}
    for key, value in pairs:
        ensure(key not in obj, "duplicate JSON key")
        obj[key] = value
    return obj


def read_json(data):
    return json.loads(data, object_pairs_hook=unique)


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def gh(*args):
    """Literal, audited read commands only. No shell, write verbs, or dispatch."""
    ensure(args and (
        args[:2] == ("release", "download") or
        args[:2] == ("attestation", "verify") or
        (args[0] == "api" and len(args) == 2 and
         re.fullmatch(r"repos/pgextwin/plpgsql_check/(?:releases/tags/v2\\.10\\.14-windows\\.1|git/ref/tags/v2\\.10\\.14-windows\\.1|actions/runs/[1-9][0-9]*)", args[1]))
    ), "non-readonly or unallowlisted gh command")
    try:
        p = subprocess.run(("gh",) + args, capture_output=True, text=True,
                           timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Unavailable("GitHub CLI/network operation unavailable") from exc
    if p.returncode:
        err = p.stderr.lower()
        if any(s in err for s in ("403", "401", "429", "rate limit", "timeout",
                                   "connection", "network", "tls", "could not resolve",
                                   "authentication", "not logged in", "bad credentials",
                                   "503", "502", "500")):
            raise Unavailable("GitHub authentication/network unavailable")
        raise Deny("GitHub read/signature verification rejected: " + args[0] + " " + args[1])
    return p.stdout


def api(path):
    return read_json(gh("api", "repos/pgextwin/plpgsql_check/" + path))


def expected_names():
    names = {"SHA256SUMS.txt"}
    for major in MAJORS:
        stem = STEM.format(major)
        names.update({stem + ".zip", stem + ".spdx.json",
                      stem + ".vulnerabilities.json"})
    return names


def inventory(folder, release):
    ensure(release.get("id") == RELEASE_ID and release.get("tag_name") == TAG
           and release.get("draft") is False and release.get("prerelease") is False
           and release.get("target_commitish") == TAG_SHA,
           "Release identity or published state mismatch")
    assets = release.get("assets")
    ensure(isinstance(assets, list) and len(assets) == 16, "Release asset inventory incomplete")
    names = [a.get("name") for a in assets if isinstance(a, dict)]
    ensure(len(names) == len(set(names)) and set(names) == expected_names(),
           "unexpected/duplicate Release asset inventory")
    ensure({p.name for p in folder.iterdir() if p.is_file()} == expected_names(),
           "missing/extra downloaded asset")
    hashes = {}
    for asset in assets:
        name = asset["name"]
        path = folder / name
        ensure(asset.get("state") == "uploaded" and isinstance(asset.get("size"), int)
               and asset["size"] == path.stat().st_size and path.stat().st_size > 0,
               "Release asset missing/incomplete: " + name)
        digest = sha256(path)
        ensure(asset.get("digest") == "sha256:" + digest,
               "GitHub Release asset digest mismatch: " + name)
        hashes[name] = digest
    sums = {}
    for line in (folder / "SHA256SUMS.txt").read_text(encoding="ascii").splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        ensure(m is not None and m[2] not in sums, "invalid/duplicate SHA256SUMS record")
        sums[m[2]] = m[1]
    ensure(set(sums) == expected_names() - {"SHA256SUMS.txt"},
           "SHA256SUMS manifest incomplete")
    ensure(all(hashes[name] == digest for name, digest in sums.items()),
           "published ZIP/SBOM/Grype SHA256SUMS mismatch")
    return hashes


def check_run(run, tag_sha, run_id):
    ensure(run.get("id") == run_id and run.get("head_sha") == tag_sha
           and run.get("head_branch") == "main"
           and run.get("event") == "workflow_dispatch"
           and run.get("path") == ".github/workflows/promote.yml"
           and run.get("status") == "completed",
           "attested Release run origin mismatch")
    # Historical run can report failure AFTER successful attested builds.
    # Do not falsely represent a failed publication workflow as SUCCESS.
    return {"runId": run_id, "runConclusion": run.get("conclusion"),
            "runUrl": "https://github.com/pgextwin/plpgsql_check/actions/runs/" + str(run_id)}


def subject_proof(verification, predicate, name, digest):
    ensure(isinstance(verification, list) and verification, "missing verified attestation")
    for item in verification:
        statement = (item.get("verificationResult") or {}).get("statement") or {}
        if statement.get("predicateType") == predicate and any(
            isinstance(s, dict) and s.get("name") == name and
            (s.get("digest") or {}).get("sha256") == digest
            for s in statement.get("subject") or []
        ):
            return
    raise Deny("verified attestation predicate/ZIP subject mismatch")


def verify_attestations(zip_path, sbom_path, digest):
    for predicate in (PROVENANCE, SPDX):
        result = read_json(gh("attestation", "verify", str(zip_path),
                              "--repo", REPO, "--signer-workflow", SIGNER,
                              "--predicate-type", predicate, "--format", "json"))
        subject_proof(result, predicate, zip_path.name, digest)
        if predicate == SPDX:
            with tempfile.TemporaryDirectory(prefix="pgextwin-spdx-") as temp:
                proof = Path(temp) / "verified.json"
                proof.write_text(json.dumps(result), encoding="utf-8")
                validate_command("verify-sbom-attestation.py",
                                 "--verification-json", str(proof),
                                 "--sbom", str(sbom_path), "--zip", str(zip_path))


def validate_command(name, *args):
    p = subprocess.run((sys.executable, str(ROOT / "scripts" / name), *args),
                       capture_output=True, text=True, timeout=90, check=False)
    ensure(p.returncode == 0, "existing independent verifier rejected: " + name)


def validate_local(zip_path, sbom_path, report_path, major):
    validate_command("validate-package-metadata.py", "--schema",
                     str(ROOT / "schema/package-info.schema.json"), "--zip", str(zip_path))
    validate_command("validate-sbom.py", "--sbom", str(sbom_path), "--zip", str(zip_path),
                     "--expected-extension", "plpgsql_check",
                     "--expected-version", "2.10.14")
    validate_command("validate-vulnerability-report.py",
                     "--report", str(report_path), "--sbom", str(sbom_path),
                     "--zip", str(zip_path), "--expected-extension", "plpgsql_check",
                     "--postgresql-major", str(major))


def check_packages(folder, hashes, tag_sha, get_run=api,
                   local_validator=validate_local, attest=verify_attestations):
    runs = set()
    results = {}
    for major in MAJORS:
        stem = STEM.format(major)
        z = folder / (stem + ".zip")
        s = folder / (stem + ".spdx.json")
        g = folder / (stem + ".vulnerabilities.json")
        try:
            with ZipFile(z) as archive:
                info = [x for x in archive.infolist() if x.filename == "PACKAGE-INFO.json"]
                ensure(len(info) == 1 and info[0].file_size <= 256 * 1024,
                       "missing/duplicate/oversized PACKAGE-INFO")
                pkg = read_json(archive.read(info[0]).decode("utf-8-sig"))
        except (BadZipFile, UnicodeError, KeyError) as e:
            raise Deny("corrupt ZIP PACKAGE-INFO") from e
        source = pkg.get("source") or {}
        upstream = pkg.get("upstream") or {}
        build = pkg.get("buildInfrastructure") or {}
        workflow = pkg.get("workflowRun") or {}
        ensure(pkg.get("buildMode") == "release-attested"
               and pkg.get("package", {}).get("name") == "plpgsql_check"
               and pkg.get("package", {}).get("platform") == "windows"
               and pkg.get("package", {}).get("architecture") == "x64"
               and pkg.get("postgresql", {}).get("major") == major
               and upstream == {"repository": "okbob/plpgsql_check",
                                "ref": "v2.10.14", "version": "2.10.14",
                                "commit": UPSTREAM_SHA}
               and source.get("packagingRepository") == REPO
               and source.get("packagingCommit") == tag_sha
               and build.get("repository") == "pgextwin/build"
               and build.get("workflow") == ".github/workflows/build-extension-attested.yml"
               and re.fullmatch(r"[0-9a-f]{40}", str(build.get("commit", "")))
               and workflow.get("event") == "workflow_dispatch"
               and workflow.get("ref") == "refs/heads/main"
               and isinstance(workflow.get("id"), int) and workflow["id"] > 0
               and isinstance(workflow.get("attempt"), int)
               and workflow["attempt"] > 0,
               "PACKAGE-INFO source/major/release builder identity mismatch")
        runs.add(workflow["id"])
        ensure(len(runs) == 1, "inconsistent Release build run IDs across majors")
        local_validator(z, s, g, major)
        attest(z, s, hashes[z.name])
        results[str(major)] = hashes[z.name]
    run_id = next(iter(runs))
    details = check_run(get_run("actions/runs/" + str(run_id)), tag_sha, run_id)
    details["zipSha256ByMajor"] = results
    return details


def main():
    try:
        first = api("releases/tags/" + TAG)
        tag = api("git/ref/tags/" + TAG)
        ensure(tag.get("object", {}).get("type") == "commit"
               and tag.get("object", {}).get("sha") == TAG_SHA,
               "Release tag SHA mismatch")
        with tempfile.TemporaryDirectory(prefix="pgextwin-public-signed-readonly-") as tmp:
            path = Path(tmp)
            gh("release", "download", TAG, "--repo", REPO, "--dir", str(path))
            hashes = inventory(path, first)
            proof = check_packages(path, hashes, TAG_SHA)
            # Re-fetch mutable GitHub metadata; not an atomic tag/publish gate.
            second = api("releases/tags/" + TAG)
            tag2 = api("git/ref/tags/" + TAG)
            ensure(tag == tag2 and
                   [(a["id"], a["digest"]) for a in first["assets"]] ==
                   [(a["id"], a["digest"]) for a in second["assets"]],
                   "TOCTOU Release asset/tag change during verification")
        print(json.dumps({"status": "PASS_SIGNED_PUBLIC_BYTES_ONLY", "releaseId": RELEASE_ID,
                          "tag": TAG, "tagSha": TAG_SHA, **proof,
                          "publishableReceipt": False, "mutationsEnabled": False},
                         sort_keys=True))
    except Unavailable as exc:
        print("BLOCKED_AUTH_OR_NETWORK / DENY: " + str(exc), file=sys.stderr)
        raise SystemExit(3)
    except (Deny, OSError, ValueError, TypeError, IndexError,
            subprocess.TimeoutExpired) as exc:
        print("DENY_UNVERIFIED_EVIDENCE: " + str(exc), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
