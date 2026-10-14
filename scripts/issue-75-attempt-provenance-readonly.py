#!/usr/bin/env python3
"""Issue #75 PRE-G4: inert, pure attempt/provenance join, never a publisher.

Inputs (including alleged gh verification results) are untrusted. Offline
fixtures cannot demonstrate authentic signatures or authorize publication.
"""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
import re
from zipfile import ZipFile, BadZipFile

SIGNER_SHA = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
SIGNER_PATH = ".github/workflows/build-extension-attested.yml"
PROMOTE_PATH = ".github/workflows/promote.yml"
PROVENANCE = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document/v2.3"
ISSUER = "https://token.actions.githubusercontent.com"


class Deny(ValueError):
    pass


class Unavailable(Deny):
    pass


def require(ok, reason):
    if not ok:
        raise Deny(reason)


def positive_int(value):
    return type(value) is int and value > 0


def full_sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def unique(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result, "duplicate JSON key")
        result[k] = v
    return result


def package_from_zip(data):
    require(type(data) is bytes, "ZIP must be local bytes")
    try:
        with ZipFile(BytesIO(data)) as archive:
            info = [i for i in archive.infolist() if i.filename == "PACKAGE-INFO.json"]
            require(len(info) == 1 and info[0].file_size <= 256 * 1024,
                    "missing/duplicate/oversized PACKAGE-INFO")
            return json.loads(archive.read(info[0]).decode("utf-8-sig"),
                              object_pairs_hook=unique)
    except (BadZipFile, UnicodeError, KeyError, json.JSONDecodeError) as exc:
        raise Deny("unreadable ZIP PACKAGE-INFO") from exc


def fetch_twice(read, run_id):
    """Dependency-injected GET-only reader; no transport, no write primitives."""
    require(positive_int(run_id), "invalid Actions run ID")
    snapshots = []
    for _ in range(2):
        try:
            value = read("actions/runs/" + str(run_id))
        except Exception as exc:
            raise Unavailable("Actions API error/timeout/401/403/429/5xx") from exc
        require(type(value) is dict, "incomplete/unknown Actions API response")
        snapshots.append(value)
    require(snapshots[0] == snapshots[1], "Actions run TOCTOU between GETs")
    return snapshots[0]


def check_run(run, repo, packaging_sha, run_id, attempt):
    require(type(run) is dict and type(run.get("repository")) is dict,
            "Actions run/repository absent")
    require(type(run.get("id")) is int and run["id"] == run_id
            and type(run.get("run_attempt")) is int and run["run_attempt"] == attempt
            and run.get("head_sha") == packaging_sha
            and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == PROMOTE_PATH
            and run["repository"].get("full_name") == repo
            and run.get("status") == "completed",
            "authenticated Actions run identity/attempt mismatch")


def check_pkg(pkg, major, repo, packaging_sha, upstream_sha, signer_sha,
              run_id, attempt):
    require(type(pkg) is dict, "PACKAGE-INFO invalid")
    source, upstream, build, workflow = (
        pkg.get(k) for k in ("source", "upstream", "buildInfrastructure", "workflowRun"))
    require(all(type(x) is dict for x in (source, upstream, build, workflow)),
            "missing PACKAGE-INFO required objects")
    require(pkg.get("buildMode") == "release-attested"
            and type(pkg.get("package")) is dict
            and pkg["package"].get("name") == repo.split("/")[1]
            and type(pkg.get("postgresql")) is dict
            and pkg["postgresql"].get("major") == major
            and source.get("packagingRepository") == repo
            and source.get("packagingCommit") == packaging_sha
            and upstream.get("commit") == upstream_sha
            and build.get("repository") == "pgextwin/build"
            and build.get("workflow") == SIGNER_PATH
            and build.get("commit") == signer_sha,
            "PACKAGE-INFO source/upstream/PG/build mismatch")
    require(type(workflow.get("id")) is int and workflow["id"] == run_id
            and type(workflow.get("attempt")) is int and workflow["attempt"] == attempt
            and workflow.get("url") == f"https://github.com/{repo}/actions/runs/{run_id}"
            and workflow.get("event") == "workflow_dispatch"
            and workflow.get("ref") == "refs/heads/main",
            "PACKAGE-INFO run ID/attempt/event/ref mismatch")


def check_statement(entries, predicate_type, zip_name, digest, sbom,
                    repo, packaging_sha, signer_sha, invocation):
    """Policy for a verified result; does NOT verify signatures itself.

    The parsed certificate fields must come from a separately authenticated
    gh attestation verify operation. JSON fixture fields can be forged.
    Statement predicate fields remain workflow-controlled.
    """
    require(type(entries) is list and bool(entries), "missing attestation")
    for item in entries:
        if type(item) is not dict:
            continue
        verified = item.get("verificationResult")
        if type(verified) is not dict:
            continue
        statement, signature = verified.get("statement"), verified.get("signature")
        if type(statement) is not dict or type(signature) is not dict:
            continue
        subjects = statement.get("subject")
        if statement.get("predicateType") != predicate_type or type(subjects) is not list or not any(
            type(s) is dict and s.get("name") == zip_name
            and type(s.get("digest")) is dict and s["digest"].get("sha256") == digest
            for s in subjects
        ):
            continue
        cert = signature.get("certificate")
        require(type(cert) is dict and type(verified.get("verifiedTimestamps")) is list
                and bool(verified["verifiedTimestamps"]),
                "unverified/missing certificate or timestamps")
        require(cert.get("issuer") == ISSUER
                and cert.get("runnerInvocationURI") == invocation
                and cert.get("sourceRepositoryURI") == "https://github.com/" + repo
                and cert.get("sourceRepositoryDigest") == packaging_sha
                and cert.get("sourceRepositoryRef") == "refs/heads/main"
                and cert.get("buildSignerURI") ==
                    "https://github.com/pgextwin/build/" + SIGNER_PATH + "@refs/heads/main"
                and cert.get("buildSignerDigest") == signer_sha
                and cert.get("buildTrigger") == "workflow_dispatch",
                "certificate issuer/run attempt/source/signer mismatch")
        predicate = statement.get("predicate")
        require(type(predicate) is dict, "missing signed predicate")
        if predicate_type == SPDX:
            require(predicate == sbom and predicate.get("spdxVersion") == "SPDX-2.3",
                    "SPDX predicate disagrees with standalone SBOM")
        else:
            details = predicate.get("runDetails")
            require(type(details) is dict and type(details.get("metadata")) is dict
                    and details["metadata"].get("invocationId") == invocation
                    and type(details.get("builder")) is dict
                    and bool(details["builder"].get("id"))
                    and type(predicate.get("buildDefinition")) is dict,
                    "SLSA invocation/build definition mismatch")
        return
    raise Deny("no matching signed statement/ZIP digest/predicate")


def inspect_offline(zips, sboms, proofs, run, *, repo, packaging_sha, upstream_sha,
                    signer_sha=SIGNER_SHA, majors=(14, 15, 16, 17, 18)):
    """Synthetic structural checks always remain BLOCKED, never a receipt."""
    require(full_sha(packaging_sha) and full_sha(upstream_sha)
            and full_sha(signer_sha) and signer_sha == SIGNER_SHA,
            "untrusted/non-pinned full SHA")
    require(type(majors) in (tuple, list) and bool(majors)
            and all(positive_int(x) for x in majors)
            and len(set(majors)) == len(majors), "invalid PG-major matrix")
    require(all(type(mapping) is dict and set(mapping) == set(majors)
                for mapping in (zips, sboms, proofs)),
            "incomplete/mixed/extra PG assets")
    packages = {major: package_from_zip(zips[major]) for major in majors}
    run_fields = [pkg.get("workflowRun") if type(pkg) is dict else None
                  for pkg in packages.values()]
    require(all(type(w) is dict and positive_int(w.get("id"))
                and positive_int(w.get("attempt")) for w in run_fields),
            "missing/null/boolean/zero/string run attempt")
    run_id, attempt = run_fields[0]["id"], run_fields[0]["attempt"]
    require(all(w["id"] == run_id and w["attempt"] == attempt for w in run_fields),
            "PG-major run ID/attempt mix")
    check_run(run, repo, packaging_sha, run_id, attempt)
    invocation = f"https://github.com/{repo}/actions/runs/{run_id}/attempts/{attempt}"
    digests = {}
    for major in majors:
        check_pkg(packages[major], major, repo, packaging_sha, upstream_sha,
                  signer_sha, run_id, attempt)
        sbom = sboms[major]
        require(type(sbom) is dict and sbom.get("spdxVersion") == "SPDX-2.3",
                "missing/invalid independent SBOM")
        pair = proofs[major]
        require(type(pair) is dict and set(pair) == {PROVENANCE, SPDX},
                "must provide SLSA and SPDX attestations")
        digest = sha256(zips[major]).hexdigest()
        digests[str(major)] = digest
        name = f'{repo.split("/")[1]}-pg{major}-windows-x64.zip'
        for kind in (PROVENANCE, SPDX):
            check_statement(pair[kind], kind, name, digest, sbom,
                            repo, packaging_sha, signer_sha, invocation)
    return {"decision": "BLOCKED", "attemptBinding": "NOT_CRYPTOGRAPHICALLY_ATTESTED",
            "offlineStructuralChecks": "PASS", "runId": run_id,
            "runAttempt": attempt, "zipSha256ByMajor": digests,
            "publishableReceipt": False, "mutationsEnabled": False,
            "publication": "DENY"}
