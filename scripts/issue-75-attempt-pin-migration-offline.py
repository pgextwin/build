#!/usr/bin/env python3
"""Issue #75 PRE-G4: isolated, synthetic-only future Publisher contract.

This module contains no transport, credential, Publisher, tag or Release writer.
A structurally valid forged gh result never proves a signature or grants G4.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import importlib.util
import re

_spec = importlib.util.spec_from_file_location(
    "issue75_existing_offline", Path(__file__).with_name(
        "issue-75-attempt-provenance-readonly.py"))
offline = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(offline)

MANUAL_PIN = "455f0ccc667697f600700a6e64bcfd6c57b6a977"
SIGNER_SHA = offline.SIGNER_SHA
SLSA = offline.PROVENANCE
SPDX = offline.SPDX
PUBLISHABLE = False


class Deny(ValueError):
    pass


class UnknownQuarantine(Deny):
    pass


def require(condition, reason):
    if not condition:
        raise Deny(reason)


def get_pair(snapshots, *, allow_absent=False):
    """Two independently supplied authenticated GET *shapes*; never performs GET."""
    require(type(snapshots) is list and len(snapshots) == 2,
            "missing authenticated GET pair")
    require(all(type(s) is dict for s in snapshots),
            "API unavailable/malformed 401/403/429/5xx/timeout")
    require(snapshots[0] == snapshots[1], "TOCTOU inconsistent GET snapshots")
    response = snapshots[0]
    if allow_absent:
        require(response == {"status": 404}, "tag/Release collision or API uncertainty")
    else:
        require(response.get("status") == 200 and type(response.get("data")) is dict,
                "API unavailable/incomplete non-200")
    return response.get("data")


def proof_statement(entry, kind, *, repo, sha, signer_sha, run_id, attempt,
                    event, zip_name, zip_digest, sbom):
    """Interpret mock X.509-shaped data; caller MUST cryptographically verify separately."""
    require(type(entry) is dict and set(entry) == {"verificationResult"},
            "missing/ambiguous verified attestation")
    v = entry["verificationResult"]
    require(type(v) is dict and type(v.get("statement")) is dict
            and type(v.get("signature")) is dict
            and type(v["signature"].get("certificate")) is dict
            and type(v.get("verifiedTimestamps")) is list
            and len(v["verifiedTimestamps"]) > 0
            and all(type(t) is dict and bool(t) for t in v["verifiedTimestamps"]),
            "missing/invalid signed certificate or trusted timestamps")
    statement, cert = v["statement"], v["signature"]["certificate"]
    require(statement.get("predicateType") == kind
            and type(statement.get("subject")) is list
            and len(statement["subject"]) == 1
            and statement["subject"][0] == {
                "name": zip_name, "digest": {"sha256": zip_digest}},
            "wrong or ambiguous SLSA/SPDX ZIP subject")
    uri = f"https://github.com/{repo}/actions/runs/{run_id}/attempts/{attempt}"
    signer_uri = ("https://github.com/pgextwin/build/"
                  + offline.SIGNER_PATH + "@" + signer_sha)
    config_uri = (f"https://github.com/{repo}/"
                  + offline.PROMOTE_PATH + "@refs/heads/main")
    require("runnerInvocationURI" not in cert
            and cert.get("issuer") == offline.ISSUER
            and cert.get("runInvocationURI") == uri
            and cert.get("buildSignerURI") == signer_uri
            and cert.get("subjectAlternativeName") == signer_uri
            and cert.get("buildSignerDigest") == signer_sha
            and cert.get("sourceRepositoryURI") == "https://github.com/" + repo
            and cert.get("sourceRepositoryDigest") == sha
            and cert.get("sourceRepositoryRef") == "refs/heads/main"
            and cert.get("buildConfigURI") == config_uri
            and cert.get("buildConfigDigest") == sha
            and cert.get("githubWorkflowSHA") == sha
            and cert.get("githubWorkflowRef") == "refs/heads/main"
            and cert.get("buildTrigger") == event,
            "OIDC signer/source/runInvocationURI/attempt/caller identity mismatch")
    predicate = statement.get("predicate")
    require(type(predicate) is dict, "missing signed predicate")
    if kind == SPDX:
        require(predicate == sbom and predicate.get("spdxVersion") == "SPDX-2.3",
                "SPDX attested predicate differs from standalone SBOM")
    else:
        details = predicate.get("runDetails")
        require(type(details) is dict
                and type(details.get("metadata")) is dict
                and details["metadata"].get("invocationId") == uri
                and type(details.get("builder")) is dict
                and bool(details["builder"].get("id"))
                and type(predicate.get("buildDefinition")) is dict,
                "SLSA predicate builder/run mismatch")


def inspect_inert(evidence):
    """Never returns a PUBLISH permission: schema/identity-only future pin rehearsal.

    Evidence is a test input. Even a mock 'verificationResult' is untrusted, and
    API GET pairs do not make the tag reservation atomic.
    """
    require(type(evidence) is dict, "evidence shape")
    if evidence.get("writerState") != "NOT_STARTED":
        raise UnknownQuarantine("UNKNOWN_QUARANTINE: writer started/ambiguous; no retry")
    repo, tag = evidence.get("repo"), evidence.get("releaseTag")
    sha, signer = evidence.get("packagingSha"), evidence.get("signerSha")
    require(type(repo) is str
            and re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*", repo) is not None,
            "repository identity")
    require(type(tag) is str and re.fullmatch(
        r"v[0-9]+\.[0-9]+\.[0-9]+-windows\.[1-9][0-9]*", tag) is not None,
        "tag format")
    require(offline.full_sha(sha) and signer == SIGNER_SHA
            and evidence.get("legacyPublisherPin") == MANUAL_PIN,
            "immutable manual Publisher/builder/packaging SHA contract")
    proposed = evidence.get("proposedPublisherPin")
    require(proposed is None or offline.full_sha(proposed),
            "proposed pin must be a full immutable SHA (design-only)")
    majors = evidence.get("majors")
    require(type(majors) is list and bool(majors)
            and all(offline.positive_int(n) for n in majors)
            and majors == sorted(set(majors)), "full ordered maintained PG matrix")
    by_major = evidence.get("byMajor")
    require(type(by_major) is dict and set(by_major) == set(majors),
            "missing/extra/partial PG major")
    upstream = evidence.get("upstreamByMajor")
    require(type(upstream) is dict and set(upstream) == set(majors)
            and all(offline.full_sha(v) for v in upstream.values()),
            "per-PG upstream source pin")

    run = get_pair(evidence.get("runSnapshots"))
    run_id, attempt = run.get("id"), run.get("run_attempt")
    require(offline.positive_int(run_id) and offline.positive_int(attempt),
            "API run/attempt exact positive integer required")
    require(type(run.get("repository")) is dict
            and run["repository"].get("full_name") == repo
            and run.get("head_sha") == sha
            and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == offline.PROMOTE_PATH
            and run.get("status") == "completed"
            and run.get("conclusion") == "success",
            "future eligible run API event/path/branch/head/status must succeed")
    get_pair(evidence.get("tagSnapshots"), allow_absent=True)
    get_pair(evidence.get("releaseSnapshots"), allow_absent=True)
    digests = {}
    for major in majors:
        row = by_major[major]
        require(type(row) is dict and set(row) == {"zip", "sbom", "proofs"},
                "incomplete/extra artifact triplet")
        data, sbom, proofs = row["zip"], row["sbom"], row["proofs"]
        require(type(data) is bytes, "ZIP bytes not supplied")
        pkg = offline.package_from_zip(data)
        require(type(pkg) is dict
                and pkg.get("buildMode") == "release-attested"
                and type(pkg.get("package")) is dict
                and pkg["package"].get("name") == repo.split("/")[1]
                and type(pkg.get("postgresql")) is dict
                and type(pkg["postgresql"].get("major")) is int
                and pkg["postgresql"]["major"] == major
                and type(pkg.get("upstream")) is dict
                and pkg["upstream"].get("commit") == upstream[major]
                and type(pkg.get("source")) is dict
                and pkg["source"].get("packagingRepository") == repo
                and pkg["source"].get("packagingCommit") == sha
                and type(pkg.get("buildInfrastructure")) is dict
                and pkg["buildInfrastructure"].get("repository") == "pgextwin/build"
                and pkg["buildInfrastructure"].get("workflow") == offline.SIGNER_PATH
                and pkg["buildInfrastructure"].get("commit") == signer,
                "PACKAGE-INFO PG/source/upstream/signer mismatch")
        wr = pkg.get("workflowRun")
        require(type(wr) is dict
                and type(wr.get("id")) is int and wr["id"] == run_id
                and type(wr.get("attempt")) is int and wr["attempt"] == attempt
                and wr.get("url") == f"https://github.com/{repo}/actions/runs/{run_id}"
                and wr.get("event") == run["event"]
                and wr.get("ref") == "refs/heads/main",
                "PACKAGE-INFO vs independently authenticated run ID/attempt/event")
        require(type(sbom) is dict and sbom.get("spdxVersion") == "SPDX-2.3",
                "independent SPDX invalid")
        require(type(proofs) is dict and set(proofs) == {SLSA, SPDX}
                and all(type(proofs[k]) is list and len(proofs[k]) == 1
                        for k in (SLSA, SPDX)), "exact SLSA/SPDX pair required")
        digest = sha256(data).hexdigest()
        name = f"{repo.split('/')[1]}-pg{major}-windows-x64.zip"
        for kind in (SLSA, SPDX):
            proof_statement(proofs[kind][0], kind, repo=repo, sha=sha,
                            signer_sha=signer, run_id=run_id, attempt=attempt,
                            event=run["event"], zip_name=name, zip_digest=digest,
                            sbom=sbom)
        digests[str(major)] = digest
    return {"decision": "BLOCKED", "offlineContract": "PASS",
            "cryptographicVerification": "NOT_PERFORMED",
            "pinCutover": "NOT_AUTHORIZED", "liveJit": "NOT_PERFORMED",
            "runId": run_id, "runAttempt": attempt, "zipSha256ByMajor": digests,
            "publishableReceipt": False, "mutationsEnabled": False,
            "publication": "DENY", "g4": "NO_GO", "g5": "NO_GO"}
