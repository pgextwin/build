#!/usr/bin/env python3
"""R08-01 strict independent App-origin Sigstore join, nonpublishing.

Inputs are receipts ONLY: authenticity depends on two separate preceding jobs
each independently downloading actual signed PG ZIP/SPDX/Grype and invoking
real gh attestation verify. This join grants NO Publisher authority.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "r08_join_identity", ROOT / "scripts/fleet-release-identity.py")
ident = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ident)

SOURCE = "APP_BOT_PREPARE_WORKFLOW_DISPATCH_SIGNED_BUILD_ONLY"
STATUS = "VERIFIED_APP_PREPARE_OIDC_NONPUBLISHING"
SHA = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
CALLER = ".github/workflows/issue311-request-local-prepare.yml"
ACTOR = "pgextwin-issue311-prepare-coord[bot]"

class Denied(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Denied(reason)

def unique(pairs):
    result = {}
    for key, val in pairs:
        need(key not in result, "duplicate evidence field")
        result[key] = val
    return result

def read_json(path):
    p = Path(path)
    need(p.is_file() and not p.is_symlink() and 0 < p.stat().st_size < 2_000_000,
         "missing/unsafe original audit JSON")
    data = json.loads(p.read_text("utf-8-sig"), object_pairs_hook=unique)
    need(type(data) is dict, "audit JSON must be object")
    return data

def verify(first, second, manifest, lifecycle, *, repository, sha, run_id):
    need(repository == "pgextwin/orafce" and type(sha) is str
         and SHA.fullmatch(sha) and type(run_id) is int and run_id > 0,
         "pilot repository/run identity invalid")
    need(type(manifest) is dict and manifest.get("name") == "orafce",
         "manifest not bound to pilot repository")
    try:
        majors = ident.maintained_majors(manifest, lifecycle)
    except (ident.Denied, ValueError, TypeError, KeyError) as exc:
        raise Denied("untrusted maintained PG matrix") from exc
    need(majors == [14, 15, 16, 17, 18], "pilot must have all PG14-18")
    immutable = (
        "schemaVersion", "status", "sourceKind", "repository", "mainMergeSha",
        "requestId", "centralRequestId", "centralRunId", "centralArtifactId",
        "centralHeadSha", "centralRequestRawSha256", "centralOuterZipSha256",
        "localWorkflow", "localActor", "localActorId",
        "runId", "runAttempt", "maintainedMajors",
        "zipSha256ByMajor", "spdxSha256ByMajor", "grypeSha256ByMajor",
        "grypePolicyByMajor", "cryptographicVerification", "signedArtifactsVerified",
        "publishableReceipt", "publicationAuthorized",
        "publisherSourceKindAuthorized", "automaticReleaseEnabled",
    )
    for label, item, job in (("first", first, "r08_signed_audit_first"),
                             ("second", second, "r08_signed_audit_second")):
        need(item.get("schemaVersion") == 1 and item.get("status") == STATUS
             and item.get("sourceKind") == SOURCE
             and item.get("repository") == repository
             and item.get("mainMergeSha") == sha
             and item.get("runId") == run_id and item.get("runAttempt") == 1
             and item.get("auditorJob") == job
             and item.get("localWorkflow") == CALLER
             and item.get("localActor") == ACTOR
             and item.get("localActorId") == 350058024
             and type(item.get("requestId")) is str
             and re.fullmatch(r"r-20[0-9]{6}-r06coordlocal[a-z0-9-]{4,40}", item["requestId"])
             and type(item.get("centralRequestId")) is str
             and re.fullmatch(r"r-20[0-9]{6}-r06prepare[a-z0-9-]{4,40}",
                              item["centralRequestId"])
             and type(item.get("centralRunId")) is int and item["centralRunId"] > 0
             and type(item.get("centralArtifactId")) is int and item["centralArtifactId"] > 0
             and type(item.get("centralHeadSha")) is str
             and SHA.fullmatch(item["centralHeadSha"])
             and all(type(item.get(k)) is str and DIGEST.fullmatch(item[k])
                     for k in ("centralRequestRawSha256", "centralOuterZipSha256"))
             and item.get("maintainedMajors") == majors
             and item.get("cryptographicVerification") == "REAL_GH_ATTESTATION_VERIFY"
             and item.get("signedArtifactsVerified") is True
             and all(item.get(k) is False for k in
                     ("publishableReceipt", "publicationAuthorized",
                      "publisherSourceKindAuthorized", "automaticReleaseEnabled")),
             "non-original or privileged " + label + " Sigstore receipt")
        for field in ("zipSha256ByMajor", "spdxSha256ByMajor",
                      "grypeSha256ByMajor"):
            obj = item.get(field)
            need(type(obj) is dict and set(obj) == {str(x) for x in majors}
                 and all(type(v) is str and DIGEST.fullmatch(v)
                         for v in obj.values()), "incomplete " + label + " " + field)
        risks = item.get("grypePolicyByMajor")
        need(type(risks) is dict and set(risks) == {str(x) for x in majors},
             "Grype policy evidence not exhaustive")
    need(all(first.get(k) == second.get(k) for k in immutable),
         "two independently signed source/PG/ZIP/SBOM/Grype audits disagree")
    return {
        "schemaVersion": 1,
        "status": "TWO_INDEPENDENT_APP_OIDC_SIGSTORE_AUDITS_NONPUBLISHING",
        "sourceKind": SOURCE,
        "repository": repository, "localProtectedMainSha": sha,
        "localRunId": run_id, "localRunAttempt": 1,
        "requestId": first["requestId"],
        "centralRequestId": first["centralRequestId"],
        "centralRunId": first["centralRunId"],
        "centralArtifactId": first["centralArtifactId"],
        "centralHeadSha": first["centralHeadSha"],
        "centralRequestRawSha256": first["centralRequestRawSha256"],
        "centralOuterZipSha256": first["centralOuterZipSha256"],
        "auditorJobs": ["r08_signed_audit_first", "r08_signed_audit_second"],
        "maintainedMajors": majors,
        "zipSha256ByMajor": first["zipSha256ByMajor"],
        "spdxSha256ByMajor": first["spdxSha256ByMajor"],
        "grypeSha256ByMajor": first["grypeSha256ByMajor"],
        "signedArtifactsVerified": True, "independentSigstoreAudits": 2,
        "publisherSourceKindAuthorized": False,
        "publicationAuthorized": False, "runtimeEnabled": False,
    }

def main():
    p = argparse.ArgumentParser()
    for field in ("first", "second", "manifest", "lifecycle", "output"):
        p.add_argument("--" + field, required=True)
    a = p.parse_args()
    try:
        need(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and os.environ.get("GITHUB_REF") == "refs/heads/main"
             and os.environ.get("GITHUB_ACTOR") == ACTOR
             and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
             and os.environ.get("GITHUB_JOB") == "r08_dual_audit_join",
             "different local source/run identity")
        evidence = verify(
            read_json(a.first), read_json(a.second), read_json(a.manifest),
            read_json(a.lifecycle), repository=os.environ["GITHUB_REPOSITORY"],
            sha=os.environ["GITHUB_SHA"], run_id=int(os.environ["GITHUB_RUN_ID"]))
        Path(a.output).write_text(json.dumps(evidence, sort_keys=True, indent=2)+"\n",
                                  encoding="utf-8")
        print("R08_TWO_INDEPENDENT_REAL_APP_SIGSTORE_AUDITS; PUBLISH_DENY")
        return 0
    except (Denied, ident.Denied, OSError, KeyError, ValueError, TypeError) as exc:
        print("R08_APP_DUAL_SIGSTORE_DENY: " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
