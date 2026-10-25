#!/usr/bin/env python3
"""Typed NONPUBLISHING intent from a genuine merged candidate and stable decision.

This pure library cannot mint a Release receipt, launch a signed build or call
GitHub. Inputs are NOT authenticated by this module: the future runner must
independently download the original decision artifact and current GitHub data.
It deliberately preserves the existing manual-only policy and DENY default.
"""
from __future__ import annotations

from datetime import date
import importlib.util
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fleet_release_identity", ROOT / "fleet-release-identity.py")
ident = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ident)
SHA = re.compile(r"^[0-9a-f]{40}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
CANDIDATE = re.compile(r"^auto-candidate/([0-9a-f]{20})$")


_policy_spec=importlib.util.spec_from_file_location("shared_fleet_policy",ROOT/"fleet-policy.py")
fleet_policy=importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(fleet_policy)

class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def plan(*, witness, decision, pr, manifest, lifecycle, fleet, central_policy, local_candidate_policy,
         today=None):
    """Check exact machine-readable joins, returning only a nonpublishing plan.

    A green candidate CI and unsigned ZIP digest are never evidence of signed
    Release provenance, even when the data comes from a real Actions artifact.
    """
    require(type(witness) is dict and type(decision) is dict and type(manifest) is dict,
            "missing or malformed independent candidate evidence")
    repository = "pgextwin/" + str(manifest.get("name", ""))
    require(manifest.get("name") in ident.UPSTREAMS
            and witness.get("repository") == repository
            and decision.get("extension") == manifest["name"]
            and decision.get("repository") == manifest["upstream"].get("repository"),
            "exact extension/repository/upstream identity mismatch")
    try:
        roster=fleet_policy.central_policy(fleet,central_policy,
            audited={"pgextwin/"+n for n in ident.UPSTREAMS})
        require(repository in roster,"unknown signing target")
    except fleet_policy.Denied as exc:
        raise Denied("candidate fleet/central policy mismatch") from exc
    require(type(local_candidate_policy) is dict
            and type(local_candidate_policy.get("schemaVersion")) is int
            and type(local_candidate_policy.get("enabled")) is bool
            and local_candidate_policy == {"schemaVersion": 1, "enabled": True,
                                           "releasePolicy": "manual-only",
                                           "workflow": "windows.yml"},
            "local candidate policy not the established manual-only contract")
    require(type(witness.get("schemaVersion")) is int
            and witness["schemaVersion"] == 1
            and witness.get("status") == "MERGED_NATIVE_CANDIDATE_NONPUBLISHING"
            and type(witness.get("candidatePr")) is int and witness["candidatePr"] > 0
            and type(witness.get("candidateCiRunId")) is int
            and witness["candidateCiRunId"] > 0
            and type(witness.get("nativeAuditRunId")) is int
            and witness["nativeAuditRunId"] > 0
            and type(witness.get("nativeAuditArtifactId")) is int
            and witness["nativeAuditArtifactId"] > 0
            and type(witness.get("mainMergeSha")) is str
            and SHA.fullmatch(witness["mainMergeSha"])
            and type(witness.get("candidateHeadSha")) is str
            and SHA.fullmatch(witness["candidateHeadSha"]),
            "real protected-merge witness identity is incomplete")
    require(type(pr) is dict and type(pr.get("number")) is int
            and pr["number"] == witness["candidatePr"]
            and pr.get("state") == "closed" and pr.get("merged") is True
            and pr.get("draft") is False
            and pr.get("merge_commit_sha") == witness["mainMergeSha"]
            and (pr.get("head") or {}).get("sha") == witness["candidateHeadSha"]
            and (pr.get("head") or {}).get("ref") == witness.get("candidateBranch")
            and (pr.get("base") or {}).get("ref") == "main"
            and (pr.get("user") or {}).get("login") == "github-actions[bot]",
            "merged candidate PR does not match protected native witness")
    for forbidden in ("signedArtifactsVerified", "publishableReceipt",
                      "publicationAuthorized", "automaticReleaseEnabled"):
        require(witness.get(forbidden) is False,
                "unsigned audit illegally claims publisher authorization")
    require(type(decision.get("schemaVersion")) is int and decision["schemaVersion"] == 1
            and decision.get("status") == "candidate"
            and decision.get("releasePolicy") == "manual-only"
            and type(decision.get("candidateId")) is str
            and type(decision.get("branch")) is str
            and CANDIDATE.fullmatch(decision["branch"]) is not None
            and decision["branch"] == "auto-candidate/" + decision["candidateId"]
            and witness.get("candidateBranch") == decision["branch"],
            "decision artifact does not identify this merged bot candidate")
    try:
        majors = ident.maintained_majors(manifest, lifecycle, today=today or date.today())
        pins = ident.sources(manifest)
        tag_stem = ident.tag_stem(manifest)
    except (ident.Denied, ValueError, KeyError, TypeError) as exc:
        raise Denied("invalid maintained PG majors, upstream pins or version: " + str(exc)) from exc
    require(witness.get("maintainedMajors") == majors
            and witness.get("releaseTagStem") == tag_stem
            and type(witness.get("sourcesAndZipDigests")) is list
            and len(witness["sourcesAndZipDigests"]) == len(majors),
            "verified major matrix or candidate Release tag stem differs")
    for major, evidence in zip(majors, witness["sourcesAndZipDigests"]):
        require(type(evidence) is dict and type(evidence.get("major")) is int
                and evidence["major"] == major
                and evidence.get("sourceSha") == pins[major]["commit"]
                and type(evidence.get("zipSha256")) is str
                and HASH.fullmatch(evidence["zipSha256"]),
                "candidate ZIP hash/upstream commit is not exactly bound")
    updates = decision.get("updates")
    require(type(updates) is list and len(updates) > 0, "no original stable update decisions")
    per_major = "perPostgresql" in manifest["upstream"]
    expected = {u.get("major") for u in updates if type(u) is dict}
    require(len(expected) == len(updates)
            and (expected <= set(majors) if per_major else
                 len(updates) == 1 and expected == {None}),
            "duplicated or out-of-matrix stable update decisions")
    for update in updates:
        require(type(update) is dict and update.get("initialOnly") is not True,
                "unexpected first-release or malformed decision")
        source = pins[update["major"]] if per_major else pins[majors[-1]]
        require(update.get("ref") == source["ref"]
                and str(update.get("version")) == str(source["version"])
                and update.get("commit") == source["commit"]
                and type(update.get("commit")) is str
                and SHA.fullmatch(update["commit"]),
                "original stable decision not identical to merged source")
    return {
        "schemaVersion": 1, "status": "ELIGIBLE_FOR_FURTHER_SIGNED_BUILD_AUDIT_NONPUBLISHING",
        "repository": repository, "candidatePr": witness["candidatePr"],
        "candidateBranch": decision["branch"],
        "candidateHeadSha": witness["candidateHeadSha"],
        "mainMergeSha": witness["mainMergeSha"],
        "candidateCiRunId": witness["candidateCiRunId"],
        "nativeAuditRunId": witness["nativeAuditRunId"],
        "nativeAuditArtifactId": witness["nativeAuditArtifactId"],
        "maintainedMajors": majors, "releaseTagStem": tag_stem,
        "signedArtifactsVerified": False, "publishableReceipt": False,
        "publicationAuthorized": False, "automaticReleaseEnabled": False,
    }


if __name__ == "__main__":
    raise SystemExit("Nonpublishing library only; cannot issue a Release receipt.")
