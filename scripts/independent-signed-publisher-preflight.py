#!/usr/bin/env python3
"""Separate-job signed-candidate second opinion, strictly NONPUBLISHING.

The caller MUST independently run real gh attestation verify and re-download
original signed ZIP/SPDX/Grype into a fresh READ-only job using the pinned
automatic-signed-candidate-audit.py. This pure comparator does NOT verify
signatures, use tokens, grant Publisher rights or create tags.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "second_opinion_release_identity", ROOT / "fleet-release-identity.py")
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)
SHA = re.compile(r"^[0-9a-f]{40}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
DENIALS = ("publishableReceipt", "publicationAuthorized", "automaticReleaseEnabled")


class Denied(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise Denied(why)


def unique(items):
    obj = {}
    for key, value in items:
        require(key not in obj, "duplicate evidence JSON key")
        obj[key] = value
    return obj


def read_json(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink(), "missing or unsafe evidence path")
    value = json.loads(p.read_text("utf-8-sig"), object_pairs_hook=unique)
    require(type(value) is dict, "evidence must be one JSON object")
    return value


def compare(first, second, *, repo, sha, run_id, attempt, manifest, lifecycle,
            event, ref):
    """Compare first-job bytes to an independently re-verified second-job audit.

    Successful *real* Sigstore verification is a mandatory prerequisite in the
    calling GitHub job, NOT something this comparison alone can establish.
    """
    require(type(repo) is str and repo.startswith("pgextwin/")
            and repo == "pgextwin/" + str(manifest.get("name"))
            and repo.split("/")[1] in identity.UPSTREAMS
            and type(sha) is str and SHA.fullmatch(sha)
            and type(run_id) is int and run_id > 0
            and type(attempt) is int and attempt > 0
            and event == "push" and ref == "refs/heads/main",
            "not a protected original main/push candidate identity")
    try:
        majors = identity.maintained_majors(manifest, lifecycle)
        identity.sources(manifest)
    except (identity.Denied, KeyError, TypeError, ValueError) as exc:
        raise Denied("untrusted extension source or PostgreSQL lifecycle") from exc
    for label, audit in (("origin", first), ("independent", second)):
        require(type(audit) is dict and type(audit.get("schemaVersion")) is int
                and audit["schemaVersion"] == 1
                and audit.get("status") == "VERIFIED_SIGNED_CANDIDATE_NONPUBLISHING"
                and audit.get("cryptographicVerification") == "REAL_GH_ATTESTATION_VERIFY"
                and audit.get("signedArtifactsVerified") is True
                and all(audit.get(k) is False for k in DENIALS)
                and audit.get("repository") == repo
                and audit.get("mainMergeSha") == sha
                and type(audit.get("runId")) is int
                and audit["runId"] == run_id
                and type(audit.get("runAttempt")) is int
                and audit["runAttempt"] == attempt
                and audit.get("maintainedMajors") == majors,
                label + " signed proof has invalid main/run/attempt or grants PUBLISH")
        required_keys = {str(m) for m in majors}
        for asset in ("zip", "spdx", "grype"):
            hashes = audit.get(asset + "Sha256ByMajor")
            require(type(hashes) is dict and set(hashes) == required_keys
                    and all(type(x) is str and HASH.fullmatch(x)
                            for x in hashes.values()),
                    label + " has missing or forged " + asset + " SHA256 matrix")
        risks = audit.get("grypePolicyByMajor")
        require(type(risks) is dict and set(risks) == required_keys,
                label + " has partial Grype risk matrix")
        for major in required_keys:
            r = risks[major]
            require(type(r) is dict and r.get("status") == "NO_BLOCKING_FINDINGS"
                    and type(r.get("blockingFindingCount")) is int
                    and r["blockingFindingCount"] == 0
                    and r.get("publicationAuthorized") is False
                    and type(r.get("findingCountBySeverity")) is dict
                    and all(type(r["findingCountBySeverity"].get(k)) is int
                            and r["findingCountBySeverity"][k] == 0
                            for k in ("Critical", "High", "Unknown")),
                    label + " contains blocking or incomplete Grype findings")
        require("publisherWriteEnabled" not in audit
                and "authorizationMode" not in audit
                and "releaseTag" not in audit
                and "operator" not in audit,
                label + " evidence includes illicit Publisher authorization")
    # Every current value, not just ZIP SHA256, must be byte-for-byte bound
    # between original signed-audit output and the second independent runner.
    require(first == second, "independent Sigstore/ZIP/SPDX/Grype/attempt evidence drift")
    return {"schemaVersion": 1,
            "status": "INDEPENDENT_SIGNED_RECHECK_MATCH_NONPUBLISHING",
            "repository": repo, "mainMergeSha": sha,
            "runId": run_id, "runAttempt": attempt,
            "maintainedMajors": majors,
            "assetByteDigestsMatch": True,
            "signedCandidateReverifiedBySeparateJob": True,
            "publishableReceipt": False, "publicationAuthorized": False,
            "automaticReleaseEnabled": False, "publisherWriteEnabled": False,
            "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO"}


def main():
    p = argparse.ArgumentParser()
    for name in ("first", "second", "manifest", "lifecycle", "output"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    try:
        obj = compare(
            read_json(a.first), read_json(a.second),
            repo=os.environ.get("GITHUB_REPOSITORY"),
            sha=os.environ.get("GITHUB_SHA"),
            run_id=int(os.environ.get("GITHUB_RUN_ID", "0")),
            attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")),
            manifest=read_json(a.manifest), lifecycle=read_json(a.lifecycle),
            event=os.environ.get("GITHUB_EVENT_NAME"),
            ref=os.environ.get("GITHUB_REF"))
        Path(a.output).write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n", "utf-8")
        print("INDEPENDENT_SIGSTORE_SECOND_OPINION_MATCH; PUBLISH DENY")
        return 0
    except (Denied, OSError, KeyError, ValueError, TypeError,
            identity.Denied) as exc:
        print("INDEPENDENT_SIGNED_PUBLISHER_PREFLIGHT_DENY: " + str(exc),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
