#!/usr/bin/env python3
"""Shared 17-extension signed-build -> Publisher policy boundary (READ ONLY).

This bridge runs immediately AFTER the actual gh/Sigstore/ZIP verifier in the
same trusted, immutable reusable workflow job. It cannot mint a publishable
receipt, request a token, dispatch a workflow, create a tag, or call GitHub.
Current fleet + local/central + unattended policies independently block writes.
A future Publisher MUST reauthenticate real signature/PR/run/authorisation and
must not treat this nonpublishing observation as permission. Issue #75.
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


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


identity = module("bridge_release_identity", "fleet-release-identity.py")
unattended_policy = module("bridge_unattended_policy", "unattended-policy.py")
SHA = re.compile(r"^[0-9a-f]{40}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")


class Denied(ValueError):
    pass


def require(condition, detail):
    if not condition:
        raise Denied(detail)


def load_object(path):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate policy/audit JSON key")
            result[key] = value
        return result
    value = json.loads(Path(path).read_text("utf-8-sig"), object_pairs_hook=unique)
    require(type(value) is dict, "expected JSON object")
    return value


def bridge(audit, *, repo, sha, run_id, attempt, event, ref,
           fleet, central, local, unattended):
    """Establish verified READ-ONLY handoff while NEVER authorizing publication.

    audit MUST have been emitted by the immutable cryptographic verifier in this
    same job. This function is not an independent proof of genuine signatures.
    """
    require(type(repo) is str and REPO.fullmatch(repo)
            and type(sha) is str and SHA.fullmatch(sha)
            and type(run_id) is int and run_id > 0
            and type(attempt) is int and attempt > 0
            and event == "push" and ref == "refs/heads/main",
            "not a genuine main/push runtime identity")
    require(type(audit) is dict
            and type(audit.get("schemaVersion")) is int
            and audit["schemaVersion"] == 1
            and audit.get("status") == "VERIFIED_SIGNED_CANDIDATE_NONPUBLISHING"
            and audit.get("cryptographicVerification") == "REAL_GH_ATTESTATION_VERIFY"
            and audit.get("repository") == repo
            and audit.get("mainMergeSha") == sha
            and type(audit.get("runId")) is int
            and audit["runId"] == run_id
            and type(audit.get("runAttempt")) is int
            and audit["runAttempt"] == attempt
            and audit.get("signedArtifactsVerified") is True
            and all(audit.get(key) is False for key in
                    ("publishableReceipt", "publicationAuthorized",
                     "automaticReleaseEnabled")),
            "real cryptographic audit binding invalid or tried to grant PUBLISH")
    try:
        expected_roster = {"pgextwin/" + name for name in identity.UPSTREAMS}
    except (TypeError, AttributeError) as exc:
        raise Denied("release registry unavailable") from exc
    require(len(expected_roster) == 17 and repo in expected_roster,
            "repository is not one of the same 17 protected extensions")
    majors = audit.get("maintainedMajors")
    # Preserve the SHA256 of every verified on-disk ZIP, SPDX and Grype byte
    # stream, not just ZIP bytes. These are integrity evidence, NOT independent
    # cryptographic proofs of all three assets or Publisher authorization.
    digests = {kind: audit.get(kind + "Sha256ByMajor")
               for kind in ("zip", "spdx", "grype")}
    require(type(majors) is list and len(majors) >= 1
            and len(majors) <= 5 and all(type(v) is int and 14 <= v <= 18 for v in majors)
            and majors == sorted(set(majors))
            and all(type(values) is dict
                    and set(values) == {str(m) for m in majors}
                    and all(type(v) is str and HASH.fullmatch(v)
                            for v in values.values())
                    for values in digests.values()),
            "incomplete/ambiguous Windows ZIP/SPDX/Grype SHA256 matrices")
    # An authenticated Grype report may identify real blockers; a CLEAN scan
    # still cannot bypass the existing independent Publisher authorization.
    grype_risk = audit.get("grypePolicyByMajor")
    require(type(grype_risk) is dict and set(grype_risk) == {str(m) for m in majors}
            and all(type(v) is dict
                    and v.get("status") in ("BLOCKING_FINDINGS", "NO_BLOCKING_FINDINGS")
                    and type(v.get("blockingFindingCount")) is int
                    and v["blockingFindingCount"] >= 0
                    and v.get("publicationAuthorized") is False
                    and type(v.get("findingCountBySeverity")) is dict
                    and set(v["findingCountBySeverity"]) ==
                        {"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
                    and all(type(c) is int and c >= 0
                            for c in v["findingCountBySeverity"].values())
                    and v["blockingFindingCount"] == sum(
                        v["findingCountBySeverity"][k]
                        for k in ("Critical", "High", "Unknown"))
                    and (v["status"] == "BLOCKING_FINDINGS") ==
                        (v["blockingFindingCount"] > 0)
                    for v in grype_risk.values()),
            "untrusted or incomplete per-PG blocking Grype scan verdict")
    require(type(fleet) is dict and type(fleet.get("schemaVersion")) is int
            and fleet["schemaVersion"] == 1
            and fleet.get("releasePolicy") == "manual-only"
            and type(fleet.get("entries")) is list and len(fleet["entries"]) == 17,
            "fleet automatic release policy is not independently valid")
    rows = fleet["entries"]
    require(all(type(v) is dict for v in rows)
            and {v.get("repository") for v in rows} == expected_roster
            and all(v.get("mode") == "BUILD" and v.get("candidateEnabled") is True
                    and v.get("releasePolicy") == "manual-only" for v in rows),
            "fleet roster, BUILD lane, or manual-only gate mismatched")
    require(type(central) is dict and type(central.get("schemaVersion")) is int
            and central["schemaVersion"] == 1
            and central.get("releasePolicy") == "manual-dispatch"
            and type(central.get("allowedRepositories")) is list
            and len(central["allowedRepositories"]) == 17
            and set(central["allowedRepositories"]) == expected_roster,
            "central Release authorization is NOT the established manual gate")
    require(local == {"schemaVersion": 1, "enabled": True,
                      "releasePolicy": "manual-dispatch"},
            "local Release policy must stay in the existing manual mode")
    try:
        mode = unattended_policy.evaluate(unattended, fleet)
    except (unattended_policy.PolicyDenied, TypeError, KeyError, ValueError) as exc:
        raise Denied("unattended policy invalid") from exc
    require(mode.get("status") == "OBSERVE_ONLY"
            and mode.get("automaticPublicationAuthorized") is False
            and unattended.get("mode") == "OBSERVE"
            and unattended.get("defaultAction") == "DENY"
            and unattended["controls"].get("automaticFormalRelease") is False,
            "existing OBSERVE/DENY safety gate may not be weakened by this bridge")
    return {
        "schemaVersion": 1,
        "status": "PUBLISH_DENY",
        "repository": repo,
        "mainMergeSha": sha,
        "runId": run_id,
        "runAttempt": attempt,
        "verifiedAuditStatus": audit["status"],
        "maintainedMajors": majors,
        "zipSha256ByMajor": digests["zip"],
        "spdxSha256ByMajor": digests["spdx"],
        "grypeSha256ByMajor": digests["grype"],
        "grypePolicyByMajor": grype_risk,
        "policyBlockers": [
            "CENTRAL_MANUAL_DISPATCH",
            "LOCAL_MANUAL_DISPATCH",
            "FLEET_MANUAL_ONLY",
            "UNATTENDED_OBSERVE_DENY",
            *(["BLOCKING_GRYPE_FINDINGS"] if any(
                v["blockingFindingCount"] for v in grype_risk.values()) else []),
            "INDEPENDENT_PUBLISHER_AUTHORIZATION_NOT_ESTABLISHED",
        ],
        "publishableReceipt": False,
        "publicationAuthorized": False,
        "automaticReleaseEnabled": False,
        "publisherWriteEnabled": False,
        "goB": "NO_GO",
        "g4": "NO_GO",
        "g5": "NO_GO",
    }


def main():
    parser = argparse.ArgumentParser()
    for name in ("audit", "fleet", "central-policy", "local-policy",
                 "unattended", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        info = bridge(
            load_object(args.audit),
            repo=os.environ.get("GITHUB_REPOSITORY"),
            sha=os.environ.get("GITHUB_SHA"),
            run_id=int(os.environ.get("GITHUB_RUN_ID", "0")),
            attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")),
            event=os.environ.get("GITHUB_EVENT_NAME"),
            ref=os.environ.get("GITHUB_REF"),
            fleet=load_object(args.fleet),
            central=load_object(args.central_policy),
            local=load_object(args.local_policy),
            unattended=load_object(args.unattended))
        Path(args.output).write_text(json.dumps(info, indent=2) + "\n", "utf-8")
        print("PUBLISH_DENY: signed-build audit observed; effective policy still blocks formal Release.")
        return 0
    except (Denied, OSError, TypeError, ValueError, KeyError) as exc:
        print("SIGNED_PUBLISHER_BRIDGE_DENY: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
