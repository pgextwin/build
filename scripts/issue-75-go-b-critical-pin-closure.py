#!/usr/bin/env python3
"""Issue #75: bounded immutable critical-pin closure and security-boundary record.

Pure offline evidence classifier. It never gets a token, fetches GitHub data,
starts a process, generates receipts, calls a Publisher or authorizes writes.
Caller must independently authenticate immutable GitHub GETs; the tracked
snapshot alone is not a full transitive dependency proof or runtime isolation.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "issue75_existing_recovery_classifier",
    ROOT / "scripts/release-recovery-evidence.py")
recovery = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(recovery)

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
PILOT = "98452723fcad2aedafb1c02a210f35950f7e8cf2"
LEGACY = "455f0ccc667697f600700a6e64bcfd6c57b6a977"
SIGNER = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
BASE_CURRENT = "2fa0dd844fdef66e529c090625c6e6f0aa105a67"
SIGNER_BLOB = "93a0a7641253735cf5adb845c768981c79f75b46"
LEGACY_PUBLISHER_BLOB = "85cbe8e6893477210831c6a813fe796f23d7eb08"
CURRENT_PUBLISHER_BLOB = "0ba9700d9b4472d62bdd7137347e4194438a9e66"
PROMOTE_BLOB = "3ae586814b063fefa5c3a554758f13467bb23ea5"

ROOTS = {
    "pilot": ("pgextwin/plpgsql_check", PILOT),
    "legacy": ("pgextwin/build", LEGACY),
    "signer": ("pgextwin/build", SIGNER),
    "current": ("pgextwin/build", BASE_CURRENT),
}
EXPECTED_PATHS = {
    "pilot": frozenset({
        ".github/workflows/promote.yml", "config/release-promotion.json",
        "config/extension.json", "config/test-contract.json"}),
    "legacy": frozenset({
        ".github/workflows/build-extension-attested.yml",
        "scripts/fleet-promotion-gate.py", "scripts/fleet-publish-release.py",
        "scripts/fleet-release-identity.py", "metadata/release-promotion.json",
        "metadata/automation-fleet.json", "metadata/postgresql.json"}),
    "signer": frozenset({
        ".github/workflows/build-extension-attested.yml",
        "scripts/resolve-matrix.ps1", "scripts/finalize-package.ps1",
        "scripts/verify-sbom-attestation.py",
        "scripts/validate-package-metadata.py",
        "scripts/validate-test-contract.py",
        "schema/package-info.schema.json",
        "schema/test-contract.schema.json", "metadata/postgresql.json"}),
    "current": frozenset({
        ".github/workflows/build-extension-attested.yml",
        "scripts/fleet-promotion-gate.py", "scripts/fleet-publish-release.py",
        "scripts/fleet-release-identity.py",
        "scripts/issue-75-publisher-preflight.py",
        "scripts/issue-75-attempt-pin-migration-offline.py",
        "scripts/issue-75-attempt-provenance-readonly.py",
        "scripts/release-authorization.py", "scripts/release-recovery-evidence.py",
        "metadata/release-promotion.json", "metadata/automation-fleet.json",
        "metadata/postgresql.json"}),
}
BOUND_BLOBS = {
    ("pilot", ".github/workflows/promote.yml"): PROMOTE_BLOB,
    ("legacy", "scripts/fleet-publish-release.py"): LEGACY_PUBLISHER_BLOB,
    ("current", "scripts/fleet-publish-release.py"): CURRENT_PUBLISHER_BLOB,
    ("legacy", "scripts/fleet-promotion-gate.py"):
        "6abf79d6a037a9ca5e77d5ce7803d520701e290c",
    ("current", "scripts/fleet-promotion-gate.py"):
        "cdcc84862b108758bd5918efd63b1a50bb8ff935",
    ("current", "scripts/issue-75-publisher-preflight.py"):
        "eb89283a76d325d493cdfb9f36881c43998448c8",
    ("current", "scripts/release-recovery-evidence.py"):
        "41760a940a5f0e0a493600898c809b1881f57c48",
}
GAPS = frozenset({
    "legacyPublisherMissingAttemptScopedGuard",
    "legacyPublisherMissingSignerAndSourceDigestPins",
    "activePublisherRecoverySchemaV1",
    "noRealSignedPublisherPositivePrewrite",
    "noVerifiedReaderTokenRuntimeSeparation",
    "noPublisherRepinAuthorization",
    "noLiveCrashSafeRecoveryAcceptance",
})
PERMISSIONS = {
    "authorizePermissions": frozenset({
        "contents:read", "actions:read", "pull-requests:read"}),
    "buildPermissions": frozenset({
        "contents:read", "id-token:write", "attestations:write",
        "artifact-metadata:write"}),
    "publishPermissions": frozenset({
        "contents:write", "actions:read", "attestations:read"}),
    "catalogPermissions": frozenset({"contents:read"}),
    "catalogAppPermissions": frozenset({"catalog:actions:write"}),
}

class Deny(ValueError):
    pass

def require(value, reason):
    if not value:
        raise Deny(reason)

def pairs_unique(items):
    out = {}
    for key, value in items:
        require(key not in out, "duplicate JSON key in purported evidence")
        out[key] = value
    return out

def read_record(path):
    require(isinstance(path, Path) and path.is_file(), "snapshot file missing")
    require(path.stat().st_size < 128_000, "oversize immutable evidence file")
    try:
        return json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=pairs_unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Deny("unreadable immutable snapshot") from exc

def inspect(snapshot, *, v2=None, remote=None):
    """Record-only structural check of already-observed immutable Git blobs.

    Even an internally coherent snapshot is not authenticated by this function.
    The optional recovery check delegates to the existing pure v2 classifier.
    """
    require(type(snapshot) is dict and snapshot.get("schemaVersion") == 1
            and snapshot.get("evidenceKind") ==
            "ISSUE75_IMMUTABLE_CRITICAL_DEPENDENCY_SNAPSHOT",
            "unrecognized evidence contract")
    roots = snapshot.get("roots")
    require(type(roots) is dict and set(roots) == set(ROOTS),
            "missing/extra trust-root entry")
    all_blobs = {}
    for name, (repo, commit) in ROOTS.items():
        entry = roots[name]
        require(type(entry) is dict
                and entry.get("repository") == repo
                and entry.get("commit") == commit
                and type(entry.get("blobs")) is dict
                and set(entry["blobs"]) == EXPECTED_PATHS[name],
                "untrusted immutable critical-path closure: " + name)
        require(all(type(blob) is str and SHA40.fullmatch(blob)
                    for blob in entry["blobs"].values()),
                "missing/invalid Git blob SHA in " + name)
        all_blobs[name] = entry["blobs"]
    for (root, path), expected in BOUND_BLOBS.items():
        require(all_blobs[root][path] == expected,
                "critical Git blob SHA changed: " + root + "/" + path)
    for root in ("legacy", "signer", "current"):
        require(all_blobs[root][".github/workflows/build-extension-attested.yml"]
                == SIGNER_BLOB, "signer workflow bytes not pinned identically")
    for path in ("scripts/fleet-release-identity.py",
                 "metadata/postgresql.json"):
        require(all_blobs["legacy"][path] == all_blobs["current"][path],
                "shared identity/lifecycle contract drift")
    require(all_blobs["signer"]["metadata/postgresql.json"] ==
            all_blobs["legacy"]["metadata/postgresql.json"],
            "signer lifecycle metadata diverges from Publisher")
    require(all_blobs["current"]["scripts/fleet-promotion-gate.py"] !=
            all_blobs["legacy"]["scripts/fleet-promotion-gate.py"] and
            all_blobs["current"]["scripts/fleet-publish-release.py"] !=
            all_blobs["legacy"]["scripts/fleet-publish-release.py"],
            "legacy and unapproved newer Publisher conflated")
    flow = snapshot.get("pilotWorkflow")
    require(type(flow) is dict
            and flow.get("publisherCheckoutSha") == LEGACY
            and flow.get("authorizeCheckoutSha") == LEGACY
            and flow.get("signerReusableSha") == SIGNER
            and flow.get("trigger") == "workflow_dispatch"
            and flow.get("persistCredentials") is False,
            "pilot route unexpectedly repinned or trigger/checkout changed")
    for key, expected in PERMISSIONS.items():
        v = flow.get(key)
        require(type(v) is list and len(v) == len(expected)
                and all(type(a) is str for a in v)
                and set(v) == expected,
                "missing/overbroad static job permissions: " + key)
    require("contents:write" not in flow["authorizePermissions"]
            and "contents:write" not in flow["buildPermissions"]
            and "id-token:write" not in flow["publishPermissions"]
            and "catalog:actions:write" not in flow["publishPermissions"],
            "privileged caller role combination")
    require(type(snapshot.get("knownGaps")) is list
            and len(snapshot["knownGaps"]) == len(GAPS)
            and set(snapshot["knownGaps"]) == GAPS,
            "unresolved real acceptance gaps concealed")
    acceptance = snapshot.get("acceptance")
    require(type(acceptance) is dict
            and set(acceptance) == {
                "signedArtifactsVerified", "publisherLivePositiveProven",
                "writerTokenIsolationProven", "pinCutoverAuthorized",
                "recoveryV2WriterDeployed", "publishableReceipt",
                "publicationAuthorized", "goB", "g4", "g5"},
            "unknown acceptance/permission field")
    for key in ("signedArtifactsVerified", "publisherLivePositiveProven",
                "writerTokenIsolationProven", "pinCutoverAuthorized",
                "recoveryV2WriterDeployed", "publishableReceipt",
                "publicationAuthorized"):
        require(acceptance[key] is False,
                "forged capability flag: " + key)
    require(all(acceptance[k] == "NO_GO" for k in ("goB", "g4", "g5")),
            "premature promotion of GO B/G4/G5")
    classification = "NOT_OBSERVED"
    if v2 is not None or remote is not None:
        result = recovery.classify_recovery_evidence(v2, remote)
        classification = result["classification"]
        require(result["publicationAuthorized"] is False
                and result["retryAuthorized"] is False
                and result["mutationAuthorized"] is False,
                "recovery classifier crossed writer boundary")
    return {
        "decision": "PASS_READONLY_CRITICAL_PIN_CLOSURE_ONLY",
        "publisherActualPin": LEGACY,
        "publisherCurrentReviewedSha": BASE_CURRENT,
        "signerPin": SIGNER,
        "signerBlobShared": True,
        "criticalPathsObserved": sum(len(x) for x in EXPECTED_PATHS.values()),
        "readerRuntimeCredentialsVerified": False,
        "writerIsolationRuntimeVerified": False,
        "recoveryV2Classification": classification,
        "recoveryV2WriterDeployed": False,
        "realPositivePrewriteVerified": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
        "publishableReceipt": False,
        "publicationAuthorized": False,
        "mutationAuthorized": False,
    }

def main(argv=None):
    p = argparse.ArgumentParser(description="Issue 75 inert pin closure, no writes")
    p.add_argument("--snapshot", required=True)
    args = p.parse_args(argv)
    try:
        print(json.dumps(inspect(read_record(Path(args.snapshot))),
                         sort_keys=True))
        return 0  # Success of an inert validator, NEVER a Publisher authorization.
    except (Deny, KeyError, TypeError) as exc:
        print(json.dumps({"decision": "DENY_READONLY_CRITICAL_PIN_CLOSURE",
                          "reason": str(exc) if isinstance(exc, Deny)
                                    else "malformed trust-root evidence",
                          "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
                          "publicationAuthorized": False}, sort_keys=True))
        return 2

if __name__ == "__main__":
    sys.exit(main())
