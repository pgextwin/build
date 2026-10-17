#!/usr/bin/env python3
"""Issue #75: offline, fail-closed pinned dependency delta (no GitHub, no token, no writer).

Authenticated immutable GitHub GET observations must be obtained independently.
Matching this record establishes only a bounded source-graph inventory, NOT a
complete executable dependency closure, runtime credentials, or GO B acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "evidence/issue-75/critical-pin-closure-20261017.json"
DELTA = ROOT / "evidence/issue-75/transitive-dependency-delta-20261017.json"
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

baseline = load(ROOT / "scripts/issue-75-go-b-critical-pin-closure.py",
                "issue75_existing_critical_snapshot")
class Deny(ValueError):
    pass

# Exact additions observed under immutable Git tree GETs. The 32 source Blob
# record is reused and never edited. These are Git blob object IDs, not ZIP
# digests, action transitive attestation, or runtime file-byte hashes.
EXTRA = {
    "pilot:config/export-audit.json": "51ecd6ced788a54489e469c6b20e4fedb4484f88",
    "pilot:windows/ci/build.ps1": "abb70ec55193c7c9eebe9aa2d72f0bf49e57daab",
    "pilot:windows/ci/install.ps1": "da2b07f4052833d37572035715b7263911e15019",
    "pilot:windows/ci/package.ps1": "aea30d03a3d0129007d3a216cc38ebeca8598723",
    "pilot:windows/ci/smoke-test.ps1": "3aa02d0d866ebcba55bf274d6373ecc1871652eb",
    "signer:scripts/install-postgresql.ps1": "c40c7c59df30800d46d0cd4928b40ea0e715212f",
    "signer:scripts/install-syft.ps1": "08cdfde4a51c8ea36100b910d87bad62a1456ac6",
    "signer:scripts/generate-sbom.ps1": "e427f92cc32715a2db9b1b7df7d50bcb26cf5a0e",
    "signer:scripts/install-grype.ps1": "1312bae41b730e61fdb4589d76c3d221b2bd15b7",
    "signer:scripts/scan-vulnerabilities.ps1": "9fc0084070b74ccd6314ca052fa15095bea2c055",
    "signer:scripts/validate-sbom.py": "0200e9b013cb2c398c038e32b43b417a1df3a457",
    "signer:scripts/validate-vulnerability-report.py": "a99eafcc0361ef8e2926cbde05838a22acae8b12",
    "signer:config/grype-report-only.yaml": "b8b79e2c07a9d275188bd0394f965e90e4b3233e",
}
# Static pins seen in source. Versions/ranges are explicitly not bit-digests.
EXTERNAL = {
    "ext:actions/checkout": ("github_action", "3d3c42e5aac5ba805825da76410c181273ba90b1", "git_ref_only"),
    "ext:actions/setup-python": ("github_action", "ece7cb06caefa5fff74198d8649806c4678c61a1", "git_ref_only"),
    "ext:actions/upload-artifact": ("github_action", "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "git_ref_only"),
    "ext:actions/download-artifact": ("github_action", "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", "git_ref_only"),
    "ext:actions/attest": ("github_action", "1e69f48acb82d1966a394da916b4c1698aa569d6", "git_ref_only"),
    "ext:actions/create-github-app-token": ("github_action", "bcd2ba49218906704ab6c1aa796996da409d3eb1", "git_ref_only"),
    "ext:syft-zip": ("release_download", "8b56e8285e295e0bbed26eeea9b16ed51c493be97ccdf42dae6326c84fe8e19f", "sha256_in_installer_source_only"),
    "ext:grype-zip": ("release_download", "32e3c811f31822d17592908bafdc6288aaaca3d52583c479167a8dc8399ed65d", "sha256_in_installer_source_only"),
    "ext:chocolatey-postgresql": ("package_manager", "postgresql14=14.24.0;postgresql15=15.19.0;postgresql16=16.15.5;postgresql17=17.11.4;postgresql18=18.6.5", "version_only"),
    "ext:python-jsonschema": ("python_package", "jsonschema>=4,<5", "floating"),
    "ext:python-meson-ninja": ("python_package", "meson==1.8.3;ninja==1.11.1.4", "version_only"),
    "ext:windows-runner": ("runner_image", "windows-latest", "floating"),
    "ext:ubuntu-runner": ("runner_image", "ubuntu-latest", "floating"),
    "ext:vs-msvc": ("toolchain", "vswhere -latest;VC.Tools.x86.x64", "floating"),
    "ext:grype-db": ("remote_database", "grype db update", "floating"),
    "ext:upstream-source": ("upstream_git", "ccdbcce9de51f01e1138c270aeb9fe4e26c6e911", "git_ref_only"),
}
REQUIRED_EDGES = {
    ("pilot:.github/workflows/promote.yml", "legacy:scripts/fleet-promotion-gate.py"),
    ("pilot:.github/workflows/promote.yml", "legacy:scripts/fleet-publish-release.py"),
    ("pilot:.github/workflows/promote.yml", "signer:.github/workflows/build-extension-attested.yml"),
    ("signer:.github/workflows/build-extension-attested.yml", "signer:scripts/install-postgresql.ps1"),
    ("signer:.github/workflows/build-extension-attested.yml", "signer:scripts/install-syft.ps1"),
    ("signer:.github/workflows/build-extension-attested.yml", "signer:scripts/install-grype.ps1"),
    ("signer:.github/workflows/build-extension-attested.yml", "signer:scripts/generate-sbom.ps1"),
    ("signer:.github/workflows/build-extension-attested.yml", "signer:scripts/scan-vulnerabilities.ps1"),
    ("signer:.github/workflows/build-extension-attested.yml", "signer:scripts/validate-sbom.py"),
    ("signer:.github/workflows/build-extension-attested.yml", "signer:scripts/validate-vulnerability-report.py"),
    ("signer:scripts/scan-vulnerabilities.ps1", "signer:config/grype-report-only.yaml"),
    ("pilot:windows/ci/build.ps1", "pilot:config/export-audit.json"),
    ("pilot:windows/ci/build.ps1", "ext:python-meson-ninja"),
    ("pilot:windows/ci/build.ps1", "ext:vs-msvc"),
    ("pilot:windows/ci/build.ps1", "ext:upstream-source"),
    ("signer:scripts/install-postgresql.ps1", "ext:chocolatey-postgresql"),
    ("signer:scripts/install-syft.ps1", "ext:syft-zip"),
    ("signer:scripts/install-grype.ps1", "ext:grype-zip"),
    ("signer:scripts/scan-vulnerabilities.ps1", "ext:grype-db"),
    ("signer:.github/workflows/build-extension-attested.yml", "ext:python-jsonschema"),
    ("pilot:.github/workflows/promote.yml", "ext:ubuntu-runner"),
    ("signer:.github/workflows/build-extension-attested.yml", "ext:windows-runner"),
}
GAPS = {
    "thirdPartyActionTransitiveDependencies", "runnerImageUnpinned",
    "chocolateyBinaryDigestAbsent", "pythonDependencyWheelHashesAbsent",
    "vsToolchainMutable", "grypeDatabaseMutable",
    "noRealSignedPublisherPositivePrewrite", "noVerifiedReaderTokenScopes",
    "noLiveWriterTokenIsolation", "noLiveCrashSafeWriter",
    "signerCheckoutPersistsJobCredential", "runtimeWorkflowCheckoutResolutionUnproven",
}

def require(ok, message):
    if not ok:
        raise Deny(message)

def read_json(path):
    require(path.is_file() and path.stat().st_size < 128000, "missing/large evidence")
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, "duplicate JSON key")
            result[k] = v
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)

def git_blob_id(blob):
    return hashlib.sha1(b"blob " + str(len(blob)).encode("ascii") + b"\0" + blob).hexdigest()

def inspect(delta, base, *, base_bytes):
    baseline.inspect(base)
    require(git_blob_id(base_bytes) == delta.get("baseline", {}).get("gitBlob") ==
            "b846c8c55e1ffbaab126d4674de9d7dc52376cf0",
            "immutable previous 32-Blob record mismatch")
    require(type(delta) is dict and delta.get("schemaVersion") == 1 and
            delta.get("evidenceKind") == "ISSUE75_TRANSITIVE_DEPENDENCY_DELTA_DENY_ONLY",
            "unknown dependency evidence kind")
    origin = delta.get("baseline")
    require(type(origin) is dict and
            origin.get("path") == "evidence/issue-75/critical-pin-closure-20261017.json"
            and origin.get("rootNames") == ["pilot", "legacy", "signer", "current"]
            and origin.get("blobCount") == 32, "root or original 32 Blob mismatch")
    require(type(delta.get("additionalGitBlobs")) is dict and
            delta["additionalGitBlobs"] == EXTRA, "newly observed Git Blob missing/drift")
    local = {name + ":" + path: sha
             for name, record in base["roots"].items()
             for path, sha in record["blobs"].items()}
    require(not (set(local) & set(EXTRA)), "new evidence overwrote original 32")
    local.update(EXTRA)
    ext = delta.get("externalDependencies")
    require(type(ext) is dict and set(ext) == set(EXTERNAL), "missing or added external dependency")
    for key, (kind, pin, verification) in EXTERNAL.items():
        item = ext[key]
        require(type(item) is dict and set(item) == {"kind", "pin", "verification", "gap"}
                and (item["kind"], item["pin"], item["verification"]) ==
                (kind, pin, verification) and
                type(item["gap"]) is str and bool(item["gap"].strip()),
                "external dependency pin/status forged: " + key)
        if verification in ("git_ref_only", "sha256_in_installer_source_only"):
            require(bool((SHA64 if verification.startswith("sha256") else SHA40).fullmatch(pin)),
                    "incorrect external hash namespace")
    all_nodes = set(local) | set(ext)
    links = delta.get("edges")
    require(type(links) is list and len(links) == 54, "dependency edge count drift")
    pairs = []
    for link in links:
        require(type(link) is dict and set(link) == {"from", "to"} and
                type(link["from"]) is str and type(link["to"]) is str,
                "invalid dependency edge")
        src, dst = link["from"], link["to"]
        require(src in local and dst in all_nodes and src != dst,
                "dependency to/from unknown or non-source node")
        pairs.append((src, dst))
    require(len(set(pairs)) == len(pairs) and REQUIRED_EDGES <= set(pairs),
            "missing core edge, duplicate, or unexpected dependency")
    for key in EXTRA:
        require(any(dst == key for _, dst in pairs), "orphan additional Git blob")
    for key in ext:
        require(any(dst == key for _, dst in pairs), "unreachable external dependency")
    # Detect any directed cycle, including paths spanning pilot, legacy and signer.
    adj = {}
    for src, dst in pairs:
        adj.setdefault(src, []).append(dst)
    entered, finished = set(), set()
    def visit(node):
        require(node not in entered, "dependency cycle")
        if node in finished:
            return
        entered.add(node)
        for child in adj.get(node, []):
            visit(child)
        entered.remove(node)
        finished.add(node)
    for node in all_nodes:
        visit(node)
    creds = delta.get("credentialBoundaries")
    require(type(creds) is dict and set(creds) == {"reader", "signer", "writer",
                "pilotAuthorizePublisherPersistCredentials",
                "readerCheckoutPersistCredentials", "artifactLeakageRuntimeVerified"},
            "missing credential boundary record")
    reader, signer, writer = (creds[n] for n in ("reader", "signer", "writer"))
    require(type(reader) is dict and reader.get("job") == "issue75_reader_probe"
            and reader.get("permissions") == ["actions:read", "contents:read"]
            and reader.get("separateTokenContext") is True
            and reader.get("usesWriterCredential") is False
            and reader.get("runtimeTokenScopesVerified") is False,
            "reader/writer token boundary not accepted")
    require(type(signer) is dict and signer.get("permissions") ==
            ["contents:read", "id-token:write", "attestations:write",
             "artifact-metadata:write"] and
            signer.get("runtimeTokenScopesVerified") is False and
            signer.get("checkoutPersistCredentials") is True,
            "signer permission/status drift")
    require(type(writer) is dict and writer.get("permissions") ==
            ["contents:write", "actions:read", "attestations:read"] and
            writer.get("runThisStep") is False and
            writer.get("tokenMintedThisStep") is False and
            writer.get("runtimeTokenScopesVerified") is False,
            "writer was claimed active")
    require(creds["pilotAuthorizePublisherPersistCredentials"] is False and
            creds["readerCheckoutPersistCredentials"] is False and
            creds["artifactLeakageRuntimeVerified"] is False,
            "unreviewed checkout/artifact security status")
    accepted = delta.get("acceptance")
    require(type(accepted) is dict and set(accepted) == {
        "internalClosureAuthenticated", "externalClosureAuthenticated",
        "liveSignedPublisherPrewrite", "goB", "g4", "g5",
        "publicationAuthorized", "mutationAuthorized"}, "capability keys drift")
    require(all(accepted[k] is False for k in (
        "internalClosureAuthenticated", "externalClosureAuthenticated",
        "liveSignedPublisherPrewrite", "publicationAuthorized", "mutationAuthorized"))
        and all(accepted[k] == "NO_GO" for k in ("goB", "g4", "g5")),
        "forged real Publisher approval")
    require(type(delta.get("knownUnresolved")) is list and
            len(delta["knownUnresolved"]) == len(GAPS) and
            set(delta["knownUnresolved"]) == GAPS, "unresolved dynamic dependencies hidden")
    return {"decision": "INTERNAL_BLOB_SUBGRAPH_RECORDED_EXTERNAL_INCOMPLETE",
            "originalGitBlobs": len(local) - len(EXTRA), "addedGitBlobs": len(EXTRA),
            "totalGitBlobs": len(local), "dependencyEdges": len(pairs),
            "unverifiedExternalDependencies": len(ext),
            "readerTokenScopesVerified": False, "writerTokenIsolationVerified": False,
            "signedPublisherPrewriteVerified": False, "goB": "NO_GO",
            "g4": "NO_GO", "g5": "NO_GO", "publicationAuthorized": False,
            "mutationAuthorized": False}

def main(argv=None):
    p = argparse.ArgumentParser(description="Offline bounded dependency graph; NO-GO")
    p.add_argument("--delta", type=Path, default=DELTA)
    args = p.parse_args(argv)
    try:
        raw = BASE.read_bytes()
        print(json.dumps(inspect(read_json(args.delta), read_json(BASE),
                                 base_bytes=raw), sort_keys=True))
        return 0  # Offline inventory valid, NOT an execution/go-live receipt.
    except (Deny, OSError, UnicodeError, ValueError, TypeError, KeyError,
            RecursionError, baseline.Deny) as exc:
        print(json.dumps({"decision": "DENY_DEPENDENCY_EVIDENCE",
                          "reason": str(exc), "publicationAuthorized": False,
                          "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO"},
                         sort_keys=True))
        return 2

if __name__ == "__main__":
    sys.exit(main())
