#!/usr/bin/env python3
"""Private-only four-caller Signer cryptographic verifier; not a Publisher.

Never invoked by public CI. A future authorized private runtime MUST use real
subprocess.run. Existing Issue75 X509/ZIP/attempt policy is reused. A mocked
process, self-asserted certificate or test success is never Release authority.
"""
from __future__ import annotations
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "issue75_existing_preflight", ROOT / "issue-75-publisher-preflight.py")
preflight = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(preflight)

ISSUER = "https://token.actions.githubusercontent.com"
SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"
SIGNER_SHA = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
REPO = "pgextwin/plpgsql_check"  # backward-compatible original pilot
TARGET_REPOSITORIES = frozenset((
    "pgextwin/plpgsql_check", "pgextwin/pgtap",
    "pgextwin/pg_variables", "pgextwin/pg_store_plans",
))
# Only these four deployed shared-Promotion callers are covered by this
# dormant, nonpublishing verifier. Runtime signer acceptance is NOT_PROVEN.
# Actual upstream refs are not uniformly v-prefixed: pg_store_plans uses 1.10.
# The immutable fleet-release-identity.asset_stem retains authoritative names.
ASSET_NAME = re.compile(
    r"[a-z][a-z0-9_]*(?:-v?[0-9][A-Za-z0-9.+_-]*)?"
    r"-pg(?:14|15|16|17|18)-windows-x64\.zip\Z"
)
PREDICATES = (preflight.PROVENANCE, preflight.SPDX)
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
MAX_ATTEST_STDOUT = 1_000_000
MAX_ZIP = 600_000_000
MAX_SBOM = 8_000_000

class Deny(ValueError):
    pass

def need(condition):
    if not condition:
        raise Deny("unproven cryptographic signer identity")

def regular(path, limit):
    need(isinstance(path, Path) and path.is_absolute() and
         path.is_file() and not path.is_symlink())
    need(0 < path.stat().st_size <= limit)
    return path

def sha256_file(path):
    digest = sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def command(artifact, *, packaging_sha, predicate, repository=REPO):
    need(type(repository) is str and repository in TARGET_REPOSITORIES)
    need(isinstance(artifact, Path) and artifact.is_absolute())
    need(type(packaging_sha) is str and bool(SHA40.fullmatch(packaging_sha)))
    need(predicate in PREDICATES)
    return [
        "gh", "attestation", "verify", str(artifact),
        "--repo", repository, "--signer-workflow", SIGNER,
        "--signer-digest", SIGNER_SHA, "--source-digest", packaging_sha,
        "--source-ref", "refs/heads/main",
        "--cert-oidc-issuer", ISSUER,
        "--predicate-type", predicate, "--deny-self-hosted-runners",
        "--format", "json",
    ]

def invoke_crypto(argv, *, runner=subprocess.run):
    """The real verifier process exit code gates cryptographic trust."""
    need(type(argv) is list and len(argv) == 21)
    need(argv[:3] == ["gh", "attestation", "verify"])
    try:
        finished = runner(argv, capture_output=True, text=True,
                          timeout=120, check=False)
        need(type(finished.returncode) is int and finished.returncode == 0)
        need(type(finished.stdout) is str and
             0 < len(finished.stdout.encode("utf-8")) <= MAX_ATTEST_STDOUT)
        return finished.stdout  # Never log this or process stderr.
    except Exception:
        raise Deny("cryptographic verifier failed or unavailable") from None

def verify_pair(zip_file, sbom_file, *, packaging_sha, run_id, attempt,
                repository=REPO, gh_runner=subprocess.run):
    """Nonpublishing, future-private runtime entrypoint. No CLI or workflow."""
    try:
        need(type(repository) is str and repository in TARGET_REPOSITORIES)
        need(type(packaging_sha) is str and bool(SHA40.fullmatch(packaging_sha)))
        need(type(run_id) is int and run_id > 0)
        need(type(attempt) is int and attempt == 1)
        regular(zip_file, MAX_ZIP)
        regular(sbom_file, MAX_SBOM)
        # The archive and SPDX must belong to the exact same allowlisted
        # extension, release version and supported PG major before gh runs.
        extension = repository.split("/", 1)[1]
        need(bool(ASSET_NAME.fullmatch(zip_file.name)) and
             zip_file.name.startswith(extension + "-") and
             sbom_file.name == zip_file.name[:-4] + ".spdx.json")
        digest = sha256_file(zip_file)
        with sbom_file.open("rb") as f:
            raw = f.read(MAX_SBOM + 1)
        need(len(raw) <= MAX_SBOM)
        sbom = json.loads(raw.decode("utf-8-sig"),
                          object_pairs_hook=preflight._unique)
        need(type(sbom) is dict and sbom.get("spdxVersion") == "SPDX-2.3")
        for predicate in PREDICATES:
            stdout = invoke_crypto(
                command(zip_file, packaging_sha=packaging_sha,
                        predicate=predicate, repository=repository),
                runner=gh_runner)
            preflight.verified_claims(
                stdout, predicate=predicate, repo=repository,
                packaging_sha=packaging_sha, run_id=run_id,
                attempt=attempt, zip_name=zip_file.name,
                zip_digest=digest, sbom=sbom)
        return {
            "classification": "SIGNER_CRYPTO_PROCESS_AND_PIN_POLICY_PASSED",
            "verifiedArtifactSha256": digest,
            "targetRepository": repository,
            "signerPinnedWorkflow": SIGNER,
            "signerPinnedSha": SIGNER_SHA,
            "attempt": attempt,
            "signerVerificationIsPublicationApproval": False,
            "writerVerified": False,
            "crossJobTokenNonPropagationVerified": False,
            "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
            "publicationAuthorized": False,
        }
    except Exception:
        raise Deny("incomplete independent Signer cryptographic proof") from None
