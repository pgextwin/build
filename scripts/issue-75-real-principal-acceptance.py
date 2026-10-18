#!/usr/bin/env python3
"""Issue #75 fail-closed real-principal acceptance *preflight*.

A previously observed Reader/Signer/Writer negative run and immutable source
ledgers are admission prerequisites, NOT a Signer OIDC, Writer App installation
or token non-propagation proof. No network, credential, signing, shell,
release receipt or publishing operations exist in this verifier.

The --mode require-real entrypoint deliberately DENIES until a separately
authorized, genuinely cryptographic and authenticated runtime verifier exists.
No input JSON, caller booleans, test fixture or return code can make it GO.
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
RECORD = ROOT / "evidence/issue-75/real-principal-acceptance-prewrite-deny-20261018.json"
MAX_BYTES = 8192

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

graph = load("scripts/issue-75-transitive-dependency-delta.py", "issue75_old_auth_graph")
hardening = load("scripts/issue-75-signer-checkout-hardening.py", "issue75_old_checkout_hardening")
custody = load("scripts/issue-75-active-principal-custody-readonly.py", "issue75_old_custody")

class Deny(ValueError):
    pass

def need(x):
    if not x:
        raise Deny("missing or untrusted real-principal acceptance prerequisite")

def exact(obj, keys):
    need(type(obj) is dict and set(obj) == set(keys))
    return obj

def same(obj, expected):
    need(type(obj) is dict and obj == expected)

def unique(pairs):
    out = {}
    for k, v in pairs:
        need(k not in out)
        out[k] = v
    return out

def read_record(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    need(b"\x00" not in raw)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise Deny("invalid evidence record") from None
    need(type(doc) is dict)
    return doc

def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()

def verify_existing_roots():
    """Reuse and never rewrite the immutable 32+13 source dependency guards."""
    baseline_raw = graph.BASE.read_bytes()
    delta_raw = graph.DELTA.read_bytes()
    need(git_blob(baseline_raw) == "b846c8c55e1ffbaab126d4674de9d7dc52376cf0")
    need(git_blob(delta_raw) == "a8aa5b75972048bfc2e70fcdbdcfd0a799001389")
    out = graph.inspect(graph.read_json(graph.DELTA),
                        graph.read_json(graph.BASE), base_bytes=baseline_raw)
    need(out["originalGitBlobs"] == 32 and out["addedGitBlobs"] == 13)
    need(out["goB"] == "NO_GO" and out["publicationAuthorized"] is False)
    signer = hardening.inspect(hardening.record(hardening.EVIDENCE.read_bytes()),
                               hardening.SIGNER.read_bytes())
    need(signer["checkoutHardeningProposed"] == 5)
    need(signer["checkoutHardeningDeployed"] == 0)
    need(signer["publicationAuthorized"] is False)
    return True

def validate(record):
    exact(record, {"schemaVersion", "evidenceKind", "sourceOnly", "baseline",
                   "negativeRuntime", "requiredFutureIndependentProofs", "acceptance"})
    need(type(record["schemaVersion"]) is int and record["schemaVersion"] == 1)
    need(record["evidenceKind"] == "ISSUE75_REAL_PRINCIPAL_ACCEPTANCE_PREWRITE_DENY")
    need(record["sourceOnly"] is True)
    same(record["baseline"], {
        "buildMainBefore": "afdfb07d85608180b472288a3646447dbd4e67dd",
        "pilotProtectedMain": custody.PILOT_SHA,
        "publisherGitBlob": custody.PUBLISHER_SOURCE_BLOB,
        "publisherPin": custody.PUBLISHER_PIN,
        "signerPin": custody.SIGNER_PIN,
        "reused32GitBlobLedger": "b846c8c55e1ffbaab126d4674de9d7dc52376cf0",
        "reused13GitBlobDelta": "a8aa5b75972048bfc2e70fcdbdcfd0a799001389"})
    runtime = exact(record["negativeRuntime"], {
        "runId", "attempt", "event", "headSha", "parentConclusion",
        "reader", "signer", "writer"})
    need(type(runtime["runId"]) is int and runtime["runId"] == 39104746046)
    need(type(runtime["attempt"]) is int and runtime["attempt"] == 1)
    need(runtime["event"] == "push")
    need(runtime["headSha"] == record["baseline"]["buildMainBefore"])
    need(runtime["parentConclusion"] == "success")
    same(runtime["reader"], {
        "jobId": 117608071252, "conclusion": "success",
        "sourceDecision": "ACTIVE_SOURCE_GET4_NEGATIVE_GAPS_CONFIRMED",
        "identityDecision": "READER_GET4_NEGATIVE_ONLY",
        "effectiveTokenScopesProven": False})
    same(runtime["signer"], {
        "jobId": 117608071136, "conclusion": "success",
        "decision": "SIGNER_UNPROVISIONED_NO_WRITE",
        "oidcCertificateCryptographicallyVerified": False,
        "checkoutHardeningDeployed": False})
    same(runtime["writer"], {
        "jobId": 117608071199, "conclusion": "success",
        "decision": "WRITER_UNPROVISIONED_NO_WRITE",
        "independentInstallationId": None, "installationTokenMinted": False})
    need(len({runtime[r]["jobId"] for r in ("reader", "signer", "writer")}) == 3)

    # These are *required future independent inputs*, not evidence supplied by
    # this public, negative-only run. Never accept a self-reported 'verified'.
    future = exact(record["requiredFutureIndependentProofs"],
                   {"signer", "writer", "custody"})
    same(future["signer"], {
        "verifiedSigstoreCertificateSubject": None,
        "verifiedOIDCIssuer": None,
        "verifiedSignerWorkflow": None,
        "verifiedRunAttempt": None,
        "trustedVerifierProcess": None})
    same(future["writer"], {
        "installationId": None, "installationOwner": None,
        "installationRepository": None,
        "grantContentsWriteVerified": False,
        "tokenLifetimeVerified": False,
        "separatePrincipalVerified": False,
        "trustedVerifierProcess": None})
    same(future["custody"], {
        "uniqueJobsVerified": False,
        "ephemeralTokenNonPropagationVerified": False,
        "noCrossJobArtifactTokenTransferVerified": False,
        "signerCheckoutCredentialsNonPersistentVerified": False,
        "trustedPrivateExecutorVerified": False})
    same(record["acceptance"], {
        "runtimeSignerOIDCProven": False,
        "runtimeWriterIndependentPrincipalProven": False,
        "runtimeCredentialNonPropagationProven": False,
        "signedPublisherPositivePrewriteProven": False,
        "publishableReceipt": False,
        "publicationAuthorized": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO"})

    return {
        "schemaVersion": 1,
        "decision": "NEGATIVE_WITNESS_ACCEPTED_REAL_PRINCIPALS_NOT_PROVEN",
        "negativeSourceRunId": runtime["runId"],
        "originalGitBlobsReused": 32,
        "additionalGitBlobsReused": 13,
        "actualSignerOIDCProven": False,
        "actualIndependentWriterProven": False,
        "tokenNonPropagationRuntimeProven": False,
        "actualPublisherPositivePrewriteProven": False,
        "realPrincipalAcceptance": "NOT_PROVEN",
        "publishableReceipt": False,
        "publicationAuthorized": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO"}

def denied():
    return {"schemaVersion": 1, "decision": "DENY_REAL_PRINCIPAL_AUTHENTICATION",
            "realPrincipalAcceptance": "NOT_PROVEN",
            "publicationAuthorized": False, "publishableReceipt": False,
            "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO"}

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("static", "require-real"), required=True)
    parser.add_argument("--evidence", type=Path, default=RECORD)
    args = parser.parse_args(argv)
    outcome = denied()
    status = 2
    try:
        need(args.evidence.is_file() and args.evidence.stat().st_size <= MAX_BYTES)
        verify_existing_roots()
        record = read_record(args.evidence.read_bytes())
        outcome = validate(record)
        if args.mode == "static":
            status = 0
        else:
            # STOP: structured records, source-only GETs and a passed unit test
            # cannot verify Sigstore cryptography, installation token provenance,
            # isolation/no transfer or genuinely signed Publisher prewrite.
            outcome = denied()
    except Exception:
        # Even malformed/untrusted evidence cannot leak secret-like exceptions.
        outcome = denied()
    print(json.dumps(outcome, sort_keys=True))
    return status

if __name__ == "__main__":
    sys.exit(main())
