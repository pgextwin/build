#!/usr/bin/env python3
"""#75 live, GET-only active Publisher/Signer *source* custody negative witness.

Reuse the audited GET-only transport, Reader trusted-main context and immutable
Signer checkout candidate. No secrets, write, dispatch, signer, Publisher or
artifact. A verified source topology is NOT a verified runtime auth principal.
"""
from __future__ import annotations
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

transport = load("issue-75-go-b-live-readonly.py", "issue75_reused_go_b_getonly")
reader = load("issue-75-principal-boundaries.py", "issue75_reused_main_reader_context")
hardening = load("issue-75-signer-checkout-hardening.py", "issue75_reused_signer_hardening")

PILOT_SHA = "98452723fcad2aedafb1c02a210f35950f7e8cf2"
PUBLISHER_SOURCE_BLOB = "3ae586814b063fefa5c3a554758f13467bb23ea5"
PUBLISHER_PIN = "455f0ccc667697f600700a6e64bcfd6c57b6a977"
SIGNER_PIN = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
PROMOTE_PREFIX = "contents/.github/workflows/promote.yml?ref="
# PILOT_SHA remains the historical 2026-10-18 pilot anchor, NOT a current
# protected-main HEAD pin. Live HEAD can advance without changing promoter
# source. The actual workflow bytes MUST still equal PUBLISHER_SOURCE_BLOB.

class Deny(ValueError):
    pass
def need(ok):
    if not ok:
        raise Deny("active source identity or credential custody unproven")

def block_jobs(src):
    need(type(src) is str and len(src) < 80000)
    need(src.startswith("name: Promote verified upstream candidate"))
    need("\n  workflow_dispatch:\n" in src)
    need("pull_request_target:" not in src and "pull_request:" not in src)
    start = src.find("\njobs:\n")
    need(start >= 0)
    job_source = src[start + len("\njobs:\n"):]
    parts = list(re.finditer(r"(?m)^  ([a-z][a-z0-9_]*):\n", job_source))
    jobs = {}
    for i, match in enumerate(parts):
        name = match.group(1)
        need(name not in jobs)
        end = parts[i + 1].start() if i + 1 < len(parts) else len(job_source)
        jobs[name] = job_source[match.end():end]
    need(set(jobs) == {"authorize", "release_build", "publish",
                       "catalog_sync", "catalog_not_configured"})
    return jobs

def scopes(job):
    match = re.search(r"(?m)^    permissions:\n((?:      [a-z-]+: (?:read|write)\n)+)", job)
    need(match is not None and job.count("    permissions:\n") == 1)
    entries = [line.strip().split(": ") for line in match.group(1).splitlines()]
    need(all(len(p) == 2 for p in entries))
    result = dict(entries)
    need(len(result) == len(entries))
    return result

def classify_source(src):
    """Pure negative source classification; no simulated claim of runtime scope."""
    jobs = block_jobs(src)
    need(scopes(jobs["authorize"]) ==
         {"contents": "read", "actions": "read", "pull-requests": "read"})
    need(scopes(jobs["release_build"]) ==
         {"contents": "read", "id-token": "write",
          "attestations": "write", "artifact-metadata": "write"})
    need(scopes(jobs["publish"]) ==
         {"contents": "write", "actions": "read", "attestations": "read"})
    need(scopes(jobs["catalog_sync"]) == {"contents": "read"})
    need("    permissions:\n" not in jobs["catalog_not_configured"])
    for job in ("authorize", "publish"):
        need(jobs[job].count("persist-credentials: false") == 2)
        need(jobs[job].count("ref: " + PUBLISHER_PIN) == 1)
        need(jobs[job].count("GH_TOKEN: " + "$"+"{{ github.token }}") == 1)
        need("secrets." not in jobs[job] and "create-github-app-token@" not in jobs[job])
    need("needs: authorize" in jobs["release_build"])
    need("uses: pgextwin/build/.github/workflows/build-extension-attested.yml@" +
         SIGNER_PIN in jobs["release_build"])
    need("GH_TOKEN:" not in jobs["release_build"] and
         "secrets." not in jobs["release_build"])
    need("needs: [authorize, release_build]" in jobs["publish"])
    need("contents: write" not in jobs["catalog_sync"])
    need("needs: publish" in jobs["catalog_sync"])
    need("repositories: catalog" in jobs["catalog_sync"])
    need("permission-actions: write" in jobs["catalog_sync"])
    need("secrets.PGEXTWIN_CATALOG_APP_PRIVATE_KEY" in jobs["catalog_sync"])
    need("GH_TOKEN: " + "$"+"{{ steps.app-token.outputs.token }}" in jobs["catalog_sync"])
    need("GH_TOKEN:" not in jobs["catalog_not_configured"])
    return {
        "readerJobPermissions": "contents:read,actions:read",
        "signerJobPermissionsDeclared": "contents:read,id-token:write,attestations:write,artifact-metadata:write",
        "publisherJobPermissionsDeclared": "contents:write,actions:read,attestations:read",
        "writerCredentialSource": "github.token",
        "distinctWriterInstallationPrincipalVerified": False,
        "signerOIDCPermissionDeclared": True,
        "signerOIDCIdentityVerified": False,
        "productionCheckoutPersistenceGap": True,
        "catalogAppTokenDistinctDownstreamOnly": True,
    }

def inspect(get, *, signer_raw):
    # Use the existing immutable-root and five-checkout proof; it MUST still
    # reject changed Signer bytes and never claim a deployed remediation.
    proposed = hardening.hardened_signer(signer_raw)
    need(hardening.blob(proposed) != hardening.EXPECTED_SIGNER)
    branch1 = get("branches/main")
    need(type(branch1) is dict and branch1.get("protected") is True and
         type(branch1.get("commit")) is dict)
    current_sha = branch1["commit"].get("sha")
    need(type(current_sha) is str and
         re.fullmatch(r"[0-9a-f]{40}", current_sha) is not None)
    source_path = PROMOTE_PREFIX + current_sha
    source1 = get(source_path)
    branch2 = get("branches/main")
    source2 = get(source_path)
    # Current main can move independently of the historical immutable signer
    # pin; constrain CURRENT main to double-GET stability and exact source.
    need(branch2 == branch1 and branch2.get("protected") is True and
         branch2["commit"].get("sha") == current_sha)
    pins = []
    for entry in (source1, source2):
        need(type(entry) is dict and entry.get("sha") == PUBLISHER_SOURCE_BLOB)
        p = transport.workflow_pins(entry)   # audited immutable Git Blob check
        need(p["publisherPin"] == PUBLISHER_PIN and
             p["signerPin"] == SIGNER_PIN and
             p["workflowBlob"] == PUBLISHER_SOURCE_BLOB)
        body = entry.get("content", "")
        need(type(body) is str and len(body) < 100000)
        raw = base64.b64decode("".join(body.split()), validate=True)
        need(len(raw) < 80000)
        classification = classify_source(raw.decode("utf-8"))
        pins.append(classification)
    need(source1 == source2 and pins[0] == pins[1])
    return {**pins[0], "currentProtectedPilotMainSha": current_sha,
            "historicalPilotAnchorSha": PILOT_SHA}

def report(decision, topology=None):
    output = {
        "schemaVersion": 1,
        "evidenceKind": "ISSUE75_ACTIVE_PINNED_PRINCIPAL_CUSTODY_GET_ONLY",
        "decision": decision,
        "runtimePrincipalSeparation": "NOT_PROVEN",
        "signerOIDCIdentityVerified": False,
        "writerInstallationIdentityVerified": False,
        "writerTokenScopeRuntimeVerified": False,
        "signerCredentialHardeningDeployed": False,
        "signedPublisherPositivePrewriteVerified": False,
        "releaseAuthorized": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO"}
    if topology is not None:
        output.update(topology)
        output["pilotMainSha"] = topology["currentProtectedPilotMainSha"]
        output["historicalPilotAnchorSha"] = PILOT_SHA
        output["publisherSourceGitBlob"] = PUBLISHER_SOURCE_BLOB
        output["publisherPin"] = PUBLISHER_PIN
        output["signerPin"] = SIGNER_PIN
        output["authenticatedGetCount"] = 4
    return output

def main():
    out = report("DENY_UNPROVEN_ACTIVE_PINNED_PRINCIPALS")
    try:
        # Use the previous trusted-main Reader context, not a new role grant.
        sha, run_id, attempt = reader.context(os.environ, "reader")
        token = os.environ.get("GH_TOKEN", "")
        need(type(token) is str and bool(token))
        result = inspect(
            lambda path: transport.get_json(
                path, token=token, run_id=run_id, attempt=attempt,
                sha=(path[len(PROMOTE_PREFIX):] if
                     path.startswith(PROMOTE_PREFIX) else PILOT_SHA)),
            signer_raw=hardening.SIGNER.read_bytes())
        out = report("ACTIVE_SOURCE_GET4_NEGATIVE_GAPS_CONFIRMED", result)
        out["readerMainSha"] = sha
        code = 0
    except Exception:
        # Never expose token, HTTP error bodies/headers, or source response text.
        code = 2
    print(json.dumps(out, sort_keys=True))
    return code

if __name__ == "__main__":
    sys.exit(main())
