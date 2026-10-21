#!/usr/bin/env python3
"""Issue #75: pure fail-closed, PRE-G4 current-main Publisher preflight.

No network, token, process execution, publish capability, or trust grant lives
here. Callers must supply authenticated Actions GET results and successful
REAL gh attestation verify --format json output; fixtures are NOT signatures.
"""
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "issue75_pin_contract_for_main_guard",
    ROOT / "issue-75-attempt-pin-migration-offline.py")
pin = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pin)

SIGNER_SHA = pin.SIGNER_SHA
SIGNER_PATH = pin.offline.SIGNER_PATH
PROVENANCE = pin.SLSA
SPDX = pin.SPDX
PROMOTE_PATH = pin.offline.PROMOTE_PATH
AUTHORIZE = "Verify manual operator confirmation and immutable candidate evidence"
BUILD = "Fresh attested Windows maintained PG14–18 build from validated main"
RESOLVE = BUILD + " / Resolve extension and PostgreSQL matrix"
PUBLISH = "Verify signatures and SHA; create-only formal publication"
DOWNSTREAM = {
    "Dispatch signed Release Catalog PR generation with short-lived App token",
    "Flag post-release Catalog dispatch as blocked (not falsely successful)",
}


class Deny(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise Deny(why)


def positive(v):
    return type(v) is int and v > 0


def attempt_from_env(env, run_id, repo):
    require(positive(run_id) and env.get("GITHUB_RUN_ID") == str(run_id)
            and env.get("GITHUB_REPOSITORY") == repo
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
            "untrusted manual Publisher environment or run ID")
    text = env.get("GITHUB_RUN_ATTEMPT", "")
    require(type(text) is str and re.fullmatch(r"[1-9][0-9]*", text) is not None,
            "missing/noncanonical GITHUB_RUN_ATTEMPT")
    return int(text)


def validate_pkg(pkg, *, major, repo, packaging_sha, upstream_sha,
                 run_id, attempt):
    require(type(pkg) is dict, "invalid PACKAGE-INFO")
    src = pkg.get("source")
    upstream = pkg.get("upstream")
    build = pkg.get("buildInfrastructure")
    wf = pkg.get("workflowRun")
    require(all(type(i) is dict for i in (src, upstream, build, wf)),
            "missing PACKAGE-INFO source/builder/workflow")
    require(type(pkg.get("postgresql")) is dict
            and type(pkg["postgresql"].get("major")) is int
            and pkg["postgresql"]["major"] == major
            and src.get("packagingRepository") == repo
            and src.get("packagingCommit") == packaging_sha
            and upstream.get("commit") == upstream_sha
            and build.get("repository") == "pgextwin/build"
            and build.get("workflow") == SIGNER_PATH
            and build.get("commit") == SIGNER_SHA,
            "PACKAGE-INFO trusted source, PG or fixed builder mismatch")
    require(positive(wf.get("id")) and wf["id"] == run_id
            and positive(wf.get("attempt")) and wf["attempt"] == attempt
            and wf.get("url") == f"https://github.com/{repo}/actions/runs/{run_id}"
            and wf.get("event") == "workflow_dispatch"
            and wf.get("ref") == "refs/heads/main",
            "PACKAGE-INFO exact run/attempt/event/ref mismatch")


def validate_snapshot(run, page, *, repo, sha, run_id, attempt, majors):
    require(type(run) is dict and type(run.get("repository")) is dict,
            "Actions run GET failed")
    require(positive(run.get("id")) and run["id"] == run_id
            and positive(run.get("run_attempt")) and run["run_attempt"] == attempt
            and run.get("repository", {}).get("full_name") == repo
            and run.get("head_sha") == sha
            and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == PROMOTE_PATH
            and run.get("status") == "in_progress"
            and run.get("conclusion") is None,
            "Actions active manual run identity/status/attempt mismatch")
    require(type(page) is dict and type(page.get("jobs")) is list
            and positive(page.get("total_count"))
            and len(page["jobs"]) == page["total_count"]
            and len(page["jobs"]) < 100,
            "missing/paginated/incomplete attempt-scoped job page")
    expected = {AUTHORIZE, RESOLVE, PUBLISH} | {
        BUILD + f" / PostgreSQL {m} / Windows x64" for m in majors}
    allowed = expected | DOWNSTREAM
    seen = {}
    for job in page["jobs"]:
        require(type(job) is dict and positive(job.get("id"))
                and type(job.get("name")) is str
                and job["name"] not in seen and job["name"] in allowed
                and positive(job.get("run_id")) and job["run_id"] == run_id
                and positive(job.get("run_attempt"))
                and job["run_attempt"] == attempt
                and job.get("head_sha") == sha,
                "unknown/duplicate/cross-run/cross-attempt job")
        seen[job["name"]] = job
    require(expected <= set(seen), "missing authorize/resolve/signed PG matrix/publish job")
    for name in expected - {PUBLISH}:
        require(seen[name].get("status") == "completed"
                and seen[name].get("conclusion") == "success",
                "incomplete/failed/skipped authorize or signed build job: " + name)
    require(seen[PUBLISH].get("status") == "in_progress"
            and seen[PUBLISH].get("conclusion") is None,
            "Publisher must be active before write")
    for name in DOWNSTREAM & set(seen):
        require(seen[name].get("status") in ("queued", "waiting", "pending")
                and seen[name].get("conclusion") is None,
                "unexpected downstream job state")
    return (run_id, attempt, repo, sha, tuple(sorted(
        (name, job["id"], job["run_attempt"], job["status"],
         job.get("conclusion")) for name, job in seen.items())))


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate key in gh verified JSON")
        obj[key] = value
    return obj


def verified_claims(raw, *, predicate, repo, packaging_sha,
                    run_id, attempt, zip_name, zip_digest, sbom):
    """Parse ONLY stdout from successful actual gh attestation verify.

    Cryptographic trust is provided by the caller's strict CLI invocation
    and zero exit status, never by this parser or mocked verificationResult.
    """
    try:
        items = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, TypeError) as exc:
        raise Deny("unreadable/ambiguous gh verified evidence") from exc
    require(type(items) is list, "gh verified result not an array")
    found = []
    for item in items:
        if type(item) is not dict:
            continue
        verification = item.get("verificationResult")
        if type(verification) is not dict:
            continue
        stmt = verification.get("statement")
        if type(stmt) is dict and stmt.get("predicateType") == predicate:
            subjects = stmt.get("subject")
            if type(subjects) is list and any(
                    type(s) is dict and s.get("name") == zip_name
                    and type(s.get("digest")) is dict
                    and s["digest"].get("sha256") == zip_digest
                    for s in subjects):
                found.append(item)
    require(len(found) == 1, "missing/duplicate verified ZIP digest predicate")
    # Modern gh attestation verify --format json returns both the signed
    # attestation bundle and its cryptographically verified result. The
    # preexisting offline pure shape guard accepts ONLY verificationResult;
    # project the verified claim after rejecting unexpected envelope fields.
    # The caller must still enforce an actual zero-exit gh cryptographic run.
    item = found[0]
    require(set(item) in ({"verificationResult"},
                           {"attestation", "verificationResult"}),
            "unexpected gh verified attestation envelope")
    if "attestation" in item:
        require(type(item["attestation"]) is dict and bool(item["attestation"]),
                "empty/malformed cryptographic attestation bundle")
    try:
        pin.proof_statement(
            {"verificationResult": item["verificationResult"]},
            predicate, repo=repo, sha=packaging_sha,
            signer_sha=SIGNER_SHA, run_id=run_id, attempt=attempt,
            event="workflow_dispatch", zip_name=zip_name,
            zip_digest=zip_digest, sbom=sbom)
    except (pin.Deny, pin.offline.Deny, TypeError, KeyError) as exc:
        raise Deny("verified X.509/immutable signer/source/attempt/SPDX mismatch") from exc
