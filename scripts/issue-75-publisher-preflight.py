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
PUSH_PATH = ".github/workflows/update-watch.yml"
# These are real protected main/push jobs, distinct from the manual Publisher.
SIGNED_PUSH_JOBS = (
    "Audit real single manifest-only protected candidate main push",
    "Attest original candidate after verified protected main merge (NO PUBLISH)",
    "Verify actual signed ZIP/SPDX/Grype provenance without Publisher rights",
    "Independently reverify signed candidate before future Publisher (NO PUBLISH)",
)
SIGNED_PUSH_ARTIFACTS = frozenset({
    "automatic-signed-candidate-audit-nonpublishing",
    "independent-signed-publisher-preflight-nonpublishing",
})
AUTHORIZE = "Verify manual operator confirmation and immutable candidate evidence"
BUILD = "Fresh attested Windows maintained PG14–18 build from validated main"
RESOLVE = BUILD + " / Resolve extension and PostgreSQL matrix"
PUBLISH = "Verify signatures and SHA; create-only formal publication"
WRAPPER_PREFIX = "Invoke shared exact-SHA manual signed promotion / "
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
                 run_id, attempt, event="workflow_dispatch"):
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
    require(event in ("workflow_dispatch", "push")
            and (event != "push" or attempt == 1),
            "unknown signed run event or replay attempt")
    require(positive(wf.get("id")) and wf["id"] == run_id
            and positive(wf.get("attempt")) and wf["attempt"] == attempt
            and wf.get("url") == f"https://github.com/{repo}/actions/runs/{run_id}"
            and wf.get("event") == event
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
    wrappers = set()
    for job in page["jobs"]:
        require(type(job) is dict and type(job.get("name")) is str,
                "missing job name")
        raw_name = job["name"]
        wrapped = raw_name.startswith(WRAPPER_PREFIX)
        name = raw_name[len(WRAPPER_PREFIX):] if wrapped else raw_name
        wrappers.add(wrapped)
        require(type(job) is dict and positive(job.get("id"))
                and type(job.get("name")) is str
                and name not in seen and name in allowed
                and positive(job.get("run_id")) and job["run_id"] == run_id
                and positive(job.get("run_attempt"))
                and job["run_attempt"] == attempt
                and job.get("head_sha") == sha,
                "unknown/duplicate/cross-run/cross-attempt job")
        seen[name] = job
    require(len(wrappers) == 1, "mixed direct/shared job identity")
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



def validate_completed_push_snapshot(run, jobs, artifacts, *, repo, sha, run_id,
                                     attempt):
    """Strict original completed signed main/push identity; NO publication grant.

    This checks authenticated GET metadata, not bytes or cryptographic
    signatures. An isolated Publisher must ALSO independently download the
    original ZIP/SPDX/Grype and run real gh attestation verify before WRITE.
    """
    require(positive(run_id) and attempt == 1 and type(attempt) is int
            and type(repo) is str and re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*", repo)
            and type(sha) is str and re.fullmatch(r"[0-9a-f]{40}", sha),
            "invalid original signed run identity")
    require(type(run) is dict and type(run.get("repository")) is dict
            and run["repository"].get("full_name") == repo
            and type(run.get("id")) is int and run["id"] == run_id
            and type(run.get("run_attempt")) is int
            and run["run_attempt"] == attempt
            and run.get("head_sha") == sha and run.get("head_branch") == "main"
            and run.get("event") == "push" and run.get("path") == PUSH_PATH
            and run.get("status") == "completed"
            and run.get("conclusion") == "success",
            "not original successful completed signed main/push run")
    require(type(jobs) is dict and type(jobs.get("total_count")) is int
            and 0 < jobs["total_count"] < 100
            and type(jobs.get("jobs")) is list
            and len(jobs["jobs"]) == jobs["total_count"],
            "incomplete/paginated signed jobs")
    matches = {}
    for job in jobs["jobs"]:
        require(type(job) is dict and positive(job.get("id"))
                and positive(job.get("run_id")) and job["run_id"] == run_id
                and type(job.get("run_attempt")) is int
                and job["run_attempt"] == attempt
                and job.get("head_sha") == sha
                and type(job.get("name")) is str,
                "cross-run/cross-attempt or incomplete signed job")
        for expected in SIGNED_PUSH_JOBS:
            if job["name"] == expected or job["name"].endswith(" / " + expected):
                require(expected not in matches
                        and job.get("status") == "completed"
                        and job.get("conclusion") == "success",
                        "duplicate/failed/skipped required signed job")
                matches[expected] = job["id"]
    require(set(matches) == set(SIGNED_PUSH_JOBS),
            "missing required independent Sigstore/Windows job")
    require(type(artifacts) is dict
            and type(artifacts.get("total_count")) is int
            and 0 < artifacts["total_count"] < 100
            and type(artifacts.get("artifacts")) is list
            and len(artifacts["artifacts"]) == artifacts["total_count"],
            "incomplete/paginated signed audit artifacts")
    found = {}
    for artifact in artifacts["artifacts"]:
        require(type(artifact) is dict and type(artifact.get("name")) is str,
                "invalid signed artifact inventory entry")
        if artifact["name"] in SIGNED_PUSH_ARTIFACTS:
            require(artifact["name"] not in found
                    and positive(artifact.get("id"))
                    and positive(artifact.get("size_in_bytes"))
                    and artifact.get("expired") is False
                    and type(artifact.get("workflow_run")) is dict
                    and artifact["workflow_run"].get("id") == run_id
                    and artifact["workflow_run"].get("head_sha") == sha,
                    "duplicate/expired/cross-run signed audit artifact")
            found[artifact["name"]] = (artifact["id"], artifact["size_in_bytes"])
    require(set(found) == SIGNED_PUSH_ARTIFACTS,
            "missing original and independent signed audit artifacts")
    # Stable fingerprint for pre/post independent byte verification comparison.
    # Do not return authorization flags or mistake GET metadata for signatures.
    return (repo, sha, run_id, attempt, tuple(sorted(matches.items())),
            tuple(sorted(found.items())))


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate key in gh verified JSON")
        obj[key] = value
    return obj


def verified_claims(raw, *, predicate, repo, packaging_sha,
                    run_id, attempt, zip_name, zip_digest, sbom,
                    event="workflow_dispatch", config_path=PROMOTE_PATH):
    """Parse ONLY stdout from successful actual gh attestation verify.

    Cryptographic trust is provided by the caller's strict CLI invocation
    and zero exit status, never by this parser or mocked verificationResult.
    """
    require((event, config_path) in (("workflow_dispatch", PROMOTE_PATH),
                                    ("push", PUSH_PATH))
            and (event != "push" or attempt == 1),
            "unrecognized or replayed signed-workflow identity")
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
            event=event, zip_name=zip_name,
            zip_digest=zip_digest, sbom=sbom, config_path=config_path)
    except (pin.Deny, pin.offline.Deny, TypeError, KeyError) as exc:
        raise Deny("verified X.509/immutable signer/source/attempt/SPDX mismatch") from exc
