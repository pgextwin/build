#!/usr/bin/env python3
"""Read-only issuer binding for LA1 tickets; never authorization.

V1 has no issuer-main, issuance-run or claim-commit fields. issuance_policy is
a REQUIRED trusted, per-ticket policy snapshot supplied independently of live
facts (not inferred from the run/ref being verified). See docs/local-auth-live.md.
The authority policy is metadata/local-candidate-authority.json, unchanged.
LA1 remains responsible for strict ticket, signature, inputs and time checks.

facts can replace all GitHub reads in offline tests; api can replace just GETs.
Neither interface grants execution, signing, dispatch or publication rights.
"""

import base64
import binascii
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess

spec = importlib.util.spec_from_file_location(
    "local_auth_verifier", Path(__file__).with_name("verify-local-authorized-candidate.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

ISSUER_REPOSITORY = "pgextwin/local-auth-issuer"
ISSUER_WORKFLOW = ".github/workflows/issue-ticket.yml"
ISSUER_KEY_ID = "local-auth-prod-1"
MAX_FACT_BYTES = 1048576
ISSUANCE_FIELDS = frozenset({
    "repository", "mainSha", "workflowPath", "workflowId", "runId",
    "claimCommitSha", "requestId", "ticketSha256",
})


def _require(condition, code):
    if not condition:
        raise verifier.TicketRejected(code)


def _validate_issuance_policy(issuance_policy):
    _require(type(issuance_policy) is dict and set(issuance_policy) == ISSUANCE_FIELDS,
             "INVALID_ISSUANCE_POLICY")
    _require(issuance_policy["repository"] == ISSUER_REPOSITORY, "ISSUER_REPOSITORY_MISMATCH")
    _require(issuance_policy["workflowPath"] == ISSUER_WORKFLOW, "ISSUER_WORKFLOW_MISMATCH")
    for field, length in (("mainSha", 40), ("claimCommitSha", 40),
                          ("requestId", 32), ("ticketSha256", 64)):
        verifier._hex(issuance_policy[field], length, "INVALID_ISSUANCE_POLICY")
    for field in ("workflowId", "runId"):
        verifier._positive_integer(issuance_policy[field], "INVALID_ISSUANCE_POLICY")


def github_get(endpoint):
    """Authenticated github.com GET only; no arbitrary hosts, URLs or writes."""
    prefix = "repos/" + ISSUER_REPOSITORY
    allowed = {
        prefix, prefix + "/git/ref/heads/main",
    }
    # Values are deliberately narrow even when called outside fetch_live_facts.
    suffix_pattern = (r"/(?:actions/(?:runs|workflows)/[1-9][0-9]*"
                      r"|git/ref/claims/[0-9a-f]{32}"
                      r"|contents/claim\.json\?ref=[0-9a-f]{40})")
    _require(type(endpoint) is str and
             (endpoint in allowed or re.fullmatch(re.escape(prefix) + suffix_pattern, endpoint)),
             "LIVE_ENDPOINT_DENIED")
    environment = dict(os.environ)
    environment.pop("GH_DEBUG", None)
    try:
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint],
            capture_output=True, env=environment, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise verifier.TicketRejected("LIVE_FETCH_FAILED") from None
    _require(result.returncode == 0, "LIVE_FETCH_FAILED")
    _require(len(result.stdout) <= MAX_FACT_BYTES, "LIVE_FACT_TOO_LARGE")
    try:
        value = verifier._parse_json(result.stdout.decode("utf-8"), MAX_FACT_BYTES)
    except UnicodeDecodeError:
        raise verifier.TicketRejected("INVALID_LIVE_FACTS") from None
    _require(type(value) is dict, "INVALID_LIVE_FACTS")
    return value


def fetch_live_facts(issuance_policy, *, api=github_get):
    """Small replaceable fetch layer. Exact claim ref, immutable claim contents."""
    _validate_issuance_policy(issuance_policy)
    prefix = "repos/" + ISSUER_REPOSITORY
    return {
        "repository": api(prefix),
        "main": api(prefix + "/git/ref/heads/main"),
        "run": api(prefix + "/actions/runs/" + str(issuance_policy["runId"])),
        "workflow": api(prefix + "/actions/workflows/" + str(issuance_policy["workflowId"])),
        "claimRef": api(prefix + "/git/ref/claims/" + issuance_policy["requestId"]),
        "claimFile": api(prefix + "/contents/claim.json?ref=" + issuance_policy["claimCommitSha"]),
    }


def _check_facts(ticket, issuance_policy, evidence, facts):
    _require(type(facts) is dict, "INVALID_LIVE_FACTS")
    for field in ("repository", "main", "run", "workflow", "claimRef", "claimFile"):
        _require(type(facts.get(field)) is dict, "INVALID_LIVE_FACTS")
    repository, main, run, workflow, ref, file = (
        facts[field] for field in ("repository", "main", "run", "workflow", "claimRef", "claimFile"))
    _require(repository.get("full_name") == ISSUER_REPOSITORY and
             repository.get("default_branch") == "main", "ISSUER_REPOSITORY_MISMATCH")
    verifier._positive_integer(repository.get("id"), "INVALID_LIVE_FACTS")
    _require(main.get("ref") == "refs/heads/main" and
             type(main.get("object")) is dict and main["object"].get("type") == "commit" and
             main["object"].get("sha") == issuance_policy["mainSha"], "ISSUER_MAIN_MISMATCH")
    for field in ("repository", "head_repository"):
        repo = run.get(field)
        _require(type(repo) is dict and repo.get("full_name") == ISSUER_REPOSITORY and
                 type(repo.get("id")) is int and repo["id"] == repository["id"],
                 "ISSUER_RUN_REPOSITORY_MISMATCH")
    _require(type(run.get("id")) is int and run["id"] == issuance_policy["runId"],
             "ISSUER_RUN_MISMATCH")
    _require(type(run.get("run_attempt")) is int and run["run_attempt"] == 1,
             "ISSUER_RUN_ATTEMPT_MISMATCH")
    _require(run.get("head_branch") == "main" and run.get("head_sha") == issuance_policy["mainSha"],
             "ISSUER_RUN_MAIN_MISMATCH")
    _require(run.get("event") == "workflow_dispatch" and run.get("status") == "completed" and
             run.get("conclusion") == "success", "ISSUER_RUN_NOT_SUCCESSFUL")
    _require(run.get("path") == ISSUER_WORKFLOW and
             type(run.get("workflow_id")) is int and run["workflow_id"] == issuance_policy["workflowId"] and
             type(workflow.get("id")) is int and workflow["id"] == issuance_policy["workflowId"] and
             workflow.get("path") == ISSUER_WORKFLOW, "ISSUER_WORKFLOW_MISMATCH")
    _require(ref.get("ref") == "refs/claims/" + ticket["requestId"] and
             type(ref.get("object")) is dict and ref["object"].get("type") == "commit" and
             ref["object"].get("sha") == issuance_policy["claimCommitSha"], "CLAIM_REF_MISMATCH")
    _require(file.get("type") == "file" and file.get("path") == "claim.json" and
             file.get("encoding") == "base64" and type(file.get("content")) is str,
             "INVALID_CLAIM_FILE")
    try:
        raw = base64.b64decode(file["content"].replace("\n", ""), validate=True)
        claim = verifier._parse_json(raw.decode("utf-8"), verifier.MAX_TICKET_BYTES)
    except (UnicodeError, ValueError, binascii.Error):
        raise verifier.TicketRejected("INVALID_CLAIM_FILE") from None
    blob_sha = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    _require(file.get("sha") == blob_sha and type(file.get("size")) is int and
             file["size"] == len(raw) and verifier.canonical_json(claim) == raw, "INVALID_CLAIM_FILE")
    expected = {
        "requestId": ticket["requestId"], "ticketSha256": evidence["ticketSha256"],
        "issuerRepository": ISSUER_REPOSITORY, "issuerRunId": str(issuance_policy["runId"]),
        "issuerRunAttempt": "1", "operation": ticket["operation"],
    }
    _require(type(claim) is dict and set(claim) == set(expected) | {"recordedAt"} and
             all(claim.get(key) == value for key, value in expected.items()), "CLAIM_BINDING_MISMATCH")
    recorded = verifier._timestamp(claim["recordedAt"], "INVALID_CLAIM_FILE")
    _require(verifier._timestamp(ticket["issuedAt"]) <= recorded < verifier._timestamp(ticket["expiresAt"]),
             "CLAIM_TIME_MISMATCH")


def verify_live_binding(ticket_obj, inputs_bytes, policy, fleet_repositories, now, *,
                        issuance_policy, facts=None, api=github_get):
    """Verify LA1 first, then bind trusted expectations to fresh issuer evidence.

    Pass the checked-out authority policy and an independent trusted issuance
    policy. facts is ONLY for trusted fixtures; production callers omit it.
    A successful return is evidence only, including under a test DENY policy.
    """
    evidence = verifier.verify_ticket(ticket_obj, inputs_bytes, policy, fleet_repositories, now)
    _require(policy["issuerKeyId"] == ISSUER_KEY_ID, "PINNED_KEY_MISMATCH")
    _validate_issuance_policy(issuance_policy)
    _require(issuance_policy["requestId"] == ticket_obj["requestId"] and
             issuance_policy["ticketSha256"] == evidence["ticketSha256"], "ISSUANCE_TICKET_MISMATCH")
    if facts is None:
        facts = fetch_live_facts(issuance_policy, api=api)
    _check_facts(ticket_obj, issuance_policy, evidence, facts)
    return dict(evidence, status="VERIFIED_LIVE_BINDING_ONLY", authorized=False, publication=False,
                issuerRepository=ISSUER_REPOSITORY, issuerMainSha=issuance_policy["mainSha"],
                issuerRunId=issuance_policy["runId"], issuerRunAttempt=1,
                claimCommitSha=issuance_policy["claimCommitSha"])
