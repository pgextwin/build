#!/usr/bin/env python3
"""#75: trusted-main, nonpublishing principal boundary negative witness.

Only Reader makes bounded authenticated GitHub GETs. Signer and Writer are
inert roles with no privileged credential provisioned. No token contents,
response bodies, artifacts, signing, publication or mutations are emitted.
Passing this probe NEVER proves real three-principal authentication.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPO = "pgextwin/build"
WORKFLOW = ".github/workflows/issue-75-principal-boundaries.yml"
ROLE_JOBS = {"reader": "reader", "signer": "signer_denied", "writer": "writer_denied"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
INT = re.compile(r"[1-9][0-9]*\Z")

class Deny(ValueError):
    pass

def need(condition):
    if not condition:
        raise Deny("unproven trusted-main negative witness")

def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value)
        value[key] = item
    return value

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Deny("redirect denied")

def get_json(path, token, opener=None):
    """Closed endpoint allowlist, no redirects, no request method other than GET."""
    need(path == "branches/main" or
         bool(re.fullmatch(r"actions/runs/[1-9][0-9]*", path)))
    need(type(token) is str and bool(token))
    call = opener or build_opener(NoRedirect()).open
    request = Request("https://api.github.com/repos/" + REPO + "/" + path,
                      headers={"Authorization": "Bearer " + token,
                               "Accept": "application/vnd.github+json"},
                      method="GET")
    try:
        with call(request, timeout=20) as response:
            need(response.status == 200)
            need("next" not in response.headers.get("Link", "").lower())
            body = response.read(1_000_001)
            need(len(body) <= 1_000_000)
            data = json.loads(body.decode("utf-8"), object_pairs_hook=unique)
            need(type(data) is dict)
            return data
    except (HTTPError, URLError, TimeoutError, OSError,
            ValueError, UnicodeError) as exc:
        raise Deny("GET unavailable or malformed") from None

def context(env, role):
    need(role in ROLE_JOBS and env.get("GITHUB_REPOSITORY") == REPO)
    need(env.get("GITHUB_EVENT_NAME") == "push")
    need(env.get("GITHUB_REF") == "refs/heads/main")
    need(env.get("GITHUB_JOB") == ROLE_JOBS[role])
    need(env.get("GITHUB_WORKFLOW_REF") ==
         REPO + "/" + WORKFLOW + "@refs/heads/main")
    sha = env.get("GITHUB_SHA", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    need(bool(SHA.fullmatch(sha)) and bool(INT.fullmatch(run_id)) and
         bool(INT.fullmatch(attempt)) and int(attempt) == 1)
    # A rerun is not silently promoted to evidence from the original attempt.
    return sha, int(run_id), int(attempt)

def report(role, decision, *, run_id=None, sha=None):
    out = {"schemaVersion": 1, "evidenceKind": "ISSUE75_TRUSTED_MAIN_NO_WRITE",
           "role": role, "decision": decision,
           "authenticationBoundary": "NOT_PROVEN",
           "readerAuthenticatedGetObserved": decision == "READER_GET4_NEGATIVE_ONLY",
           "readerEffectiveScopesVerified": False,
           "signerRealIdentityVerified": False,
           "writerRealIdentityVerified": False,
           "crossRoleTokenDistinctnessVerified": False,
           "writerCredentialMinted": False,
           "signedPublisherPositivePrewriteVerified": False,
           "runtimeClosureProven": False, "publicationAuthorized": False,
           "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO"}
    if run_id is not None:
        out["runId"] = run_id
    if sha is not None:
        out["mainSha"] = sha
    return out

def inspect(role, env, get):
    sha, run_id, attempt = context(env, role)
    if role != "reader":
        need(not env.get("GH_TOKEN") and not env.get("GITHUB_TOKEN"))
        # These jobs may access the ephemeral built-in github.token context in
        # principle; no App/Signer/Writer credential is acquired or used here.
        return report(role, role.upper() + "_UNPROVISIONED_NO_WRITE",
                      run_id=run_id, sha=sha)
    need(bool(env.get("GH_TOKEN")))
    path = "actions/runs/" + str(run_id)
    # Independent repeated GETs: compare only stable identity fields of a
    # currently running workflow. No conclusion/success assertion is possible.
    run_a, branch_a = get(path), get("branches/main")
    run_b, branch_b = get(path), get("branches/main")
    expected = {"id": run_id, "run_attempt": attempt, "head_sha": sha,
                "event": "push", "head_branch": "main", "path": WORKFLOW}
    for item in (run_a, run_b):
        need(type(item) is dict)
        need(all(item.get(key) == value for key, value in expected.items()))
        need(item.get("status") in ("queued", "in_progress", "completed"))
    for item in (branch_a, branch_b):
        need(type(item) is dict and item.get("protected") is True)
        need(type(item.get("commit")) is dict and
             item["commit"].get("sha") == sha)
    return report(role, "READER_GET4_NEGATIVE_ONLY", run_id=run_id, sha=sha)

def main():
    role = "INVALID"
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--role", choices=sorted(ROLE_JOBS), required=True)
        role = parser.parse_args().role
        env = os.environ
        token = env.get("GH_TOKEN", "")
        out = inspect(role, env, lambda path: get_json(path, token))
        code = 0
    except Exception:
        # Never print exception text, HTTP headers/body, token or Git config.
        out = report(role, "DENY_MISSING_OR_MISMATCHED_RUNTIME_EVIDENCE")
        code = 2
    print(json.dumps(out, sort_keys=True))
    return code

if __name__ == "__main__":
    sys.exit(main())
