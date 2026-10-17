#!/usr/bin/env python3
"""Issue #75 GO B: independent, read-only live Publisher prewrite observer.

Only bounded GitHub REST GETs. No git, gh, subprocess, dispatch, receipt,
signing, Release writer, PATCH, POST, DELETE, retry, or publication permission.
This observer reuses the existing signed-Publisher topology validator; even a
positive metadata observation NEVER authenticates SLSA/SPDX or approves GO B.
Run only with a separate appropriately scoped read-only GH_TOKEN. The observer
cannot prove the privileges of a supplied token.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "issue75_go_b_existing_pure_guard", HERE / "issue-75-publisher-preflight.py")
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

REPO = "pgextwin/plpgsql_check"
LEGACY_PIN = "455f0ccc667697f600700a6e64bcfd6c57b6a977"
SIGNER_PIN = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
SHA = re.compile(r"[0-9a-f]{40}\Z")
REQUIRED = frozenset({
    "syntax", guard.RESOLVE.replace(guard.BUILD + " / ", "windows / "),
    "windows / PostgreSQL 15 / Windows x64",
    "windows / PostgreSQL 16 / Windows x64",
    "windows / PostgreSQL 17 / Windows x64",
    "windows / PostgreSQL 18 / Windows x64",
    "Regression-test immutable Release preflight", "Windows required summary",
})
# This is the same eight-context pilot branch protection contract. In
# particular PG14's Windows matrix is audited but is not a required context.
assert len(REQUIRED) == 8

class Deny(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Deny(why)

def unique(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate GitHub JSON key")
        obj[key] = value
    return obj

def api_path_ok(path, run_id, attempt, sha):
    """No arbitrary URL, repo, endpoint, method or query injection."""
    allowed = {
        "branches/main",
        "actions/runs/" + str(run_id),
        ("actions/runs/" + str(run_id) + "/attempts/" + str(attempt)
         + "/jobs?per_page=100"),
        "commits/" + sha + "/check-runs?per_page=100",
        "contents/.github/workflows/promote.yml?ref=" + sha,
    }
    return path in allowed

def get_json(path, *, token, run_id, attempt, sha, opener=urlopen):
    require(type(token) is str and bool(token), "read-only GH_TOKEN missing")
    require(type(run_id) is int and run_id > 0
            and type(attempt) is int and attempt > 0
            and type(sha) is str and SHA.fullmatch(sha),
            "invalid immutable read-only GET identity")
    require(api_path_ok(path, run_id, attempt, sha), "GET endpoint not allowlisted")
    request = Request("https://api.github.com/repos/" + REPO + "/" + path,
                      headers={"Authorization": "Bearer " + token,
                               "Accept": "application/vnd.github+json"},
                      method="GET")
    try:
        with opener(request, timeout=25) as response:
            require(response.status == 200, "read-only GitHub GET non-200")
            require(not re.search(r'\brel\s*=\s*"?next"?',
                                  response.headers.get("Link", ""), re.I),
                    "paginated GitHub data; incomplete GET")
            body = response.read(2_000_001)
            require(len(body) <= 2_000_000, "oversized GitHub GET response")
            result = json.loads(body.decode("utf-8"),
                                object_pairs_hook=unique)
            require(type(result) is dict, "GitHub GET must return object")
            return result
    except (HTTPError, URLError, TimeoutError, UnicodeError, json.JSONDecodeError,
            OSError) as exc:
        # No token, Authorization header, response body or arbitrary server
        # error message is included in the returned audit output.
        raise Deny("GitHub GET unavailable or unauthenticated") from exc

def workflow_pins(blob):
    require(type(blob) is dict and blob.get("encoding") == "base64"
            and type(blob.get("content")) is str
            and type(blob.get("sha")) is str and SHA.fullmatch(blob["sha"]),
            "no immutable GitHub promote.yml content object")
    try:
        raw = base64.b64decode(blob["content"], validate=False)
        require(len(raw) <= 128 * 1024, "oversized workflow file")
        src = raw.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise Deny("unreadable pinned workflow file") from exc
    refs = re.findall(r"^\s+ref:\s*([0-9a-f]{40})\s*$", src, re.M)
    signer = re.findall(
        r"^\s+uses:\s+pgextwin/build/\.github/workflows/"
        r"build-extension-attested\.yml@([0-9a-f]{40})\s*$", src, re.M)
    require(len(refs) == 2 and refs[0] == refs[1]
            and len(signer) == 1 and signer[0] == SIGNER_PIN,
            "unknown Publisher checkout or reusable signer pins")
    require("workflow_dispatch:" in src and "contents: write" in src,
            "unknown signed Publisher workflow topology")
    return {"publisherPin": refs[0], "signerPin": signer[0],
            "workflowBlob": blob["sha"]}

def protected_main(branch, checks, *, sha):
    require(type(branch) is dict and type(branch.get("commit")) is dict
            and branch["commit"].get("sha") == sha
            and branch.get("protected") is True,
            "head is not the protected current main")
    rule = branch.get("protection", {}).get("required_status_checks")
    require(type(rule) is dict and type(rule.get("checks")) is list,
            "required App15368 branch rule not available")
    selected = rule["checks"]
    names = [x.get("context") for x in selected if type(x) is dict]
    require(len(selected) == 8 and len(set(names)) == 8
            and set(names) == REQUIRED
            and all(x.get("app_id") == 15368 for x in selected),
            "required App15368 context/rule drift")
    require(type(checks) is dict and type(checks.get("check_runs")) is list,
            "commit check-runs unavailable")
    results = checks["check_runs"]
    require(checks.get("total_count") == len(results) and len(results) < 100,
            "incomplete or paginated main check-runs")
    relevant = [x for x in results if type(x) is dict
                and x.get("name") in REQUIRED]
    require(len(relevant) == 8
            and {x.get("name") for x in relevant} == REQUIRED
            and all(type(x.get("app")) is dict
                    and x["app"].get("id") == 15368
                    and x.get("status") == "completed"
                    and x.get("conclusion") == "success"
                    for x in relevant),
            "main required App15368 check incomplete, duplicate or failed")

def observe(read, *, run_id):
    """Reuse strict existing topology predicate on two independent GET rounds.

    A caller-supplied read(path, *, run_id, attempt, sha) must perform
    authenticated allowed GitHub GETs. No self-claims prove real signing.
    Output never permits any release, tag, credential or recovery mutation.
    """
    require(type(run_id) is int and run_id > 0, "invalid run ID")
    root_path = "actions/runs/" + str(run_id)
    # First run GET pins the attempt/SHA used to construct subsequent URLs.
    first = read(root_path, run_id=run_id, attempt=1, sha="0" * 40)
    require(type(first) is dict and first.get("id") == run_id
            and type(first.get("run_attempt")) is int
            and first["run_attempt"] > 0
            and type(first.get("head_sha")) is str
            and SHA.fullmatch(first["head_sha"]),
            "unusable authenticated Run identity")
    attempt, sha = first["run_attempt"], first["head_sha"]
    def get(path):
        return read(path, run_id=run_id, attempt=attempt, sha=sha)
    jobs_path = (f"actions/runs/{run_id}/attempts/{attempt}"
                 "/jobs?per_page=100")
    check_path = f"commits/{sha}/check-runs?per_page=100"
    workflow_path = f"contents/.github/workflows/promote.yml?ref={sha}"
    a = (first, get(jobs_path), get("branches/main"),
         get(check_path), get(workflow_path))
    b = (get(root_path), get(jobs_path), get("branches/main"),
         get(check_path), get(workflow_path))
    # Requiring stable complete authenticated observations intentionally
    # rejects races or job transitions during the read-only probe.
    require(a == b, "TOCTOU: authenticated read snapshots differ")
    branch, checks = a[2], a[3]
    protected_main(branch, checks, sha=sha)
    pins = workflow_pins(a[4])
    for root, page in ((a[0], a[1]), (b[0], b[1])):
        try:
            guard.validate_snapshot(root, page, repo=REPO, sha=sha,
                                    run_id=run_id, attempt=attempt,
                                    majors=[14, 15, 16, 17, 18])
        except (guard.Deny, TypeError, KeyError, ValueError) as exc:
            raise Deny("no live signed-Publisher prewrite topology") from exc
    # An actual positive topology is necessary, but cannot authenticate any
    # signed ZIPs or establish writer isolation / permission grants by itself.
    return {"decision": "BLOCKED_GO_B", "observation":
            "LIVE_SIGNED_PUBLISHER_TOPOLOGY_METADATA_ONLY",
            "runId": run_id, "runAttempt": attempt, "packagingSha": sha,
            "publisherPin": pins["publisherPin"],
            "signerPin": pins["signerPin"],
            "deployedPinState": ("LEGACY_UNACCEPTED" if
                                 pins["publisherPin"] == LEGACY_PIN else
                                 "UNAPPROVED_PIN_CHANGE"),
            "signedArtifactsVerified": False, "publishableReceipt": False,
            "publicationAuthorized": False, "writerEnabled": False,
            "retryAuthorized": False, "mutationAuthorized": False,
            "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO"}

def main(argv=None):
    parser = argparse.ArgumentParser(description="GET-only GO B witness; never publish")
    parser.add_argument("--run-id", type=int, required=True)
    args = parser.parse_args(argv)
    result = {"decision": "BLOCKED_GO_B", "observation": "UNVERIFIED_OR_DENIED",
              "signedArtifactsVerified": False, "publishableReceipt": False,
              "publicationAuthorized": False, "writerEnabled": False,
              "mutationAuthorized": False,
              "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO"}
    token = os.environ.get("GH_TOKEN", "")
    try:
        require(bool(token), "GH_TOKEN absent")
        result = observe(
            lambda path, **ident: get_json(path, token=token, **ident),
            run_id=args.run_id)
        # Even a true in-progress topology is not a complete GO B acceptance.
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Deny, guard.Deny, TypeError, KeyError) as exc:
        # Do not print third-party HTTP error text or token.
        result["reason"] = (str(exc) if isinstance(exc, Deny)
                            else "existing prewrite guard denied")
        print(json.dumps(result, sort_keys=True))
        return 2

if __name__ == "__main__":
    sys.exit(main())
