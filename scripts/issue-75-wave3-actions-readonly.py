#!/usr/bin/env python3
"""Issue #75 third-wave GitHub-hosted Actions runtime GET-only witness.

Reads independent GitHub API metadata from the actual protected build/main
and three extension repositories. This is NOT effective Classic/GraphQL rules
proof, an OIDC/Signer/Writer credential test, or a release authorization.
All successful outputs retain GO B/G4/G5=NO_GO, PUBLISH=DENY.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

BUILD = "pgextwin/build"
TARGETS = ("pgextwin/pgtap", "pgextwin/pg_variables", "pgextwin/pg_store_plans")
SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_JSON = 2_000_000
SUMMARY = "Windows required summary"
ADMISSION = "publication_admission / Observe PR or main event; publication remains DENY"
REQUIRED = tuple(f"windows / PostgreSQL {i} / Windows x64" for i in range(14, 19))
HISTORICAL_SIGNER = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
HISTORICAL_PUBLISHER = "455f0ccc667697f600700a6e64bcfd6c57b6a977"
PROMOTION_FILES = (".github/workflows/promote.yml",
                   "config/release-promotion.json")
MAX_PROMOTION_FILE = 64_000

class Deny(ValueError):
    pass

def need(ok):
    if not ok:
        raise Deny("incomplete or conflicting exact-head third-wave metadata")

def unique(pairs):
    value = {}
    for k, v in pairs:
        need(k not in value)
        value[k] = v
    return value

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, url):
        raise Deny("GitHub redirect prohibited")

def allow(repository, path):
    need(repository in (BUILD,) + TARGETS)
    need(path in ("branches/main", "releases?per_page=1") or
         bool(re.fullmatch(r"commits/[0-9a-f]{40}/check-runs\?per_page=100", path)) or
         any(re.fullmatch(r"contents/" + re.escape(name) +
                              r"\?ref=[0-9a-f]{40}", path)
             for name in PROMOTION_FILES))

class GetOnly:
    def __init__(self, token, opener=None):
        need(isinstance(token, str) and bool(token))
        self.token = token
        self.open = opener or build_opener(NoRedirect()).open

    def get(self, repo, path):
        allow(repo, path)
        request = Request("https://api.github.com/repos/" + repo + "/" + path,
                          headers={
                              "Authorization": "Bearer " + self.token,
                              "Accept": "application/vnd.github+json",
                              "X-GitHub-Api-Version": "2022-11-28",
                              "User-Agent": "pgextwin-issue75-wave3-getonly/1",
                          }, method="GET")
        try:
            with self.open(request, timeout=20) as response:
                need(response.status == 200)
                need(not re.search(r'\brel\s*=\s*"?next"?',
                                   response.headers.get("Link", ""), re.I))
                raw = response.read(MAX_JSON + 1)
                need(0 < len(raw) <= MAX_JSON)
                return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        except (HTTPError, URLError, OSError, TimeoutError,
                UnicodeError, ValueError):
            raise Deny("unavailable authenticated GET evidence") from None

def checked_main(repo, api):
    record = api.get(repo, "branches/main")
    need(type(record) is dict and record.get("protected") is True)
    head = (record.get("commit") or {}).get("sha")
    need(type(head) is str and SHA.fullmatch(head) is not None)
    return record, head

def checks_for(head, branch, runs):
    expected = (SUMMARY,) + REQUIRED + (ADMISSION,)
    need(type(runs) is dict and type(runs.get("check_runs")) is list)
    jobs = runs["check_runs"]
    need(type(runs.get("total_count")) is int and
         runs["total_count"] == len(jobs) and 7 <= len(jobs) <= 100)
    native = (branch.get("protection") or {}).get("required_status_checks") or {}
    need(native.get("enforcement_level") == "everyone")
    need(native.get("checks") == [{"context": SUMMARY, "app_id": 15368}])
    for name in expected:
        same = [j for j in jobs if type(j) is dict and j.get("name") == name]
        need(len(same) == 1)
        job = same[0]
        need(job.get("head_sha") == head and
             job.get("status") == "completed" and
             job.get("conclusion") == "success" and
             (job.get("app") or {}).get("id") == 15368)
    return len(expected)

def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") +
                        b"\0" + raw).hexdigest()

def pinned_contents(api, repo, head, path):
    need(path in PROMOTION_FILES and type(head) is str and SHA.fullmatch(head))
    doc = api.get(repo, "contents/" + path + "?ref=" + head)
    need(type(doc) is dict and doc.get("type") == "file" and
         doc.get("path") == path and doc.get("encoding") == "base64" and
         type(doc.get("size")) is int and 0 < doc["size"] <= MAX_PROMOTION_FILE)
    encoded = doc.get("content")
    need(type(encoded) is str and len(encoded) < MAX_PROMOTION_FILE * 2)
    # GitHub wraps base64 in newlines. Refuse non-base64 characters,
    # unexpected whitespace, padding errors, or ambiguous representations.
    need(re.fullmatch(r"[A-Za-z0-9+/=\n]+", encoded) is not None)
    try:
        raw = base64.b64decode(encoded.replace("\n", ""), validate=True)
    except (ValueError, binascii.Error):
        raise Deny("invalid pinned promotion content") from None
    need(len(raw) == doc["size"] and
         type(doc.get("sha")) is str and git_blob(raw) == doc["sha"])
    return raw, doc["sha"]

def promotion_policy(raw):
    need(type(raw) is bytes and b"\r" not in raw)
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError):
        raise Deny("invalid local promotion policy") from None
    need(type(obj) is dict and set(obj) ==
         {"schemaVersion", "enabled", "releasePolicy"} and
         type(obj["schemaVersion"]) is int and obj["schemaVersion"] == 1 and
         obj["enabled"] is False and obj["releasePolicy"] == "manual-dispatch")
    return True

def promotion_workflow(raw):
    """Conservative source-level proof of legacy manual-only wiring.

    This is not YAML semantic parsing or a guarantee that a Publisher cannot
    be reached by some other workflow. A mismatch fails the GET-only witness.
    """
    need(type(raw) is bytes and b"\r" not in raw and
         b"\x00" not in raw and len(raw) <= MAX_PROMOTION_FILE)
    try:
        source = raw.decode("utf-8")
    except UnicodeError:
        raise Deny("invalid promotion YAML") from None
    # Restrict event names at the root indentation under the ONE on: block.
    roots = list(re.finditer(r"(?m)^on:\s*$", source))
    need(len(roots) == 1)
    remaining = source[roots[0].end():]
    next_root = re.search(r"(?m)^[A-Za-z][A-Za-z_-]*:", remaining)
    events = remaining[:next_root.start()] if next_root else remaining
    need(re.findall(r"(?m)^  ([A-Za-z_]+):", events) ==
         ["workflow_dispatch"])
    signer_line = ("    uses: pgextwin/build/.github/workflows/"
                   "build-extension-attested.yml@" + HISTORICAL_SIGNER)
    publisher_line = "          ref: " + HISTORICAL_PUBLISHER
    need(source.count(signer_line) == 1 and
         source.count(publisher_line) == 2 and
         source.count("      confirm_release:") == 1 and
         source.count("        description: Type PUBLISH") == 1 and
         source.count("  release_build:") == 1 and
         source.count("  publish:") == 1 and
         source.count("  authorize:") == 1 and
         "    needs: authorize" in source and
         "    needs: [authorize, release_build]" in source and
         "    name: Check signatures, exact SHA256 and create-only Release ID" in source)
    return True

def promotion_boundary(api, repo, head):
    workflow, workflow_sha = pinned_contents(api, repo, head, PROMOTION_FILES[0])
    policy, policy_sha = pinned_contents(api, repo, head, PROMOTION_FILES[1])
    promotion_workflow(workflow)
    promotion_policy(policy)
    return {
        "workflowBlob": workflow_sha,
        "policyBlob": policy_sha,
        "legacySignerRef": HISTORICAL_SIGNER,
        "legacyPublisherRef": HISTORICAL_PUBLISHER,
    }

def inspect(env, api):
    need(env.get("GITHUB_REPOSITORY") == BUILD and
         env.get("GITHUB_EVENT_NAME") == "push" and
         env.get("GITHUB_REF") == "refs/heads/main" and
         env.get("GITHUB_RUN_ATTEMPT") == "1")
    source = env.get("GITHUB_SHA")
    need(type(source) is str and SHA.fullmatch(source) is not None)
    own_a, sha_a = checked_main(BUILD, api)
    need(sha_a == source)
    result = []
    for repo in TARGETS:
        branch_a, head_a = checked_main(repo, api)
        runs = api.get(repo, "commits/" + head_a + "/check-runs?per_page=100")
        checks_for(head_a, branch_a, runs)
        releases = api.get(repo, "releases?per_page=1")
        need(type(releases) is list and len(releases) <= 1)
        promotion_a = promotion_boundary(api, repo, head_a)
        # Second independent GET: reject HEAD movement or protection/check drift.
        branch_b, head_b = checked_main(repo, api)
        need(head_b == head_a and branch_a == branch_b)
        checks_b = api.get(repo, "commits/" + head_b + "/check-runs?per_page=100")
        need(checks_b == runs)
        releases_b = api.get(repo, "releases?per_page=1")
        need(releases_b == releases)
        promotion_b = promotion_boundary(api, repo, head_b)
        need(promotion_b == promotion_a)
        result.append({
            "repository": repo, "mainSha": head_a,
            "protectedMainObserved": True,
            "requiredApp15368ChecksObserved": 1,
            "successfulExactHeadWindowsMajors": [14, 15, 16, 17, 18],
            "readOnlyAdmissionObserved": True,
            "publicReleasePresent": bool(releases),
            "disabledManualPromotionPolicyObserved": True,
            "legacySignerPublisherPinsObserved": True,
            "promotionPolicyBlob": promotion_a["policyBlob"],
            "promotionWorkflowBlob": promotion_a["workflowBlob"],
            "independentWriterProvisionedByThisWorkflow": False,
            "effectiveRulesCryptographicallyProven": False,
            "runtimeSignerIdentityVerified": False,
            "independentWriterVerified": False,
        })
    own_b, sha_b = checked_main(BUILD, api)
    need(sha_b == sha_a and own_a == own_b)
    return {
        "schemaVersion": 1,
        "classification": "LIVE_THREE_TARGET_METADATA_NEGATIVE_ONLY",
        "sourceMainSha": source,
        "targets": result,
        "authMethod": "JOB_SCOPED_READ_TOKEN_GET_ONLY",
        "source45GitBlobBaselineRevalidatedByThisJob": False,
        "independentProtectionAdminReaderVerified": False,
        "effectiveClassicGraphqlProtectionVerified": False,
        "readerSignerWriterRuntimeSeparationVerified": False,
        "actualSignerOidcCertificateVerified": False,
        "actualIndependentAppWriterVerified": False,
        "actualSignedPublisherPositivePrewriteVerified": False,
        "crashSafePublisherRecoveryVerified": False,
        "publishableReceipt": False, "publicationAuthorized": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
    }

def denied():
    return {
        "schemaVersion": 1,
        "classification": "DENY_INCOMPLETE_WAVE3_LIVE_READS",
        "publishableReceipt": False, "publicationAuthorized": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["observe"], required=True)
    args = parser.parse_args()
    try:
        need(args.mode == "observe")
        answer = inspect(os.environ, GetOnly(os.environ["GH_TOKEN"]))
        rc = 0
    except Exception:
        answer, rc = denied(), 2
    print(json.dumps(answer, ensure_ascii=False, sort_keys=True))
    return rc

if __name__ == "__main__":
    sys.exit(main())
