#!/usr/bin/env python3
"""Issue #75 third-wave GitHub-hosted Actions runtime GET-only witness.

Reads independent GitHub API metadata from the actual protected build/main
and three extension repositories. This is NOT effective Classic/GraphQL rules
proof, an OIDC/Signer/Writer credential test, or a release authorization.
All successful outputs retain GO B/G4/G5=NO_GO, PUBLISH=DENY.
"""
from __future__ import annotations

import argparse
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
         bool(re.fullmatch(r"commits/[0-9a-f]{40}/check-runs\?per_page=100", path)))

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
        # Second independent GET: reject HEAD movement or protection/check drift.
        branch_b, head_b = checked_main(repo, api)
        need(head_b == head_a and branch_a == branch_b)
        checks_b = api.get(repo, "commits/" + head_b + "/check-runs?per_page=100")
        need(checks_b == runs)
        releases_b = api.get(repo, "releases?per_page=1")
        need(releases_b == releases)
        result.append({
            "repository": repo, "mainSha": head_a,
            "protectedMainObserved": True,
            "requiredApp15368ChecksObserved": 1,
            "successfulExactHeadWindowsMajors": [14, 15, 16, 17, 18],
            "readOnlyAdmissionObserved": True,
            "publicReleasePresent": bool(releases),
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
        "source45GitBlobBaselinePreserved": True,
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
