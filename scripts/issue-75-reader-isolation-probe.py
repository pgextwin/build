#!/usr/bin/env python3
"""PR-only, read-only token separation witness. Never a signed Publisher proof.

Reuses the existing allowlisted GET transport; no custom HTTP, no credential
dump, no token introspection, no artifact, no POST and no publication receipt.
"""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import sys

PATH = Path(__file__).resolve().parent / "issue-75-go-b-live-readonly.py"
spec = importlib.util.spec_from_file_location("issue75_existing_getonly_transport", PATH)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)

CANDIDATE_RUN = 39021934569
SHA = "4899b5c1da8e2fb681381fff4fa2ab41882cb0bc"
PR_BRANCH = "issue-75-transitive-closure-reader-isolation"

class Deny(ValueError):
    pass

def inspect(get, *, repository, event, head_ref, job, run_id, attempt):
    if repository != "pgextwin/build" or event != "pull_request" or \
            head_ref != PR_BRANCH or job != "issue75_reader_probe" or \
            not run_id.isdecimal() or not attempt.isdecimal() or \
            int(run_id) < 1 or int(attempt) < 1:
        raise Deny("unexpected identity or event; no reader probe")
    path = f"actions/runs/{CANDIDATE_RUN}"
    a = get(path, run_id=CANDIDATE_RUN, attempt=1, sha=SHA)
    b = get(path, run_id=CANDIDATE_RUN, attempt=1, sha=SHA)
    if a != b or type(a) is not dict or a.get("id") != CANDIDATE_RUN or \
            a.get("head_sha") != SHA or a.get("status") != "completed" or \
            a.get("conclusion") != "success" or \
            a.get("path") != ".github/workflows/windows.yml" or \
            a.get("head_branch") != "auto-candidate/29d1c1984a1b44a55107":
        raise Deny("duplicate, mismatched, or non-unsigned stable GET run")
    return {"decision": "PR_READER_GET2_NEGATIVE_ONLY",
            "readerRunId": int(run_id), "readerAttempt": int(attempt),
            "readerJob": job, "observedRunId": CANDIDATE_RUN,
            "observedHead": SHA, "GETs": 2,
            "tokenScopesVerified": False, "writerTokenSeen": False,
            "signedPublisherPrewriteVerified": False, "goB": "NO_GO",
            "g4": "NO_GO", "g5": "NO_GO", "publicationAuthorized": False}

def main():
    output = {"decision": "GET_NOT_PROVEN", "tokenScopesVerified": False,
              "signedPublisherPrewriteVerified": False, "goB": "NO_GO",
              "g4": "NO_GO", "g5": "NO_GO", "publicationAuthorized": False}
    try:
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise Deny("reader token unavailable")
        output = inspect(
            lambda path, **kw: reader.get_json(path, token=token, **kw),
            repository=os.environ.get("GITHUB_REPOSITORY", ""),
            event=os.environ.get("GITHUB_EVENT_NAME", ""),
            head_ref=os.environ.get("GITHUB_HEAD_REF", ""),
            job=os.environ.get("GITHUB_JOB", ""),
            run_id=os.environ.get("GITHUB_RUN_ID", ""),
            attempt=os.environ.get("GITHUB_RUN_ATTEMPT", ""))
    except (Deny, reader.Deny, KeyError, TypeError, ValueError) as exc:
        # Exception details may include untrusted response content, so neither
        # print them nor copy them into any artifact.
        output["reasonCode"] = "READER_GET_OR_IDENTITY_UNPROVEN"
    print(json.dumps(output, sort_keys=True))
    # A negative probe must not accidentally become a required promotion gate.
    # Tests enforce NO_GO even when the two authenticated GETs succeeded.
    return 0

if __name__ == "__main__":
    sys.exit(main())
