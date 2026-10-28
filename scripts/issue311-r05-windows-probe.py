#!/usr/bin/env python3
"""R05 isolated original Windows cross-repo read-only and negative terminal proof.

This script has no dispatch, token write, release, signer, lease or Publisher access.
The controlled negative target MUST first pass an authenticated exact-main GET.
"""
from __future__ import annotations
import hashlib
import importlib.util
import io
import json
import os
import subprocess
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request
import zipfile

REQUEST_ID = "r-20261029-r05winnegative02"
REQUEST_PATH = Path(".github/execution-requests/" + REQUEST_ID + ".json")
TARGETS = {
    "pgextwin/orafce": "e96941dd3ec09f88011feb1165a3f6f83231460f",
    "pgextwin/pg_ivm": "6e3904af78cccbd67ce84eef183ceda9f4eef553",
}
NEGATIVE_REPO = "pgextwin/pg_ivm"
ARTIFACT_PREFIX = "issue311-r05win-"


def get_json(url: str, token: str, *, attempts: int = 2):
    for number in range(attempts):
        try:
            request = urllib.request.Request(url, headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            })
            with urllib.request.urlopen(request, timeout=25) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or number + 1 == attempts:
                raise
            time.sleep(2)
    raise ValueError("bounded API attempts exhausted")


def original_request_bytes():
    """Use committed Git blob; Windows checkout can rewrite LF to CRLF.

    The original request raw SHA256 must be computed over the immutable Git
    blob, never over a platform-dependent working tree checkout.
    """
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != os.environ["GITHUB_SHA"]:
        raise ValueError("checked out HEAD differs from original event SHA")
    return subprocess.check_output(
        ["git", "show", "HEAD:" + REQUEST_PATH.as_posix()])


def request_binding(raw, expected_hash):
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError("request original-byte SHA mismatch")
    obj = json.loads(raw)
    if (obj.get("requestId") != REQUEST_ID or obj.get("mode") != "AUDIT_ONLY"
            or obj.get("approval", {}).get("publicReleaseAuthorized") is not False
            or obj["approval"].get("publicationGrants") != []
            or {t["repo"]: t["mainSha"] for t in obj["targets"]} != TARGETS):
        raise ValueError("not the two exact nonpublishing target snapshots")
    return obj


def admit():
    spec = importlib.util.spec_from_file_location("contract", "scripts/issue311-request-contract.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    raw = original_request_bytes()
    validated = mod.validate_declaration(raw, REQUEST_PATH.as_posix())
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    if not (validated["requestId"] == REQUEST_ID and validated["mode"] == "AUDIT_ONLY"
            and validated["actorAuthenticated"] is False and validated["publicationAuthorized"] is False
            and os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
            and os.environ["GITHUB_EVENT_NAME"] == "push"
            and os.environ["GITHUB_REF"] == "refs/heads/main"
            and os.environ["GITHUB_ACTOR"] == "ShutenOishi"
            and (event.get("sender") or {}).get("login") == "ShutenOishi"
            and event.get("after") == os.environ["GITHUB_SHA"]
            and event.get("ref") == "refs/heads/main"
            and event.get("repository", {}).get("full_name") == "pgextwin/build"
            and event.get("created") is False and event.get("deleted") is False):
        raise ValueError("original protected main-push event denied")
    request_binding(raw, validated["rawSha256"])
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("raw_sha=" + validated["rawSha256"] + "\n")
    print("R05_WINDOWS_READONLY_ADMITTED originalSha256=" + validated["rawSha256"])


def inspect():
    repo = os.environ["REMOTE_REPO"]
    receipt = {
        "requestId": REQUEST_ID, "repo": repo,
        "runId": int(os.environ["GITHUB_RUN_ID"]),
        "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "requestRawSha256": os.environ["REQUEST_SHA"], "runnerOS": os.environ["RUNNER_OS"],
        "remoteVerified": False, "result": "FAILED", "publishAuthorized": False,
    }
    try:
        raw = original_request_bytes()
        request_binding(raw, os.environ["REQUEST_SHA"])
        if not (repo in TARGETS and os.environ["REMOTE_SHA"] == TARGETS[repo]
                and os.environ["RUNNER_OS"] == "Windows"
                and os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
                and os.environ["GITHUB_EVENT_NAME"] == "push"):
            raise ValueError("Windows/target/event not authenticated")
        data = get_json("https://api.github.com/repos/" + repo + "/branches/main",
                        os.environ["GH_TOKEN"])
        if (data.get("name") != "main" or data.get("protected") is not True
                or data.get("commit", {}).get("sha") != TARGETS[repo]):
            raise ValueError("remote protected main snapshot changed")
        receipt.update(remoteVerified=True, mainSha=TARGETS[repo], result="SUCCESS")
        if repo == NEGATIVE_REPO:
            receipt.update(result="FAILED", failureClass="CONTROLLED_AFTER_VERIFIED_GET",
                           reason="Intentional isolated R05 child failure after genuine remote GET")
    except Exception as exc:
        receipt["reason"] = str(exc)[:250]
    Path("issue311-r05win-target.json").write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["result"] == "SUCCESS" else 1


def evaluate(jobs, receipts, admit_result):
    expected = set(TARGETS)
    found = {}
    for job in jobs:
        name = job.get("name", "")
        if not name.startswith("WINDOWS GET "):
            continue
        repo = name.removeprefix("WINDOWS GET ")
        if repo not in expected or repo in found:
            raise ValueError("unexpected/duplicate Windows child job")
        found[repo] = (job.get("conclusion") if job.get("status") == "completed"
                       else "incomplete")
    if set(found) != expected or set(receipts) != expected:
        raise ValueError("missing Windows child or independently hashed original receipt")
    for repo, receipt in receipts.items():
        if (receipt.get("requestId") != REQUEST_ID or receipt.get("repo") != repo
                or receipt.get("runnerOS") != "Windows"
                or receipt.get("remoteVerified") is not True
                or receipt.get("mainSha") != TARGETS[repo]
                or receipt.get("publishAuthorized") is not False):
            raise ValueError("original Windows receipt did not independently verify remote main")
    good = ("success" == admit_result
            and found["pgextwin/orafce"] == "success"
            and found[NEGATIVE_REPO] == "failure"
            and receipts["pgextwin/orafce"].get("result") == "SUCCESS"
            and receipts[NEGATIVE_REPO].get("result") == "FAILED"
            and receipts[NEGATIVE_REPO].get("failureClass") == "CONTROLLED_AFTER_VERIFIED_GET")
    return {"terminal": "FAILED", "controlledNegativeProved": bool(good),
            "perTarget": found,
            "reason": ("Original Windows matrix child failure correctly propagated"
                       if good else "Unexpected failure/skip/missing child or invalid original proof")}


def aggregate():
    result = {
        "requestId": REQUEST_ID, "runId": int(os.environ["GITHUB_RUN_ID"]),
        "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "terminal": "FAILED", "controlledNegativeProved": False, "publishAuthorized": False,
        "persistenceAccepted": False, "reason": "Original evidence unavailable",
    }
    try:
        token = os.environ["GH_TOKEN"]
        base = "https://api.github.com/repos/pgextwin/build/actions/runs/" + str(result["runId"])
        jobs = get_json(base + "/jobs?per_page=100", token)
        artifacts = get_json(base + "/artifacts?per_page=100", token)
        if jobs.get("total_count", 999) > 100 or artifacts.get("total_count", 999) > 100:
            raise ValueError("truncated original jobs or artifacts")
        receipts = {}
        digests = {}
        for artifact in artifacts["artifacts"]:
            name = artifact["name"]
            if not name.startswith(ARTIFACT_PREFIX):
                continue
            repo = "pgextwin/" + name.removeprefix(ARTIFACT_PREFIX)
            if repo not in TARGETS or repo in receipts or artifact.get("expired") is not False:
                raise ValueError("duplicate/expired/unknown original artifact")
            request = urllib.request.Request(artifact["archive_download_url"], headers={
                "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ValueError("oversized original receipt ZIP")
            digest = hashlib.sha256(raw).hexdigest()
            if artifact.get("digest") != "sha256:" + digest:
                raise ValueError("original ZIP actual bytes/digest mismatch")
            with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
                members = zipped.namelist()
                if members != ["issue311-r05win-target.json"]:
                    raise ValueError("unexpected ZIP member")
                receipt = json.loads(zipped.read(members[0]))
            if (receipt.get("runId") != result["runId"]
                    or receipt.get("runAttempt") != result["runAttempt"]
                    or receipt.get("requestRawSha256") != os.environ["REQUEST_SHA"]):
                raise ValueError("cross-run/replayed original ZIP")
            receipts[repo] = receipt
            digests[repo] = digest
        result.update(evaluate(jobs["jobs"], receipts, os.environ["ADMIT_RESULT"]))
        result["originalZipSha256"] = digests
    except Exception as exc:
        result["reason"] = str(exc)[:350]
    Path("issue311-r05win-terminal.json").write_text(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    # A negative acceptance run stays red. Never upgrade a failed original run.
    return 1


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "admit":
        admit()
    elif command == "inspect":
        sys.exit(inspect())
    elif command == "aggregate":
        sys.exit(aggregate())
    else:
        raise SystemExit("expected admit|inspect|aggregate")
