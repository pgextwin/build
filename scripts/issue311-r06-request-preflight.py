#!/usr/bin/env python3
"""R06 independent nonpublishing original ZIP and exact 17-target preflight.

Trusted main workflow_run.completed callback; it accepts only its own new
request-driven push source, never previous scheduled watch artifacts or metadata.
No local candidate creation; existing schedule-only admission is unchanged.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


scan = load("r06scan", "scripts/issue311-r06-request-scan.py")
contract = scan.contract
store = scan.store
bridge = scan.bridge
RECEIPT = "issue311-r06-original-preflight.json"


def require(ok, message):
    if not ok:
        raise ValueError("R06_PREFLIGHT_DENY " + message)


def authenticated_source(event):
    source = event.get("workflow_run", {})
    require(event.get("action") == "completed"
            and event.get("repository", {}).get("full_name") == "pgextwin/build"
            and type(source.get("id")) is int and source["id"] > 0
            and source.get("name") == scan.WORKFLOW
            and source.get("path") == scan.WORKFLOW_PATH
            and source.get("event") == "push"
            and source.get("head_branch") == "main"
            and source.get("actor", {}).get("login") == "ShutenOishi"
            and source.get("status") == "completed"
            and source.get("conclusion") == "success"
            and source.get("run_attempt") == 1
            and re.fullmatch(r"[0-9a-f]{40}", source.get("head_sha", "")),
            "not an authenticated successful new original scan source")
    actual = bridge.get_json("repos/pgextwin/build/actions/runs/" + str(source["id"]))
    for field in ("id", "workflow_id", "run_attempt", "head_sha", "event", "path",
                  "head_branch", "conclusion"):
        require(actual.get(field) == source.get(field),
                "REST/event original run mismatch " + field)
    require(actual.get("status") == "completed"
            and actual.get("actor", {}).get("login") == "ShutenOishi",
            "original run not successful/allowed")
    return source


def original_request(source):
    path = scan.REQUEST_PATH
    record = bridge.get_json("repos/pgextwin/build/contents/" + path +
                             "?ref=" + source["head_sha"])
    require(record.get("encoding") == "base64", "request original bytes unavailable")
    raw = base64.b64decode(record["content"].replace("\r", "").replace("\n", ""),
                           validate=True)
    require(store.blob_hash(raw) == record.get("sha"), "request original Git blob mismatch")
    declaration = contract.validate_declaration(raw, path)
    request = json.loads(raw, object_pairs_hook=store.unique_pairs)
    require(declaration["requestId"] == scan.REQUEST
            and declaration["mode"] == "AUDIT_ONLY"
            and len(declaration["targets"]) == 17
            and set(declaration["targets"]) == set(scan.win.TARGETS)
            and {t["repo"]: t["mainSha"] for t in request["targets"]}
            == scan.win.TARGETS
            and request["source"]["fleetRegistryBlobSha"] == scan.FLEET_BLOB
            and request["approval"]["publicReleaseAuthorized"] is False
            and request["approval"]["publicationGrants"] == []
            and request["allowFutureUpdates"] is False,
            "not a fixed read-only 17-target request")
    commit = bridge.get_json("repos/pgextwin/build/commits/" + source["head_sha"])
    require(commit.get("parents", [{}])[0].get("sha") == request["source"]["centralMainSha"],
            "pre-request protected main SHA differs")
    return declaration, request


def original_zip(source):
    sid = source["id"]
    jobs = bridge.get_json(
        "repos/pgextwin/build/actions/runs/" + str(sid) + "/jobs?per_page=100")
    require(jobs.get("total_count") == len(jobs.get("jobs", [])) == 1,
            "original source jobs missing/paginated")
    job = jobs["jobs"][0]
    require(job.get("run_id") == sid and job.get("status") == "completed"
            and job.get("conclusion") == "success"
            and job.get("name") == "Scan immutable one-shot 17 protected upstreams, no candidate",
            "source scan job not successful")
    artifacts = bridge.get_json(
        "repos/pgextwin/build/actions/runs/" + str(sid) + "/artifacts?per_page=100")
    require(artifacts.get("total_count") == len(artifacts.get("artifacts", [])) == 1,
            "original scan ZIP missing/duplicated")
    entry = artifacts["artifacts"][0]
    require(entry.get("name") == scan.ARTIFACT
            and entry.get("expired") is False
            and entry.get("workflow_run", {}).get("id") == sid
            and re.fullmatch(r"sha256:[0-9a-f]{64}", entry.get("digest", "")),
            "foreign/expired/malformed original scan ZIP")
    raw, sha = bridge.original_zip(entry, scan.RECEIPT)
    return raw, sha, entry["id"]


def cross_repo_protected_main(repo):
    require(repo in scan.win.TARGETS, "remote repo outside frozen 17 allowlist")
    return scan.win.old.get_json(
        "https://api.github.com/repos/" + repo + "/branches/main",
        os.environ["GH_TOKEN"])


def verify_for_source(source, *, transport="workflow_run.completed"):
    declaration, request = original_request(source)
    proof, zip_sha, artifact_id = original_zip(source)
    targets = {x["repo"]: x["mainSha"] for x in request["targets"]}
    require(proof.get("schemaVersion") == 1
            and proof.get("requestId") == scan.REQUEST
            and proof.get("requestSha256") == declaration["rawSha256"]
            and proof.get("sourceHeadSha") == source["head_sha"]
            and proof.get("sourceRunId") == source["id"]
            and proof.get("sourceRunAttempt") == 1
            and proof.get("sourceEvent") == "push"
            and proof.get("registryGitBlobSha") == scan.FLEET_BLOB
            and proof.get("result") == "SCANNED"
            and proof.get("publicationAuthorized") is False
            and proof.get("admissionScope") == "AUDIT_ONLY_REQUEST_READONLY_SCAN_NOT_SCHEDULE"
            and proof.get("targetMainSha") == targets,
            "original source cannot authorize this request")
    found = scan.inspect_report(proof.get("report"), targets)
    require(proof.get("perTargetStatus") ==
            {repo: x["status"] for repo, x in found.items()},
            "report and supplied target status differ")
    for repo, sha in sorted(targets.items()):
        # R05's vetted cross-repository protected branch GET is intentionally
        # separate from the strictly build-only original-artifact API helper.
        # Never widen the build-only reader or transfer the Writer App token.
        remote = cross_repo_protected_main(repo)
        require(remote.get("name") == "main"
                and remote.get("protected") is True
                and remote.get("commit", {}).get("sha") == sha,
                "local exact main drift/preflight denied " + repo)
    return {"schemaVersion": 1, "requestId": scan.REQUEST,
            "requestSha256": declaration["rawSha256"],
            "sourceHeadSha": source["head_sha"],
            "sourceRunId": source["id"], "sourceRunAttempt": 1,
            "completionRunId": int(os.environ["GITHUB_RUN_ID"]),
            "completionRunAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "result": "SCANNED_VERIFIED", "targetCount": 17,
            "verifiedTargets": sorted(targets),
            "originalZipArtifactId": artifact_id,
            "originalZipSha256": zip_sha,
            "updatesDetected": proof["report"]["updatesDetected"],
            "eventTransport": transport,
            "publicationAuthorized": False, "candidateAdmissionAuthorized": False,
            "sourceKind": "AUTHENTICATED_REQUEST_READONLY_SCAN",
            "genuineSchedule": False}


def verify():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                       object_pairs_hook=store.unique_pairs)
    return verify_for_source(authenticated_source(event))


def main():
    result = {"requestId": scan.REQUEST, "result": "FAILED",
              "publicationAuthorized": False, "candidateAdmissionAuthorized": False}
    try:
        require(os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
                and os.environ["GITHUB_EVENT_NAME"] == "workflow_run"
                and os.environ["GITHUB_REF"] == "refs/heads/main"
                and os.environ["GITHUB_RUN_ATTEMPT"] == "1",
                "not trusted completion context")
        result = verify()
    except Exception as exc:
        result["reason"] = str(exc)[:400]
    Path(RECEIPT).write_text(json.dumps(result, sort_keys=True) + "\n",
                             encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] == "SCANNED_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main() if sys.argv[1:] == ["verify"] else 2)
