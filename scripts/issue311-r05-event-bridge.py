#!/usr/bin/env python3
"""Issue #311 R05: independently verify a genuine completed workflow_run 17-target handoff.

READ-ONLY. A missing/failed/skipped child or original ZIP produces FAILED, never
NO_UPDATE. An absent workflow_run delivery cannot be detected by this callback;
the source workflow independently emits its own finite fail-closed terminal.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_WORKFLOW = ".github/workflows/issue311-r05-event-source.yml"
REQUEST = "r-20261029-r05event17a"
REQUEST_PATH = ".github/execution-requests/" + REQUEST + ".json"
ZIP_PREFIX = "issue311-r05-event-target-"
ZIP_TERMINAL = "issue311-r05-event-source-terminal"
MAX_BYTES = 4_000_000

spec = importlib.util.spec_from_file_location(
    "r05repo", ROOT / "scripts" / "issue311-r05-aggregate.py")
aggregate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aggregate)


def require(ok, message):
    if not ok:
        raise ValueError("R05_EVENT_DENY " + message)


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON keys")
        result[key] = value
    return result


class SecureRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward the bearer token from api.github.com to artifact storage."""
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        before = urllib.parse.urlparse(request.full_url)
        after = urllib.parse.urlparse(newurl)
        require(after.scheme == "https", "insecure artifact redirect")
        if before.hostname != after.hostname:
            return urllib.request.Request(
                newurl, headers={"User-Agent": "pgextwin-issue311-readonly-artifact"})
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def get_bytes(endpoint):
    require(endpoint.startswith("repos/pgextwin/build/"), "API repository scope")
    require(re.fullmatch(r"[A-Za-z0-9_./?=&%-]+", endpoint) is not None
            and ".." not in endpoint, "unsafe path")
    request = urllib.request.Request(
        "https://api.github.com/" + endpoint,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                 "Accept": "application/vnd.github+json",
                 "User-Agent": "pgextwin-issue311-event-readonly",
                 "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.build_opener(SecureRedirect()).open(request, timeout=30) as response:
        content = response.read(MAX_BYTES + 1)
    require(len(content) <= MAX_BYTES, "response limit")
    return content


def get_json(endpoint):
    return json.loads(get_bytes(endpoint), object_pairs_hook=unique_keys)


def validate_source_metadata(event, actual):
    source = event.get("workflow_run", {})
    require(event.get("action") == "completed"
            and event.get("repository", {}).get("full_name") == "pgextwin/build",
            "not original completion event")
    require(type(source.get("id")) is int and source["id"] > 0
            and source.get("name") == "Issue 311 R05 verified 17-target source event (NONPUBLISHING)"
            and source.get("path") == SOURCE_WORKFLOW
            and source.get("event") == "push"
            and source.get("head_branch") == "main"
            and source.get("run_attempt") == 1
            and source.get("status") == "completed"
            and source.get("actor", {}).get("login") == "ShutenOishi"
            and re.fullmatch(r"[0-9a-f]{40}", source.get("head_sha", "")),
            "source event fields or actor")
    for field in ("id", "workflow_id", "run_attempt", "head_sha", "path",
                  "head_branch", "event", "conclusion"):
        require(actual.get(field) == source.get(field),
                "source event/API mismatch " + field)
    require(actual.get("status") == "completed"
            and actual.get("actor", {}).get("login") == "ShutenOishi",
            "original source Run not completed / actor")
    return source


def validate_original_request(source):
    record = get_json("repos/pgextwin/build/contents/" + REQUEST_PATH
                      + "?ref=" + source["head_sha"])
    require(record.get("encoding") == "base64"
            and re.fullmatch("[0-9a-f]{40}", record.get("sha", "")),
            "request does not have Git blob proof")
    raw = base64.b64decode(record["content"], validate=False)
    git_object = b"blob " + str(len(raw)).encode() + b"\0" + raw
    require(hashlib.sha1(git_object).hexdigest() == record["sha"],
            "immutable request Git blob mismatch")
    contract_spec = importlib.util.spec_from_file_location(
        "req", ROOT / "scripts" / "issue311-request-contract.py")
    lib = importlib.util.module_from_spec(contract_spec)
    contract_spec.loader.exec_module(lib)
    declaration = lib.validate_declaration(raw, REQUEST_PATH)
    data = json.loads(raw, object_pairs_hook=unique_keys)
    require(declaration["requestId"] == REQUEST and declaration["mode"] == "AUDIT_ONLY"
            and len(declaration["targets"]) == 17
            and set(declaration["targets"]) == aggregate.REPOS
            and data["approval"]["publicReleaseAuthorized"] is False
            and data["approval"]["publicationGrants"] == []
            and data["allowFutureUpdates"] is False,
            "not exact nonpublishing 17 target request")
    require(type(data["source"]["centralMainSha"]) is str
            and re.fullmatch("[0-9a-f]{40}", data["source"]["centralMainSha"])
            and data["source"]["centralMainSha"] != source["head_sha"],
            "missing original pre-request main")
    return data, declaration["rawSha256"]


def require_jobs(jobs, source_id, outcome):
    require(jobs.get("total_count") is not None
            and jobs["total_count"] == len(jobs.get("jobs", []))
            and jobs["total_count"] <= 100, "missing/paginated source jobs")
    found = aggregate.evaluate_jobs(jobs["jobs"])
    require(set(found) == aggregate.REPOS, "17 target job coverage")
    require(all(x == "success" for x in found.values()), "failed/skipped/missing 17 child")
    require(outcome == "success", "source workflow is not successful")
    terminal = [j for j in jobs["jobs"]
                if j.get("name") == "Always aggregate original 17 target jobs even when skipped or failed"]
    require(len(terminal) == 1 and terminal[0].get("conclusion") == "success",
            "source final aggregate missing")
    require(all(j.get("run_id") == source_id for j in jobs["jobs"]),
            "foreign source job")
    return found


def parse_artifacts(artifacts, source_id):
    expected = {ZIP_PREFIX + x.removeprefix("pgextwin/") for x in aggregate.REPOS}
    expected.add(ZIP_TERMINAL)
    require(artifacts.get("total_count") == len(artifacts.get("artifacts", []))
            and len(artifacts["artifacts"]) <= 100, "missing/paginated artifact page")
    found = {}
    for entry in artifacts["artifacts"]:
        name = entry.get("name")
        if name not in expected:
            continue
        require(name not in found
                and entry.get("expired") is False
                and entry.get("workflow_run", {}).get("id") == source_id
                and re.fullmatch("sha256:[0-9a-f]{64}", entry.get("digest", "")),
                "duplicate/foreign/expired original ZIP")
        found[name] = entry
    require(set(found) == expected, "one or more original 17/terminal ZIPs missing")
    return found


def original_zip(entry, wanted_name):
    raw = get_bytes(f"repos/pgextwin/build/actions/artifacts/{entry['id']}/zip")
    require("sha256:" + hashlib.sha256(raw).hexdigest() == entry["digest"],
            "original ZIP digest mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(archive.namelist() == [wanted_name], "unexpected ZIP file entry")
        payload = archive.read(wanted_name)
    return json.loads(payload, object_pairs_hook=unique_keys), hashlib.sha256(raw).hexdigest()


def check_receipts(entries, source_id, attempt, request_sha, declared, per_job):
    hashes = {}
    for repo in sorted(aggregate.REPOS):
        name = ZIP_PREFIX + repo.removeprefix("pgextwin/")
        receipt, digest = original_zip(entries[name], "issue311-r05-target-receipt.json")
        require(receipt.get("requestId") == REQUEST
                and receipt.get("repository") == repo
                and receipt.get("runId") == source_id
                and receipt.get("runAttempt") == attempt
                and receipt.get("result") == "SUCCESS"
                and receipt.get("publicationAuthorized") is False
                and receipt.get("protected") is True
                and receipt.get("rawSha256") == request_sha
                and receipt.get("mainSha") == declared[repo]
                and per_job[repo] == "success",
                "original receipt mismatched " + repo)
        hashes[repo] = digest
    terminal, digest = original_zip(entries[ZIP_TERMINAL], "issue311-r05-17-terminal.json")
    require(terminal.get("requestId") == REQUEST
            and terminal.get("runId") == source_id
            and terminal.get("runAttempt") == attempt
            and terminal.get("terminal") == "NO_UPDATE"
            and terminal.get("publishAuthorized") is False
            and terminal.get("persistenceAccepted") is False
            and terminal.get("perTarget") == per_job,
            "source terminal cannot prove original 17")
    return hashes, digest


def verify(event):
    source_id = event.get("workflow_run", {}).get("id")
    require(type(source_id) is int and source_id > 0, "missing original Run ID")
    source = validate_source_metadata(
        event, get_json(f"repos/pgextwin/build/actions/runs/{source_id}"))
    data, raw_sha = validate_original_request(source)
    per_job = require_jobs(
        get_json(f"repos/pgextwin/build/actions/runs/{source_id}/jobs?per_page=100"),
        source_id, source["conclusion"])
    entries = parse_artifacts(
        get_json(f"repos/pgextwin/build/actions/runs/{source_id}/artifacts?per_page=100"),
        source_id)
    hashes, terminal_digest = check_receipts(
        entries, source_id, source["run_attempt"], raw_sha,
        {x["repo"]: x["mainSha"] for x in data["targets"]}, per_job)
    return {"schemaVersion": 1, "requestId": REQUEST,
            "requestSha256": raw_sha, "sourceRunId": source_id,
            "sourceRunAttempt": source["run_attempt"],
            "sourceSha": source["head_sha"],
            "result": "NO_UPDATE", "allTargets": len(hashes),
            "perTarget": per_job, "originalArtifactSha256": hashes,
            "originalTerminalZipSha256": terminal_digest,
            "eventTransport": "workflow_run.completed",
            "publisherAuthorized": False}


def main():
    receipt = {"schemaVersion": 1, "requestId": REQUEST,
               "result": "FAILED", "publisherAuthorized": False,
               "reason": "source event or immutable child proof unavailable"}
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                           object_pairs_hook=unique_keys)
        require(os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
                and os.environ["GITHUB_EVENT_NAME"] == "workflow_run"
                and os.environ["GITHUB_REF"] == "refs/heads/main",
                "wrong trusted main completed event context")
        receipt = verify(event)
    except Exception as exc:
        receipt["reason"] = str(exc)[:350]
    Path("issue311-r05-event-terminal.json").write_text(
        json.dumps(receipt, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["result"] == "NO_UPDATE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
