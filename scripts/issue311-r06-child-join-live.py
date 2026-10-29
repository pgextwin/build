#!/usr/bin/env python3
"""Independent R06 original-byte child join and finite build-only App terminal.

Only GETs public original evidence. The existing dedicated App may write only
the approved build request-lifecycle CAS. Never dispatch, sign or publish.
The missing completion is deliberately withheld from a real original source
bundle; this is a controlled transport fault, not a natural GitHub outage.
"""
from __future__ import annotations

import base64
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 4_000_000
FLEET_BLOB = "69918265dabb86b11a9406533cbe0ce495137b94"
SOURCE_NAME = "Issue 311 R06 original 17 child completion bundle (NONPUBLISHING)"
WATCH_NAME = "Issue 311 R06 independent finite child watchdog (NONPUBLISHING)"
SOURCE_PATH = ".github/workflows/issue311-r06-child-join-source.yml"
WATCH_PATH = ".github/workflows/issue311-r06-child-join-watchdog.yml"
SOURCE_ARTIFACT = "issue311-r06-child-join-original"
SOURCE_FILE = SOURCE_ARTIFACT + ".json"
FINAL_ARTIFACT = "issue311-r06-child-join-terminal"
FINAL_FILE = FINAL_ARTIFACT + ".json"
READBACK_FILE = "issue311-r06-child-join-independent-readback.json"
LOCAL_ENTRY = "issue311-r06-fleet-local-prepare-receipt.json"
LOCAL_NAME = "Issue 311 R06 fleet local PREPARE verifier (NONPUBLISHING)"
LOCAL_JOB = "Verify exact original 17 protected mains and immutable PREPARE ZIP"
VERIFY_STEP = "Verify original central source Run/job/ZIP and 17 exact SHA (NEVER WRITE)"
SHARED_VERIFY_STEP = "Authenticate protected request / central original Run-job-ZIP (NO WRITER)"
TIMEOUT_STEP = "R06 original one-shot timed-out step (real Actions timeout)"
FAIL_STEP = "R06 one-shot failure witness (nonpublishing, exact request-only push)"
MISSING_REPO = "pgextwin/orafce"
ANOMALIES = {"pgextwin/pg_bigm": "FAILED", "pgextwin/pg_cron": "SKIPPED",
             "pgextwin/pg_hint_plan": "TIMEOUT", MISSING_REPO: "MISSING_EVENT"}
SHA40 = re.compile(r"[0-9a-f]{40}$")
SHA64 = re.compile(r"[0-9a-f]{64}$")
REQUEST_ID = re.compile(r"r-20\d{6}-r06join[a-z0-9-]{4,32}$")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


store = load("r06_live_store", "scripts/issue311-lifecycle-store.py")
life = store.lifecycle
writer = load("r06_live_writer", "scripts/issue311-writer-runtime.py")
policy = load("r06_live_policy", "scripts/issue311-r06-local-child-join.py")


def need(ok, reason):
    if not ok:
        raise ValueError("R06_CHILD_LIVE_DENY " + reason)


def strict(raw):
    return json.loads(raw, object_pairs_hook=store.unique_pairs)


def utc(value):
    return life.parse_utc(value)


def now_utc():
    return datetime.now(timezone.utc)


def stamp():
    return now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")


def targets():
    raw = (ROOT / "metadata/automation-fleet.json").read_bytes()
    need(store.blob_hash(raw) == FLEET_BLOB, "trusted registry drift")
    entries = strict(raw)["entries"]
    names = {x["repository"] for x in entries}
    need(len(names) == len(entries) == 17, "registry not exact 17")
    return names


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        need(parsed.scheme == "https", "non-HTTPS redirect")
        if parsed.hostname != urllib.parse.urlparse(request.full_url).hostname:
            return urllib.request.Request(newurl, headers={"User-Agent": "pgextwin-r06-original-readonly"})
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def get_bytes(repo, endpoint):
    need(repo in targets() | {"pgextwin/build"}, "unapproved read repository")
    need(type(endpoint) is str and re.fullmatch(r"[A-Za-z0-9_./?=&%-]+", endpoint)
         and ".." not in endpoint and not endpoint.startswith("/"), "unsafe read endpoint")
    need(endpoint.startswith(("actions/", "contents/", "commits/", "pulls/", "branches/")),
         "read API outside original-evidence allowlist")
    request = urllib.request.Request("https://api.github.com/repos/" + repo + "/" + endpoint,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "pgextwin-r06-original-readonly"})
    with urllib.request.build_opener(SafeRedirect()).open(request, timeout=25) as response:
        raw = response.read(MAX_BYTES + 1)
    need(len(raw) <= MAX_BYTES, "original response too large")
    return raw


def get(repo, endpoint):
    return strict(get_bytes(repo, endpoint))


def contents(repo, path, sha):
    need(SHA40.fullmatch(sha or ""), "contents ref must be immutable SHA")
    record = get(repo, "contents/" + path + "?ref=" + sha)
    need(record.get("encoding") == "base64", "missing original Contents")
    raw = base64.b64decode(record["content"].replace("\r", "").replace("\n", ""), validate=True)
    need(store.blob_hash(raw) == record.get("sha"), "original Git blob byte mismatch")
    return raw


def single_zip(raw, digest, entry):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES
         and SHA64.fullmatch(digest or "")
         and hashlib.sha256(raw).hexdigest() == digest, "original outer ZIP SHA256 mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        need(archive.namelist() == [entry], "ambiguous/missing original ZIP entry")
        info = archive.getinfo(entry)
        need(info.file_size <= MAX_BYTES and not info.is_dir(), "oversized original JSON")
        return strict(archive.read(entry))


def artifact(repo, run_id, name, entry, *, expected_id=None, expected_digest=None):
    listing = get(repo, "actions/runs/" + str(run_id) + "/artifacts?per_page=100")
    items = listing.get("artifacts", [])
    need(listing.get("total_count") == len(items) <= 100, "incomplete artifact listing")
    matches = [a for a in items if a.get("name") == name]
    need(len(matches) == 1, "missing/duplicate original artifact")
    a = matches[0]
    digest = a.get("digest", "").removeprefix("sha256:")
    need(type(a.get("id")) is int and a.get("expired") is False
         and a.get("workflow_run", {}).get("id") == run_id
         and SHA64.fullmatch(digest), "original artifact provider identity")
    need(expected_id is None or a["id"] == expected_id, "wrong artifact ID")
    need(expected_digest is None or digest == expected_digest, "wrong provider digest")
    proof = single_zip(get_bytes(repo, "actions/artifacts/" + str(a["id"]) + "/zip"), digest, entry)
    return proof, {"id": a["id"], "zipSha256": digest, "entry": entry}


def original_run(repo, run_id, workflow_path, head=None):
    r = get(repo, "actions/runs/" + str(run_id))
    need(r.get("id") == run_id and r.get("repository", {}).get("full_name") == repo
         and r.get("path") == workflow_path and r.get("run_attempt") == 1
         and r.get("event") == "push" and r.get("head_branch") == "main"
         and r.get("actor", {}).get("login") == "ShutenOishi"
         and r.get("status") == "completed" and SHA40.fullmatch(r.get("head_sha", "")),
         "not genuine completed first-attempt protected source")
    need(head is None or r["head_sha"] == head, "original source HEAD mismatch")
    return r


def jobs(repo, run_id):
    result = get(repo, "actions/runs/" + str(run_id) + "/attempts/1/jobs?per_page=100")
    items = result.get("jobs", [])
    need(result.get("total_count") == len(items) <= 100
         and all(j.get("run_id") == run_id and j.get("status") == "completed" for j in items),
         "incomplete original job listing")
    return items


def exact_job(items, name):
    found = [j for j in items if j.get("name") == name]
    need(len(found) == 1, "missing/ambiguous original job " + name)
    return found[0]


def step(job, name, conclusion):
    found = [s for s in job.get("steps", []) if s.get("name") == name]
    need(len(found) == 1 and found[0].get("status") == "completed"
         and found[0].get("conclusion") == conclusion, "original step result mismatch " + name)
    return found[0]


def original_verification_step(repo, job, workflow_text):
    # Derive the display name from the authentic immutable workflow, not from
    # a repository-name heuristic. Both deployed labels execute the same pin.
    need(repo in targets() and type(workflow_text) is str, "unknown original verifier workflow")
    lines = workflow_text.splitlines()
    command = "        run: python .pgextwin-build/scripts/issue311-r06-fleet-local-prepare.py run"
    hits = [i for i, line in enumerate(lines) if line == command]
    need(len(hits) == 1 and
         "          ref: ff551bd2ea20da869e644691090b5ee7c82553ba\n          path: .pgextwin-build" in workflow_text,
         "original verifier command/pin mismatch")
    index = hits[0]
    headers = [i for i in range(index) if lines[i].startswith("      - ")]
    need(bool(headers), "original verifier step header missing")
    start = headers[-1]
    need(lines[start].startswith("      - name: ")
         and lines[start+1:index] == ["        env:", "          GH_TOKEN: ${{ github.token }}"],
         "original verifier step ownership/env mismatch")
    name = lines[start].removeprefix("      - name: ")
    need(name in {VERIFY_STEP, SHARED_VERIFY_STEP}, "unknown deployed original verifier label")
    return step(job, name, "success")


def protected_merge(repo, head, parent, request_path):
    branch = get(repo, "branches/main")
    need(branch.get("protected") is True and branch.get("commit", {}).get("sha") == head,
         "local protected main drift")
    commit = get(repo, "commits/" + head)
    need(commit.get("parents", [{}])[0].get("sha") == parent
         and [(f.get("status"), f.get("filename")) for f in commit.get("files", [])]
             == [("added", request_path)], "not original request-only protected parent")
    prs = get(repo, "commits/" + head + "/pulls?per_page=100")
    found = [p for p in prs if p.get("merged_at") is not None
             and p.get("merge_commit_sha") == head and p.get("base", {}).get("ref") == "main"]
    need(len(found) == 1, "original protected request PR missing/ambiguous")
    pr = get(repo, "pulls/" + str(found[0]["number"]))
    need(pr.get("merged") is True and pr.get("merge_commit_sha") == head
         and pr.get("changed_files") == 1 and pr.get("user", {}).get("login") == "ShutenOishi"
         and pr.get("merged_by", {}).get("login") == "ShutenOishi",
         "original protected request PR actor/merge mismatch")
    checks = get(repo, "commits/" + pr["head"]["sha"] + "/check-runs?per_page=100")
    rows = checks.get("check_runs", [])
    need(checks.get("total_count") == len(rows) <= 100, "incomplete required checks")
    required = [f"windows / PostgreSQL {n} / Windows x64" for n in range(14, 19)] + ["Windows required summary"]
    for name in required:
        matches = [x for x in rows if x.get("name") == name]
        need(len(matches) == 1 and matches[0].get("head_sha") == pr["head"]["sha"]
             and matches[0].get("app", {}).get("id") == 15368
             and matches[0].get("status") == "completed" and matches[0].get("conclusion") == "success",
             "required same-head App15368 CI incomplete " + name)
    return {"number": pr["number"], "headSha": pr["head"]["sha"], "mergedSha": head,
            "requiredAppId": 15368, "requiredChecks": required}


def validate_request(raw, path, *, now=None):
    need(type(raw) is bytes and 0 < len(raw) <= 16384, "join request byte limit")
    r = strict(raw)
    need(type(r) is dict and set(r) == {"schemaVersion", "kind", "requestId", "mode",
         "createdAt", "expiresAt", "requestedBy", "central", "children", "missingCompletionRepo",
         "publicReleaseAuthorized", "stateWriteScope"}, "unknown join request fields")
    need(r["schemaVersion"] == 1 and r["kind"] == "pgextwin-r06-original-child-join"
         and REQUEST_ID.fullmatch(r["requestId"])
         and path == ".github/execution-requests/" + r["requestId"] + ".json"
         and r["mode"] == "AUDIT_ONLY" and r["requestedBy"] == "ShutenOishi"
         and r["publicReleaseAuthorized"] is False
         and r["stateWriteScope"] == "BUILD_ONLY_REQUEST_LIFECYCLE"
         and r["missingCompletionRepo"] == MISSING_REPO, "unsafe join request scope")
    moment = now or now_utc()
    need(utc(r["createdAt"]) <= moment + timedelta(minutes=5)
         and utc(r["createdAt"]) < utc(r["expiresAt"]) <= utc(r["createdAt"]) + timedelta(minutes=30)
         and moment < utc(r["expiresAt"]), "expired/unbounded join request")
    c = r["central"]
    need(type(c) is dict and set(c) == {"requestId", "runId", "headSha", "artifactId", "zipSha256"}
         and type(c["runId"]) is int and c["runId"] > 0
         and type(c["artifactId"]) is int and c["artifactId"] > 0
         and re.fullmatch(r"r-20\d{6}-r06prepare[a-z0-9-]{4,40}", c["requestId"])
         and SHA40.fullmatch(c["headSha"]) and SHA64.fullmatch(c["zipSha256"]),
         "incomplete central original binding")
    need(type(r["children"]) is list and len(r["children"]) == 17, "17 original children required")
    repos, ids = set(), set()
    for x in r["children"]:
        need(type(x) is dict and set(x) == {"repo", "runId", "requestId"}
             and x["repo"] in targets() and x["repo"] not in repos
             and type(x["runId"]) is int and x["runId"] > 0 and x["runId"] not in ids
             and re.fullmatch(r"r-20\d{6}-r06local[a-z0-9-]{4,40}", x["requestId"]),
             "duplicate/invalid original local source")
        repos.add(x["repo"])
        ids.add(x["runId"])
    need(repos == targets(), "missing allowed repository")
    return r


def request_context(command):
    expected = SOURCE_NAME if command == "source" else WATCH_NAME
    ev = strict(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    head = os.environ["GITHUB_SHA"]
    need(os.environ["GITHUB_REPOSITORY"] == "pgextwin/build"
         and os.environ["GITHUB_WORKFLOW"] == expected
         and os.environ["GITHUB_EVENT_NAME"] == "push" and os.environ["GITHUB_REF"] == "refs/heads/main"
         and os.environ["GITHUB_RUN_ATTEMPT"] == "1" and os.environ["GITHUB_ACTOR"] == "ShutenOishi"
         and ev.get("sender", {}).get("login") == "ShutenOishi"
         and ev.get("repository", {}).get("full_name") == "pgextwin/build"
         and ev.get("created") is False and ev.get("deleted") is False
         and ev.get("after") == head and ev.get("before") != head,
         "not original authorized join push")
    need(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == head,
         "join checkout is not original HEAD")
    changed = subprocess.check_output(["git", "diff", "--name-status", ev["before"], head], text=True).splitlines()
    need(len(changed) == 1 and changed[0].startswith("A\t"), "join must be one new request only")
    path = changed[0][2:]
    need(path.startswith(".github/execution-requests/") and ".." not in path, "join path outside namespace")
    raw = subprocess.check_output(["git", "show", "HEAD:" + path])
    need(raw == contents("pgextwin/build", path, head), "join request original bytes mismatch")
    r = validate_request(raw, path)
    branch = get("pgextwin/build", "branches/main")
    need(branch.get("protected") is True and branch.get("commit", {}).get("sha") == head,
         "join main not exact protected HEAD")
    prs = get("pgextwin/build", "commits/" + head + "/pulls?per_page=100")
    accepted = [p for p in prs if p.get("merge_commit_sha") == head
                and p.get("merged_at") and p.get("base", {}).get("ref") == "main"]
    need(len(accepted) == 1, "join is not protected PR merge")
    pr = get("pgextwin/build", "pulls/" + str(accepted[0]["number"]))
    need(pr.get("merged") is True and pr.get("changed_files") == 1
         and pr.get("merged_by", {}).get("login") == "ShutenOishi", "join merge actor/scope")
    checks = get("pgextwin/build", "commits/" + pr["head"]["sha"] + "/check-runs?per_page=100")
    resolver = [x for x in checks.get("check_runs", []) if x.get("name") == "resolver"]
    need(len(resolver) == 1 and resolver[0].get("head_sha") == pr["head"]["sha"]
         and resolver[0].get("app", {}).get("id") == 15368
         and resolver[0].get("status") == "completed" and resolver[0].get("conclusion") == "success",
         "join required original resolver missing")
    return r, hashlib.sha256(raw).hexdigest(), head


def central_original(request):
    contract = load("r06_live_contract", "scripts/issue311-request-contract.py")
    c = request["central"]
    r = original_run("pgextwin/build", c["runId"], ".github/workflows/issue311-r06-prepare-scan.yml", c["headSha"])
    need(r.get("conclusion") == "success", "central original not successful")
    proof, meta = artifact("pgextwin/build", r["id"], "issue311-r06-prepare-original-scan",
        "issue311-r06-prepare-original-scan.json", expected_id=c["artifactId"], expected_digest=c["zipSha256"])
    need(proof.get("requestId") == c["requestId"] and proof.get("sourceRunId") == r["id"]
         and proof.get("sourceRunAttempt") == 1 and proof.get("sourceHeadSha") == r["head_sha"]
         and proof.get("sourceEvent") == "push" and proof.get("result") == "SCANNED"
         and central_scope(proof) and proof.get("fleetSize") == 17
         and set(proof.get("targetMainSha", {})) == targets(), "central original receipt scope")
    path = ".github/execution-requests/" + c["requestId"] + ".json"
    raw = contents("pgextwin/build", path, c["headSha"])
    declared = contract.validate_declaration(raw, path, now=utc(r["created_at"]))
    need(declared["rawSha256"] == proof.get("requestSha256") and declared["mode"] == "PREPARE",
         "central original request SHA/mode")
    req = strict(raw)
    need(req["approval"]["publicReleaseAuthorized"] is False and req["approval"]["publicationGrants"] == []
         and req["allowFutureUpdates"] is False
         and {t["repo"]: t["mainSha"] for t in req["targets"]} == proof["targetMainSha"],
         "central target/request mismatch")
    report = proof["report"]
    rows = report.get("extensions", [])
    need(report.get("scope") == "STABLE_UPSTREAM_GET_ONLY" and report.get("publication") == "DENY"
         and report.get("fleetSize") == 17 and report.get("indeterminate") == 0
         and report.get("candidatePrCreated") is False and len(rows) == 17
         and {x.get("repository"): x.get("mainSha") for x in rows} == proof["targetMainSha"]
         and all(x.get("status") in ("up-to-date", "update-available") for x in rows),
         "central report incomplete or privileged")
    central = {"requestId": c["requestId"], "sourceRunId": r["id"], "sourceRunAttempt": 1,
        "sourceHeadSha": r["head_sha"], "sourceArtifactId": meta["id"], "sourceZipSha256": meta["zipSha256"],
        "created_at": r["created_at"], "sourceEvent": "push", "publicationAuthorized": False,
        "targetMainSha": proof["targetMainSha"]}
    return central, req


def central_scope(proof):
    # The authentic PREPARE scan uses publicationAuthorized, whereas App
    # lifecycle state uses publisherAuthorized. Never interchange the schemas.
    return proof.get("publicationAuthorized") is False and "publisherAuthorized" not in proof


def receipt_binding(receipt, local, run, parent, central):
    need(receipt.get("schemaVersion") == 1 and receipt.get("requestId") == local["requestId"]
         and receipt.get("sourceKind") == policy.SOURCE_KIND
         and receipt.get("originalSourceRunId") == central["sourceRunId"]
         and receipt.get("originalSourceHeadSha") == central["sourceHeadSha"]
         and receipt.get("originalSourceArtifactId") == central["sourceArtifactId"]
         and receipt.get("originalOuterZipSha256Verified") == central["sourceZipSha256"]
         and receipt.get("localRunId") == run["id"] and receipt.get("localRunAttempt") == 1
         and receipt.get("localProtectedRequestParentMainSha") == parent
         and receipt.get("localProtectedHeadSha") == run["head_sha"]
         and receipt.get("localRequestSha256") == hashlib.sha256(
             contents(run["repository"]["full_name"], ".github/execution-requests/" + local["requestId"] + ".json",
                      run["head_sha"])).hexdigest()
         and receipt.get("candidateAdmissionAuthorized") is False
         and receipt.get("publisherSourceKindAuthorized") is False
         and receipt.get("publicationAuthorized") is False and receipt.get("genuineSchedule") is False
         and receipt.get("originalScanReexecuted") is False, "local original receipt binding/source-kind")


def preflight_child(central, child):
    """Authenticate declarations BEFORE any App CAS, including skipped jobs."""
    req, run = child["request"], child["run"]
    need(set(req) == {"schemaVersion", "kind", "requestId", "mode", "sourceRunId", "sourceHeadSha",
                     "sourceArtifactId", "sourceZipSha256", "centralRequestId", "targetMainSha",
                     "expiresAt", "publicReleaseAuthorized"}
         and req.get("schemaVersion") == 1 and req.get("kind") == "pgextwin-local-prepare"
         and req.get("mode") == "PREPARE" and req.get("publicReleaseAuthorized") is False
         and req.get("centralRequestId") == central["requestId"]
         and req.get("sourceRunId") == central["sourceRunId"]
         and req.get("sourceHeadSha") == central["sourceHeadSha"]
         and req.get("sourceArtifactId") == central["sourceArtifactId"]
         and req.get("sourceZipSha256") == central["sourceZipSha256"]
         and req.get("targetMainSha") == child["parentSha"] == central["targetMainSha"][child["repo"]]
         and utc(central["created_at"]) <= utc(run["created_at"]) < utc(req["expiresAt"]),
         "local original declaration crosses cycle/expiry; no App CAS allowed")
    return child


def collect_child(item, central):
    repo = item["repo"]
    run = original_run(repo, item["runId"], policy.LOCAL_WORKFLOW)
    need(run.get("name") == LOCAL_NAME, "wrong local workflow name")
    parent = central["targetMainSha"][repo]
    path = ".github/execution-requests/" + item["requestId"] + ".json"
    local = strict(contents(repo, path, run["head_sha"]))
    need(local.get("requestId") == item["requestId"], "local original request ID mismatch")
    # Before any durable write, exercise the common declaration/run binding.
    projected = {k: run[k] for k in ("id", "run_attempt", "path", "event", "head_branch", "status", "conclusion", "head_sha", "created_at")}
    projected.update(repository=repo, actor=run["actor"]["login"], protectedMain=True)
    result = {"repo": repo, "request": local, "parentSha": parent, "run": projected,
        "publisherAuthorized": False, "publicationRequested": False,
        "completionEventDelivered": repo != MISSING_REPO}
    result["protectedMerge"] = protected_merge(repo, run["head_sha"], parent, path)
    original_jobs = jobs(repo, run["id"])
    local_job = exact_job(original_jobs, LOCAL_JOB)
    result["originalJobConclusion"] = local_job["conclusion"]
    result["originalJobId"] = local_job["id"]
    result["receipt"] = None
    classification = ANOMALIES.get(repo)
    if classification == "SKIPPED":
        need(run["conclusion"] == "success" and local_job["conclusion"] == "skipped",
             "skip witness did not genuinely skip original job")
        classifier = exact_job(original_jobs, "Classify genuine original skip-only source (NONPUBLISHING)")
        need(classifier["conclusion"] == "success", "original skip classifier failed")
        listing = get(repo, "actions/runs/" + str(run["id"]) + "/artifacts?per_page=100")
        need(listing.get("total_count") == 0 and listing.get("artifacts") == [], "skipped job unexpectedly produced receipt")
        result["originalArtifact"] = None
    else:
        receipt, meta = artifact(repo, run["id"], "issue311-fleet-local-prepare-receipt", LOCAL_ENTRY)
        receipt_binding(receipt, local, run, parent, central)
        original_workflow = contents(repo, policy.LOCAL_WORKFLOW, run["head_sha"]).decode("utf-8")
        original_verification_step(repo, local_job, original_workflow)
        result["originalVerifierWorkflowSha256"] = hashlib.sha256(original_workflow.encode()).hexdigest()
        result.update(receipt=receipt, originalArtifact=meta)
        if classification in ("FAILED", "TIMEOUT"):
            need(run["conclusion"] == "failure" and local_job["conclusion"] == "failure"
                 and receipt.get("result") == "FAILED", "not actual original failure")
            log_raw = get_bytes(repo, "actions/jobs/" + str(local_job["id"]) + "/logs")
            result["originalJobLogSha256"] = hashlib.sha256(log_raw).hexdigest()
            log = log_raw.decode("utf-8", errors="replace")
            if classification == "FAILED":
                step(local_job, FAIL_STEP, "failure")
                need(receipt.get("reason") == "ISSUE311_R06_GENUINE_FAILURE_ONE_SHOT_NONPUBLISHING"
                     and "Process completed with exit code 17" in log, "failure not authenticated exit17")
            else:
                s = step(local_job, TIMEOUT_STEP, "failure")
                duration = (utc(s["completed_at"]) - utc(s["started_at"])).total_seconds()
                need(receipt.get("reason") == "ISSUE311_R06_GENUINE_TIMEOUT_ONE_SHOT_NONPUBLISHING"
                     and TIMEOUT_STEP + "\n        timeout-minutes: 1" in original_workflow
                     and duration >= 60 and ("has timed out" in log.lower() or "exceeded the maximum execution time" in log.lower()),
                     "not genuine original Actions one-minute step timeout")
                result.update(originalTimeoutStepVerified=True, originalTimeoutStepConclusion="failure",
                              originalTimeoutStepTimeoutMinutes=1)
        else:
            need(run["conclusion"] == "success" and local_job["conclusion"] == "success"
                 and receipt.get("result") in policy.NORMAL, "normal source is not successful")
    # Windows postmerge is a separate original run, never inferred from PR CI.
    listed = get(repo, "actions/runs?head_sha=" + run["head_sha"] + "&event=push&per_page=100")
    candidates = [r for r in listed.get("workflow_runs", []) if r.get("path") == ".github/workflows/windows.yml"]
    need(listed.get("total_count", 101) <= 100 and len(candidates) == 1, "Windows postmerge missing/ambiguous")
    windows = original_run(repo, candidates[0]["id"], ".github/workflows/windows.yml", run["head_sha"])
    need(windows["conclusion"] == "success", "Windows postmerge not successful")
    wjobs = jobs(repo, windows["id"])
    for name in [f"windows / PostgreSQL {n} / Windows x64" for n in range(14, 19)] + ["Windows required summary"]:
        need(exact_job(wjobs, name)["conclusion"] == "success", "Windows postmerge required job failed")
    result["windowsPostmergeRunId"] = windows["id"]
    return preflight_child(central, result)


def collect(request, central, *, include_missing):
    items = [x for x in request["children"] if include_missing or x["repo"] != MISSING_REPO]
    with ThreadPoolExecutor(max_workers=4) as executor:
        result = list(executor.map(lambda x: collect_child(x, central), items))
    need(len(result) == (17 if include_missing else 16), "wrong original bundle target count")
    return sorted(result, key=lambda x: x["repo"])


def open_app():
    key = os.environ.get("STATE_WRITER_PRIVATE_KEY")
    need(bool(key), "dedicated build-only state App unavailable")
    token = writer.mint_token(key)
    return token, store.CAS(lambda method, endpoint, body: writer.api(method, endpoint, token, body))


def canonical_hash(value):
    return hashlib.sha256(writer.canonical(value)).hexdigest()


def bounded_terminal(state, children, source_run_id, current_run_id, original_zip_sha, *, now):
    need(state["sourceRun"] == {"id": source_run_id, "attempt": 1}, "state source mismatch")
    need(utc(now) >= utc(state["expiresAt"]), "missing completion deadline not reached")
    outcomes = {x["repo"]: ("NO_UPDATE" if x["repo"] not in ANOMALIES
                and x.get("receipt", {}).get("result") == "NO_UPDATE" else "QUARANTINED") for x in children}
    need(len(children) == len(outcomes) == 17 and set(outcomes) == set(state["targets"]), "partial original child terminal")
    need(all(x.get("receipt", {}).get("result") in policy.NORMAL for x in children if x["repo"] not in ANOMALIES),
         "unknown normal child outcome")
    payload = {"op": "original-17-child-bounded-terminal", "sourceRunId": source_run_id,
               "completionRunId": current_run_id, "originalZipSha256": original_zip_sha,
               "childrenSha256": canonical_hash(children), "targetOutcomes": outcomes, "observedAt": now}
    def transform(s):
        s["targets"] = outcomes
        s["terminal"] = "QUARANTINED"
        s["completionRun"] = {"id": current_run_id, "attempt": 1}
        s["eventTransport"] = "BOUNDED_WATCHDOG"
    return life._apply(state, state["revision"], "r06-original-child-watchdog-terminal", payload, transform)


def complete_policy(central, children, run_id, observed_at):
    copies = copy.deepcopy(children)
    for x in copies:
        if x["repo"] in ANOMALIES:
            x["watchdog"] = {"sourceRunId": x["run"]["id"], "sourceRunAttempt": 1,
                "centralRunId": central["sourceRunId"], "centralRequestId": central["requestId"],
                "localRequestId": x["request"]["requestId"], "status": ANOMALIES[x["repo"]],
                "terminal": "QUARANTINED", "originalGetVerified": True,
                "durableAppCasReadbackVerified": True, "noReexecute": True,
                "publisherAuthorized": False, "watchdogRunId": run_id, "observedAt": observed_at}
    summary = policy.validate_17_original_children(central, copies)
    need(summary["outcomes"] == {x["repo"]: ("QUARANTINED" if x["repo"] in ANOMALIES
                                             else x["receipt"]["result"]) for x in copies},
         "live outcome contradicts strict policy")
    return copies, summary


def denial_proofs(central, children, terminal):
    checks = {}
    def deny(label, fn):
        try:
            fn()
        except (ValueError, KeyError):
            checks[label] = "DENY"
            return
        raise AssertionError("R06_CHILD_BAD_ACCEPT " + label)
    good = next(i for i, x in enumerate(children) if x["repo"] not in ANOMALIES)
    mutated = copy.deepcopy(children)
    mutated[good]["receipt"]["sourceKind"] = "FAKE_SCHEDULE"
    deny("originalSourceKindMutation", lambda: policy.validate_17_original_children(central, mutated))
    replay = copy.deepcopy(children)
    replay[good]["run"]["run_attempt"] = 2
    deny("originalRunAttemptReplay", lambda: policy.validate_17_original_children(central, replay))
    expired = copy.deepcopy(children)
    expired[good]["request"]["expiresAt"] = central["created_at"]
    deny("expiredLocalDeclaration", lambda: policy.validate_17_original_children(central, expired))
    deny("durableTerminalReplayNoSecondPut", lambda: life._apply(terminal, terminal["revision"],
        "r06-replay-after-original-get", {"op": "replay"}, lambda x: x.update(terminal=None)))
    return checks


def source():
    request, digest, head = request_context("source")
    central, central_request = central_original(request)
    children = collect(request, central, include_missing=False)
    # Four original job results are not converted into success; the orafce
    # completion is deliberately omitted from this actual provider ZIP.
    missing_item = next(x for x in request["children"] if x["repo"] == MISSING_REPO)
    missing_run = original_run(MISSING_REPO, missing_item["runId"], policy.LOCAL_WORKFLOW)
    missing_raw = contents(MISSING_REPO, ".github/execution-requests/" + missing_item["requestId"] + ".json", missing_run["head_sha"])
    missing = strict(missing_raw)
    state = life.new(request["requestId"], digest, head, sorted(targets()), missing["expiresAt"], max_events=100)
    token = None
    try:
        token, cas = open_app()
        initial = cas.write(state)
        blob, previous = cas.read(request["requestId"])
        bound = life.bind_source(previous, previous["revision"], "r06-original-child-source",
            run_id=int(os.environ["GITHUB_RUN_ID"]), attempt=1, head_sha=head)
        persisted = cas.write(bound, previous=previous, expected_blob=blob)
        actual_blob, actual = cas.read(request["requestId"])
        need(actual == bound, "source original state readback")
        proof = {"schemaVersion": 1, "requestId": request["requestId"], "requestSha256": digest,
            "sourceRunId": int(os.environ["GITHUB_RUN_ID"]), "sourceRunAttempt": 1, "sourceHeadSha": head,
            "central": central, "children": children, "completionBundleCount": 16,
            "withheldCompletion": missing_item, "controlledFault": "ONE_ORAFCE_COMPLETION_WITHHELD_FROM_ORIGINAL_BUNDLE",
            "stateBlobSha": actual_blob, "stateRevision": actual["revision"], "persistence": [initial, persisted],
            "result": "ORIGINAL_16_COMPLETIONS_AND_ONE_CONTROLLED_OMISSION",
            "publisherAuthorized": False, "publicationAuthorized": False,
            "centralCurrentlyExpired": now_utc() >= utc(central_request["expiresAt"])}
    finally:
        if token:
            writer.revoke_and_prove_401(token)
    Path(SOURCE_FILE).write_bytes(writer.canonical(proof))
    print("R06_CHILD_SOURCE_ORIGINAL 16 DELIVERED ONE_CONTROLLED_MISSING NO_PUBLICATION")


def find_source(head):
    # This watchdog is an independent original push, not a workflow_run child.
    # Bound every lookup and never dispatch or rerun a missing source.
    for attempt in range(36):
        listing = get("pgextwin/build", "actions/runs?head_sha=" + head + "&event=push&per_page=100")
        found = [r for r in listing.get("workflow_runs", []) if r.get("path") == SOURCE_PATH]
        need(listing.get("total_count", 101) <= 100 and len(found) <= 1, "ambiguous original join source")
        if found and found[0].get("status") == "completed":
            r = original_run("pgextwin/build", found[0]["id"], SOURCE_PATH, head)
            need(r.get("conclusion") == "success", "original child source failed; no acceptance")
            return r
        if attempt < 35:
            time.sleep(5)
    raise ValueError("R06_CHILD_LIVE_DENY bounded original source wait exhausted; no rerun")


def observe_join(request, digest, head):
    source_run = find_source(head)
    source_proof, source_meta = artifact("pgextwin/build", source_run["id"], SOURCE_ARTIFACT, SOURCE_FILE)
    central, _ = central_original(request)
    children = collect(request, central, include_missing=True)
    expected = [x for x in children if x["repo"] != MISSING_REPO]
    missing = next(x for x in request["children"] if x["repo"] == MISSING_REPO)
    need(source_proof.get("requestId") == request["requestId"] and source_proof.get("requestSha256") == digest
         and source_proof.get("sourceHeadSha") == head and source_proof.get("sourceRunId") == source_run["id"]
         and source_proof.get("sourceRunAttempt") == 1 and source_proof.get("central") == central
         and source_proof.get("children") == expected and source_proof.get("completionBundleCount") == 16
         and source_proof.get("withheldCompletion") == missing
         and source_proof.get("controlledFault") == "ONE_ORAFCE_COMPLETION_WITHHELD_FROM_ORIGINAL_BUNDLE"
         and source_proof.get("publisherAuthorized") is False and source_proof.get("publicationAuthorized") is False,
         "original source bytes do not match independent child GET/controlled omission")
    missing_child = next(x for x in children if x["repo"] == MISSING_REPO)
    need(now_utc() >= utc(missing_child["request"]["expiresAt"]), "actual missing-completion request not expired")
    return source_run, source_meta, central, children


def watchdog():
    request, digest, head = request_context("watchdog")
    source_run, source_meta, central, children = observe_join(request, digest, head)
    observed_at = stamp()
    token = None
    try:
        token, cas = open_app()
        blob, previous = cas.read(request["requestId"])
        need(previous["requestSha256"] == digest and previous["sourceHeadSha"] == head
             and previous["revision"] == 1 and previous["terminal"] is None,
             "original source checkpoint missing/stale/already terminal")
        terminal = bounded_terminal(previous, children, source_run["id"], int(os.environ["GITHUB_RUN_ID"]),
                                    source_meta["zipSha256"], now=observed_at)
        persisted = cas.write(terminal, previous=previous, expected_blob=blob)
        actual_blob, actual = cas.read(request["requestId"])
        need(actual == terminal and actual_blob == store.blob_hash(store.canonical(terminal)),
             "original durable terminal GET differs")
        verified, summary = complete_policy(central, children, int(os.environ["GITHUB_RUN_ID"]), observed_at)
        checks = denial_proofs(central, verified, actual)
        after_blob, after = cas.read(request["requestId"])
        need(after_blob == actual_blob and after == actual, "durable replay changed state")
        result = {"schemaVersion": 1, "requestId": request["requestId"], "requestSha256": digest,
            "sourceRunId": source_run["id"], "watchdogRunId": int(os.environ["GITHUB_RUN_ID"]), "watchdogRunAttempt": 1,
            "sourceArtifact": source_meta, "sourceHeadSha": head, "central": central, "children": verified,
            "strictPolicySummary": summary, "result": "QUARANTINED", "targetCount": 17,
            "stateBlobSha": actual_blob, "stateRevision": actual["revision"], "targetOutcomes": actual["targets"],
            "observedAt": observed_at, "persistence": persisted, "replay": "DENY_NO_SECOND_PUT",
            "negativeDenials": checks, "publisherAuthorized": False, "publicationAuthorized": False,
            "proofScope": "LIVE_ORIGINAL_17_CHILD_BYTES_AND_BUILD_ONLY_APP_CAS",
            "missingCompletionScope": "CONTROLLED_ORIGINAL_BUNDLE_OMISSION_NOT_NATURAL_GITHUB_OUTAGE"}
    finally:
        if token:
            writer.revoke_and_prove_401(token)
    Path(FINAL_FILE).write_bytes(writer.canonical(result))
    print("R06_CHILD_WATCHDOG_DURABLE QUARANTINED 17 ORIGINAL_GET_VERIFIED REPLAY_DENY NO_SECOND_PUT")


def readback():
    # A distinct job has only read credentials; no App key or Writer token.
    need(not os.environ.get("STATE_WRITER_PRIVATE_KEY"), "readback must have no App key")
    request, digest, head = request_context("readback")
    final, meta = artifact("pgextwin/build", int(os.environ["GITHUB_RUN_ID"]), FINAL_ARTIFACT, FINAL_FILE)
    source_run, source_meta, central, children = observe_join(request, digest, head)
    response = get("pgextwin/build", "contents/" + store.PREFIX + request["requestId"] + ".json?ref=" + store.BRANCH)
    blob, actual = store.unpack(response, request["requestId"])
    need(blob == final.get("stateBlobSha") and actual["revision"] == final.get("stateRevision") == 2
         and actual["requestSha256"] == digest and actual["sourceHeadSha"] == head
         and actual["sourceRun"] == {"id": source_run["id"], "attempt": 1}
         and actual["completionRun"] == {"id": int(os.environ["GITHUB_RUN_ID"]), "attempt": 1}
         and actual["terminal"] == "QUARANTINED" and actual["eventTransport"] == "BOUNDED_WATCHDOG"
         and actual["publisherAuthorized"] is False and actual["writeOutcomeUnknown"] is False,
         "independent original durable state readback mismatch")
    verified, summary = complete_policy(central, children, int(os.environ["GITHUB_RUN_ID"]), final["observedAt"])
    terminal_outcomes = {repo: ("NO_UPDATE" if outcome == "NO_UPDATE" else "QUARANTINED")
                         for repo, outcome in summary["outcomes"].items()}
    need(actual["targets"] == terminal_outcomes == final.get("targetOutcomes")
         and final.get("children") == verified and final.get("central") == central
         and final.get("sourceArtifact") == source_meta and final.get("publisherAuthorized") is False,
         "independent policy/original bytes differ from terminal proof")
    checks = denial_proofs(central, verified, actual)
    check_again = get("pgextwin/build", "contents/" + store.PREFIX + request["requestId"] + ".json?ref=" + store.BRANCH)
    need(store.unpack(check_again, request["requestId"]) == (blob, actual), "readonly replay altered original state")
    out = {"requestId": request["requestId"], "result": "ORIGINAL_GET_VERIFIED", "targetCount": 17,
        "stateBlobSha": blob, "stateRevision": actual["revision"], "targetOutcomes": actual["targets"],
        "terminalArtifact": meta, "negativeDenials": checks, "appKeyAvailable": False,
        "publisherAuthorized": False, "publicationAuthorized": False, "replay": "DENY_NO_PUT"}
    Path(READBACK_FILE).write_bytes(writer.canonical(out))
    print("R06_CHILD_INDEPENDENT_JOB_READBACK 17 ORIGINAL_GET_VERIFIED REPLAY_DENY NO_APP_KEY")


if __name__ == "__main__":
    commands = {"source": source, "watchdog": watchdog, "readback": readback}
    need(len(sys.argv) == 2 and sys.argv[1] in commands, "unknown bounded command")
    commands[sys.argv[1]]()
