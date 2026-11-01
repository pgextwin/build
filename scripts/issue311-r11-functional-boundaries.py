#!/usr/bin/env python3
"""Authenticated, source-pinned R11 schedule job-boundary evidence (read-only).

Inspects the real scheduled workflow YAML, never infers replacement acceptance
from a filename, a job label, or a successful prior workflow run.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request

import yaml

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
PATH = re.compile(r"\.github/workflows/[a-zA-Z0-9_.-]+\.ya?ml\Z")
REPO = re.compile(r"pgextwin/[a-zA-Z0-9_-]+\Z")

class Denied(ValueError):
    pass

def need(condition, reason):
    if not condition:
        raise Denied("R11_FUNCTION_BOUNDARY_DENY " + reason)

class UniqueLoader(yaml.BaseLoader):
    pass

def no_duplicates(loader, node):
    pairs = loader.construct_pairs(node, deep=True)
    result = {}
    for key, value in pairs:
        need(isinstance(key, str) and key not in result, "duplicate/nonstring YAML key")
        result[key] = value
    return result

UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, no_duplicates)

def workflow_boundary(raw, expected_cron):
    need(isinstance(raw, bytes) and 0 < len(raw) < 200000,
         "empty/oversized workflow")
    obj = yaml.load(raw.decode("utf-8"), Loader=UniqueLoader)
    need(isinstance(obj, dict) and isinstance(obj.get("on"), dict),
         "missing workflow event declaration")
    schedules = obj["on"].get("schedule")
    need(isinstance(schedules, list) and len(schedules) == len(expected_cron),
         "schedule count changed")
    need([x.get("cron") for x in schedules if isinstance(x, dict)] == expected_cron,
         "original cron mismatch")
    jobs = obj.get("jobs")
    need(isinstance(jobs, dict) and jobs, "missing executable jobs")
    rows = []
    for job_id, job in jobs.items():
        need(isinstance(job_id, str) and isinstance(job, dict), "malformed job")
        steps = job.get("steps", [])
        need(isinstance(steps, list), "invalid steps")
        step_rows = []
        for step in steps:
            need(isinstance(step, dict), "invalid step")
            step_rows.append({
                "name": step.get("name"), "uses": step.get("uses"),
                "if": step.get("if"),
                "runSha256": hashlib.sha256(step["run"].encode()).hexdigest()
                             if isinstance(step.get("run"), str) else None,
            })
        rows.append({
            "id": job_id, "name": job.get("name"), "if": job.get("if"),
            "needs": job.get("needs"), "uses": job.get("uses"),
            "permissions": job.get("permissions"),
            "concurrency": job.get("concurrency"),
            "steps": step_rows,
            "scheduleEligibility": "UNPROVEN_CONDITIONAL_JOB",
            "replacementAccepted": False,
        })
    need(len(rows) <= 100, "job inventory too large")
    return {"cron": expected_cron, "jobCount": len(rows),
            "jobs": rows, "replacementAccepted": False,
            "migrationAuthorized": False,
            "yamlSha256": hashlib.sha256(raw).hexdigest()}

def expected_heads(original):
    rows = original.get("extensions", []) + original.get("central", [])
    need(len(rows) == 20, "not a 20-repository original")
    heads = {}
    for row in rows:
        repo, sha = row.get("repository"), row.get("mainSha")
        need(isinstance(repo, str) and REPO.fullmatch(repo)
             and isinstance(sha, str) and SHA40.fullmatch(sha)
             and repo not in heads, "unbound or duplicate repo")
        heads[repo] = sha
    return heads

def get_workflow(repo, path, head, token):
    need(REPO.fullmatch(repo) and PATH.fullmatch(path)
         and SHA40.fullmatch(head), "unsafe raw lookup path")
    req = urllib.request.Request(
        "https://api.github.com/repos/" + repo + "/contents/" + path
        + "?ref=" + urllib.parse.quote(head),
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "pgextwin-r11-function-boundary"})
    with urllib.request.urlopen(req, timeout=35) as resp:
        need(resp.status == 200, "GitHub GET status not 200")
        info = json.loads(resp.read(300000))
    need(info.get("type") == "file" and info.get("path") == path
         and info.get("encoding") == "base64"
         and SHA40.fullmatch(str(info.get("sha", ""))),
         "untrusted Github Contents identity")
    raw = base64.b64decode(info["content"], validate=False)
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    need(blob == info["sha"], "original Git blob bytes mismatch")
    return info["sha"], raw

def produce(original, crosswalk, fetch):
    heads = expected_heads(original)
    rows = crosswalk.get("rows")
    need(crosswalk.get("repositoryCount") == 20
         and crosswalk.get("scheduleCount") == 28
         and type(rows) is list and len(rows) == 28
         and crosswalk.get("legacySchedulesRetained") is True
         and crosswalk.get("allRetirementDeniedUntilIndependentProof") is True,
         "unaccepted or incomplete prior crosswalk")
    output = []
    seen = set()
    for row in rows:
        repo, path, sha = row["repository"], row["workflow"], row["gitBlobSha"]
        need(repo in heads and PATH.fullmatch(path) and SHA40.fullmatch(sha)
             and (repo, path) not in seen and row.get("retirementAuthorized") is False
             and row.get("replacementAccepted") is False, "stale or accepted row")
        seen.add((repo, path))
        source_sha, raw = fetch(repo, path, heads[repo])
        need(source_sha == sha, "historical original workflow blob changed")
        boundary = workflow_boundary(raw, row["legacyCron"])
        output.append({"repository": repo, "workflow": path,
                       "protectedMainSha": heads[repo], "gitBlobSha": sha,
                       **boundary})
    need(len(seen) == 28 and len({x["repository"] for x in output}) == 20,
         "incomplete function inventory")
    return {"schemaVersion": 1, "kind": "R11_SOURCE_PINNED_SCHEDULE_JOB_BOUNDARIES",
            "readOnly": True, "retirementAuthorized": False,
            "allReplacementAcceptancePending": True,
            "scheduleWorkflowCount": 28, "repositoryCount": 20, "rows": output}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True)
    parser.add_argument("--crosswalk", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    need(os.getenv("GH_TOKEN") and os.getenv("GITHUB_REPOSITORY") == "pgextwin/build",
         "original authenticated build-only runner required")
    original = json.loads(Path(args.original).read_text("utf-8"))
    crosswalk = json.loads(Path(args.crosswalk).read_text("utf-8"))
    result = produce(original, crosswalk,
                     lambda repo, path, head: get_workflow(repo, path, head, os.environ["GH_TOKEN"]))
    data = (json.dumps(result, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()
    if args.verify:
        need(Path(args.output).read_bytes() == data, "independent original job-boundary mismatch")
        print("R11_INDEPENDENT_SOURCE_PINNED_JOB_BOUNDARIES_MATCH", hashlib.sha256(data).hexdigest())
    else:
        Path(args.output).write_bytes(data)
        print("R11_SCHEDULE_FUNCTION_BOUNDARIES_PENDING", len(result["rows"]), hashlib.sha256(data).hexdigest())

if __name__ == "__main__":
    main()
