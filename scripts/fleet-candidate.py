#!/usr/bin/env python3
"""Connect the protected fleet scan to the existing candidate planner and proposer."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
PILOTS = ("pgextwin/pg_ivm",)
APP_SLUG = "pgextwin-fleet-candidate"
MANIFEST = "config/extension.json"
WATCH = "config/update-watch.json"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


receipt = load_script("verify-scheduled-fleet-candidate")
candidate = load_script("candidate-update")
fleet = load_script("fleet-control")
local_auth = load_script("local-auth-candidate")
issuance = load_script("local-auth-issuance")


def execution_mode():
    mode = candidate.read(ROOT / local_auth.AUTHORITY)["mode"]
    receipt.need(mode in ("DENY", "ENFORCE"), "unsupported local authorization mode")
    return mode


def repositories(context):
    if execution_mode() == "DENY":
        return PILOTS
    return sorted(repository for repository, entry in fleet.validate(context[3]).items()
                  if entry["candidateEnabled"] is True)


def same_run():
    env = os.environ
    receipt.need(env.get("GITHUB_REPOSITORY") == receipt.BUILD
                 and env.get("GITHUB_REF") == "refs/heads/main"
                 and env.get("GITHUB_EVENT_NAME") == "schedule"
                 and env.get("GITHUB_RUN_ATTEMPT") == "1"
                 and env.get("GITHUB_WORKFLOW_REF") ==
                 receipt.BUILD + "/" + receipt.WATCH_PATH + "@refs/heads/main",
                 "direct candidate requires the original central schedule on main")
    sha = env["GITHUB_SHA"]
    run_id = int(env["GITHUB_RUN_ID"])
    token = env["PGEXTWIN_SCAN_READ_TOKEN"]
    receipt.need(token and run_id > 0 and receipt.SHA.fullmatch(sha)
                 and candidate.execute("git", "-C", str(ROOT), "rev-parse", "HEAD") == sha,
                 "central checkout or run identity unavailable")
    endpoint = receipt.HOST + receipt.BUILD
    run_url = endpoint + "/actions/runs/" + str(run_id)
    run = receipt.api(run_url, token)
    branch = receipt.api(endpoint + "/branches/main", token)
    receipt.need(run.get("id") == run_id and run.get("head_sha") == sha
                 and branch.get("protected") is True and branch["commit"]["sha"] == sha,
                 "central run or protected main changed")
    inventory = receipt.api(run_url + "/attempts/1/jobs?per_page=100", token)
    jobs = inventory["jobs"]
    scans = [job for job in jobs if job.get("name") == "readonly-fleet"]
    receipt.need(inventory.get("total_count") == len(jobs) and len(scans) == 1,
                 "central scan job is missing or ambiguous")
    receipt.verify_replay_source_blobs(sha, sha, token)
    registry = receipt.fetch_live_manifest(sha, token)
    return run, branch, scans[0], registry


def target(report, context, repository):
    receipt.need(repository in repositories(context), "repository is outside the direct candidate rollout")
    run, branch, scan, registry = context
    rows = [row for row in report["extensions"] if row.get("repository") == repository]
    receipt.need(len(rows) == 1, "unique target scan row required")
    row = rows[0]
    current = receipt.api(receipt.HOST + repository + "/branches/main",
                          os.environ["PGEXTWIN_SCAN_READ_TOKEN"])
    sha = branch["commit"]["sha"]
    mode = receipt.validate(report, run, branch, current, repository, row["mainSha"],
                            sha, datetime.now(timezone.utc), registry=registry,
                            workflow_sha=sha, scan_job=scan)
    return row, mode


def select(report, context):
    matrix = []
    lines = []
    for repository in repositories(context):
        row, mode = target(report, context, repository)
        decision = "update detected" if mode == "candidate" else "no update"
        lines.append(f"- `{repository}` at `{row['mainSha']}` — {decision}")
        if mode == "candidate":
            matrix.append({"repository": repository, "sha": row["mainSha"],
                           "extension": repository.split("/")[1]})
    return matrix, lines


def checked_plan(report, context, repository, fetch=candidate.api):
    row, mode = target(report, context, repository)
    receipt.need(mode == "candidate", "proposals require a detected update in this run")
    receipt.need(candidate.execute("git", "rev-parse", "HEAD") == row["mainSha"]
                 and candidate.execute("git", "remote", "get-url", "origin") ==
                 "https://github.com/" + repository
                 and not candidate.execute("git", "status", "--porcelain", "--", MANIFEST, WATCH),
                 "target checkout differs from scanned protected main")
    extension = candidate.read(MANIFEST)
    watch = candidate.load_watch(extension, WATCH)
    policy = candidate.publication_policy.load_candidate_policy(ROOT)
    allowed, mode = fleet.decide(context[3], repository, extension, watch, "candidate", policy)
    if not allowed:
        return candidate.suppressed(extension, mode)
    record = candidate.plan(extension, watch, policy, fetch=fetch,
                            lifecycle=candidate.read(ROOT / "metadata/postgresql.json"))
    observed = {(item.get("postgresqlMajor"), item["current"]["ref"],
                 str(item["current"]["version"]), item["candidate"]["ref"],
                 str(item["candidate"]["version"])) for item in row["updates"]}
    receipt.need(all((item["major"], item["oldRef"], item["oldVersion"],
                      item["ref"], item["version"]) in observed and
                     not item["pinOnly"] and not item["initialOnly"]
                     for item in record["updates"]),
                 "upstream update changed since the central scan")
    return record


def propose(report, context, repository, record, writer, fetch=candidate.api):
    receipt.need(record.get("status") == "candidate", "a candidate decision is required")
    fresh = checked_plan(report, context, repository, fetch=fetch)
    receipt.need({k: v for k, v in fresh.items() if k != "detectedAt"} ==
                 {k: v for k, v in record.items() if k != "detectedAt"},
                 "candidate plan changed before proposal")
    _, branch, _, _ = context
    row, _ = target(report, context, repository)
    if execution_mode() == "ENFORCE":
        repository_sha = row["mainSha"]
        run_id = int(os.environ["GITHUB_RUN_ID"])
        # Refuse stale policy and unsupported sources before any issuer dispatch.
        prepared = local_auth.prepare(repository, repository_sha, run_id, fetch=fetch)
        receipt.need(local_auth.verifier._parse_json(
            prepared[3].decode("utf-8"), local_auth.verifier.MAX_INPUTS_BYTES)["plan"] ==
            {k: v for k, v in fresh.items() if k != "detectedAt"},
            "candidate plan differs from the independently verified sources")
        ticket, inputs, receipt_policy = issuance.receive(
            repository, repository_sha, run_id, local_auth.verifier)
        current = local_auth.prepare(repository, repository_sha, run_id, fetch=fetch)
        receipt.need(current == prepared, "candidate authority or source inputs changed during issuance")
        local_auth.authorize(ticket, inputs, receipt_policy, current,
                             now=datetime.now(timezone.utc), api=issuance.get)
    token = os.environ["PGEXTWIN_SCAN_READ_TOKEN"]
    receipt.need(receipt.api(receipt.HOST + receipt.BUILD + "/branches/main", token) == branch,
                 "central protected main changed before proposal")
    candidate.propose_candidate(record, MANIFEST, repository, WATCH, writer=writer, fetch=fetch)


def app_writer():
    env = os.environ
    receipt.need(env.get("PGEXTWIN_WRITER_SLUG") == APP_SLUG
                 and env.get("GH_TOKEN") and env["GH_TOKEN"] != env["PGEXTWIN_SCAN_READ_TOKEN"],
                 "dedicated candidate App token required")
    login = APP_SLUG + "[bot]"
    account = candidate.github_get_json("https://api.github.com/users/" + quote(login, safe=""),
                                        env["PGEXTWIN_SCAN_READ_TOKEN"])
    receipt.need(account.get("login") == login and account.get("type") == "Bot"
                 and type(account.get("id")) is int and account["id"] > 0,
                 "dedicated candidate App bot identity unavailable")
    return login, account["id"]


def emit(path_var, line):
    with open(os.environ[path_var], "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def read_api(url):
    return candidate.github_get_json(url, os.environ["PGEXTWIN_SCAN_READ_TOKEN"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("select", "plan", "propose"))
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--repository")
    parser.add_argument("--record", type=Path)
    args = parser.parse_args()
    if args.action != "select" and (not args.repository or args.record is None):
        parser.error("plan and propose require an enabled repository and decision file")
    try:
        receipt.need(args.snapshot.is_file() and not args.snapshot.is_symlink()
                     and 0 < args.snapshot.stat().st_size <= 262144,
                     "missing or oversized same-run scan")
        report = receipt.strict_json(args.snapshot.read_text(encoding="utf-8"))
        context = same_run()
        if args.action == "select":
            matrix, lines = select(report, context)
            summary = "## Scheduled candidate selection\n\n" + "\n".join(lines)
            emit("GITHUB_STEP_SUMMARY", summary)
            print(summary)
            emit("GITHUB_OUTPUT", "matrix=" + json.dumps({"include": matrix}))
            emit("GITHUB_OUTPUT", "has_updates=" + str(bool(matrix)).lower())
        elif args.action == "plan":
            record = checked_plan(report, context, args.repository, fetch=read_api)
            args.record.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            emit("GITHUB_OUTPUT", "candidate=" + str(record["status"] == "candidate").lower())
            emit("GITHUB_OUTPUT", "authorization_mode=" + execution_mode())
            emit("GITHUB_STEP_SUMMARY", f"`{args.repository}` candidate decision: {record['status']}")
        else:
            propose(report, context, args.repository, candidate.read(args.record), app_writer(), fetch=read_api)
        return 0
    except (receipt.Denied, candidate.WatchError, OSError, ValueError, KeyError, TypeError,
            local_auth.subprocess.SubprocessError) as exc:
        print("Central candidate failed closed: " + str(exc), file=sys.stderr)
        emit("GITHUB_STEP_SUMMARY", "Central candidate deferred. See the failed step for details.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
