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

import candidate_branch
import fleet_candidate_origin as origin

ROOT = Path(__file__).resolve().parents[1]
PILOTS = ("pgextwin/pg_ivm",)
APP_SLUG = origin.APP["slug"]
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
local_auth_central = load_script("local_auth_central")


def execution_mode(*, central_policy=None):
    if central_policy is not None:
        return central_policy.get("mode")
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
    receipt.need(report.get("indeterminate") == 0, "indeterminate fleet scan cannot select candidates")
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


def checked_plan(report, context, repository, fetch=candidate.api, *,
                 target_repository=None, manifest_path=MANIFEST, watch_path=WATCH):
    row, mode = target(report, context, repository)
    receipt.need(mode == "candidate", "proposals require a detected update in this run")
    effective_repo = target_repository or repository
    base_sha = context[1]["commit"]["sha"] if effective_repo == receipt.BUILD else row["mainSha"]
    receipt.need(candidate.execute("git", "rev-parse", "HEAD") == base_sha
                 and candidate.execute("git", "remote", "get-url", "origin") ==
                 "https://github.com/" + effective_repo
                 and not candidate.execute("git", "status", "--porcelain", "--", manifest_path, watch_path),
                 "target checkout differs from scanned protected main")
    extension = candidate.read(manifest_path)
    branch_style = candidate_branch.branch_style_for_repository(effective_repo, extension["name"])
    watch = candidate.load_watch(extension, watch_path)
    policy = candidate.publication_policy.load_candidate_policy(ROOT)
    allowed, mode = fleet.decide(context[3], repository, extension, watch, "candidate", policy)
    if not allowed:
        return candidate.suppressed(extension, mode)
    record = candidate.plan(extension, watch, policy, fetch=fetch,
                            lifecycle=candidate.read(ROOT / "metadata/postgresql.json"),
                            branch_style=branch_style)
    observed = {(item.get("postgresqlMajor"), item["current"]["ref"],
                 str(item["current"]["version"]), item["candidate"]["ref"],
                 str(item["candidate"]["version"])) for item in row["updates"]}
    receipt.need(all((item["major"], item["oldRef"], item["oldVersion"],
                      item["ref"], item["version"]) in observed and
                     not item["pinOnly"] and not item["initialOnly"]
                     for item in record["updates"]),
                 "upstream update changed since the central scan")
    return record


def propose(report, context, repository, record, writer, fetch=candidate.api, *,
            origin_path, decision_id, target_repository=None, manifest_path=MANIFEST, watch_path=WATCH,
            auth_evidence_path=None):
    effective_repo = target_repository or repository
    central = effective_repo == receipt.BUILD
    if central:
        authority_policy = local_auth_central.load_policy(ROOT)
        local_auth_central.need(type(authority_policy) is dict, "INVALID_POLICY")
        local_auth_central.require_enforce_mode(execution_mode(central_policy=authority_policy))
    receipt.need(record.get("status") == "candidate", "a candidate decision is required")
    manifest_path = str(manifest_path)
    watch_path = str(watch_path)
    prepare_scope, authorize_scope = {}, {}
    if central:
        registered = local_auth_central.registered_extensions(fleet.validate(context[3]))
        extension = repository.partition("/")[2]
        planned_changes = [{"filename": manifest_path, "status": "modified"}]
        local_auth_central.enforce_central_candidate(
            policy=authority_policy, repository=effective_repo, extension=extension,
            registered_extensions=registered, branch=record.get("branch"),
            expected_candidate_id=record.get("candidateId"), changes=planned_changes)
    fresh = checked_plan(report, context, repository, fetch=fetch, target_repository=target_repository,
                         manifest_path=manifest_path, watch_path=watch_path)
    receipt.need({k: v for k, v in fresh.items() if k != "detectedAt"} ==
                 {k: v for k, v in record.items() if k != "detectedAt"},
                 "candidate plan changed before proposal")
    if central:
        prepare_scope = {"extension": fresh["extension"], "registered_extensions": registered,
                         "changes": planned_changes}
        authorize_scope = {"changes": planned_changes}
    _, branch, _, _ = context
    row, _ = target(report, context, repository)
    base_sha = branch["commit"]["sha"] if central else row["mainSha"]
    if central or execution_mode() == "ENFORCE":
        run_id = int(os.environ["GITHUB_RUN_ID"])
        # Refuse stale policy and unsupported sources before any issuer dispatch.
        prepared = local_auth.prepare(effective_repo, base_sha, run_id, fetch=fetch, **prepare_scope)
        receipt.need(local_auth.verifier._parse_json(
            prepared[3].decode("utf-8"), local_auth.verifier.MAX_INPUTS_BYTES)["plan"] ==
            {k: v for k, v in fresh.items() if k != "detectedAt"},
            "candidate plan differs from the independently verified sources")
        ticket, inputs, receipt_policy = issuance.receive(
            effective_repo, base_sha, run_id, local_auth.verifier)
        current = local_auth.prepare(effective_repo, base_sha, run_id, fetch=fetch, **prepare_scope)
        receipt.need(current == prepared, "candidate authority or source inputs changed during issuance")
        auth_evidence = local_auth.authorize(ticket, inputs, receipt_policy, current,
                                            now=datetime.now(timezone.utc), api=issuance.get, **authorize_scope)
        if auth_evidence_path is not None:
            evidence = auth_evidence["centralEvidence"] if central else auth_evidence
            Path(auth_evidence_path).write_bytes(local_auth.verifier.canonical_json(evidence))
    token = os.environ["PGEXTWIN_SCAN_READ_TOKEN"]
    receipt.need(receipt.api(receipt.HOST + receipt.BUILD + "/branches/main", token) == branch,
                 "central protected main changed before proposal")
    repo = fetch(receipt.HOST + effective_repo)
    receipt.need(repo.get("full_name") == effective_repo and origin.positive(repo.get("id"))
                 and origin.positive(decision_id), "target repository or decision artifact ID missing")
    origin_base = {
        "schemaVersion": 1, "repository": effective_repo, "repositoryId": repo["id"],
        "appId": origin.APP["appId"], "botUserId": origin.APP["botUserId"],
        "runId": context[0]["id"], "runAttempt": context[0]["run_attempt"],
        "runSha": context[0]["head_sha"], "decisionArtifactId": decision_id,
        "baseSha": base_sha,
    }
    origin_holder = {}

    def origin_body(ref, effective_record, predecessor):
        origin_record = {**origin_base, "decision": effective_record}
        if predecessor is not None:
            predecessor_id, predecessor_number = predecessor
            origin_record["regeneration"] = {
                "predecessorCandidateId": predecessor_id,
                "predecessorPrNumber": predecessor_number,
            }
        origin_record["headSha"] = candidate.execute("git", "rev-parse", ref)
        origin_record["manifestBlob"] = candidate.execute("git", "rev-parse", ref + ":" + manifest_path)
        origin_holder["record"] = origin_record
        return origin.marker(origin_record)

    def on_created(url, effective_record, predecessor):
        prefix = "https://github.com/" + effective_repo + "/pull/"
        number = url.removeprefix(prefix)
        receipt.need(url.startswith(prefix) and number.isascii() and number.isdecimal()
                     and int(number) > 0, "created candidate PR URL is invalid")
        origin_record = origin_holder.get("record")
        receipt.need(type(origin_record) is dict and origin_record.get("decision") == effective_record
                     and ((predecessor is None and "regeneration" not in origin_record) or
                          (predecessor is not None and origin_record.get("regeneration") == {
                              "predecessorCandidateId": predecessor[0],
                              "predecessorPrNumber": predecessor[1]})),
                     "created candidate origin does not match its effective decision")
        pr = fetch(receipt.HOST + effective_repo + "/pulls/" + number)
        origin.validate_pr(effective_repo, pr, origin_record)
        receipt.need(pr["number"] == int(number) and pr.get("state") == "open"
                     and pr.get("merged") is False and pr["base"].get("sha") == base_sha
                     and origin.parse_marker(pr["body"]) == origin_record,
                     "created candidate PR differs from the exact protected proposal")
        origin_path.write_bytes(origin.proof_bytes(origin_record, pr["number"]))
        emit("GITHUB_OUTPUT", "origin_artifact=" + origin.artifact_name(effective_repo, origin_record, pr["number"]))

    candidate.propose_candidate(record, manifest_path, effective_repo, watch_path, writer=writer, fetch=fetch,
                                origin_body=origin_body, on_created=on_created)


def app_writer():
    env = os.environ
    receipt.need(env.get("PGEXTWIN_WRITER_SLUG") == APP_SLUG
                 and env.get("GH_TOKEN") and env["GH_TOKEN"] != env["PGEXTWIN_SCAN_READ_TOKEN"],
                 "dedicated candidate App token required")
    login = APP_SLUG + "[bot]"
    account = candidate.github_get_json("https://api.github.com/users/" + quote(login, safe=""),
                                        env["PGEXTWIN_SCAN_READ_TOKEN"])
    origin.check_app(origin.github)
    receipt.need(origin.app_identity(account),
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
    parser.add_argument("--decision-id", type=int)
    parser.add_argument("--origin", type=Path)
    parser.add_argument("--auth-evidence", type=Path)
    args = parser.parse_args()
    if args.action != "select" and (not args.repository or args.record is None):
        parser.error("plan and propose require an enabled repository and decision file")
    if args.action == "propose" and (args.origin is None or not origin.positive(args.decision_id)):
        parser.error("propose requires the exact decision artifact ID and an origin output file")
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
            propose(report, context, args.repository, candidate.read(args.record), app_writer(), fetch=read_api,
                    origin_path=args.origin, decision_id=args.decision_id, auth_evidence_path=args.auth_evidence)
        return 0
    except (candidate.WatchError, OSError, ValueError, KeyError, TypeError,
            local_auth.subprocess.SubprocessError) as exc:
        print("Central candidate failed closed: " + str(exc), file=sys.stderr)
        emit("GITHUB_STEP_SUMMARY", "Central candidate deferred. See the failed step for details.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
