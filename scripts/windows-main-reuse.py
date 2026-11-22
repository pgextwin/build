#!/usr/bin/env python3
"""Record resolved Windows CI inputs and decide whether a main build can be skipped."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.request import Request, urlopen


RECORD_PREFIX = "PGEXTWIN_INPUT_RECORD="
RECORD_LINE = re.compile(
    r"(?:\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z )?"
    + RECORD_PREFIX + r"(.*)"
)
WORKFLOW_PATH = "pgextwin/build/.github/workflows/build-extension.yml"
MATRIX_JOB_NAME = "Resolve extension and PostgreSQL matrix"
SUMMARY_NAME = "Windows required summary"
SHA = re.compile(r"[0-9a-f]{40}")
ENV_FIELDS = {
    "repository": "GITHUB_REPOSITORY",
    "checkout_commit": "CHECKOUT_COMMIT",
    "checkout_tree": "CHECKOUT_TREE",
    "pr_head_sha": "PR_HEAD_SHA",
    "build_sha": "BUILD_SHA",
    "extension_name": "EXTENSION_NAME",
    "upstream_repository": "UPSTREAM_REPOSITORY",
    "upstream_mode": "UPSTREAM_MODE",
    "upstream_ref": "UPSTREAM_REF",
    "upstream_version": "UPSTREAM_VERSION",
    "verify_upstream_license": "VERIFY_UPSTREAM_LICENSE",
    "license_files": "LICENSE_FILES",
}
CHECKOUT_FIELDS = {"checkout_commit", "checkout_tree", "pr_head_sha"}
RECORD_FIELDS = {"schemaVersion", "matrix", *ENV_FIELDS}


class NoReuse(Exception):
    """The available evidence does not support reuse."""


def get(path):
    """Read a GitHub REST response, following the signed job-log redirect."""
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    request = Request(api_url + path, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    # The GitHub token belongs on the API request only, including for log downloads.
    request.add_unredirected_header("Authorization", f"Bearer {os.environ['GITHUB_TOKEN']}")
    with urlopen(request, timeout=10) as response:
        if path.endswith("/logs"):
            return response.read().decode("utf-8")
        return json.load(response)


def record_inputs(env):
    values = {key: env[name] for key, name in ENV_FIELDS.items() if key != "pr_head_sha"}
    return dict(values, schemaVersion=1, pr_head_sha=env.get("PR_HEAD_SHA", ""),
                matrix=json.loads(env["MATRIX"]))


def encode_record(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)


def record_from_log(log):
    matches = [match[1] for line in log.splitlines()
               if (match := RECORD_LINE.fullmatch(line))]
    if len(matches) != 1:
        raise NoReuse("input_record_not_unique")
    return json.loads(matches[0])


def same_inputs(current, source):
    return (
        all(RECORD_FIELDS <= record.keys() and type(record["schemaVersion"]) is int
            and record["schemaVersion"] == 1 for record in (current, source))
        and encode_record({key: value for key, value in current.items() if key not in CHECKOUT_FIELDS})
        == encode_record({key: value for key, value in source.items() if key not in CHECKOUT_FIELDS})
    )


def pinned_matrix(matrix):
    entries = matrix["include"]
    return (type(entries) is list and bool(entries)
            and all(isinstance(entry.get("upstreamCommit"), str)
                    and entry["upstreamCommit"].strip() for entry in entries))


def successful(item):
    return item["status"] == "completed" and item["conclusion"] == "success"


def positive_id(value):
    if type(value) is not int or value < 1:
        raise NoReuse("invalid_identifier")
    return value


def github_sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise NoReuse("invalid_sha")
    return value


def collection(get, path, key):
    """Read all pages, abandoning evidence if the response is incomplete."""
    separator = "&" if "?" in path else "?"
    path += separator + "per_page=100"
    payload = get(path)
    total = payload["total_count"]
    items = payload[key]
    # The workflow-run search has a 1,000-result limit.
    if type(total) is not int or not len(items) <= total < 1000:
        raise NoReuse("incomplete_api_results")
    for page in range(2, (total + 99) // 100 + 1):
        payload = get(f"{path}&page={page}")
        if payload["total_count"] != total:
            raise NoReuse("incomplete_api_results")
        items.extend(payload[key])
    if len(items) != total or len({item["id"] for item in items}) != total:
        raise NoReuse("incomplete_api_results")
    return items


def find_source(*, repository, push_sha, current, current_tree, current_build_sha, get):
    repo = f"/repos/{repository}"
    github_sha(push_sha)
    github_sha(current_tree)
    github_sha(current_build_sha)
    if (current["repository"] != repository or current["checkout_commit"] != push_sha
            or current["checkout_tree"] != current_tree or current["build_sha"] != current_build_sha):
        raise NoReuse("current_record_mismatch")
    if not pinned_matrix(current["matrix"]):
        raise NoReuse("upstream_not_pinned")

    pulls = get(f"{repo}/commits/{push_sha}/pulls?per_page=100")
    merged = [pr for pr in pulls if pr["merged_at"] and pr["base"]["ref"] == "main"]
    if len(pulls) >= 100 or len(merged) != 1 or merged[0]["merge_commit_sha"] != push_sha:
        raise NoReuse("merged_pr_not_unique")
    pr = merged[0]
    pr_number = positive_id(pr["number"])
    pr_head = github_sha(pr["head"]["sha"])

    # Bind the PR Run by its head SHA (the design's key). The REST run's
    # pull_requests array is often empty, so it cannot carry the binding.
    runs = collection(get, f"{repo}/actions/workflows/windows.yml/runs?event=pull_request"
                           f"&head_sha={pr_head}", "workflow_runs")
    matching = [run for run in runs
                if run["head_sha"] == pr_head
                and (run["head_repository"] or {}).get("full_name") == repository]
    if len(matching) != 1:
        raise NoReuse("pr_run_not_unique")
    run = matching[0]
    if run["event"] != "pull_request" or not successful(run):
        raise NoReuse("pr_run_not_successful")
    run_id = positive_id(run["id"])
    attempt = positive_id(run["run_attempt"])
    suite_id = positive_id(run["check_suite_id"])
    workflow_shas = [workflow["sha"] for workflow in run["referenced_workflows"]
                     if workflow["path"].partition("@")[0] == WORKFLOW_PATH]
    if workflow_shas != [current_build_sha]:
        raise NoReuse("referenced_workflow_mismatch")

    checks = collection(get, f"{repo}/check-suites/{suite_id}/check-runs", "check_runs")
    if not any(check["name"] == SUMMARY_NAME and successful(check) for check in checks):
        raise NoReuse("required_summary_missing")

    jobs = collection(get, f"{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
    matrix_jobs = [job for job in jobs if MATRIX_JOB_NAME in job["name"]]
    if len(matrix_jobs) != 1 or not successful(matrix_jobs[0]):
        raise NoReuse("matrix_job_not_unique_or_successful")
    job_id = positive_id(matrix_jobs[0]["id"])
    source = record_from_log(get(f"{repo}/actions/jobs/{job_id}/logs"))
    if source["pr_head_sha"] != pr_head or source["checkout_tree"] != current_tree:
        raise NoReuse("source_checkout_mismatch")

    # The REST run's head can be the PR head even when checkout used a synthetic
    # merge commit. Verify the actual checkout and any distinct REST head.
    commits = dict.fromkeys((pr_head, github_sha(run["head_sha"]),
                             github_sha(source["checkout_commit"])))
    if any(get(f"{repo}/git/commits/{sha}")["tree"]["sha"] != current_tree for sha in commits):
        raise NoReuse("tree_mismatch")
    if not same_inputs(current, source):
        raise NoReuse("resolved_inputs_differ")
    return {
        "reuse_applied": "true",
        "reuse_reason": "matched",
        "reuse_source_pr": pr_number,
        "reuse_source_run_id": run_id,
        "reuse_source_attempt": attempt,
        "reuse_source_build_sha": current_build_sha,
    }


def fallback(reason):
    return {
        "reuse_applied": "false",
        "reuse_reason": reason,
        "reuse_source_pr": "",
        "reuse_source_run_id": "",
        "reuse_source_attempt": "",
        "reuse_source_build_sha": "",
    }


def determine(*, enabled_list, current_record, current_tree, current_build_sha, env=None, get=get):
    env = os.environ if env is None else env
    try:
        enabled = json.loads(Path(enabled_list).read_text(encoding="utf-8"))["enabledRepositories"]
        if type(enabled) is not list or any(type(repo) is not str for repo in enabled):
            raise NoReuse("invalid_enabled_list")
        repository = env["GITHUB_REPOSITORY"]
        if repository not in enabled:
            return fallback("not_enabled")
        return find_source(repository=repository, push_sha=env["GITHUB_SHA"],
                           current=json.loads(current_record), current_tree=current_tree,
                           current_build_sha=current_build_sha, get=get)
    except NoReuse as exc:
        return fallback(str(exc))
    except Exception:
        # API, JSON and I/O errors all leave the normal Windows matrix eligible.
        return fallback("evidence_unavailable")


def write_result(result):
    if result["reuse_applied"] == "true":
        repo = os.environ["GITHUB_REPOSITORY"]
        pr = result["reuse_source_pr"]
        run_id = result["reuse_source_run_id"]
        attempt = result["reuse_source_attempt"]
        build_sha = result["reuse_source_build_sha"]
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write(
                "### Windows CI reused from a successful PR\n\n"
                f"- [PR #{pr}](https://github.com/{repo}/pull/{pr})\n"
                f"- [Run {run_id}, attempt {attempt}]"
                f"(https://github.com/{repo}/actions/runs/{run_id}/attempts/{attempt})\n"
                f"- Build SHA `{build_sha}`\n"
            )
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("".join(f"{name}={value}\n" for name, value in result.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    modes.add_parser("record")
    determine_parser = modes.add_parser("determine")
    for flag in ("enabled-list", "current-record", "current-tree", "current-build-sha"):
        determine_parser.add_argument(f"--{flag}", required=True)
    try:
        args = parser.parse_args()
    except SystemExit as exc:
        if sys.argv[1:2] != ["determine"] or exc.code == 0:
            raise
        result = fallback("invalid_arguments")
    else:
        if args.mode == "record":
            print(RECORD_PREFIX + encode_record(record_inputs(os.environ)))
            return
        result = determine(enabled_list=args.enabled_list, current_record=args.current_record,
                           current_tree=args.current_tree, current_build_sha=args.current_build_sha)
    try:
        write_result(result)
    except (OSError, KeyError):
        try:
            write_result(fallback("result_write_failed"))
        except (OSError, KeyError):
            print("Windows CI reuse output unavailable; running the normal matrix.", file=sys.stderr)


if __name__ == "__main__":
    main()
