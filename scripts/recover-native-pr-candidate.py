#!/usr/bin/env python3
"""Recover an approved native PR CI audit from a genuine schedule (READ-ONLY).

GitHub may create workflow_run(action_required) before a first-time PR workflow
is approved, and rerun attempt 2 may finish without a new completed event.
Never rerun CI or treat an earlier SKIPPED workflow_run as audited.
Only one current bot-owned draft candidate and one matching successful original
native run may be reconciled; shared native identity and App15368 gates remain.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("original_native_validator", SCRIPT_DIR / "verify-native-pr-run.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
Denied = native.Denied


def require(ok, message):
    if not ok:
        raise Denied(message)


def get_json(repo, resource):
    require(native.REPO.fullmatch(repo) is not None, "repository not allowlisted")
    require(resource == "pulls?state=open&per_page=100" or
            re.fullmatch(r"actions/runs\?event=pull_request&head_sha=[a-f0-9]{40}&per_page=100",resource),
            "non-read-only or unexpected discovery path")
    p = subprocess.run(["gh", "api", "--method", "GET", "repos/" + repo + "/" + resource],
                       capture_output=True, text=True, timeout=40, check=False)
    if p.returncode != 0 or len(p.stdout) >= 2_000_000:
        raise native.Unavailable("authenticated discovery GET unavailable")
    return json.loads(p.stdout)


def open_candidate(pulls, repo=None):
    if type(pulls) is not list or len(pulls) >= 100:
        raise native.Unavailable("candidate PR list truncated")
    owned = []
    for pr in pulls:
        if (type(pr) is not dict or pr.get("state") != "open"
                or not ((pr.get("user") or {}).get("login") == native.origin.LEGACY
                        or native.origin.is_app(pr))):
            continue
        # Fleet recovery uses the REST PR's target repository for discovery.
        target = repo if repo is not None else ((pr.get("base") or {}).get("repo") or {}).get("full_name")
        try:
            native.parse_candidate_branch(target, (pr.get("head") or {}).get("ref"))
        except Denied:
            continue
        owned.append(pr)
    require(len(owned) <= 1, "ambiguous bot candidates; no automatic selection")
    return owned[0] if owned else None


def exact_native_run(repo, pr, inventory):
    if not (type(inventory) is dict and type(inventory.get("total_count")) is int
            and type(inventory.get("workflow_runs")) is list
            and len(inventory["workflow_runs"]) == inventory["total_count"] < 100):
        raise native.Unavailable("native CI run inventory truncated or invalid")
    head = (pr.get("head") or {}).get("sha")
    branch = (pr.get("head") or {}).get("ref")
    require(native.SHA.fullmatch(head or "") and (pr.get("base") or {}).get("ref") == "main",
            "candidate head or target invalid")
    # A stale/failed run is never substituted by a different HEAD or dispatch.
    matches = [r for r in inventory["workflow_runs"] if type(r) is dict
               and r.get("name") == "Windows CI/CD"
               and r.get("path") == ".github/workflows/windows.yml"
               and r.get("event") == "pull_request"
               and r.get("head_sha") == head
               and r.get("head_branch") == branch
               and (r.get("head_repository") or {}).get("full_name") == repo]
    require(len(matches) == 1, "missing or ambiguous exact native PR Windows CI run")
    return matches[0]


def successful_run_id(run):
    require(run.get("status") == "completed" and run.get("conclusion") == "success"
            and native.required_check.positive(run.get("id"))
            and native.required_check.positive(run.get("run_attempt")),
            "original native PR run not successfully completed"
            f" ({run.get('status')}/{run.get('conclusion')})")
    return run["id"]


def choose_candidate(repo, pulls, inventory, *, verify_origin=None):
    pr = open_candidate(pulls, repo)
    if pr is None:
        return None
    native.origin.author(repo, pr, verify_origin=verify_origin, denied=Denied)
    return successful_run_id(exact_native_run(repo, pr, inventory))


def reconcile(repo, event_name, ref, github_sha, pulls, inventory, fetch):
    require(event_name == "schedule" and ref == "refs/heads/main"
            and native.REPO.fullmatch(repo or "") is not None
            and native.SHA.fullmatch(github_sha or ""),
            "not genuine trusted main schedule")
    pr = open_candidate(pulls, repo)
    if pr is None:
        return None
    context, _ = authenticate(pr, exact_native_run(repo, pr, inventory), fetch,
                              repo=repo, expected_main=github_sha)
    return context


def authenticate(selected, indexed, fetch, *, repo, expected_main):
    """Use one PR files GET for native verification and caller byte binding."""
    run_id = successful_run_id(indexed)
    run = fetch("actions/runs/" + str(run_id))
    require(type(run) is dict and all(run.get(k) == indexed.get(k) for k in (
        "id", "head_sha", "head_branch", "event", "path", "workflow_id",
        "status", "conclusion", "run_attempt", "check_suite_id")),
        "re-fetched native run changed identity or attempt")
    associations = fetch("commits/" + run["head_sha"] + "/pulls?per_page=100")
    require(type(associations) is list and len(associations) == 1 and type(associations[0]) is dict,
            "missing or ambiguous independent HEAD->PR association")
    pr_number = associations[0].get("number")
    require(native.required_check.positive(pr_number) and pr_number == selected.get("number"),
            "independent HEAD association disagrees with selected candidate PR")
    pr = fetch("pulls/" + str(pr_number))
    files = fetch("pulls/" + str(pr_number) + "/files?per_page=100")
    merge = fetch("git/ref/pull/" + str(pr_number) + "/merge")
    main = fetch("branches/main")
    require(main.get("commit", {}).get("sha") == expected_main,
            "schedule source is no longer exact protected main")
    checks = fetch("commits/" + run["head_sha"] + "/check-runs?per_page=100")
    verified = native.validate(repo, run, pr, files, merge, main, checks,
                               associated_pulls=associations, verify_origin=native.origin.verify)
    # No authorization or signed-release proof comes from reconciliation.
    require(verified.get("candidateRunId") == run_id
            and verified.get("publicationAuthorized") is False
            and verified.get("signedArtifactsVerified") is False,
            "reconciliation produced unsafe downstream authority")
    verified["scheduleRecovery"] = True
    verified["scheduleMainSha"] = expected_main
    return verified, files


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args()
    try:
        repo = os.environ["GITHUB_REPOSITORY"]
        require(bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")),
                "authenticated read-only token unavailable")
        pulls = get_json(repo, "pulls?state=open&per_page=100")
        selected = open_candidate(pulls, repo)
        sha = (selected.get("head") or {}).get("sha") if selected else None
        require(sha is None or native.SHA.fullmatch(sha), "invalid candidate HEAD")
        inventory = (get_json(repo, "actions/runs?event=pull_request&head_sha=" + sha + "&per_page=100")
                     if sha else {"total_count":0,"workflow_runs":[]})
        result = reconcile(repo, os.environ.get("GITHUB_EVENT_NAME"),
                           os.environ.get("GITHUB_REF"), os.environ.get("GITHUB_SHA"),
                           pulls,
                           inventory,
                           lambda resource: native.gh_get(repo, resource))
        if result is None:
            print("NO_OWNED_OPEN_CANDIDATE; no new audit artifact")
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                    f.write("found=false\n")
            return 0
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                for key, source in (("run_id", "candidateRunId"), ("branch", "branch"),
                                    ("head", "candidateHeadSha"), ("merge", "packagingMergeSha"),
                                    ("pr", "candidatePr")):
                    f.write(key + "=" + str(result[source]) + "\n")
                f.write("found=true\n")
        print("GENUINE_SCHEDULE_APPROVED_NATIVE_PR_RECOVERY_READONLY_RUN=" +
              str(result["candidateRunId"]))
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        print("NATIVE_SCHEDULE_RECOVERY_DENIED:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
