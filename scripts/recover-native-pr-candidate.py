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
CANDIDATE = re.compile(r"^auto-candidate/[0-9a-f]{20}$")


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
    require(p.returncode == 0 and len(p.stdout) < 2_000_000, "authenticated discovery GET unavailable")
    return json.loads(p.stdout)


def choose_candidate(repo, pulls, inventory):
    require(isinstance(pulls, list) and len(pulls) < 100, "candidate PR list truncated")
    require(isinstance(inventory, dict)
            and type(inventory.get("total_count")) is int
            and inventory["total_count"] < 100
            and isinstance(inventory.get("workflow_runs"), list),
            "native CI run inventory truncated or invalid")
    owned = [p for p in pulls if type(p) is dict
             and p.get("state") == "open"
             and (p.get("user") or {}).get("login") == "github-actions[bot]"
             and CANDIDATE.fullmatch((p.get("head") or {}).get("ref", ""))]
    require(len(owned) <= 1, "ambiguous bot candidates; no automatic selection")
    if not owned:
        return None
    pr = owned[0]
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
    r = matches[0]
    require(r.get("status") == "completed" and r.get("conclusion") == "success"
            and type(r.get("id")) is int and r["id"] > 0
            and type(r.get("run_attempt")) is int and r["run_attempt"] >= 1,
            "original native PR run not successfully completed")
    return r["id"]


def reconcile(repo, event_name, ref, github_sha, pulls, inventory, fetch):
    require(event_name == "schedule" and ref == "refs/heads/main"
            and native.REPO.fullmatch(repo or "") is not None
            and native.SHA.fullmatch(github_sha or ""),
            "not genuine trusted main schedule")
    run_id = choose_candidate(repo, pulls, inventory)
    if run_id is None:
        return None
    run = fetch("actions/runs/" + str(run_id))
    require(run.get("id") == run_id, "re-fetched native run changed identity")
    associations = fetch("commits/" + run["head_sha"] + "/pulls?per_page=100")
    require(type(associations) is list and len(associations) == 1,
            "missing or ambiguous independent HEAD->PR association")
    pr_number = associations[0]["number"]
    pr = fetch("pulls/" + str(pr_number))
    files = fetch("pulls/" + str(pr_number) + "/files?per_page=100")
    merge = fetch("git/ref/pull/" + str(pr_number) + "/merge")
    main = fetch("branches/main")
    require(main.get("commit", {}).get("sha") == github_sha,
            "schedule source is no longer exact protected main")
    checks = fetch("commits/" + run["head_sha"] + "/check-runs?per_page=100")
    verified = native.validate(repo, run, pr, files, merge, main, checks,
                               associated_pulls=associations)
    # No authorization or signed-release proof comes from reconciliation.
    require(verified.get("candidateRunId") == run_id
            and verified.get("publicationAuthorized") is False
            and verified.get("signedArtifactsVerified") is False,
            "reconciliation produced unsafe downstream authority")
    verified["scheduleRecovery"] = True
    verified["scheduleMainSha"] = github_sha
    return verified


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args()
    try:
        repo = os.environ["GITHUB_REPOSITORY"]
        require(bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")),
                "authenticated read-only token unavailable")
        pulls = get_json(repo, "pulls?state=open&per_page=100")
        owned = [p for p in pulls if type(p) is dict
                 and p.get("state") == "open"
                 and (p.get("user") or {}).get("login") == "github-actions[bot]"
                 and CANDIDATE.fullmatch((p.get("head") or {}).get("ref", ""))]
        require(len(owned) <= 1, "ambiguous bot candidates")
        sha = (owned[0].get("head") or {}).get("sha") if owned else None
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
