#!/usr/bin/env python3
"""Nonpublishing, protected-PR-only Auto-merge for a single verified shared workflow pin.

Run ONLY from a trusted caller's original Windows workflow_run (or trusted
workflow_dispatch with an independently supplied original run ID). Never use
pull_request_target with untrusted checkout. GitHub must still enforce required
checks, up-to-date branch protection and merge authorization.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$")
PATH = ".github/workflows/update-watch.yml"
SHARED = "pgextwin/build/.github/workflows/operator-update-auto.yml"
REQUIRED = {"windows / Resolve extension and PostgreSQL matrix",
            "Windows required summary"}
REQUIRED |= {f"windows / PostgreSQL {x} / Windows x64" for x in range(14, 19)}
# Existing external safety denials are not cleared by repository Auto-merge.
HELD = {"pgextwin/pg_bigm", "pgextwin/orafce"}


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def pin_change(patch):
    """Require precisely one old/new immutable reusable-workflow uses line."""
    require(type(patch) is str and len(patch) < 10000, "missing/oversized PR patch")
    changes = [s for s in patch.splitlines()
               if (s.startswith("+") and not s.startswith("+++"))
               or (s.startswith("-") and not s.startswith("---"))]
    require(len(changes) == 2, "unexpected changes beyond one workflow pin")
    removed = [s[1:] for s in changes if s.startswith("-")]
    added = [s[1:] for s in changes if s.startswith("+")]
    rule = re.compile(r"^\s+uses: " + re.escape(SHARED) + r"@([0-9a-f]{40})$")
    require(len(removed) == len(added) == 1, "pin diff shape changed")
    before, after = rule.fullmatch(removed[0]), rule.fullmatch(added[0])
    require(before is not None and after is not None
            and before.group(1) != after.group(1), "not an exact immutable pin update")
    return before.group(1), after.group(1)


def admit(*, repository, expected_head, expected_central, pr, files, ci_run,
          checks, metadata, main, central, fleet, central_runs):
    """Validate independently retrieved GitHub snapshots; return inert CLI arguments."""
    require(type(repository) is str and repository.startswith("pgextwin/")
            and repository not in HELD, "unregistered or external-safety-held repository")
    require(type(fleet) is dict and fleet.get("schemaVersion") == 1
            and sum(e.get("repository") == repository for e in fleet.get("entries", [])) == 1,
            "repository not unique in protected central fleet")
    require(type(expected_head) is str and SHA.fullmatch(expected_head)
            and type(expected_central) is str and SHA.fullmatch(expected_central),
            "expected full immutable SHAs missing")
    require(metadata.get("full_name") == repository
            and metadata.get("allow_auto_merge") is True
            and metadata.get("allow_squash_merge") is True
            and main.get("protected") is True
            and main.get("name") == "main", "Auto-merge or protected-main policy absent")
    require((central.get("commit") or {}).get("sha") == expected_central
            and central.get("protected") is True,
            "central protected main differs from validated workflow pin")
    require(any(r.get("event") == "push" and r.get("head_sha") == expected_central
                and r.get("status") == "completed" and r.get("conclusion") == "success"
                and r.get("run_attempt") == 1
                for r in central_runs), "central original main/push CI absent")
    require(type(pr) is dict and pr.get("state") == "open"
            and pr.get("draft") is False and pr.get("merged") is False
            and pr.get("mergeable") is True and pr.get("mergeable_state") == "clean"
            and type(pr.get("number")) is int and pr["number"] > 0,
            "PR is not ready, clean and mergeable")
    head = pr.get("head") or {}
    require(head.get("sha") == expected_head
            and head.get("repo", {}).get("full_name") == repository
            and str(head.get("ref", "")).startswith("auto-pin/")
            and (pr.get("base") or {}).get("ref") == "main"
            and (pr.get("base") or {}).get("repo", {}).get("full_name") == repository
            and (pr.get("user") or {}).get("login") in {"ShutenOishi", "github-actions[bot]"},
            "unexpected PR identity, author, head or base")
    require(type(files) is list and len(files) == 1
            and files[0].get("filename") == PATH
            and files[0].get("status") == "modified"
            and files[0].get("changes") == 2,
            "PR modifies files other than exact shared pin")
    old, new = pin_change(files[0].get("patch"))
    require(new == expected_central, "PR attempts an unvalidated central pin")
    run_pulls = ci_run.get("pull_requests") or []
    require(ci_run.get("event") == "pull_request"
            and ci_run.get("run_attempt") == 1
            and ci_run.get("status") == "completed"
            and ci_run.get("conclusion") == "success"
            and ci_run.get("head_sha") == expected_head
            and ci_run.get("head_branch") == head.get("ref")
            and (ci_run.get("head_repository") or {}).get("full_name") == repository
            and str(ci_run.get("path", "")).endswith("/windows.yml")
            and ci_run.get("associated_pr_number") == pr["number"]
            and (not run_pulls or
                 (len(run_pulls) == 1 and run_pulls[0].get("number") == pr["number"])),
            "original exact-head native PR Windows CI unproven")
    require(type(checks) is list and len(checks) < 100, "invalid/truncated exact-head checks")
    success = {c.get("name") for c in checks
               if c.get("status") == "completed"
               and c.get("conclusion") == "success"
               and (c.get("app") or {}).get("id") == 15368}
    need = REQUIRED if repository != "pgextwin/plpgsql_check" else (
        (REQUIRED - {"windows / PostgreSQL 14 / Windows x64"})
        | {"syntax", "Regression-test immutable Release preflight"})
    require(need <= success, "required original App15368 checks not fully successful")
    return ["gh", "pr", "merge", str(pr["number"]), "-R", repository,
            "--auto", "--squash", "--match-head-commit", expected_head]


def gh_api(path):
    result = subprocess.run(["gh", "api", "--method", "GET", path],
                            text=True, capture_output=True, check=False)
    require(result.returncode == 0, "GitHub GET failed: " + path + ": " + result.stderr[:180])
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise Denied("GitHub returned non-JSON GET: " + path) from exc


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repository", required=True)
    p.add_argument("--run-id", required=True, type=int)
    p.add_argument("--expected-central", required=True)
    p.add_argument("--fleet", default="metadata/automation-fleet.json")
    p.add_argument("--execute", action="store_true")
    a = p.parse_args()
    try:
        require(a.run_id > 0 and os.getenv("GH_TOKEN"), "trusted GitHub token or run missing")
        require(a.repository == os.getenv("GITHUB_REPOSITORY"), "caller repo identity mismatch")
        run = gh_api(f"repos/{a.repository}/actions/runs/{a.run_id}")
        # GitHub often returns [] for original pull_request workflow_run.pull_requests.
        # Bind identity using the exact-head commit-to-PR REST association.
        require(type(run.get("head_sha")) is str
                and SHA.fullmatch(run["head_sha"]), "invalid original run head SHA")
        associated = gh_api(
            f"repos/{a.repository}/commits/{run['head_sha']}/pulls?per_page=100")
        require(type(associated) is list and len(associated) == 1,
                "exact-head commit must identify exactly one GitHub PR")
        number = associated[0].get("number")
        require(type(number) is int and number > 0, "invalid independent PR association")
        run["associated_pr_number"] = number
        pr = gh_api(f"repos/{a.repository}/pulls/{number}")
        files = gh_api(f"repos/{a.repository}/pulls/{number}/files?per_page=100")
        check_payload = gh_api(f"repos/{a.repository}/commits/{pr['head']['sha']}/check-runs?per_page=100")
        require(check_payload.get("total_count", 0) < 100, "check run pagination required")
        central_runs = gh_api("repos/pgextwin/build/actions/workflows/validate.yml/runs"
                              f"?event=push&head_sha={a.expected_central}&per_page=30")
        args = admit(
            repository=a.repository, expected_head=run.get("head_sha"),
            expected_central=a.expected_central, pr=pr, files=files,
            ci_run=run, checks=check_payload["check_runs"],
            metadata=gh_api(f"repos/{a.repository}"),
            main=gh_api(f"repos/{a.repository}/branches/main"),
            central=gh_api("repos/pgextwin/build/branches/main"),
            central_runs=central_runs["workflow_runs"],
            fleet=json.loads(Path(a.fleet).read_text(encoding="utf-8")))
        print("ADMITTED NONPUBLISHING AUTO-MERGE:", " ".join(args))
        if a.execute:
            result = subprocess.run(args, check=False)
            require(result.returncode == 0, "GitHub refused protected native Auto-merge")
        else:
            print("DRY-RUN: no change was made")
        return 0
    except (Denied, KeyError, TypeError, OSError, ValueError) as exc:
        print("AUTO-MERGE DENIED:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
