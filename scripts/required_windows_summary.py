#!/usr/bin/env python3
"""Fail-closed, fixed-name Windows required CI result for maintained-PG matrix.

Never publishes or dispatches. Relies only on GitHub Actions 'needs.windows.result'
for the COMPLETE reusable Windows matrix (not on volatile per-PG job names).
"""
from __future__ import annotations
import os
import re
import sys


def verified_matrix_result(value):
    return type(value) is str and value == "success"


def print_reuse_source():
    if os.environ.get("REUSE_APPLIED") != "true":
        return
    pr = os.environ.get("REUSE_SOURCE_PR", "")
    run_id = os.environ.get("REUSE_SOURCE_RUN_ID", "")
    attempt = os.environ.get("REUSE_SOURCE_ATTEMPT", "")
    if not all(re.fullmatch(r"[1-9][0-9]*", value) for value in (pr, run_id, attempt)):
        return

    source_pr = f"PR #{pr}"
    source_run = f"Run {run_id}, attempt {attempt}"
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repo) and not repo.endswith(("/.", "/..")):
        base_url = f"https://github.com/{repo}"
        source_pr += f" ({base_url}/pull/{pr})"
        source_run += f" ({base_url}/actions/runs/{run_id}/attempts/{attempt})"
    print(f"WINDOWS CI REUSED: {source_pr}, {source_run}")


def main():
    if not verified_matrix_result(os.environ.get("WINDOWS_MATRIX_RESULT")):
        print("WINDOWS REQUIRED SUMMARY DENIED: full maintained-PG Windows matrix "
              "was not successful", file=sys.stderr)
        return 2
    print("WINDOWS REQUIRED SUMMARY VERIFIED: full maintained-PG Windows matrix "
          "completed successfully")
    print_reuse_source()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
