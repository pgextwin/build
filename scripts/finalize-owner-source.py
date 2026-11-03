#!/usr/bin/env python3
"""Admit only the genuine owner issue_comment signed-main source at package finalization.

Read-only live GitHub GET. Signing-only source proof: NEVER authorizes Release.
The actual event stays issue_comment; no synthetic push, dispatch or schedule.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

AUTH_PATH = Path(__file__).with_name("chat-signed-main-auth.py")
spec = importlib.util.spec_from_file_location("pgextwin_owner_auth", AUTH_PATH)
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)


def live_get(repo: str, resource: str, token: str) -> dict:
    auth.need(bool(token) and auth.REPOSITORY.fullmatch(repo),
              "missing scoped GitHub API identity")
    req = Request(
        f"https://api.github.com/repos/{repo}/{resource}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "pgextwin-owner-signed-finalizer",
        },
        method="GET",
    )
    with urlopen(req, timeout=20) as response:
        auth.need(response.status == 200, "GitHub GET failed")
        return json.load(response)


def authenticate(event: dict, fleet: dict, env: dict, get) -> dict:
    repo = env.get("GITHUB_REPOSITORY")
    auth.need(type(repo) is str and auth.REPOSITORY.fullmatch(repo),
              "invalid repository")
    auth.need(type(event) is dict and type(event.get("issue")) is dict
              and type(event.get("comment")) is dict, "invalid owner event")
    issue_number = event["issue"].get("number")
    comment_id = event["comment"].get("id")
    run_id = env.get("GITHUB_RUN_ID")
    auth.need(type(issue_number) is int and issue_number > 0
              and type(comment_id) is int and comment_id > 0
              and type(run_id) is str and run_id.isdecimal()
              and int(run_id) > 0, "missing source identifiers")
    # All objects are fresh original GitHub GET, never caller-supplied proof.
    live = get(repo, f"issues/comments/{comment_id}")
    branch = get(repo, "branches/main")
    run = get(repo, f"actions/runs/{run_id}")
    result = auth.check(event, live, branch, run, fleet, env, issue_number)
    auth.need(result.get("sourceKind") == "OWNER_ISSUE_COMMENT_MAIN_SIGNING"
              and result.get("sourceEvent") == "issue_comment"
              and result.get("PUBLISH") == "DENY"
              and result.get("publisherEligible") is False
              and result.get("publicationAuthorized") is False,
              "owner signing proof must not grant publication")
    return result


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--event", required=True)
    p.add_argument("--fleet", required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--ref", required=True)
    args = p.parse_args()
    try:
        env = dict(os.environ)
        auth.need(args.repository == env.get("GITHUB_REPOSITORY")
                  and args.run_id == env.get("GITHUB_RUN_ID")
                  and args.ref == env.get("GITHUB_REF")
                  and args.ref == "refs/heads/main"
                  and env.get("GITHUB_EVENT_NAME") == "issue_comment"
                  and env.get("GITHUB_RUN_ATTEMPT") == "1"
                  and Path(args.event).resolve()
                      == Path(env["GITHUB_EVENT_PATH"]).resolve(),
                  "unbound original owner signing runtime")
        token = env.get("GH_TOKEN")
        auth.need(bool(token), "missing read-only GitHub API token")
        def read(path: str):
            return json.loads(Path(path).read_text(encoding="utf-8"))
        result = authenticate(
            read(args.event), read(args.fleet), env,
            lambda repo, resource: live_get(repo, resource, token))
        auth.need(result["runId"] == int(args.run_id)
                  and result["repository"] == args.repository,
                  "owner source/run mismatch")
        print("FINALIZER_OWNER_ISSUE_COMMENT_SIGNING_AUTHENTICATED; PUBLISH_DENY")
        return 0
    except (auth.Denied, ValueError, TypeError, KeyError, OSError,
            RuntimeError, json.JSONDecodeError) as exc:
        print("FINALIZER_OWNER_ISSUE_COMMENT_DENIED", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
