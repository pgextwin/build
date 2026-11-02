#!/usr/bin/env python3
"""Fail-closed owner on-demand protected-main signing intent (NO PUBLISH).

This is a distinct issue_comment source kind, never a synthetic push/schedule
or a Publisher admission receipt. The caller's original event and current
GitHub REST objects must agree before a real main-ref signing build may start.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

OWNER = {"login": "ShutenOishi", "id": 27071164, "type": "User"}
REPOSITORY = re.compile(r"pgextwin/[a-z][a-z0-9_]*\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
COMMAND = "/pgextwin sign-main"
WORKFLOW = ".github/workflows/chat-signed-main.yml"


class Denied(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Denied(why)


def owner(user):
    return (type(user) is dict
            and all(user.get(k) == v for k, v in OWNER.items()))


def check(event, live, branch, run, fleet, env, issue_number):
    repo = env.get("GITHUB_REPOSITORY")
    need(type(repo) is str and REPOSITORY.fullmatch(repo)
         and type(issue_number) is int and issue_number > 0, "invalid caller")
    need(type(fleet) is dict and fleet.get("schemaVersion") == 1
         and type(fleet.get("entries")) is list, "untrusted fleet")
    registered = [e.get("repository") for e in fleet["entries"] if type(e) is dict]
    need(len(registered) == len(fleet["entries"])
         and len(registered) == len(set(registered))
         and repo in registered, "not in immutable protected fleet")
    need(env.get("GITHUB_EVENT_NAME") == "issue_comment"
         and env.get("GITHUB_REF") == "refs/heads/main"
         and env.get("GITHUB_RUN_ATTEMPT") == "1"
         and env.get("GITHUB_ACTOR") == OWNER["login"]
         and env.get("GITHUB_TRIGGERING_ACTOR") == OWNER["login"]
         and env.get("GITHUB_ACTOR_ID") == str(OWNER["id"])
         and type(env.get("GITHUB_SHA")) is str
         and SHA.fullmatch(env["GITHUB_SHA"]), "wrong original runtime")
    need(type(event) is dict and event.get("action") == "created"
         and owner(event.get("sender"))
         and (event.get("repository") or {}).get("full_name") == repo,
         "wrong genuine event")
    issue, comment = event.get("issue"), event.get("comment")
    issue_url = f"https://api.github.com/repos/{repo}/issues/{issue_number}"
    need(type(issue) is dict and issue.get("number") == issue_number
         and "pull_request" not in issue and type(comment) is dict
         and type(comment.get("id")) is int and comment["id"] > 0
         and comment.get("issue_url") == issue_url
         and comment.get("body") == COMMAND
         and comment.get("created_at") == comment.get("updated_at")
         and owner(comment.get("user")), "forged/edited original comment")
    need(type(live) is dict and live.get("id") == comment["id"]
         and live.get("body") == COMMAND and live.get("issue_url") == issue_url
         and live.get("created_at") == comment["created_at"]
         and live.get("updated_at") == comment["updated_at"]
         and owner(live.get("user")), "changed/deleted live owner command")
    need(type(branch) is dict and branch.get("name") == "main"
         and branch.get("protected") is True
         and (branch.get("commit") or {}).get("sha") == env["GITHUB_SHA"],
         "protected main advanced/unverified")
    need(type(run) is dict and run.get("id") == int(env["GITHUB_RUN_ID"])
         and run.get("run_attempt") == 1
         and run.get("event") == "issue_comment"
         and run.get("path") == WORKFLOW
         and run.get("head_branch") == "main"
         and run.get("head_sha") == env["GITHUB_SHA"]
         and (run.get("repository") or {}).get("full_name") == repo,
         "different GitHub original run/ref/source kind")
    return {"schemaVersion": 1, "sourceKind": "OWNER_ISSUE_COMMENT_MAIN_SIGNING",
            "repository": repo, "mainSha": env["GITHUB_SHA"],
            "issueNumber": issue_number, "commentId": comment["id"],
            "runId": run["id"], "runAttempt": 1, "signingEligible": True,
            "publisherEligible": False, "publicationAuthorized": False,
            "sourceEvent": "issue_comment", "PUBLISH": "DENY"}


def main():
    p = argparse.ArgumentParser()
    for arg in ("event", "live", "branch", "run", "fleet", "output"):
        p.add_argument("--" + arg, required=True)
    p.add_argument("--issue", type=int, required=True)
    args = p.parse_args()
    try:
        def read(path):
            return json.loads(Path(path).read_text("utf-8"))
        result = check(read(args.event), read(args.live), read(args.branch),
                       read(args.run), read(args.fleet), os.environ, args.issue)
        Path(args.output).write_text(json.dumps(result, sort_keys=True) + "\n", "utf-8")
        print("AUTHENTIC_OWNER_MAIN_SIGNING_ONLY; PUBLISH_DENY")
        return 0
    except (Denied, ValueError, TypeError, KeyError, OSError):
        print("OWNER_MAIN_SIGNING_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
