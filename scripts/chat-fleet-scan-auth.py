#!/usr/bin/env python3
"""Authenticate a genuine owner-created Issue #311 scan request (READ ONLY).

This request does not grant candidate, signing, Publisher or Release authority.
Existing schedule/source gates remain independent.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

OWNER_LOGIN = "ShutenOishi"
OWNER_ID = 27071164
COMMAND = "/pgextwin scan"
ISSUE_URL = "https://api.github.com/repos/pgextwin/build/issues/311"


class ScanDenied(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise ScanDenied(why)


def owner(person):
    return (type(person) is dict
            and person.get("login") == OWNER_LOGIN
            and type(person.get("id")) is int
            and person["id"] == OWNER_ID
            and person.get("type") == "User")


def validate_event(event, env):
    require(type(event) is dict, "invalid event root")
    require(env.get("GITHUB_EVENT_NAME") == "issue_comment"
            and env.get("GITHUB_REPOSITORY") == "pgextwin/build"
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("GITHUB_ACTOR") == OWNER_LOGIN
            and env.get("GITHUB_TRIGGERING_ACTOR") == OWNER_LOGIN
            and env.get("GITHUB_ACTOR_ID") == str(OWNER_ID),
            "untrusted GitHub trigger")
    issue, comment = event.get("issue"), event.get("comment")
    require(event.get("action") == "created"
            and type(issue) is dict and issue.get("number") == 311
            and "pull_request" not in issue
            and type(comment) is dict
            and type(comment.get("id")) is int and comment["id"] > 0
            and comment.get("body") == COMMAND
            and comment.get("issue_url") == ISSUE_URL
            and comment.get("created_at") == comment.get("updated_at")
            and owner(event.get("sender")) and owner(comment.get("user")),
            "invalid owner scan comment")
    return comment["id"]


def validate_live(event, live, env):
    comment_id = validate_event(event, env)
    require(type(live) is dict
            and live.get("id") == comment_id
            and live.get("body") == COMMAND
            and live.get("issue_url") == ISSUE_URL
            and live.get("created_at") == live.get("updated_at")
            and live.get("created_at") == event["comment"]["created_at"]
            and owner(live.get("user")),
            "owner scan request deleted or edited")
    return comment_id


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--live")
    args = parser.parse_args()
    try:
        event = json.loads(Path(args.event).read_text(encoding="utf-8"))
        cid = validate_event(event, os.environ)
        if args.live:
            live = json.loads(Path(args.live).read_text(encoding="utf-8"))
            cid = validate_live(event, live, os.environ)
        print(cid)
        return 0
    except (ScanDenied, ValueError, OSError, TypeError, KeyError):
        print("SCAN_DENIED: untrusted or changed owner request", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
