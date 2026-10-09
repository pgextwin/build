#!/usr/bin/env python3
"""Central live policy gate. Declarative main policy may change; executable code remains SHA-pinned."""
from __future__ import annotations
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
from update_watch_lib import WatchError, github_get_json

CONTROL_URL = "https://api.github.com/repos/pgextwin/build/contents/metadata/automation-fleet.json?ref=main"
REPOSITORY = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
STRATEGIES = {"github-releases", "github-tags", "github-releases-per-postgresql"}
MODES = {"OFF", "WATCH", "BUILD"}
EXPECTED_FIELDS = {"repository", "mode", "strategy", "scheduleUtc", "candidateEnabled", "releasePolicy", "reason"}

def validate(registry):
    if not isinstance(registry, dict) or set(registry) != {"schemaVersion", "scheduleUtc", "releasePolicy", "entries"}:
        raise WatchError("unsupported fleet policy fields")
    if type(registry["schemaVersion"]) is not int or registry["schemaVersion"] != 1:
        raise WatchError("unsupported fleet schema version")
    if registry["scheduleUtc"] != "0 0 * * *" or registry["releasePolicy"] != "manual-only":
        raise WatchError("fleet must use daily UTC 00:00 and manual releases")
    entries = registry["entries"]
    if not isinstance(entries, list) or not entries:
        raise WatchError("fleet registry must contain entries")
    seen = set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != EXPECTED_FIELDS:
            raise WatchError("invalid fleet entry")
        repo = item["repository"]
        if not isinstance(repo, str) or not REPOSITORY.fullmatch(repo) or repo in seen:
            raise WatchError("invalid or duplicate repository")
        seen.add(repo)
        if item["mode"] not in MODES or item["strategy"] not in STRATEGIES:
            raise WatchError("invalid mode or watch strategy")
        if item["scheduleUtc"] != registry["scheduleUtc"] or item["releasePolicy"] != "manual-only":
            raise WatchError("fleet entry disagrees with schedule or release policy")
        if type(item["candidateEnabled"]) is not bool or type(item["reason"]) is not str:
            raise WatchError("invalid candidateEnabled or reason type")
        if item["mode"] != "BUILD" and item["candidateEnabled"]:
            raise WatchError("non-BUILD entry cannot enable candidates")
        if item["mode"] == "BUILD" and not item["candidateEnabled"]:
            raise WatchError("BUILD entry must explicitly enable candidate builds")
    return {entry["repository"]: entry for entry in entries}

def get_live(fetch=github_get_json):
    payload = fetch(CONTROL_URL, os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    if not isinstance(payload, dict) or payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
        raise WatchError("cannot read authoritative central fleet policy")
    try:
        decoded = base64.b64decode(payload["content"], validate=False)
        policy = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise WatchError("malformed central fleet policy") from exc
    validate(policy)
    return policy

def decide(policy, repository, extension, watch, action, candidate_policy=None):
    entries = validate(policy)
    if repository not in entries:
        raise WatchError("unregistered caller repository")
    entry = entries[repository]
    if repository != "pgextwin/" + extension.get("name", ""):
        raise WatchError("extension name and repository differ")
    if entry["strategy"] != watch.get("strategy") or extension.get("upstream", {}).get("repository") != watch.get("repository"):
        raise WatchError("fleet strategy or upstream identity mismatch")
    if action not in {"watch", "candidate"}:
        raise WatchError("invalid requested action")
    if action == "watch":
        return entry["mode"] != "OFF", entry["mode"]
    if entry["mode"] != "BUILD":
        return False, entry["mode"]
    if not isinstance(candidate_policy, dict):
        raise WatchError("BUILD mode requires local opt-in policy")
    if candidate_policy != {"schemaVersion":1,"enabled":True,"releasePolicy":"manual-only","workflow":"windows.yml"}:
        raise WatchError("local candidate opt-in is missing or inconsistent")
    return True, entry["mode"]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--extension", required=True)
    parser.add_argument("--watch", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--action", choices=["watch", "candidate"], required=True)
    parser.add_argument("--candidate-policy")
    args = parser.parse_args()
    try:
        extension = json.loads(Path(args.extension).read_text(encoding="utf-8"))
        watch = json.loads(Path(args.watch).read_text(encoding="utf-8"))
        policy = json.loads(Path(args.candidate_policy).read_text(encoding="utf-8")) if args.candidate_policy else None
        allowed, mode = decide(get_live(), args.repository, extension, watch, args.action, policy)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
                handle.write("allowed=" + str(allowed).lower() + "\n")
                handle.write("mode=" + mode + "\n")
        print(json.dumps({"repository": args.repository, "mode": mode, "allowed": allowed, "action": args.action}))
        return 0
    except (WatchError, OSError, ValueError, TypeError, KeyError) as exc:
        print("FLEET CONTROL FAILED CLOSED: " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
