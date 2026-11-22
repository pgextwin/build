#!/usr/bin/env python3
"""Central live policy gate. Declarative main policy may change; executable code remains SHA-pinned."""
from __future__ import annotations
import importlib.util
import argparse
import base64
import json
import os
from pathlib import Path
import sys
from update_watch_lib import WatchError, github_get_json, load_watch

CONTROL_URL = "https://api.github.com/repos/pgextwin/build/contents/metadata/automation-fleet.json?ref=main"
BUILD_ROOT = Path(__file__).resolve().parents[1]

_policy_spec=importlib.util.spec_from_file_location("shared_fleet_policy",Path(__file__).with_name("fleet-policy.py"))
fleet_policy=importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(fleet_policy)

_publication_spec = importlib.util.spec_from_file_location(
    "publication_policy", BUILD_ROOT / "scripts" / "publication-policy.py")
publication_policy = importlib.util.module_from_spec(_publication_spec)
_publication_spec.loader.exec_module(publication_policy)

def validate(registry):
    try:
        return fleet_policy.validate_registry(registry)
    except fleet_policy.Denied as exc:
        raise WatchError(str(exc)) from exc

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
    if (("strategy" in entry and entry["strategy"] != watch.get("strategy"))
            or extension.get("upstream", {}).get("repository") != watch.get("repository")):
        raise WatchError("fleet strategy or upstream identity mismatch")
    if action not in {"watch", "candidate"}:
        raise WatchError("invalid requested action")
    if action == "watch":
        return entry["mode"] != "OFF", entry["mode"]
    if entry["mode"] != "BUILD":
        return False, entry["mode"]
    if not isinstance(candidate_policy, dict):
        raise WatchError("BUILD mode requires local opt-in policy")
    if candidate_policy != publication_policy.load_candidate_policy(BUILD_ROOT):
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
        watch = load_watch(extension, args.watch)
        if args.candidate_policy is None:
            policy = publication_policy.load_candidate_policy(BUILD_ROOT)
        else:
            policy = json.loads(Path(args.candidate_policy).read_text(encoding="utf-8"))
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
