#!/usr/bin/env python3
"""Step 19 stable candidate planning and once-only Windows CI dispatch; never publishes releases."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote

from update_watch_lib import WatchError, detect_extension_update, github_get_json, natural_key, utc_now, validate_watch_semantics

HEX_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
MARKER_PREFIX = "pgextwin-candidate:v1"


def read(path):
    item = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(item, dict):
        raise WatchError("JSON root must be an object")
    return item


def policy_valid(policy):
    if set(policy) != {"schemaVersion", "enabled", "releasePolicy", "workflow"} or policy["schemaVersion"] != 1:
        raise WatchError("unsupported candidate policy")
    if type(policy["enabled"]) is not bool or policy["releasePolicy"] != "manual-only" or policy["workflow"] != "windows.yml":
        raise WatchError("Step 19 allows only explicit opt-in with manual-only Release policy")


def api(url):
    item = github_get_json(url, os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    if not isinstance(item, dict):
        raise WatchError("upstream response must be an object")
    return item


def peel_tag(repository, tag, fetch=api):
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", tag) or tag.startswith("-") or ".." in tag:
        raise WatchError("invalid upstream tag")
    prefix = "https://api.github.com/repos/" + repository
    target = fetch(prefix + "/git/ref/tags/" + quote(tag, safe="/")).get("object")
    for i in range(5):
        if not isinstance(target, dict) or target.get("type") not in {"commit", "tag"}:
            raise WatchError("unsupported or missing Git tag object")
        sha = target.get("sha")
        if not isinstance(sha, str) or not HEX_SHA.fullmatch(sha):
            raise WatchError("invalid object SHA")
        if target["type"] == "commit":
            return sha.lower()
        tag_object = fetch(prefix + "/git/tags/" + sha)
        if i == 0 and tag_object.get("tag") != tag:
            raise WatchError("annotated tag name does not match")
        target = tag_object.get("object")
    raise WatchError("annotated tag nesting too deep")


def plan(extension, watch, policy, fetch=api):
    policy_valid(policy)
    validate_watch_semantics(extension, watch)
    result = {"schemaVersion": 1, "extension": extension["name"], "repository": watch["repository"],
              "detectedAt": utc_now(), "releasePolicy": "manual-only",
              "status": "disabled" if not policy["enabled"] else "no-op", "updates": []}
    if not policy["enabled"]:
        return result
    observation = detect_extension_update(extension, watch, fetch, result["detectedAt"], "pgextwin/build", "step19")
    if observation["status"] == "up-to-date":
        return result
    if observation["status"] != "update-available" or not observation["updates"]:
        raise WatchError("indeterminate candidate detection")
    for one in observation["updates"]:
        c = one["candidate"]
        old = one["current"]
        if natural_key(c["version"]) <= natural_key(str(old["version"])):
            raise WatchError("downgrade or same-version switch is forbidden")
        result["updates"].append({
            "major": one.get("postgresqlMajor"),
            "oldRef": old["ref"], "oldVersion": str(old["version"]),
            "ref": c["ref"], "version": str(c["version"]),
            "commit": peel_tag(watch["repository"], c["ref"], fetch),
            "notes": c.get("url", ""),
        })
    stable = json.dumps(sorted([(x["major"], x["ref"], x["commit"]) for x in result["updates"]],
                               key=lambda x: str(x[0])), separators=(",", ":"))
    digest = hashlib.sha256((watch["repository"] + "\n" + stable).encode()).hexdigest()[:20]
    result.update({"candidateId": digest, "branch": "auto-candidate/" + digest, "status": "candidate"})
    return result


def apply(extension, record):
    if record.get("status") != "candidate" or extension["name"] != record["extension"]:
        raise WatchError("candidate manifest identity mismatch")
    modified = copy.deepcopy(extension)
    per_major = "perPostgresql" in modified["upstream"]
    if not per_major and len(record["updates"]) != 1:
        raise WatchError("uniform extension should have one new stable candidate")
    for update in record["updates"]:
        target = modified["upstream"]["perPostgresql"].get(str(update["major"])) if per_major else modified["upstream"]
        if not isinstance(target, dict):
            raise WatchError("unsupported PostgreSQL series")
        if target["ref"] != update["oldRef"] or str(target["version"]) != update["oldVersion"]:
            raise WatchError("configured version changed since plan")
        if natural_key(update["version"]) <= natural_key(update["oldVersion"]):
            raise WatchError("candidate cannot downgrade")
        target.update({"ref": update["ref"], "version": update["version"], "commit": update["commit"]})
    return modified


def execute(*args):
    r = subprocess.run(list(args), text=True, capture_output=True, check=False)
    if r.returncode != 0:
        raise WatchError(args[0] + " exited " + str(r.returncode) + ": " + r.stderr[:500])
    return r.stdout.strip()


def propose(record, manifest_path, repository):
    if record.get("status") != "candidate" or repository != os.environ.get("GITHUB_REPOSITORY"):
        raise WatchError("untrusted candidate caller")
    if os.environ.get("GITHUB_REF") != "refs/heads/main" or not os.environ.get("GH_TOKEN"):
        raise WatchError("proposer requires trusted main and GH_TOKEN")
    config = read(manifest_path)
    if config["upstream"]["repository"] != record["repository"]:
        raise WatchError("upstream repository changed")
    changed = apply(config, record)
    for update in record["updates"]:
        if peel_tag(record["repository"], update["ref"]) != update["commit"]:
            raise WatchError("upstream tag moved after plan")
    branch = record["branch"]
    if not re.fullmatch(r"auto-candidate/[0-9a-f]{20}", branch):
        raise WatchError("invalid immutable candidate branch")
    marker = "<!-- " + MARKER_PREFIX + ":" + record["candidateId"] + " -->"
    remote = execute("git", "ls-remote", "--heads", "origin", "refs/heads/" + branch)
    if remote:
        execute("git", "fetch", "--no-tags", "origin", "refs/heads/" + branch + ":refs/remotes/origin/" + branch)
        message = execute("git", "log", "-1", "--format=%B", "refs/remotes/origin/" + branch)
        if marker not in message:
            raise WatchError("existing branch is human-owned or otherwise untrusted")
        actual = json.loads(execute("git", "show", "refs/remotes/origin/" + branch + ":" + manifest_path))
        if actual != changed:
            raise WatchError("existing branch differs from immutable candidate")
    else:
        execute("git", "checkout", "-b", branch)
        Path(manifest_path).write_text(json.dumps(changed, indent=2) + "\n", encoding="utf-8")
        execute("git", "config", "user.name", "github-actions[bot]")
        execute("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
        execute("git", "add", "--", manifest_path)
        execute("git", "commit", "-m", "chore: propose upstream candidate\n\n" + marker)
        execute("git", "push", "--set-upstream", "origin", branch)
    prs = json.loads(execute("gh", "pr", "list", "--repo", repository, "--head", branch, "--state", "all",
                            "--limit", "100", "--json", "number,body,state,url"))
    if len(prs) > 1:
        raise WatchError("multiple PRs for candidate")
    if prs:
        if marker not in (prs[0].get("body") or ""):
            raise WatchError("candidate PR is not automation-owned")
        if prs[0]["state"] != "OPEN":
            print("Candidate PR already closed: never reopen or rebuild")
            return
        url = prs[0]["url"]
    else:
        body = [marker, "## Automated upstream Windows candidate (NOT a Release)", "",
                "This PR was created by Step 19 and is draft until reviewed.",
                "The candidate CI is explicitly dispatched because GITHUB_TOKEN PR CI may await approval.",
                "No Release, Catalog or Website mutation occurs.", "",
                "| PG series | Previous | Candidate | Pinned upstream commit | Release notes |",
                "| --- | --- | --- | --- | --- |"]
        for u in record["updates"]:
            body.append("| " + str(u["major"] or "all configured") + " | " +
                        u["oldVersion"] + " (" + u["oldRef"] + ") | " +
                        u["version"] + " (" + u["ref"] + ") | " + u["commit"] +
                        " | " + str(u["notes"]) + " |")
        body += ["", "Manual review: source diff, license, export audit, Test Contract, Windows compatibility.",
                 "A separate attested Release build and publication gate remain mandatory."]
        body_path = Path(os.environ.get("RUNNER_TEMP", ".")) / "pgextwin-candidate-pr.md"
        body_path.write_text("\n".join(body) + "\n", encoding="utf-8")
        url = execute("gh", "pr", "create", "--repo", repository, "--head", branch, "--base", "main",
                      "--title", "chore: candidate " + record["extension"] + " " +
                      record["updates"][0]["version"], "--body-file", str(body_path), "--draft")
    print("Candidate PR: " + url)
    runs = json.loads(execute("gh", "run", "list", "--repo", repository, "--workflow", "windows.yml",
                              "--branch", branch, "--event", "workflow_dispatch", "--limit", "100",
                              "--json", "databaseId,event,status,conclusion,url"))
    if runs:
        print("Candidate dispatched previously; no repeat build")
        return
    execute("gh", "workflow", "run", "windows.yml", "--repo", repository, "--ref", branch)
    print("Windows CI dispatched for " + branch)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="action", required=True)
    a = sub.add_parser("plan")
    for key in ("extension", "watch", "policy", "output"):
        a.add_argument("--" + key, required=True)
    b = sub.add_parser("propose")
    for key in ("record", "extension", "repository"):
        b.add_argument("--" + key, required=True)
    args = p.parse_args()
    try:
        if args.action == "plan":
            record = plan(read(args.extension), read(args.watch), read(args.policy))
            Path(args.output).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                    f.write("candidate=" + str(record["status"] == "candidate").lower() + "\n")
            print(json.dumps(record))
        else:
            propose(read(args.record), args.extension, args.repository)
        return 0
    except (WatchError, OSError, ValueError, KeyError, TypeError) as err:
        print("Candidate automation failed CLOSED: " + str(err), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
