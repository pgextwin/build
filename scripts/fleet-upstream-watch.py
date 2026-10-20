#!/usr/bin/env python3
"""Daily stable-upstream audit of all fleet entries; GET-only, never a candidate."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys

from update_watch_lib import WatchError, detect_extension_update, github_get_json, utc_now, validate_watch_semantics
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fleet_control", ROOT / "scripts/fleet-control.py")
fleet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fleet)
BASE = "https://api.github.com/repos/"
SHA = re.compile(r"^[0-9a-f]{40}$")


def load_at_commit(repository, sha, path, fetch):
    url = BASE + repository + "/contents/" + path + "?ref=" + sha
    body = fetch(url)
    if not isinstance(body, dict) or body.get("encoding") != "base64" or not isinstance(body.get("content"), str):
        raise WatchError("missing authenticated GitHub content blob")
    try:
        payload = base64.b64decode(body["content"], validate=False)
        if len(payload) > 262144:
            raise ValueError("oversized manifest")
        doc = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeError, KeyError) as exc:
        raise WatchError("invalid pinned config content") from exc
    if not isinstance(doc, dict):
        raise WatchError("config JSON root is not an object")
    return doc


def snapshot(repository, entry, fetch):
    before = fetch(BASE + repository + "/branches/main")
    if not isinstance(before, dict) or before.get("protected") is not True:
        raise WatchError("unprotected or unverifiable upstream manifest main")
    sha = (before.get("commit") or {}).get("sha")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise WatchError("unknown protected main commit")
    ext = load_at_commit(repository, sha, "config/extension.json", fetch)
    watch = load_at_commit(repository, sha, "config/update-watch.json", fetch)
    if ext.get("name") != repository.split("/")[-1]:
        raise WatchError("extension identity mismatch")
    validate_watch_semantics(ext, watch)
    if watch.get("strategy") != entry["strategy"]:
        raise WatchError("local watch strategy differs from central fleet")
    if entry["mode"] == "OFF":
        return {"repository": repository, "mainSha": sha, "status": "CENTRALLY_DISABLED", "updates": []}
    observed = detect_extension_update(ext, watch, fetch, utc_now(), "pgextwin/build", sha)
    after = fetch(BASE + repository + "/branches/main")
    if (not isinstance(after, dict) or after.get("protected") is not True
            or (after.get("commit") or {}).get("sha") != sha):
        raise WatchError("protected extension main changed during audit")
    return {"repository": repository, "mainSha": sha, "status": observed["status"],
            "updates": observed.get("updates", []),
            "candidate": observed.get("candidate"), "current": observed.get("current")}


def scan(registry, fetch):
    entries = fleet.validate(registry)
    if len(entries) != 17:
        raise WatchError("all 17 existing extension watches must be inventoried")
    results = []
    for repository, entry in sorted(entries.items()):
        try:
            results.append(snapshot(repository, entry, fetch))
        except (WatchError, KeyError, TypeError, ValueError, OSError) as exc:
            results.append({"repository": repository, "status": "INDETERMINATE",
                            "updates": [], "reason": type(exc).__name__})
    if len(results) != 17 or len({x["repository"] for x in results}) != 17:
        raise WatchError("partial or ambiguous fleet coverage")
    failures = [x["repository"] for x in results if x["status"] == "INDETERMINATE"]
    changed = [x["repository"] for x in results if x["status"] == "update-available"]
    return {"schemaVersion": 1, "generatedAt": utc_now(), "scope": "STABLE_UPSTREAM_GET_ONLY",
            "publication": "DENY", "candidatePrCreated": False, "fleetSize": 17,
            "updatesDetected": len(changed), "indeterminate": len(failures),
            "extensions": results}


def markdown(report):
    rows = ["## pgextwin 17-extension stable upstream watch", "",
            "Read-only daily audit; no source update, candidate PR, Release, or publication authorization.",
            "", "| Extension | Upstream | Status |",
            "| --- | --- | --- |"]
    for item in report["extensions"]:
        candidate = item.get("candidate")
        version = "—"
        if isinstance(candidate, dict):
            version = str(candidate.get("version") or candidate.get("perPostgresql") or "—")[:80]
        rows.append("| " + item["repository"].split("/")[-1] + " | " + version.replace("|", "/") +
                    " | " + item["status"] + " |")
    rows += ["", "Detected updates: " + str(report["updatesDetected"]),
             "Indeterminate: " + str(report["indeterminate"]),
             "PUBLISH=DENY; candidate creation still requires owner UPDATE and exact main SHA."]
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    summary = Path(args.summary)
    try:
        policy = json.loads(Path(args.policy).read_text("utf-8"))
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            raise WatchError("read-only GitHub token missing")
        report = scan(policy, lambda url: github_get_json(url, token))
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        summary.write_text(markdown(report), encoding="utf-8")
        return 2 if report["indeterminate"] else 0
    except (WatchError, OSError, json.JSONDecodeError, ValueError, KeyError) as exc:
        output.write_text(json.dumps({"status":"INDETERMINATE", "publication":"DENY",
                                      "error":type(exc).__name__}) + "\n", encoding="utf-8")
        summary.write_text("## Fleet upstream watch INDETERMINATE\n\nNo publication authorization.\n", encoding="utf-8")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
