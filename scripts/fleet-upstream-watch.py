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
import time

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


# A transient API transport error is not equivalent to an up-to-date result.
# Keep the first authentic failed attempt visible and bound retries strictly.
def transient_upstream_error(exc):
    if not isinstance(exc, WatchError):
        return False
    message = str(exc).lower()
    if not message.startswith("upstream query failed:"):
        return False
    return (bool(re.search(r"http error (?:429|500|502|503|504)\b", message))
            or any(term in message for term in (
                "timed out", "temporary failure", "connection reset",
                "connection aborted", "remote end closed connection")))


def safe_failure_code(exc):
    # Never write tokens, full third-party URLs, or GitHub response bodies
    # into the shared audit artifact. A type alone concealed the source of
    # the first real hourly pg_cron INDETERMINATE incident (run 40054693145).
    message = str(exc).lower()
    if isinstance(exc, WatchError) and message.startswith("upstream query failed:"):
        status = re.search(r"http error (\d{3})\b", message)
        return "UPSTREAM_HTTP_" + status.group(1) if status else "UPSTREAM_TRANSPORT"
    if isinstance(exc, WatchError):
        if "protected extension main changed during audit" in message:
            return "PROTECTED_MAIN_DRIFT"
        if "upstream response must be a json array" in message:
            return "UPSTREAM_INVALID_RESPONSE"
        return "WATCH_VALIDATION_ERROR"
    return "AUDIT_EXCEPTION"


def bounded_snapshot(repository, entry, fetch, pause=time.sleep):
    for attempt in range(2):
        try:
            return snapshot(repository, entry, fetch)
        except WatchError as exc:
            if attempt == 0 and transient_upstream_error(exc):
                pause(2)
                continue
            raise
    raise WatchError("bounded snapshot exhausted without a result")


def scan(registry, fetch):
    entries = fleet.validate(registry)
    results = []
    for repository, entry in sorted(entries.items()):
        try:
            results.append(bounded_snapshot(repository, entry, fetch))
        except (WatchError, KeyError, TypeError, ValueError, OSError) as exc:
            results.append({"repository": repository, "status": "INDETERMINATE",
                            "updates": [], "reason": type(exc).__name__,
                            "reasonCode": safe_failure_code(exc)})
    if len(results) != len(entries) or {x["repository"] for x in results} != set(entries):
        raise WatchError("partial or ambiguous fleet coverage")
    failures = [x["repository"] for x in results if x["status"] == "INDETERMINATE"]
    changed = [x["repository"] for x in results if x["status"] == "update-available"]
    return {"schemaVersion": 1, "generatedAt": utc_now(), "scope": "STABLE_UPSTREAM_GET_ONLY",
            "publication": "DENY", "candidatePrCreated": False, "fleetSize": len(entries),
            "updatesDetected": len(changed), "indeterminate": len(failures),
            "extensions": results}


def markdown(report):
    rows = ["## pgextwin registered-fleet stable upstream watch", "",
            "Read-only hourly audit; no source update, candidate PR, Release, or publication authorization.",
            "", "| Extension | Upstream | Status |",
            "| --- | --- | --- |"]
    for item in report["extensions"]:
        candidate = item.get("candidate")
        version = "—"
        if isinstance(candidate, dict):
            version = str(candidate.get("version") or candidate.get("perPostgresql") or "—")[:80]
        status = item["status"]
        if status == "INDETERMINATE":
            status += " (" + item.get("reasonCode", "AUDIT_EXCEPTION") + ")"
        rows.append("| " + item["repository"].split("/")[-1] + " | " + version.replace("|", "/") +
                    " | " + status + " |")
    rows += ["", "Detected updates: " + str(report["updatesDetected"]),
             "Indeterminate: " + str(report["indeterminate"]),
             "PUBLISH=DENY; candidate creation independently rechecks the central schedule and exact main SHA."]
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
