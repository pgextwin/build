#!/usr/bin/env python3
"""Record per-repository original native PR audits on the protected central schedule."""
from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CENTRAL = "pgextwin/build"
CANDIDATE_SECONDS = 120
FLEET_SECONDS = 38 * 60


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recovery = load("central_native_recovery", "scripts/recover-native-pr-candidate.py")
native = recovery.native
candidate = load("central_candidate_bytes", "scripts/verify-candidate.py")
contents = load("central_candidate_contents", "scripts/github_contents.py")
Denied = native.Denied
Unavailable = native.Unavailable
require = native.require


def gh_json(repo, endpoint):
    require(native.REPO.fullmatch(repo or ""), "nonregistered repo format")
    require(endpoint == "branches/main" or
            re.fullmatch(r"contents/config/extension\.json\?ref=[a-f0-9]{40}", endpoint),
            "unexpected GitHub GET endpoint")
    p = subprocess.run(["gh", "api", "--method", "GET", "repos/" + repo + "/" + endpoint],
                       capture_output=True, text=True, check=False, timeout=60)
    if p.returncode != 0 or len(p.stdout) >= 2_000_000:
        raise Unavailable("authenticated GitHub GET failed: " + repo)
    return json.loads(p.stdout)


def central_schedule_gate():
    sha = os.environ.get("GITHUB_SHA", "")
    run = os.environ.get("GITHUB_RUN_ID", "")
    require(os.environ.get("GITHUB_EVENT_NAME") == "schedule"
            and os.environ.get("GITHUB_REPOSITORY") == CENTRAL
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
            and native.SHA.fullmatch(sha) and re.fullmatch(r"[1-9][0-9]*", run)
            and bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")),
            "central trusted first-attempt main schedule required")
    source = gh_json(CENTRAL, "branches/main")
    require(source.get("protected") is True and source.get("commit", {}).get("sha") == sha,
            "scheduled central SHA not exact protected current main")
    return {"repository": CENTRAL, "event": "schedule", "sourceSha": sha,
            "runId": int(run), "runAttempt": 1}


def membership(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    require(doc.get("schemaVersion") == 1 and type(doc.get("entries")) is list,
            "invalid immutable central fleet roster")
    targets = []
    for entry in doc["entries"]:
        require(type(entry) is dict, "invalid fleet entry")
        if entry.get("mode") == "BUILD" and entry.get("candidateEnabled") is True:
            repo = entry.get("repository")
            require(type(repo) is str and native.REPO.fullmatch(repo),
                    "unsafe central registered repository")
            targets.append(repo)
    require(0 < len(targets) < 100 and len(targets) == len(set(targets)),
            "missing, duplicated or unbounded candidate fleet")
    return targets


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def recover_one(repo, lifecycle, result):
    # Record the start of the list read so a merge racing this GET cannot
    # turn an in-window missing candidate into a post-merge observation.
    observed = utc_now()
    pulls = recovery.get_json(repo, "pulls?state=open&per_page=100")
    if type(pulls) is list and len(pulls) < 100:
        result["observedAt"] = observed
    pr = recovery.open_candidate(pulls)
    if pr is None:
        return {"status": "no_candidate", "reason": "no owned open candidate PR"}

    head = (pr.get("head") or {}).get("sha")
    number = pr.get("number")
    base = (pr.get("base") or {}).get("sha")
    require(native.SHA.fullmatch(head or "") and native.required_check.positive(number),
            "invalid candidate PR or HEAD")
    result.update(candidatePr=number, candidateHeadSha=head)
    require(native.SHA.fullmatch(base or ""), "invalid candidate base SHA")
    inventory = recovery.get_json(
        repo, "actions/runs?event=pull_request&head_sha=" + head + "&per_page=100")
    indexed = recovery.exact_native_run(repo, pr, inventory)
    status, conclusion = indexed.get("status"), indexed.get("conclusion")
    if ((status == "completed" and conclusion == "action_required")
            or status in ("requested", "pending", "waiting", "queued", "in_progress")):
        return {"status": "waiting",
                "reason": f"original native PR run not successfully completed ({status}/{conclusion})"}
    context, files = recovery.authenticate(
        pr, indexed, lambda endpoint: native.gh_get(repo, endpoint),
        repo=repo, expected_main=base)
    require(native.required_check.positive(indexed.get("workflow_id")),
            "missing original native workflow ID")
    manifest = gh_json(repo, "contents/config/extension.json?ref=" + head)
    try:
        ext = contents.decode_json_file(manifest, "config/extension.json")
    except ValueError as exc:
        raise Denied(str(exc)) from exc
    require(manifest["sha"] == files[0]["sha"], "PR manifest bytes differ from exact PR patch")
    require(ext.get("name") == repo.split("/")[1], "candidate manifest identity mismatch")

    with tempfile.TemporaryDirectory(prefix="pgextwin-original-native-") as tmp:
        p = subprocess.run(["gh", "run", "download", str(context["candidateRunId"]),
                            "--repo", repo, "--dir", tmp],
                           text=True, capture_output=True, timeout=CANDIDATE_SECONDS, check=False)
        if p.returncode != 0:
            raise Unavailable("original Actions artifact download denied: " + p.stderr[:500])
        outcome = candidate.audit(
            Path(tmp), ext, lifecycle, context["candidateRunId"], head, context["branch"],
            "success", date.today(), event="pull_request", merge_sha=context["packagingMergeSha"],
            pr_number=number, run_attempt=context["candidateRunAttempt"])
    if outcome["status"] != "VERIFIED":
        errors = ["PG " + str(row["major"]) + ": " + row["error"]
                  for row in outcome["majors"] if row["status"] == "FAILED"]
        raise Denied("original ZIP/SPDX/Grype byte audit failed: " + "; ".join(errors))
    return {"status": "verified", "targetMainSha": base, "manifestBlob": manifest["sha"],
            "workflowId": indexed["workflow_id"], "native": context, "candidateAudit": outcome}


class CandidateTimeout(Exception):
    pass


def candidate_timeout(signum, frame):
    raise CandidateTimeout("candidate audit exceeded its time budget")


def collect(targets, lifecycle):
    deadline = time.monotonic() + FLEET_SECONDS
    previous_handler = signal.signal(signal.SIGALRM, candidate_timeout)
    results = {}
    try:
        for repo in targets:
            result = {"observedAt": None}
            results[repo] = result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result.update(status="unavailable", reason="fleet audit time budget exhausted")
                continue
            try:
                try:
                    signal.setitimer(signal.ITIMER_REAL, min(remaining, CANDIDATE_SECONDS))
                    outcome = recover_one(repo, lifecycle, result)
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
            except (Unavailable, CandidateTimeout, OSError, subprocess.TimeoutExpired, json.JSONDecodeError,
                    AttributeError, KeyError, TypeError) as exc:
                outcome = {"status": "unavailable", "reason": str(exc)}
            except ValueError as exc:
                outcome = {"status": "rejected", "reason": str(exc)}
            result.update(outcome)
    finally:
        signal.signal(signal.SIGALRM, previous_handler)
    return results


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--fleet", default="metadata/automation-fleet.json")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    try:
        auditor = central_schedule_gate()
        lifecycle = json.loads((ROOT / "metadata/postgresql.json").read_text(encoding="utf-8"))
        results = collect(membership(ROOT / args.fleet), lifecycle)
        report = {"schemaVersion": 2, "auditor": auditor, "results": results,
                  "signedArtifactsVerified": False, "publicationAuthorized": False,
                  "publishableReceipt": False}
        with tempfile.TemporaryDirectory(dir=args.output.parent) as tmp:
            pending = Path(tmp) / args.output.name
            pending.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            pending.replace(args.output)
        lines = ["Central read-only native PR audit results (PUBLISH_DENY)", ""]
        for repo, row in results.items():
            identity = f" #{row['candidatePr']} {row['candidateHeadSha']}" if "candidatePr" in row else ""
            reason = " ".join(row.get("reason", "").split())[:500]
            lines.append(f"- {repo}{identity}: {row['status']} {reason}".rstrip())
        summary = "\n".join(lines) + "\n"
        print(summary, end="")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
                out.write(summary)
        return 0
    except (ValueError, TypeError, KeyError, OSError, subprocess.TimeoutExpired) as exc:
        print("CENTRAL_NATIVE_AUDIT_FAIL_CLOSED:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
