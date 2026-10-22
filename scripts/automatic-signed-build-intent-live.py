#!/usr/bin/env python3
"""Authenticate original scheduled candidate decisions after a real protected main push.

A nonpublishing 17-extension adapter. The original decision artifact and the
current main manifest are fetched independently from GitHub; all fields remain
untrusted until checked by automatic-signed-build-intent.plan(). This module
does not mint authorization, launch a Signer, create tags or publish a Release.
"""
from __future__ import annotations

import argparse
import base64
from datetime import date
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("automatic_signing_plan",
                                               ROOT / "automatic-signed-build-intent.py")
intent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intent)

SHA = re.compile(r"^[a-f0-9]{40}$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
BRANCH = re.compile(r"^auto-candidate/[a-f0-9]{20}$")
WORKFLOW = ".github/workflows/update-watch.yml"
NAME = "Upstream candidate after verified central daily fleet scan"


class Denied(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise Denied(why)


def no_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "duplicate JSON key in original decision artifact")
        out[key] = value
    return out


def parse_json(data):
    return json.loads(data, object_pairs_hook=no_duplicate_keys)


def github(repo, suffix):
    require(type(repo) is str and REPO.fullmatch(repo), "invalid repository")
    allowed = (
        suffix == "actions/runs?per_page=100"
        or bool(re.fullmatch(r"actions/runs/[1-9][0-9]*/artifacts\?per_page=100", suffix))
        or bool(re.fullmatch(r"pulls/[1-9][0-9]*", suffix))
        or suffix == "branches/main"
        or bool(re.fullmatch(r"contents/config/(extension|candidate-build)\.json\?ref=[a-f0-9]{40}", suffix))
    )
    require(allowed, "non-allowlisted read-only GitHub resource")
    result = subprocess.run(["gh", "api", "--method", "GET", "repos/" + repo + "/" + suffix],
                            capture_output=True, text=True, timeout=45, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 3 * 1024 * 1024,
            "authenticated GitHub GET denied or incomplete")
    return parse_json(result.stdout)


def original_file(repo, run_id):
    with tempfile.TemporaryDirectory() as td:
        command = ["gh", "run", "download", str(run_id), "--repo", repo,
                   "--name", "candidate-decision", "--dir", td]
        process = subprocess.run(command, capture_output=True, text=True,
                                 timeout=90, check=False)
        require(process.returncode == 0, "real candidate-decision artifact download failed")
        items = list(Path(td).rglob("*"))
        require(len(items) == 1 and items[0].is_file()
                and items[0].name == "candidate-plan.json"
                and 0 < items[0].stat().st_size < 256_000,
                "unexpected original decision artifact bytes")
        return parse_json(items[0].read_text("utf-8"))


def only_manifest(source, path):
    require(type(source) is dict and source.get("path") == path
            and source.get("encoding") == "base64"
            and type(source.get("content")) is str
            and type(source.get("sha")) is str,
            "current protected-main config file not verified")
    try:
        return parse_json(base64.b64decode(source["content"], validate=True))
    except (ValueError, TypeError) as e:
        raise Denied("current protected-main config bytes malformed") from e


def bind(*, repository, event, witness, fleet, central_policy, lifecycle,
         api=github, download=original_file, today=None):
    """Join protected main witness -> scheduled origin -> original decision.

    Scanning is bounded to a complete 100-run GitHub listing. A missing/expired
    origin is DENY, not approval. An older identical candidate is valid only
    after the complete SHA/version decision is checked against main pins.
    """
    require(type(repository) is str and REPO.fullmatch(repository)
            and type(event) is dict and event.get("ref") == "refs/heads/main"
            and (event.get("repository") or {}).get("full_name") == repository
            and event.get("created") is False and event.get("deleted") is False
            and type(event.get("after")) is str and SHA.fullmatch(event["after"])
            and type(witness) is dict
            and witness.get("repository") == repository
            and witness.get("mainMergeSha") == event["after"]
            and type(witness.get("candidatePr")) is int
            and witness["candidatePr"] > 0
            and type(witness.get("candidateBranch")) is str
            and BRANCH.fullmatch(witness["candidateBranch"]),
            "untrusted main-push witness or candidate identity")
    after = event["after"]
    branch = api(repository, "branches/main")
    require((branch.get("commit") or {}).get("sha") == after,
            "main advanced since original protected candidate push")
    pr = api(repository, "pulls/" + str(witness["candidatePr"]))
    manifest = only_manifest(api(repository, "contents/config/extension.json?ref=" + after),
                             "config/extension.json")
    local = only_manifest(api(repository, "contents/config/candidate-build.json?ref=" + after),
                          "config/candidate-build.json")
    inventory = api(repository, "actions/runs?per_page=100")
    require(type(inventory) is dict and type(inventory.get("total_count")) is int
            and 0 <= inventory["total_count"] < 100
            and type(inventory.get("workflow_runs")) is list
            and len(inventory["workflow_runs"]) == inventory["total_count"],
            "scheduled run list missing, duplicated or truncated; do not guess origin")
    merged_at = pr.get("merged_at")
    require(type(merged_at) is str and merged_at
            and type(pr.get("created_at")) is str,
            "candidate merge chronology is unavailable")
    matches = []
    for run in inventory["workflow_runs"]:
        if not (type(run) is dict and run.get("path") == WORKFLOW
                and run.get("name") == NAME
                and run.get("event") == "schedule"
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and run.get("head_branch") == "main"
                and type(run.get("head_sha")) is str
                and SHA.fullmatch(run["head_sha"])
                and type(run.get("id")) is int and run["id"] > 0
                and type(run.get("created_at")) is str
                and run["created_at"] < merged_at):
            continue
        artifacts = api(repository, "actions/runs/" + str(run["id"]) + "/artifacts?per_page=100")
        require(type(artifacts) is dict and type(artifacts.get("total_count")) is int
                and 0 <= artifacts["total_count"] < 100
                and type(artifacts.get("artifacts")) is list
                and len(artifacts["artifacts"]) == artifacts["total_count"],
                "candidate artifact inventory incomplete")
        eligible = [a for a in artifacts["artifacts"] if type(a) is dict
                    and a.get("name") == "candidate-decision"]
        require(len(eligible) <= 1, "duplicate original decisions in a schedule run")
        if not eligible:
            continue
        artifact = eligible[0]
        require(artifact.get("expired") is False
                and type(artifact.get("id")) is int and artifact["id"] > 0
                and type(artifact.get("size_in_bytes")) is int
                and 0 < artifact["size_in_bytes"] < 256_000
                and (artifact.get("workflow_run") or {}).get("id") == run["id"]
                and (artifact.get("workflow_run") or {}).get("head_sha") == run["head_sha"],
                "original scheduled candidate artifact is not bound to real run")
        decision = download(repository, run["id"])
        if type(decision) is not dict or decision.get("branch") != witness["candidateBranch"]:
            continue
        # Never skip a malformed *matching* original decision and substitute an older one.
        try:
            approved = intent.plan(
                witness=witness, decision=decision, pr=pr, manifest=manifest,
                lifecycle=lifecycle, fleet=fleet, central_policy=central_policy,
                local_candidate_policy=local, today=today or date.today())
        except (intent.Denied, ValueError, KeyError, TypeError) as exc:
            raise Denied("original candidate decision does not match protected main: " + str(exc)) from exc
        matches.append((run["created_at"], run["id"], artifact["id"], approved))
    require(bool(matches), "no authenticated scheduled original decision matches candidate")
    matches.sort(reverse=True, key=lambda item: (item[0], item[1]))
    _, original_run_id, original_artifact_id, result = matches[0]
    result["originalDecisionRunId"] = original_run_id
    result["originalDecisionArtifactId"] = original_artifact_id
    require(result.get("publicationAuthorized") is False
            and result.get("publishableReceipt") is False
            and result.get("signedArtifactsVerified") is False
            and result.get("automaticReleaseEnabled") is False,
            "original decision binder cannot authorize publishing")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", required=True)
    parser.add_argument("--witness", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    try:
        require(os.environ.get("GITHUB_EVENT_NAME") == "push"
                and os.environ.get("GITHUB_REF") == "refs/heads/main"
                and type(os.environ.get("GITHUB_SHA")) is str
                and bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
                and os.environ.get("GITHUB_EVENT_PATH"),
                "trusted real main push GitHub runner required")
        event = parse_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_text("utf-8"))
        require(event.get("after") == os.environ["GITHUB_SHA"],
                "main push event SHA not equal to Actions runtime SHA")
        root = Path(args.build_root)
        def config(name):
            return parse_json((root / "metadata" / name).read_text("utf-8"))
        witness = parse_json(Path(args.witness).read_text("utf-8"))
        result = bind(repository=os.environ["GITHUB_REPOSITORY"],
                      event=event, witness=witness,
                      fleet=config("automation-fleet.json"),
                      central_policy=config("release-promotion.json"),
                      lifecycle=config("postgresql.json"))
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n", "utf-8")
        print(result["status"] + ": decision " + str(result["originalDecisionRunId"]))
        return 0
    except (Denied, OSError, KeyError, TypeError, ValueError,
            subprocess.TimeoutExpired) as err:
        print("LIVE_SIGNED_BUILD_INTENT_DENY: " + str(err), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
