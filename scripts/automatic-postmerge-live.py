#!/usr/bin/env python3
"""Issue #75: live, read-only protected candidate-merge evidence resolution.

This is a *witness* for an eventual signed-release admission stage, NOT an
authorization, Signer or Publisher. Runs only on an authentic main/push event.
Fetches all GitHub PR/commit/CI/audit data independently with GET-only gh API
and inspects original native candidate audit artifact bytes. No GitHub writes.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

binder = load("issue75_native_candidate_binder", "bind-native-candidate-audit.py")
download = load("issue75_native_audit_download", "bind-native-candidate-audit-live.py")
bridge = load("issue75_protected_merge_bridge", "automatic-postmerge-audit-bridge.py")

SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
AUDIT_NAME = "candidate-audit-native-pr"
AUDIT_WORKFLOW = "Upstream candidate after verified central daily fleet scan"


class Denied(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise Denied(why)


def get(repo, path):
    require(type(repo) is str and REPO.fullmatch(repo)
            and type(path) is str
            and "\n" not in path and "\r" not in path
            and not path.startswith("/") and ".." not in path,
            "unsafe GitHub API target")
    cmd = ["gh", "api", "--method", "GET", "repos/" + repo + "/" + path]
    p = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=45)
    require(p.returncode == 0 and len(p.stdout) <= 3 * 1024 * 1024,
            "unavailable or oversized independently authenticated GitHub GET")
    return json.loads(p.stdout)


def candidate_audit_runs(page, *, parent_sha):
    """Return complete/success native-audit run candidates or fail closed."""
    require(type(parent_sha) is str and SHA.fullmatch(parent_sha),
            "missing exact previous protected-main SHA")
    require(type(page) is dict and type(page.get("total_count")) is int
            and 0 <= page["total_count"] < 100
            and type(page.get("workflow_runs")) is list
            and page["total_count"] == len(page["workflow_runs"]),
            "paginated/ambiguous workflow_run inventory")
    successes = []
    for entry in page["workflow_runs"]:
        require(type(entry) is dict, "malformed GitHub workflow_run inventory")
        if (entry.get("name") == AUDIT_WORKFLOW
                and entry.get("path") == ".github/workflows/update-watch.yml"
                and entry.get("event") == "workflow_run"
                and entry.get("head_sha") == parent_sha
                and entry.get("head_branch") == "main"
                and entry.get("status") == "completed"
                and entry.get("conclusion") == "success"):
            require(type(entry.get("id")) is int and entry["id"] > 0,
                    "missing authenticated successful audit run id")
            successes.append(entry)
    require(0 < len(successes) <= 20,
            "missing or excessive successful native-audit workflow runs")
    require(len({x["id"] for x in successes}) == len(successes),
            "duplicate successful audit run IDs")
    return successes


def authentic_run(repo, run_id, *, expected_sha):
    require(type(run_id) is int and run_id > 0, "invalid run id")
    run = get(repo, "actions/runs/" + str(run_id))
    require(type(run) is dict and run.get("id") == run_id
            and (run.get("repository") or {}).get("full_name") == repo
            and run.get("head_sha") == expected_sha,
            "untrusted live GitHub run identity")
    return run


def audit_artifact(repo, audit_run, *, pr_number, candidate_head):
    """Read actual ZIP bytes of exactly one artifact associated with this PR.

    Runs that audit another candidate are skipped; this does not downgrade
    failures or accept an unverified JSON supplied by the candidate branch.
    """
    run_id = audit_run["id"]
    inventory = get(repo, "actions/runs/" + str(run_id) + "/artifacts?per_page=100")
    require(type(inventory) is dict and type(inventory.get("total_count")) is int
            and 0 <= inventory["total_count"] < 100
            and type(inventory.get("artifacts")) is list
            and len(inventory["artifacts"]) == inventory["total_count"],
            "truncated audit artifact inventory")
    found = [x for x in inventory["artifacts"]
             if type(x) is dict and x.get("name") == AUDIT_NAME]
    # Other successful workflow_runs can have no applicable audit artifact.
    if len(found) == 0:
        return None
    require(len(found) == 1
            and type(found[0].get("id")) is int and found[0]["id"] > 0
            and found[0].get("expired") is False
            and type(found[0].get("size_in_bytes")) is int
            and found[0]["size_in_bytes"] > 0
            and (found[0].get("workflow_run") or {}).get("id") == run_id,
            "missing, duplicate or foreign real GitHub audit archive")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)
        p = subprocess.run(["gh", "run", "download", str(run_id),
                            "--repo", repo, "--name", AUDIT_NAME, "--dir", str(path)],
                           capture_output=True, text=True, check=False, timeout=90)
        require(p.returncode == 0, "original GitHub native audit ZIP bytes unavailable")
        context, audit = download.strictly_read_audit(path)
    if (context.get("candidatePr") != pr_number
            or context.get("candidateHeadSha") != candidate_head):
        return None
    require(context.get("status") == "NATIVE_PR_CI_AUTHENTICATED_NOT_PUBLISHABLE"
            and audit.get("status") == "VERIFIED",
            "candidate audit artifact is not authentic VERIFIED context")
    return found[0], context, audit


def live(*, repository, event, fleet, lifecycle):
    require(type(repository) is str and REPO.fullmatch(repository)
            and os.environ.get("GITHUB_EVENT_NAME") == "push"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_REPOSITORY") == repository
            and os.environ.get("GITHUB_ACTOR") == "ShutenOishi"
            and bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")),
            "only authenticated protected-main push from approved operator")
    require(type(event) is dict
            and (event.get("repository") or {}).get("full_name") == repository
            and event.get("ref") == "refs/heads/main"
            and type(event.get("before")) is str and SHA.fullmatch(event["before"])
            and event.get("after") == os.environ.get("GITHUB_SHA")
            and type(event.get("after")) is str and SHA.fullmatch(event["after"]),
            "current main-push event identity missing or moved")
    before, after = event["before"], event["after"]
    commit = get(repository, "commits/" + after)
    related = get(repository, "commits/" + after + "/pulls?per_page=100")
    require(type(related) is list and len(related) == 1
            and type(related[0].get("number")) is int,
            "ambiguous protected main merge PR")
    number = related[0]["number"]
    pr = get(repository, "pulls/" + str(number))
    files = get(repository, "pulls/" + str(number) + "/files?per_page=100")
    branch = get(repository, "branches/main")
    head = (pr.get("head") or {}).get("sha")
    require(type(head) is str and SHA.fullmatch(head), "invalid authentic PR head SHA")
    checks = get(repository, "commits/" + head + "/check-runs?per_page=100")
    # The merged source manifest comes from the exact protected-main SHA,
    # never from an attacker-supplied PR branch or workflow input.
    manifest_record = get(repository, "contents/config/extension.json?ref=" + after)
    require(type(manifest_record) is dict
            and manifest_record.get("encoding") == "base64"
            and manifest_record.get("path") == "config/extension.json"
            and type(manifest_record.get("content")) is str
            and type(commit.get("files")) is list and len(commit["files"]) == 1
            and manifest_record.get("sha") == commit["files"][0].get("sha"),
            "manifest bytes not bound to the one-file trusted squash merge")
    try:
        manifest = json.loads(base64.b64decode(manifest_record["content"]))
    except (ValueError, TypeError) as e:
        raise Denied("invalid actual merged source manifest JSON") from e
    require(type(manifest) is dict, "merged manifest not an object")
    # Only successful native candidate audit runs tied to the exact PREVIOUS
    # main SHA are in scope; old/stale main audits cannot certify this push.
    page = get(repository,
               "actions/runs?event=workflow_run&head_sha=" + before + "&per_page=100")
    candidates = candidate_audit_runs(page, parent_sha=before)
    verified = []
    for row in candidates:
        item = audit_artifact(repository, row, pr_number=number, candidate_head=head)
        if item is None:
            continue
        artifact, context, audited = item
        ci_id = context.get("candidateRunId")
        require(type(ci_id) is int and ci_id > 0, "missing original native CI id")
        real_ci = authentic_run(repository, ci_id, expected_sha=head)
        actual_audit_run = authentic_run(repository, row["id"], expected_sha=before)
        try:
            bound = binder.join(context=context, audit=audited,
                                ext=manifest, lifecycle=lifecycle,
                                ci_run=real_ci, audit_run=actual_audit_run,
                                artifact=artifact, repository=repository,
                                current_main_sha=before)
        except (binder.Denied, ValueError, TypeError, KeyError) as e:
            raise Denied("native audit identity/source binding rejected: " + str(e)) from e
        verified.append(bound)
    require(len(verified) == 1,
            "missing or ambiguous exact-head native signed-build candidate audit")
    try:
        result = bridge.verify(repository=repository, event=event, commit=commit,
                               pr=pr, pr_files=files, branch=branch,
                               checks=checks, bound=verified[0],
                               manifest=manifest, lifecycle=lifecycle, fleet=fleet)
    except (bridge.Denied, ValueError, KeyError, TypeError) as e:
        raise Denied("protected native-candidate merge rejected: " + str(e)) from e
    require(result["publicationAuthorized"] is False
            and result["publishableReceipt"] is False
            and result["signedArtifactsVerified"] is False
            and result["automaticReleaseEnabled"] is False,
            "read-only witness may never become a Publisher receipt")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fleet", required=True)
    parser.add_argument("--lifecycle", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    try:
        fleet = json.loads(Path(args.fleet).read_text("utf-8"))
        lifecycle = json.loads(Path(args.lifecycle).read_text("utf-8"))
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text("utf-8"))
        record = live(repository=os.environ.get("GITHUB_REPOSITORY", ""),
                      event=event, fleet=fleet, lifecycle=lifecycle)
        Path(args.out).write_text(json.dumps(record, indent=2) + "\n", "utf-8")
        print("NATIVE_POSTMERGE_AUTHENTICATED_NONPUBLISHING:", record["status"])
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired) as e:
        print("NATIVE_POSTMERGE_DENIED:", str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
