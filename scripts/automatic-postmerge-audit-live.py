#!/usr/bin/env python3
"""Trusted main-push READ-ONLY witness, joining real signed-bound candidate inputs.

Cannot create a GitHub Release, Publisher receipt, tag, or any API write.
Intended for protected `push` of a single reviewed candidate manifest.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

bridge = load("postmerge_bridge", "automatic-postmerge-audit-bridge.py")
binder = load("native_join", "bind-native-candidate-audit.py")
downloaded = load("native_live", "bind-native-candidate-audit-live.py")
contents = load("postmerge_contents", "github_contents.py")

SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def gh(repo, suffix):
    require(type(repo) is str and REPO.fullmatch(repo), "invalid repository")
    allow = [
        r"commits/[0-9a-f]{40}",
        r"commits/[0-9a-f]{40}/pulls\?per_page=100",
        r"pulls/[1-9][0-9]*",
        r"pulls/[1-9][0-9]*/files\?per_page=100",
        r"branches/main",
        r"commits/[0-9a-f]{40}/check-runs\?per_page=100",
        r"contents/config/extension.json\?ref=[0-9a-f]{40}",
        r"actions/runs\?event=workflow_run&head_sha=[0-9a-f]{40}&per_page=100",
        r"actions/runs/[1-9][0-9]*/artifacts\?per_page=100",
        r"actions/runs/[1-9][0-9]*",
    ]
    require(type(suffix) is str and any(re.fullmatch(x, suffix) for x in allow),
            "GitHub path not expressly GET allowlisted")
    p = subprocess.run(["gh","api","--method","GET","repos/"+repo+"/"+suffix],
                       capture_output=True, text=True, timeout=45, check=False)
    require(p.returncode == 0 and len(p.stdout) < 3 * 1024 * 1024,
            "authenticated GitHub REST GET failed/incomplete")
    return json.loads(p.stdout)


def audit_inventory(runs):
    """Reject pagination, duplicate run IDs, ambiguous or missing audit candidates."""
    require(type(runs) is dict
            and type(runs.get("total_count")) is int
            and 0 <= runs["total_count"] < 100
            and type(runs.get("workflow_runs")) is list
            and len(runs["workflow_runs"]) == runs["total_count"],
            "incomplete historical audit run listing")
    eligible = [x for x in runs["workflow_runs"] if type(x) is dict
                and x.get("name") == "Upstream candidate after verified central daily fleet scan"
                and x.get("path") == ".github/workflows/update-watch.yml"
                and x.get("event") == "workflow_run"
                and x.get("status") == "completed"
                and x.get("conclusion") == "success"
                and type(x.get("id")) is int and x["id"] > 0]
    require(len({x["id"] for x in eligible}) == len(eligible),
            "duplicate authoritative historical audit run IDs")
    return eligible


def eligible_artifact(artifacts, audit_run):
    require(type(artifacts) is dict and type(artifacts.get("total_count")) is int
            and 0 <= artifacts["total_count"] < 100
            and type(artifacts.get("artifacts")) is list
            and len(artifacts["artifacts"]) == artifacts["total_count"],
            "incomplete native candidate artifact inventory")
    rows = [x for x in artifacts["artifacts"]
            if type(x) is dict and x.get("name") == "candidate-audit-native-pr"
            and x.get("expired") is False
            and (x.get("workflow_run") or {}).get("id") == audit_run]
    require(len(rows) <= 1, "duplicate audit artifact within a single run")
    return rows[0] if rows else None


def live(repo, event, fleet, lifecycle, *, auth_api=gh, retrieve=None):
    """Return a proven *nonpublishing* observation using authentic run bytes."""
    require(type(repo) is str and REPO.fullmatch(repo)
            and type(event) is dict and event.get("ref") == "refs/heads/main"
            and (event.get("repository") or {}).get("full_name") == repo
            and type(event.get("after")) is str and SHA.fullmatch(event["after"])
            and type(event.get("before")) is str and SHA.fullmatch(event["before"]),
            "not an authenticated main push")
    before, after = event["before"], event["after"]
    base = "repos/" + repo + "/"
    def get(suffix):
        return auth_api(repo, suffix)
    commit = get("commits/" + after)
    linked = get("commits/" + after + "/pulls?per_page=100")
    require(type(linked) is list and len(linked) == 1
            and type(linked[0]) is dict and type(linked[0].get("number")) is int
            and linked[0]["number"] > 0, "ambiguous associated GitHub PR")
    n = linked[0]["number"]
    pr = get("pulls/" + str(n))
    require(pr.get("number") == n, "associated merged PR differs")
    files = get("pulls/" + str(n) + "/files?per_page=100")
    branch = get("branches/main")
    head = (pr.get("head") or {}).get("sha")
    require(type(head) is str and SHA.fullmatch(head), "candidate PR head invalid")
    checks = get("commits/" + head + "/check-runs?per_page=100")
    manifest = get("contents/config/extension.json?ref=" + after)
    require(type(manifest) is dict and manifest.get("path") == "config/extension.json"
            and manifest.get("encoding") == "base64"
            and type(manifest.get("content")) is str
            and type(files) is list and len(files) == 1
            and manifest.get("sha") == files[0].get("sha")
            and type(commit.get("files")) is list and len(commit["files"]) == 1
            and manifest.get("sha") == commit["files"][0].get("sha"),
            "merged manifest blob does not equal PR and current main")
    try:
        extension = contents.decode_json_file(manifest, "config/extension.json")
    except (ValueError, TypeError) as e:
        raise Denied("invalid immutable current-main source manifest") from e
    require(type(extension) is dict and extension.get("name") == repo.split("/")[1],
            "manifest does not match protected repository")
    history = audit_inventory(get("actions/runs?event=workflow_run&head_sha="
                                  + before + "&per_page=100"))
    matched = []
    for run in history:
        if run.get("head_sha") != before:
            continue
        artifacts = get("actions/runs/" + str(run["id"]) + "/artifacts?per_page=100")
        a = eligible_artifact(artifacts, run["id"])
        if a is None:
            continue
        require(type(a.get("id")) is int and a["id"] > 0
                and type(a.get("size_in_bytes")) is int
                and a["size_in_bytes"] > 0,
                "malformed real audit artifact metadata")
        if retrieve is None:
            with tempfile.TemporaryDirectory() as path:
                p = subprocess.run(["gh","run","download",str(run["id"]),
                    "--repo",repo,"--name","candidate-audit-native-pr",
                    "--dir",path],capture_output=True,text=True,timeout=90,
                    check=False)
                require(p.returncode == 0, "candidate audit download failed")
                context, audit = downloaded.strictly_read_audit(Path(path))
        else:
            context, audit = retrieve(run, a)
        # Other candidates' audit artifacts on the SAME trusted base main
        # must not stop discovery. Only matching PR+SHA+repository proceed.
        if (type(context) is not dict or context.get("candidatePr") != n
                or context.get("candidateHeadSha") != head):
            continue
        ci_id = context.get("candidateRunId")
        require(type(ci_id) is int and ci_id > 0, "native audit CI ID invalid")
        ci = get("actions/runs/" + str(ci_id))
        try:
            bound = binder.join(
                context=context,audit=audit,ext=extension,lifecycle=lifecycle,
                ci_run=ci,audit_run=run,artifact=a,repository=repo,
                current_main_sha=before)
        except (binder.Denied, ValueError, TypeError, KeyError) as exc:
            raise Denied("matched native audit failed SHA/ZIP binding: "+str(exc)) from exc
        matched.append(bound)
    require(len(matched) == 1, "unique prior authentic candidate audit is absent or ambiguous")
    try:
        result = bridge.verify(repository=repo,event=event,commit=commit,
            pr=pr,pr_files=files,branch=branch,checks=checks,
            bound=matched[0],manifest=extension,lifecycle=lifecycle,fleet=fleet)
    except (bridge.Denied, ValueError, TypeError, KeyError) as exc:
        raise Denied("postmerge bridge refused untrusted main event: "+str(exc)) from exc
    require(result.get("publicationAuthorized") is False
            and result.get("publishableReceipt") is False
            and result.get("signedArtifactsVerified") is False,
            "read-only stage illegally attempted publication")
    return result


def main():
    a=argparse.ArgumentParser()
    a.add_argument("--build-root",default=".")
    a.add_argument("--out",required=True)
    args=a.parse_args()
    try:
        repo=os.environ.get("GITHUB_REPOSITORY","")
        event_path=os.environ.get("GITHUB_EVENT_PATH","")
        require(type(repo) is str and REPO.fullmatch(repo)
                and os.environ.get("GITHUB_EVENT_NAME")=="push"
                and os.environ.get("GITHUB_REF")=="refs/heads/main"
                and bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
                and bool(event_path)
                and os.environ.get("GITHUB_SHA"), "real protected main/push GitHub runner required")
        event=json.loads(Path(event_path).read_text("utf-8"))
        require(event.get("after")==os.environ["GITHUB_SHA"],
                "GitHub push SHA differs from actual workflow identity")
        root=Path(args.build_root)
        fleet=json.loads((root/"metadata/automation-fleet.json").read_text("utf-8"))
        life=json.loads((root/"metadata/postgresql.json").read_text("utf-8"))
        result=live(repo,event,fleet,life)
        Path(args.out).write_text(json.dumps(result,indent=2)+"\n","utf-8")
        print("AUTHENTICATED_MAIN_PUSH_NATIVE_AUDIT_NONPUBLISHING",result["status"])
        return 0
    except (Denied, OSError, TypeError, KeyError, ValueError,
            subprocess.TimeoutExpired) as e:
        print("AUTOMATIC_POSTMERGE_AUDIT_DENY:",str(e),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
