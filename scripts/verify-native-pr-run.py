#!/usr/bin/env python3
"""Authenticate a completed *native* candidate PR CI run (NO publication).

Used only by trusted main workflow_run after the Windows CI/CD check succeeds.
Downloads per-major artifacts in a separately audited step. No GitHub writes,
no token from candidate branch, no release authorization or policy override.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SHA=re.compile(r"^[0-9a-f]{40}$")
REPO=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
OWNED=re.compile(r"^auto-candidate/([0-9a-f]{20})$")
class Denied(ValueError): pass

def require(x,msg):
    if not x: raise Denied(msg)

def validate(repo, run, pr, pr_files, merge_ref, main, checks, associated_pulls=None):
    require(type(repo) is str and REPO.fullmatch(repo), "unsafe target repository")
    require(type(run) is dict and run.get("event")=="pull_request"
            and run.get("name")=="Windows CI/CD"
            and run.get("status")=="completed" and run.get("conclusion")=="success"
            and type(run.get("id")) is int and run["id"]>0
            and run.get("head_repository",{}).get("full_name")==repo
            and type(run.get("pull_requests")) is list
            and len(run["pull_requests"]) <= 1
            and isinstance(run.get("head_branch"),str)
            and SHA.fullmatch(run.get("head_sha","")),
            "not an exact completed authenticated native PR Windows workflow")
    head, branch = run["head_sha"], run["head_branch"]
    owned=OWNED.fullmatch(branch)
    require(owned is not None, "Windows run does not belong to an auto-candidate")
    require(type(pr) is dict and pr.get("state")=="open"
            and pr.get("merged") is False
            and (pr.get("head") or {}).get("ref")==branch
            and (pr.get("head") or {}).get("sha")==head
            and (pr.get("head") or {}).get("repo",{}).get("full_name")==repo
            and (pr.get("base") or {}).get("ref")=="main"
            and (pr.get("base") or {}).get("repo",{}).get("full_name")==repo
            and (pr.get("user") or {}).get("login")=="github-actions[bot]"
            and type(pr.get("number")) is int and pr["number"]>0
            and "<!-- pgextwin-candidate:v1:"+owned.group(1)+" -->" in (pr.get("body") or ""),
            "candidate not owned or exact head/target moved")
    # GitHub can return [] in workflow_run.pull_requests even for a real
    # pull_request run (observed on actual HypoPG Windows Run40185975511).
    # Only an independent REST commit-to-PR GET may restore the missing join.
    # Never guess from the branch, PR title, actor or newest open PR.
    if associated_pulls is not None:
        require(type(associated_pulls) is list and len(associated_pulls)==1,
                "missing or ambiguous independent exact-HEAD PR association")
        linked=associated_pulls[0]
        require(type(linked) is dict and linked.get("number")==pr["number"]
                and (linked.get("head") or {}).get("sha")==head
                and (linked.get("head") or {}).get("ref")==branch
                and (linked.get("head") or {}).get("repo",{}).get("full_name")==repo
                and (linked.get("base") or {}).get("ref")=="main"
                and (linked.get("base") or {}).get("repo",{}).get("full_name")==repo,
                "independent commit association disagrees with exact bot PR")
    elif not run["pull_requests"]:
        raise Denied("empty run PR inventory requires independent commit association")
    if run["pull_requests"]:
        meta=run["pull_requests"][0]
        require(meta.get("number")==pr["number"]
                and (meta.get("head") or {}).get("sha")==head
                and (meta.get("head") or {}).get("ref")==branch
                and (meta.get("base") or {}).get("ref")=="main"
                and (meta.get("head") or {}).get("repo",{}).get("name")==repo.split("/")[1]
                and (meta.get("base") or {}).get("repo",{}).get("name")==repo.split("/")[1],
                "run PR metadata disagrees with exact bot candidate")
    require(type(pr_files) is list and len(pr_files)==1
            and pr_files[0].get("filename")=="config/extension.json"
            and pr_files[0].get("status")=="modified"
            and isinstance(pr_files[0].get("sha"),str)
            and SHA.fullmatch(pr_files[0]["sha"]),
            "candidate modifies files other than pinned manifest")
    require(type(merge_ref) is dict
            and (merge_ref.get("object") or {}).get("type")=="commit"
            and isinstance((merge_ref.get("object") or {}).get("sha"),str)
            and SHA.fullmatch(merge_ref["object"]["sha"])
            and pr.get("merge_commit_sha")==merge_ref["object"]["sha"],
            "synthetic PR merge reference moved or missing")
    require(type(main) is dict and main.get("name")=="main"
            and main.get("protected") is True
            and (main.get("commit") or {}).get("sha")==(pr.get("base") or {}).get("sha"),
            "candidate base is stale or main not protected")
    required=((main.get("protection") or {}).get("required_status_checks") or {}).get("checks")
    require(type(required) is list
            and any(c.get("context")=="Windows required summary" and c.get("app_id")==15368
                    for c in required if type(c) is dict), "required App15368 CI not enforced")
    require(type(checks) is dict and type(checks.get("total_count")) is int
            and checks["total_count"]<100 and type(checks.get("check_runs")) is list,
            "incomplete candidate head check-run inventory")
    matches=[c for c in checks["check_runs"] if type(c) is dict
             and c.get("name")=="Windows required summary"
             and c.get("head_sha")==head and (c.get("app") or {}).get("id")==15368
             and c.get("status")=="completed" and c.get("conclusion")=="success"]
    require(len(matches)==1,"exact-head App15368 Windows required summary not proven")
    return {"schemaVersion":1,"status":"NATIVE_PR_CI_AUTHENTICATED_NOT_PUBLISHABLE",
            "repository":repo,"candidatePr":pr["number"],"branch":branch,
            "candidateHeadSha":head,"packagingMergeSha":merge_ref["object"]["sha"],
            "candidateRunId":run["id"],"matrixResult":"success",
            "candidateAuditVerified":False,"signedArtifactsVerified":False,
            "publishableReceipt":False,"publicationAuthorized":False}

def gh_get(repo, endpoint):
    require(type(repo) is str and REPO.fullmatch(repo),"invalid GitHub owner/repository")
    require(type(endpoint) is str and (
        re.fullmatch(r"actions/runs/[1-9][0-9]*",endpoint)
        or re.fullmatch(r"pulls/[1-9][0-9]*",endpoint)
        or re.fullmatch(r"pulls/[1-9][0-9]*/files\?per_page=100",endpoint)
        or re.fullmatch(r"git/ref/pull/[1-9][0-9]*/merge",endpoint)
        or re.fullmatch(r"commits/[a-f0-9]{40}/pulls\?per_page=100",endpoint)
        or endpoint=="branches/main"
        or re.fullmatch(r"commits/[a-f0-9]{40}/check-runs\?per_page=100",endpoint)),
        "GitHub GET path not allowlisted")
    p=subprocess.run(["gh","api","--method","GET","repos/"+repo+"/"+endpoint],
                     capture_output=True,text=True,timeout=40,check=False)
    require(p.returncode==0 and len(p.stdout)<2*1024*1024,
            "independent authenticated GitHub GET unavailable or too large")
    return json.loads(p.stdout)

def live(repo, run_id, event):
    require(os.environ.get("GITHUB_EVENT_NAME")=="workflow_run"
            and os.environ.get("GITHUB_REF")=="refs/heads/main"
            and os.environ.get("GITHUB_REPOSITORY")==repo
            and bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")),
            "not a trusted main workflow_run environment")
    require(type(event) is dict and event.get("action")=="completed"
            and (event.get("repository") or {}).get("full_name")==repo
            and (event.get("workflow_run") or {}).get("id")==run_id,
            "event does not bind exact completed run")
    run=gh_get(repo,"actions/runs/"+str(run_id))
    require((event["workflow_run"]).get("head_sha")==run.get("head_sha")
            and (event["workflow_run"]).get("conclusion")=="success"
            and (event["workflow_run"]).get("event")=="pull_request"
            and (event["workflow_run"]).get("name")=="Windows CI/CD",
            "event payload differs from live run")
    # Always obtain an independent original GitHub commit->PR association.
    # The Actions run's pull_requests can legally be [] on a real PR run.
    associated=gh_get(repo,"commits/"+run["head_sha"]+"/pulls?per_page=100")
    require(type(associated) is list and len(associated)==1
            and type(associated[0]) is dict
            and type(associated[0].get("number")) is int
            and associated[0]["number"]>0,
            "missing/ambiguous independent exact-HEAD PR identity")
    num=associated[0]["number"]
    pr=gh_get(repo,"pulls/"+str(num))
    files=gh_get(repo,"pulls/"+str(num)+"/files?per_page=100")
    merge=gh_get(repo,"git/ref/pull/"+str(num)+"/merge")
    main=gh_get(repo,"branches/main")
    checks=gh_get(repo,"commits/"+run["head_sha"]+"/check-runs?per_page=100")
    return validate(repo,run,pr,files,merge,main,checks,
                    associated_pulls=associated)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--run-id",type=int,required=True)
    p.add_argument("--output",required=True)
    args=p.parse_args()
    try:
        repo=os.environ["GITHUB_REPOSITORY"]
        event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text("utf-8"))
        result=live(repo,args.run_id,event)
        out=Path(args.output)
        out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"],"a",encoding="utf-8") as o:
                for key, field in (("branch","branch"),("head","candidateHeadSha"),
                                   ("merge","packagingMergeSha"),("pr","candidatePr")):
                    o.write(key+"="+str(result[field])+"\n")
        print("NATIVE_CANDIDATE_READONLY_PROVENANCE="+result["status"])
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired) as exc:
        print("NATIVE_CANDIDATE_CI_DENIED:",str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
