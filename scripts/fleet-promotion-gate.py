#!/usr/bin/env python3
"""14-extension manually confirmed promotion authorization (NO GitHub writes).

Security invariant: only a human-triggered main workflow_dispatch with explicit
PUBLISH, live central opt-in, merged bot manifest-only PR, exact candidate
decision/run and per-major VERIFIED ZIP/SBOM/Grype can produce a receipt.
This script is not a publisher and does not reserve or publish any Release.
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

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("fleet_identity",ROOT/"fleet-release-identity.py")
ident=importlib.util.module_from_spec(spec);spec.loader.exec_module(ident)
SHA=re.compile(r"^[0-9a-f]{40}$")
HASH=re.compile(r"^[0-9a-f]{64}$")
CANDIDATE=re.compile(r"^auto-candidate/([a-f0-9]{20})$")
ACTOR=re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")

class Denied(ValueError):
    pass

def require(x,reason):
    if not x:
        raise Denied(reason)

def exec_checked(*args):
    p=subprocess.run(args,check=False,text=True,capture_output=True)
    if p.returncode:
        raise Denied("GitHub or git command failed closed: "+" ".join(args[:3])+" "+p.stderr[:250])
    return p.stdout

def api(path):
    return json.loads(exec_checked("gh","api",path))

def live_json(path):
    value=api("repos/pgextwin/build/contents/"+path+"?ref=main")
    require(value.get("encoding")=="base64" and isinstance(value.get("content"),str),
            "missing/malformed authoritative central policy")
    return json.loads(base64.b64decode(value["content"]).decode("utf-8"))

def artifact(repo,run_id,name,location):
    exec_checked("gh","run","download",str(run_id),"--repo",repo,
                 "--name",name,"--dir",str(location))
    found=list(location.rglob("*.json"))
    require(len(found)==1,"ambiguous/missing "+name+" evidence")
    return json.loads(found[0].read_text(encoding="utf-8-sig"))

def verify(repo,main_sha,tag,confirmation,actor,policy,fleet,local,ext,lifecycle,
           pr,pr_files,run,watch_run,decision,audit):
    require(repo == "pgextwin/"+str(ext.get("name")) and repo in {
        "pgextwin/"+name for name in ident.UPSTREAMS}, "unsupported fleet repository")
    require(type(policy) is dict and set(policy)=={
        "schemaVersion","allowedRepositories","releasePolicy"} and
        policy.get("schemaVersion")==1 and policy.get("releasePolicy")=="manual-dispatch"
        and isinstance(policy.get("allowedRepositories"),list)
        and len(set(policy["allowedRepositories"]))==len(policy["allowedRepositories"])
        and repo in policy["allowedRepositories"]
        and all(x in {"pgextwin/"+n for n in ident.UPSTREAMS}
                for x in policy["allowedRepositories"]), "central manual release not enabled for this repo")
    require(type(local) is dict and local=={
        "schemaVersion":1,"enabled":True,"releasePolicy":"manual-dispatch"
    }, "local main-only promotion policy not explicitly enabled")
    require(fleet.get("releasePolicy")=="manual-only" and fleet.get("scheduleUtc")=="0 0 * * *"
            and isinstance(fleet.get("entries"),list), "central fleet must remain manual-only")
    matches=[e for e in fleet["entries"] if e.get("repository")==repo]
    require(len(matches)==1 and matches[0].get("mode")=="BUILD"
            and matches[0].get("candidateEnabled") is True
            and matches[0].get("releasePolicy")=="manual-only",
            "central fleet BUILD opt-in missing")
    require(isinstance(main_sha,str) and SHA.fullmatch(main_sha), "invalid main SHA")
    require(confirmation=="PUBLISH" and isinstance(actor,str)
            and ACTOR.fullmatch(actor) and not actor.lower().endswith("bot"),
            "human operator explicit PUBLISH confirmation required")
    try:
        ident.validate_release_tag(ext,tag)
        majors=ident.maintained_majors(ext,lifecycle)
        sources=ident.sources(ext)
    except (ident.Denied,ValueError,KeyError,TypeError) as e:
        raise Denied("source and release identity failed: "+str(e)) from e
    require(type(pr) is dict and pr.get("merged") is True and pr.get("state")=="closed"
            and (pr.get("base") or {}).get("ref")=="main"
            and (pr.get("user") or {}).get("login")=="github-actions[bot]"
            and SHA.fullmatch((pr.get("head") or {}).get("sha",""))
            and SHA.fullmatch(pr.get("merge_commit_sha") or ""),
            "candidate must be bot-authored, merged to trusted main")
    branch=(pr.get("head") or {}).get("ref","")
    bm=CANDIDATE.fullmatch(branch)
    require(bm is not None and
            "<!-- pgextwin-candidate:v1:"+bm.group(1)+" -->" in (pr.get("body") or ""),
            "candidate branch or ownership marker invalid")
    require(type(pr_files) is list and len(pr_files)==1
            and pr_files[0].get("filename")=="config/extension.json",
            "candidate PR changed files other than extension manifest")
    require(run.get("event")=="workflow_dispatch" and run.get("status")=="completed"
            and run.get("conclusion")=="success" and run.get("head_branch")==branch
            and run.get("head_sha")==pr["head"]["sha"]
            and type(run.get("id")) is int,
            "candidate Windows run not verified on exact PR head")
    require(watch_run.get("head_branch")=="main" and
            watch_run.get("conclusion")=="success" and watch_run.get("status")=="completed"
            and type(watch_run.get("id")) is int,
            "upstream decision workflow did not succeed on main")
    require(decision.get("schemaVersion")==1 and decision.get("status")=="candidate"
            and decision.get("extension")==ext["name"]
            and decision.get("repository")==ext["upstream"]["repository"]
            and decision.get("releasePolicy")=="manual-only"
            and decision.get("branch")==branch
            and decision.get("candidateId")==bm.group(1),
            "candidate decision branch/upstream identity mismatch")
    updates=decision.get("updates")
    require(type(updates) is list and len(updates)>0, "empty or malformed decision")
    series=ext["upstream"].get("perPostgresql")
    updated=set()
    for u in updates:
        require(type(u) is dict and isinstance(u.get("commit"),str)
                and SHA.fullmatch(u["commit"]), "candidate update not SHA-pinned")
        major=u.get("major")
        if series is None:
            require(major is None and len(updates)==1, "uniform extension must have one update")
            key="all"
            source=sources[majors[-1]]
        else:
            require(type(major) is int and major in sources,
                    "unexpected per-PG candidate update")
            key=major
            source=sources[major]
        require(key not in updated and
                u["ref"]==source["ref"] and u["version"]==source["version"]
                and u["commit"]==source["commit"],
                "updated source differs from merged SHA-pinned manifest")
        updated.add(key)
    require(audit.get("schemaVersion")==1 and audit.get("status")=="VERIFIED"
            and audit.get("extension")==ext["name"]
            and audit.get("matrixResult")=="success"
            and audit.get("runId")==run["id"]
            and audit.get("branch")==branch and audit.get("branchSha")==pr["head"]["sha"],
            "candidate-audit identity/signature mismatch")
    items=audit.get("majors")
    require(type(items) is list and len(items)==len(majors)
            and sorted(x.get("major") for x in items)==majors,
            "incomplete/duplicated candidate major audit")
    for item in items:
        major=item["major"]; stem=ident.asset_stem(ext,major)
        require(item.get("status")=="SUCCESS"
                and item.get("sourceSha")==sources[major]["commit"]
                and isinstance(item.get("zipSha256"),str)
                and HASH.fullmatch(item["zipSha256"])
                and item.get("zip")==stem+".zip"
                and item.get("sbom")==stem+".spdx.json"
                and item.get("grype")==stem+".vulnerabilities.json",
                "candidate ZIP, SPDX, Grype or source SHA mismatch")
    return {
        "schemaVersion":1,"status":"VERIFIED_MANUAL_DISPATCH",
        "authorizationMode":"manual-dispatch","operator":actor,
        "repository":repo,"extension":ext["name"],"trustedCommit":main_sha,
        "releaseTag":tag,"majors":majors,
        "sources":[sources[m] for m in majors],
        "candidatePr":pr["number"],"candidateRunId":run["id"],
        "decisionRunId":watch_run["id"],"candidateId":bm.group(1)
    }

def main():
    p=argparse.ArgumentParser()
    for name in ("candidate-pr","candidate-run-id","decision-run-id"):
        p.add_argument("--"+name,required=True,type=int)
    for name in ("release-tag","confirm-release","extension","local-policy","lifecycle","output"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    try:
        repo=os.environ.get("GITHUB_REPOSITORY","")
        require(repo in {"pgextwin/"+n for n in ident.UPSTREAMS}
                and os.environ.get("GITHUB_REF")=="refs/heads/main"
                and os.environ.get("GITHUB_EVENT_NAME")=="workflow_dispatch",
                "only a manually dispatched trusted main is eligible")
        main_sha=os.environ.get("GITHUB_SHA","")
        require(SHA.fullmatch(main_sha), "invalid trusted SHA")
        main_head=api("repos/"+repo+"/branches/main")
        require(main_head["commit"]["sha"]==main_sha,
                "main advanced; operator must re-review")
        policy=live_json("metadata/release-promotion.json")
        fleet=live_json("metadata/automation-fleet.json")
        local=json.loads(Path(a.local_policy).read_text(encoding="utf-8"))
        ext=json.loads(Path(a.extension).read_text(encoding="utf-8"))
        lifecycle=json.loads(Path(a.lifecycle).read_text(encoding="utf-8"))
        pr=api("repos/"+repo+"/pulls/"+str(a.candidate_pr))
        require(type(pr) is dict and pr.get("merge_commit_sha"),"candidate PR absent")
        exec_checked("git","merge-base","--is-ancestor",pr["merge_commit_sha"],main_sha)
        pr_files=api("repos/"+repo+"/pulls/"+str(a.candidate_pr)+"/files?per_page=100")
        run=api("repos/"+repo+"/actions/runs/"+str(a.candidate_run_id))
        watch_run=api("repos/"+repo+"/actions/runs/"+str(a.decision_run_id))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            decision=artifact(repo,a.decision_run_id,"candidate-decision",root/"decision")
            audit=artifact(repo,a.candidate_run_id,"candidate-audit",root/"audit")
        receipt=verify(repo,main_sha,a.release_tag,a.confirm_release,
                       os.environ.get("GITHUB_ACTOR",""),policy,fleet,local,ext,
                       lifecycle,pr,pr_files,run,watch_run,decision,audit)
        Path(a.output).write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
        print("Fleet manual-only candidate and operator authorization VERIFIED; no Release published.")
        return 0
    except (Denied,ident.Denied,OSError,ValueError,KeyError,IndexError,TypeError) as e:
        print("FLEET PROMOTION DENIED (fail closed): "+str(e),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
