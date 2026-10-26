#!/usr/bin/env python3
"""Read-only bridge for real build/main scheduled original Windows CI receipts.

A successful central *schedule* never impersonates the extension-local
workflow_run, and never authorizes signatures, Release, tags or publishing.
The caller must still enforce a single genuine protected main/push merge.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("central_original_binder",
    HERE/"bind-native-candidate-audit.py")
binder=importlib.util.module_from_spec(spec)
spec.loader.exec_module(binder)

CENTRAL="pgextwin/build"
ARTIFACT="registered-original-native-pr-audits"
PATHS={
    ".github/workflows/recover-native-pr-fleet.yml":
        ("Hourly central recovery of approved original native PR artifacts (NONPUBLISHING)",
         "Independent approved attempt and original ZIP/SPDX/Grype audit (no Release)"),
    ".github/workflows/fleet-upstream-watch.yml":
        ("Hourly stable upstream updates for all 17 extensions",
         "Independent original PR artifacts audit (genuine fleet schedule only; NO PUBLISH)"),
}
REPO=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
SHA=re.compile(r"^[0-9a-f]{40}$")
class Denied(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Denied(why)

def gh(repo, endpoint):
    require(type(repo) is str and REPO.fullmatch(repo), "untrusted repo")
    allow=(endpoint=="branches/main"
           or endpoint=="actions/runs?event=schedule&per_page=100"
           or re.fullmatch(r"actions/runs/[1-9][0-9]*",endpoint)
           or re.fullmatch(r"actions/runs/[1-9][0-9]*/jobs\?per_page=100",endpoint)
           or re.fullmatch(r"actions/runs/[1-9][0-9]*/artifacts\?per_page=100",endpoint))
    require(allow and (repo==CENTRAL or endpoint.startswith("actions/runs/")),
            "unallowlisted central schedule GET")
    p=subprocess.run(["gh","api","--method","GET","repos/"+repo+"/"+endpoint],
                     capture_output=True,text=True,check=False,timeout=50)
    require(p.returncode==0 and len(p.stdout)<3_000_000,
            "authenticated central GitHub GET denied or oversized")
    return json.loads(p.stdout)

def download_original(run, artifact, target):
    require(type(target) is str and REPO.fullmatch(target),"invalid target")
    with tempfile.TemporaryDirectory(prefix="central-original-native-") as tmp:
        p=subprocess.run(["gh","run","download",str(run["id"]),
                          "--repo",CENTRAL,"--name",ARTIFACT,"--dir",tmp],
                         capture_output=True,text=True,check=False,timeout=150)
        require(p.returncode==0,"original central schedule artifact download failed")
        root=Path(tmp)
        files=list(root.iterdir())
        require(0<len(files)<100 and all(
            f.is_file() and not f.is_symlink() and
            f.resolve().parent==root.resolve() and
            re.fullmatch(r"pgextwin_[a-z][a-z0-9_]*\.json",f.name) and
            0<f.stat().st_size<256_000 for f in files),
            "unsafe or incomplete schedule audit artifact members")
        file=root/(target.replace("/","_")+".json")
        require(file in files,"exact target original native audit file missing")
        return json.loads(file.read_text(encoding="utf-8"))

def recover(repo,before,head,pr,manifest,lifecycle,*,api=gh,download=download_original):
    """Bind only the newest successful actual audit job for this precise base."""
    require(type(repo) is str and REPO.fullmatch(repo)
            and repo!=CENTRAL and type(before) is str and SHA.fullmatch(before)
            and type(head) is str and SHA.fullmatch(head)
            and type(pr) is int and pr>0,
            "invalid original native candidate merge context")
    main=api(CENTRAL,"branches/main")
    require(type(main) is dict and main.get("name")=="main"
            and main.get("protected") is True
            and type((main.get("commit") or {}).get("sha")) is str
            and SHA.fullmatch(main["commit"]["sha"]),
            "central audit source is not current protected build/main")
    central_sha=main["commit"]["sha"]
    inv=api(CENTRAL,"actions/runs?event=schedule&per_page=100")
    require(type(inv) is dict and type(inv.get("total_count")) is int
            and type(inv.get("workflow_runs")) is list
            and len(inv["workflow_runs"])<=100
            and len(inv["workflow_runs"])<=inv["total_count"]
            and len({r.get("id") for r in inv["workflow_runs"]
                     if type(r) is dict})==len(inv["workflow_runs"]),
            "untrusted or duplicate central schedule run inventory")
    runs=[r for r in inv["workflow_runs"] if type(r) is dict
          and r.get("path") in PATHS
          and r.get("name")==PATHS[r["path"]][0]
          and r.get("event")=="schedule"
          and r.get("run_attempt")==1
          and r.get("head_sha")==central_sha
          and r.get("head_branch")=="main"
          and r.get("status")=="completed"
          and r.get("conclusion")=="success"
          and type(r.get("id")) is int and r["id"]>0]
    runs.sort(key=lambda row:row["id"],reverse=True)
    for indexed in runs:
        run=api(CENTRAL,"actions/runs/"+str(indexed["id"]))
        require(type(run) is dict and run.get("id")==indexed["id"]
                and run.get("path")==indexed["path"]
                and run.get("name")==indexed["name"]
                and run.get("event")=="schedule"
                and run.get("run_attempt")==1
                and run.get("head_sha")==central_sha
                and run.get("head_branch")=="main"
                and (run.get("repository") or {}).get("full_name")==CENTRAL
                and run.get("status")=="completed"
                and run.get("conclusion")=="success",
                "central schedule Run changed or is replayed")
        jobs=api(CENTRAL,"actions/runs/"+str(run["id"])+"/jobs?per_page=100")
        require(type(jobs) is dict and type(jobs.get("total_count")) is int
                and 0<=jobs["total_count"]<100 and type(jobs.get("jobs")) is list
                and len(jobs["jobs"])==jobs["total_count"],
                "central audit job inventory incomplete")
        eligible=[j for j in jobs["jobs"] if type(j) is dict
                  and j.get("name")==PATHS[run["path"]][1]]
        require(len(eligible)<=1,"ambiguous scheduled original audit jobs")
        if not eligible or eligible[0].get("conclusion")=="skipped":
            continue
        job=eligible[0]
        require(job.get("status")=="completed" and job.get("conclusion")=="success",
                "central original schedule job is not a successful audit")
        inventory=api(CENTRAL,"actions/runs/"+str(run["id"])+"/artifacts?per_page=100")
        require(type(inventory) is dict and type(inventory.get("total_count")) is int
                and 0<=inventory["total_count"]<100
                and type(inventory.get("artifacts")) is list
                and len(inventory["artifacts"])==inventory["total_count"],
                "central native artifact inventory missing or truncated")
        found=[a for a in inventory["artifacts"] if type(a) is dict
               and a.get("name")==ARTIFACT]
        require(len(found)==1,"no unique genuine central audit artifact")
        a=found[0]
        receipt=download(run,a,repo)
        require(type(receipt) is dict and type(receipt.get("native")) is dict
                and type(receipt.get("candidateAudit")) is dict,
                "central native audit evidence malformed")
        context,audit=receipt["native"],receipt["candidateAudit"]
        require(context.get("candidatePr")==pr
                and context.get("candidateHeadSha")==head
                and receipt.get("targetRepository")==repo
                and receipt.get("targetMainSha")==before,
                "central original audit not bound to unchanged PR/base")
        ci=api(repo,"actions/runs/"+str(context.get("candidateRunId")))
        try:
            return binder.join(context=context,audit=audit,ext=manifest,
                               lifecycle=lifecycle,ci_run=ci,
                               audit_run=run,artifact=a,audit_job=job,
                               central_receipt=receipt,repository=repo,
                               current_main_sha=before)
        except (binder.Denied,KeyError,TypeError,ValueError) as exc:
            raise Denied("central original job and ZIP audit denied: "+str(exc)) from exc
    raise Denied("no genuine schedule original native audit for protected candidate")

if __name__=="__main__":
    raise SystemExit("Library only: PUBLISH_DENY")
