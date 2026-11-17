#!/usr/bin/env python3
"""Central genuine-schedule recovery of original candidate CI (READ-ONLY).

The locally emitted workflow_run can be SKIPPED when the original candidate
was awaiting GitHub approval. A later successful attempt does not necessarily
emit a fresh completed workflow_run. Do not rerun a green Windows workflow,
mutate the candidate or change its protected main (that would change the
synthetic merge SHA). Reconcile from independent protected build/main schedule.
Dynamic fleet is the sole membership source; never grant publication authority.
Jobless approval holds may instead yield a distinct dispatch byte-audit receipt;
that receipt is not native PR merge evidence and cannot enter the native binder.
"""
from __future__ import annotations
import argparse
import base64
from datetime import date
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

recovery = load("central_native_recovery", "scripts/recover-native-pr-candidate.py")
native = recovery.native
candidate = load("central_candidate_bytes", "scripts/verify-candidate.py")
Denied = native.Denied

def require(ok, why):
    if not ok:
        raise Denied(why)

def gh_json(repo, endpoint):
    require(native.REPO.fullmatch(repo or "") is not None, "nonregistered repo format")
    allowed = (endpoint == "branches/main" or
               endpoint == "pulls?state=open&per_page=100" or
               endpoint.startswith("actions/runs?event=pull_request&head_sha=") or
               endpoint.startswith("contents/config/extension.json?ref=") or
               endpoint.startswith("pulls/") or
               re.fullmatch(r"actions/runs\?event=workflow_dispatch&head_sha=[a-f0-9]{40}&per_page=100",endpoint) or
               re.fullmatch(r"actions/runs/[1-9][0-9]*(/jobs\?per_page=100)?",endpoint) or
               re.fullmatch(r"commits/[a-f0-9]{40}/(pulls|check-runs)\?per_page=100",endpoint))
    require(allowed, "unexpected GitHub GET endpoint")
    p = subprocess.run(["gh","api","--method","GET","repos/"+repo+"/"+endpoint],
                       capture_output=True,text=True,check=False,timeout=60)
    require(p.returncode == 0 and len(p.stdout) < 2_000_000,
            "authenticated GitHub GET failed: " + repo)
    return json.loads(p.stdout)

def central_schedule_gate():
    require(os.environ.get("GITHUB_EVENT_NAME") == "schedule"
            and os.environ.get("GITHUB_REPOSITORY") == "pgextwin/build"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")),
            "central trusted main schedule required")
    source = gh_json("pgextwin/build","branches/main")
    require(source.get("protected") is True
            and source.get("commit",{}).get("sha") == os.environ.get("GITHUB_SHA"),
            "scheduled central SHA not exact protected current main")

def membership(path):
    doc=json.loads(path.read_text(encoding="utf-8"))
    require(doc.get("schemaVersion")==1 and type(doc.get("entries")) is list,
            "invalid immutable central fleet roster")
    targets=[]
    for e in doc["entries"]:
        require(type(e) is dict, "invalid fleet entry")
        if e.get("mode") == "BUILD" and e.get("candidateEnabled") is True:
            repo=e.get("repository")
            require(type(repo) is str and native.REPO.fullmatch(repo),
                    "unsafe central registered repository")
            targets.append(repo)
    require(0 < len(targets) < 100 and len(targets)==len(set(targets)),
            "missing, duplicated or unbounded candidate fleet")
    return targets

def candidate_bytes(repo, head, pr_num):
    require(native.SHA.fullmatch(head or "") and type(pr_num) is int and pr_num>0,
            "untrusted manifest ref")
    doc=gh_json(repo,"contents/config/extension.json?ref="+head)
    require(doc.get("path")=="config/extension.json"
            and doc.get("encoding")=="base64"
            and type(doc.get("content")) is str, "invalid authenticated Contents encoding")
    raw=base64.b64decode(doc["content"],validate=False)
    require(0 < len(raw) < 100_000, "oversized or empty manifest")
    blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    require(doc.get("sha")==blob, "Git blob SHA mismatch")
    changed=gh_json(repo,"pulls/"+str(pr_num)+"/files?per_page=100")
    require(type(changed) is list and len(changed)==1
            and changed[0].get("filename")=="config/extension.json"
            and changed[0].get("sha")==blob, "PR manifest bytes differ from exact PR patch")
    ext=json.loads(raw)
    require(type(ext) is dict and ext.get("name")==repo.split("/")[1],
            "candidate manifest identity mismatch")
    return ext

def dispatch_after_approval_hold(repo, pulls, inventory, main):
    """Authenticate existing dispatch evidence, never relabel the held PR run."""
    require(type(pulls) is list and len(pulls)<100
            and type(inventory) is dict
            and type(inventory.get("total_count")) is int
            and type(inventory.get("workflow_runs")) is list
            and len(inventory["workflow_runs"])==inventory["total_count"]<100,
            "approval-held PR inventory incomplete")
    owned=[p for p in pulls if type(p) is dict and p.get("state")=="open"
           and (p.get("user") or {}).get("login")=="github-actions[bot]"
           and recovery.CANDIDATE.fullmatch((p.get("head") or {}).get("ref",""))]
    require(len(owned)==1, "no unique approval-held bot candidate")
    selected=owned[0]
    head,branch=selected["head"]["sha"],selected["head"]["ref"]
    def exact(run,event):
        return (type(run) is dict and run.get("event")==event
                and run.get("name")=="Windows CI/CD"
                and run.get("path")==".github/workflows/windows.yml"
                and run.get("head_sha")==head and run.get("head_branch")==branch
                and (run.get("head_repository") or {}).get("full_name")==repo)
    matches=[r for r in inventory["workflow_runs"] if exact(r,"pull_request")]
    require(len(matches)==1, "missing or ambiguous approval-held native run")
    indexed=matches[0]
    positive=native.required_check.positive
    require(positive(indexed.get("id")), "invalid approval-held run ID")
    held=gh_json(repo,"actions/runs/"+str(indexed["id"]))
    require(exact(held,"pull_request")
            and all(held.get(k)==indexed.get(k) for k in
                    ("id","status","conclusion","run_attempt","workflow_id","check_suite_id"))
            and held.get("status")=="completed" and held.get("conclusion")=="action_required"
            and all(positive(held.get(k)) for k in ("run_attempt","workflow_id","check_suite_id")),
            "original native PR run not a stable completed approval hold")
    jobs=gh_json(repo,"actions/runs/"+str(held["id"])+"/jobs?per_page=100")
    require(type(jobs) is dict and type(jobs.get("total_count")) is int
            and jobs["total_count"]==0 and jobs.get("jobs")==[],
            "approval-held native run has jobs or incomplete job inventory")
    inv=gh_json(repo,"actions/runs?event=workflow_dispatch&head_sha="+head+"&per_page=100")
    require(type(inv) is dict and type(inv.get("total_count")) is int
            and type(inv.get("workflow_runs")) is list
            and len(inv["workflow_runs"])==inv["total_count"]<100,
            "dispatch run inventory incomplete")
    matches=[r for r in inv["workflow_runs"] if exact(r,"workflow_dispatch")]
    require(len(matches)==1 and positive(matches[0].get("id")),
            "missing or ambiguous equivalent dispatch")
    run=gh_json(repo,"actions/runs/"+str(matches[0]["id"]))
    require(exact(run,"workflow_dispatch") and run.get("id")==matches[0]["id"]
            and run.get("workflow_id")==held["workflow_id"]
            and run.get("status")=="completed" and run.get("conclusion")=="success"
            and positive(run.get("run_attempt")) and positive(run.get("check_suite_id"))
            and run["check_suite_id"]!=held["check_suite_id"],
            "equivalent dispatch not successfully completed")
    associations=gh_json(repo,"commits/"+head+"/pulls?per_page=100")
    require(type(associations) is list and len(associations)==1
            and type(associations[0]) is dict
            and associations[0].get("number")==selected.get("number"),
            "dispatch HEAD has no unique independent candidate PR association")
    pr=gh_json(repo,"pulls/"+str(selected["number"]))
    require(type(pr) is dict and pr.get("number")==selected["number"] and pr.get("state")=="open"
            and pr.get("merged") is False
            and (pr.get("user") or {}).get("login")=="github-actions[bot]"
            and "<!-- pgextwin-candidate:v1:"+branch.split("/")[1]+" -->" in (pr.get("body") or ""),
            "dispatch candidate PR ownership changed")
    for linked in (pr,associations[0]):
        require((linked.get("head") or {}).get("sha")==head
                and (linked.get("head") or {}).get("ref")==branch
                and (linked.get("head") or {}).get("repo",{}).get("full_name")==repo
                and (linked.get("base") or {}).get("ref")=="main"
                and (linked.get("base") or {}).get("repo",{}).get("full_name")==repo,
                "dispatch PR association differs from exact bot candidate")
    current=gh_json(repo,"branches/main")
    require(type(current) is dict and current.get("name")=="main" and current.get("protected") is True
            and current.get("commit",{}).get("sha")==main["commit"]["sha"]
            ==(pr.get("base") or {}).get("sha"), "dispatch candidate protected base moved")
    required=((current.get("protection") or {}).get("required_status_checks") or {}).get("checks")
    require(type(required) is list and all(type(c) is dict for c in required)
            and any(c.get("context")=="Windows required summary"
            and c.get("app_id")==15368 for c in required), "required App15368 CI not enforced")
    checks=gh_json(repo,"commits/"+head+"/check-runs?per_page=100")
    require(type(checks) is dict and type(checks.get("total_count")) is int
            and type(checks.get("check_runs")) is list
            and 0<len(checks["check_runs"])==checks["total_count"]<100
            and all(type(c) is dict and positive(c.get("id")) for c in checks["check_runs"])
            and len({c["id"] for c in checks["check_runs"]})==checks["total_count"],
            "dispatch check-run inventory incomplete or duplicated")
    suite=[c for c in checks["check_runs"] if type(c.get("check_suite")) is dict
           and c["check_suite"].get("id")==run["check_suite_id"]]
    require(suite and all(c.get("head_sha")==head and type(c.get("app")) is dict
            and c["app"].get("id")==15368
            and c.get("status")=="completed" and c.get("conclusion")=="success"
            and c.get("details_url")=="https://github.com/"+repo+"/actions/runs/"+str(run["id"])+"/job/"+str(c["id"])
            for c in suite), "dispatch suite checks not all successful original App15368 jobs")
    for required_check in required:
        require(len([c for c in suite if c.get("name")==required_check.get("context")
                and required_check.get("app_id") in (None,c["app"]["id"])])==1,
                "missing or ambiguous required check in equivalent dispatch suite")
    return {"schemaVersion":1,"status":"DISPATCH_CI_AUTHENTICATED_NOT_NATIVE_PR_NOT_PUBLISHABLE",
            "repository":repo,"candidatePr":pr["number"],"candidateHeadSha":head,"branch":branch,
            "candidateRunId":run["id"],"candidateRunAttempt":run["run_attempt"],
            "candidateCheckSuiteId":run["check_suite_id"],"matrixResult":"success",
            "blockedNativePrRunId":held["id"],"blockedNativePrRunAttempt":held["run_attempt"],
            "blockedNativePrCheckSuiteId":held["check_suite_id"],
            "blockedNativePrConclusion":"action_required","blockedNativePrJobCount":0,
            "candidateAuditVerified":False,"signedArtifactsVerified":False,
            "publishableReceipt":False,"publicationAuthorized":False}

def recover_one(repo,lifecycle):
    pulls=recovery.get_json(repo,"pulls?state=open&per_page=100")
    owned=[p for p in pulls if type(p) is dict
           and p.get("state")=="open"
           and (p.get("user") or {}).get("login")=="github-actions[bot]"
           and recovery.CANDIDATE.fullmatch((p.get("head") or {}).get("ref",""))]
    require(len(owned)<=1, "ambiguous automated PR candidates in "+repo)
    if not owned:
        return None
    head=(owned[0].get("head") or {}).get("sha")
    require(native.SHA.fullmatch(head or ""), "invalid candidate HEAD")
    runs=recovery.get_json(repo,"actions/runs?event=pull_request&head_sha="+head+"&per_page=100")
    protected=gh_json(repo,"branches/main")
    require(protected.get("protected") is True
            and native.SHA.fullmatch((protected.get("commit") or {}).get("sha","")),
            "current candidate base is not a protected main")
    target_main=protected["commit"]["sha"]
    # Schedule identity belongs to central build, not the target repo. The
    # authenticated immutable target main is independently re-fetched here.
    event="pull_request"
    try:
        context=recovery.reconcile(repo,"schedule","refs/heads/main",target_main,
                                   pulls,runs,lambda endpoint:native.gh_get(repo,endpoint))
    except Denied:
        # This independently rejects failed, running, missing, ambiguous or
        # job-bearing PR runs; no other native validation failure is waived.
        context=dispatch_after_approval_hold(repo,pulls,runs,protected)
        event="workflow_dispatch"
    require(context is not None and context["candidateHeadSha"]==head,
            "candidate changed during original CI authentication")
    ext=candidate_bytes(repo,head,context["candidatePr"])
    with tempfile.TemporaryDirectory(prefix="pgextwin-original-native-") as tmp:
        p=subprocess.run(["gh","run","download",str(context["candidateRunId"]),
                          "--repo",repo,"--dir",tmp],
                         text=True,capture_output=True,timeout=720,check=False)
        require(p.returncode == 0,"original Actions artifact download denied: "+p.stderr[:500])
        outcome=candidate.audit(Path(tmp),ext,lifecycle,context["candidateRunId"],
                                context["candidateHeadSha"],context["branch"],"success",
                                date.today(),event=event,
                                merge_sha=context.get("packagingMergeSha"),
                                pr_number=context["candidatePr"] if event=="pull_request" else None)
    require(outcome.get("status")=="VERIFIED"
            and all(x.get("status")=="SUCCESS" for x in outcome.get("majors",[])),
            "original ZIP/SPDX/Grype byte audit failed")
    return {"schemaVersion":1,
            "status":("CENTRAL_GENUINE_SCHEDULE_ORIGINAL_NATIVE_CI_BYTES_VERIFIED_NONPUBLISHING"
                      if event=="pull_request" else
                      "CENTRAL_GENUINE_SCHEDULE_DISPATCH_CI_BYTES_VERIFIED_NONPUBLISHING"),
            "auditorRepository":"pgextwin/build","auditorEvent":"schedule",
            "auditorSourceSha":os.environ["GITHUB_SHA"],
            "targetMainSha":target_main,"targetRepository":repo,
            ("native" if event=="pull_request" else "dispatch"):context,"candidateAudit":outcome,
            "signedArtifactsVerified":False,"publicationAuthorized":False,
            "publishableReceipt":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--fleet",default="metadata/automation-fleet.json")
    p.add_argument("--output-dir",required=True)
    args=p.parse_args()
    try:
        central_schedule_gate()
        root=Path(args.output_dir)
        root.mkdir(parents=True,exist_ok=True)
        lifecycle=json.loads((ROOT/"metadata/postgresql.json").read_text(encoding="utf-8"))
        targets=membership(ROOT/args.fleet)
        verified=[]
        for repo in targets:
            record=recover_one(repo,lifecycle)
            if record is None:
                continue
            path=root/(repo.replace("/","_")+".json")
            path.write_text(json.dumps(record,indent=2,ensure_ascii=False)+"\n",
                            encoding="utf-8")
            verified.append((repo,record["candidateAudit"]["originEvent"],record["candidateAudit"]["runId"]))
        print("CENTRAL_SCHEDULE_NONPUBLISHING_NATIVE_AUDIT=",json.dumps(verified))
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"],"a",encoding="utf-8") as f:
                f.write("Central read-only genuine-schedule candidate CI recovery. No Release/WRITE.\n")
                for repo,event,run in verified:
                    f.write("- "+repo+" original "+event+" Run "+str(run)+": ZIP/SPDX/Grype verified\n")
        return 0
    except (Denied,ValueError,TypeError,KeyError,OSError,
            json.JSONDecodeError,subprocess.TimeoutExpired) as e:
        print("CENTRAL_NATIVE_AUDIT_FAIL_CLOSED:",str(e),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
