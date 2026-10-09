#!/usr/bin/env python3
"""Read-only operational snapshot for the nine-extension fleet."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from update_watch_lib import WatchError, github_get_json
from importlib.util import spec_from_file_location,module_from_spec

BASE="https://api.github.com/repos/"
MARKER="<!-- pgextwin-update-watch:v1:upstream:"
def request(url):
    return github_get_json(url,os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))

def most_recent(payload, key):
    if not isinstance(payload,dict) or not isinstance(payload.get(key),list):
        raise WatchError("unexpected GitHub API response for "+key)
    return payload[key]

def compact_run(run):
    if not run:
        return None
    return {"runId":run.get("id"),"url":run.get("html_url"),"startedAt":run.get("run_started_at") or run.get("created_at"),
            "updatedAt":run.get("updated_at"),"status":run.get("status"),"conclusion":run.get("conclusion"),
            "event":run.get("event"),"branch":run.get("head_branch")}

def fetch_audit(repo,run):
    artifacts=most_recent(request(BASE+repo+"/actions/runs/"+str(run["id"])+"/artifacts?per_page=100"),"artifacts")
    matches=[a for a in artifacts if a.get("name")=="candidate-audit" and not a.get("expired")]
    if len(matches)!=1:
        return None
    with tempfile.TemporaryDirectory() as temp:
        process=subprocess.run(["gh","run","download",str(run["id"]),"--repo",repo,"--name","candidate-audit",
                                "--dir",temp],text=True,capture_output=True)
        if process.returncode:
            raise WatchError("cannot fetch candidate-audit: "+process.stderr[:160])
        target=Path(temp)/"candidate-audit.json"
        if not target.is_file():
            raise WatchError("downloaded candidate audit JSON missing")
        data=json.loads(target.read_text(encoding="utf-8"))
    if (data.get("schemaVersion")!=1 or data.get("runId")!=run.get("id") or
        data.get("extension")!=repo.split("/")[-1] or data.get("status") not in {"VERIFIED","FAILED"}):
        raise WatchError("candidate audit has inconsistent identity")
    return data

def one(entry,lifecycle):
    repo=entry["repository"]
    row={"extension":repo.split("/")[-1],"repository":repo,"mode":entry["mode"],
         "scheduleUtc":entry["scheduleUtc"],"lastWatch":None,"watchResult":"UNKNOWN",
         "detectedCandidate":None,"candidatePrUrl":None,"lastWindowsCi":None,
         "lastCandidateStatus":"NOT_RUN","perMajor":[],"lastSuccessfulCandidate":None,
         "lastSuccessfulUpstreamShas":{},"errors":[]}
    try:
        runs=most_recent(request(BASE+repo+"/actions/workflows/update-watch.yml/runs?per_page=10"),"workflow_runs")
        row["lastWatch"]=compact_run(runs[0]) if runs else None
        if runs:
            row["watchResult"]= "SUCCESS" if runs[0].get("conclusion")=="success" else (
                "RUNNING" if runs[0].get("status")!="completed" else "FAILED")
    except (WatchError,ValueError,KeyError,OSError) as e:
        row["errors"].append("watch: "+str(e))
    try:
        issues=request(BASE+repo+"/issues?state=open&per_page=100")
        if not isinstance(issues,list):
            raise WatchError("unexpected Issues payload")
        owned=[i for i in issues if isinstance(i,dict) and MARKER+row["extension"]+" -->" in (i.get("body") or "")]
        if len(owned)>1:
            raise WatchError("duplicate owned update Issues")
        if owned:
            i=owned[0]
            row["detectedCandidate"]={"url":i.get("html_url"),"title":i.get("title"),
                                      "updatedAt":i.get("updated_at"),
                                      "mayBeStale":row["watchResult"]!="SUCCESS"}
    except (WatchError,ValueError,KeyError,OSError) as e:
        row["errors"].append("upstream issue: "+str(e))
    try:
        prs=request(BASE+repo+"/pulls?state=open&per_page=100")
        if not isinstance(prs,list):
            raise WatchError("unexpected PR payload")
        owned=[]
        for pr in prs:
            branch=(pr.get("head") or {}).get("ref") or ""
            m=re.fullmatch(r"auto-candidate/([0-9a-f]{20})",branch)
            if m and "<!-- pgextwin-candidate:v1:"+m.group(1)+" -->" in (pr.get("body") or ""):
                owned.append(pr)
        row["candidatePrUrl"]=owned[0].get("html_url") if len(owned)==1 else None
        if len(owned)>1:
            row["errors"].append("multiple active owned candidate PRs; inspect separately")
    except (WatchError,ValueError,KeyError,OSError) as e:
        row["errors"].append("candidate PR: "+str(e))
    try:
        runs=most_recent(request(BASE+repo+"/actions/workflows/windows.yml/runs?event=workflow_dispatch&per_page=100"),"workflow_runs")
        candidates=[r for r in runs if (r.get("head_branch") or "").startswith("auto-candidate/")]
        row["lastWindowsCi"]=compact_run(candidates[0]) if candidates else None
        if candidates:
            latest=candidates[0]
            row["lastCandidateStatus"]="RUNNING" if latest.get("status")!="completed" else "FAILED_OR_UNVERIFIED"
            audit=fetch_audit(repo,latest) if latest.get("status")=="completed" else None
            if audit:
                row["lastCandidateStatus"]=audit["status"] if latest.get("conclusion")=="success" else "FAILED"
                row["perMajor"]=audit.get("majors",[])
            for run in candidates:
                if run.get("conclusion")!="success":
                    continue
                older=fetch_audit(repo,run)
                if older and older.get("status")=="VERIFIED":
                    row["lastSuccessfulCandidate"]={"runId":run["id"],"url":run.get("html_url"),
                        "packagingCommit":older.get("branchSha")}
                    row["lastSuccessfulUpstreamShas"]={str(m["major"]):m["sourceSha"] for m in older["majors"]
                                                       if m.get("status")=="SUCCESS" and m.get("sourceSha")}
                    break
    except (WatchError,ValueError,KeyError,OSError) as e:
        row["errors"].append("candidate CI: "+str(e))
        row["lastCandidateStatus"]="INDETERMINATE"
    return row

def render(state):
    lines=["# pgextwin Fleet Automation Status","",
        "Generated "+state["generatedAt"]+"; centralized mode is live policy, GitHub runs are observed state.",
        "Status is **not** a claim of strict 09:00 execution. Unknown/stale data is not success.","",
        "## Manual candidate queue (not release approval)","",
        "A draft PR link means **manual inspection is required**, even if its latest CI is green.",
        "Never infer that a candidate is release-ready without checking the matching SHA, run, artifacts, audit and source diff.","",
        "| Extension | Mode | Last watch | Update Issue | Candidate PR (manual queue) | Candidate CI | Last verified SHA |",
        "| --- | --- | --- | --- | --- | --- | --- |"]
    for s in state["extensions"]:
        w=s["lastWatch"]
        watch=(w.get("conclusion") or w.get("status")) if w else "NOT_RUN"
        candidate=(s["detectedCandidate"] or {}).get("title") or "—"
        candidate_pr=s.get("candidatePrUrl")
        expected="https://github.com/"+s["repository"]+"/pull/"
        if candidate_pr and candidate_pr.startswith(expected) and candidate_pr[len(expected):].isdigit():
            queue="[Review candidate PR]("+candidate_pr+")"
        elif candidate_pr:
            queue="INDETERMINATE (unexpected PR URL)"
        else:
            queue="—"
        success=(s["lastSuccessfulCandidate"] or {}).get("packagingCommit") or "—"
        lines.append("| "+s["extension"]+" | "+s["mode"]+" | "+watch+" | "+candidate.replace("|","/")[:70]+
                     " | "+queue+" | "+s["lastCandidateStatus"]+" | "+success+" |")
    lines.extend(["","Latest run failures and missing artifacts remain visible even if an older candidate passed.",
                  "No item in this report authorizes merging a PR or publishing binaries.",
                  "Machine-readable state is attached to this Actions run. This status job never publishes binaries."])
    return "\n".join(lines)+"\n"

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--policy",required=True)
    p.add_argument("--lifecycle",required=True)
    p.add_argument("--json",required=True)
    p.add_argument("--markdown",required=True)
    args=p.parse_args()
    policy=json.loads(Path(args.policy).read_text())
    f=Path(__file__).with_name("fleet-control.py")
    spec=spec_from_file_location("fleet_control",f)
    module=module_from_spec(spec);spec.loader.exec_module(module)
    module.validate(policy)
    lifecycle=json.loads(Path(args.lifecycle).read_text())
    results=[one(entry,lifecycle) for entry in policy["entries"]]
    status={"schemaVersion":1,"generatedAt":datetime.now(timezone.utc).isoformat(),
            "policyRelease":"manual-only","extensions":results}
    Path(args.json).write_text(json.dumps(status,indent=2)+"\n")
    Path(args.markdown).write_text(render(status))
    errors=[s["extension"] for s in results if s["errors"]]
    if errors:
        print("WARN: indeterminate fleet rows: "+", ".join(errors))
    print(render(status))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
