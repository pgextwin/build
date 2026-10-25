#!/usr/bin/env python3
"""Select only same-run repository proofs before entering Publisher Environment.

An unrelated failed matrix row must not block a successfully reverified source.
Only fresh authenticated GitHub run/branch/jobs GETs can select a row. Selection
does not mint a receipt or token; the isolated Publisher repeats all gates.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
issuer=load("verified_selector_issuer","automatic-publisher-receipt-issuer.py")
source=load("verified_selector_source","verify-completed-signed-source.py")
SHA=re.compile(r"^[0-9a-f]{40}$")

class Denied(ValueError):pass
def require(ok,why):
    if not ok:raise Denied(why)

def select(candidates,fleet,jobs,run,branch,*,sha,run_id):
    """Return only proven rows, with no authority from matrix-wide success."""
    require(type(sha) is str and SHA.fullmatch(sha)
            and type(run_id) is int and run_id>0,
            "invalid protected Publisher run identity")
    require(type(branch) is dict and branch.get("name")=="main"
            and branch.get("protected") is True
            and (branch.get("commit") or {}).get("sha")==sha,
            "protected central main advanced or is unavailable")
    require(type(run) is dict and type(run.get("id")) is int
            and run["id"]==run_id and type(run.get("run_attempt")) is int
            and run["run_attempt"]==1 and run.get("event")=="schedule"
            and run.get("path")==issuer.SCHEDULE
            and run.get("head_sha")==sha and run.get("head_branch")=="main"
            and (run.get("repository") or {}).get("full_name")=="pgextwin/build"
            and run.get("status")=="in_progress" and run.get("conclusion") is None,
            "not this original live central Publisher schedule")
    roster=issuer.fleet_policy.members(fleet)
    require(fleet.get("releasePolicy")==issuer.MODE,
            "automatic Publisher policy has not been protected-migrated")
    require(type(candidates) is list and len(candidates)<=len(roster),
            "invalid original source candidate matrix")
    require(type(jobs) is dict and type(jobs.get("total_count")) is int
            and 0<jobs["total_count"]<100 and type(jobs.get("jobs")) is list
            and len(jobs["jobs"])==jobs["total_count"]
            and all(type(j) is dict and type(j.get("id")) is int
                    and j["id"]>0 for j in jobs["jobs"])
            and len({j["id"] for j in jobs["jobs"]})==len(jobs["jobs"]),
            "incomplete, duplicate or malformed authenticated jobs inventory")
    eligible=[];seen=set()
    for row in candidates:
        require(type(row) is dict and set(row)=={
                    "repository","name","sha","source_run"}
                and type(row.get("repository")) is str
                and row["repository"] in roster
                and row["repository"] not in seen
                and row.get("name")==row["repository"].split("/")[1]
                and type(row.get("sha")) is str and SHA.fullmatch(row["sha"])
                and type(row.get("source_run")) is int and row["source_run"]>0
                and row["source_run"]!=run_id,
                "forged, duplicate or unregistered original source row")
        seen.add(row["repository"])
        try:
            issuer.independent_source_job(jobs,repository=row["repository"],
                run_id=run_id,central_sha=sha)
        except issuer.Denied:
            # Missing, failed, skipped, replayed or ambiguous proof never enters
            # the credentialed Environment. Valid peers can still proceed.
            continue
        eligible.append(dict(row))
    return eligible

def live(candidates,fleet,*,env=os.environ,get=source.github):
    require(env.get("GITHUB_REPOSITORY")=="pgextwin/build"
            and env.get("GITHUB_EVENT_NAME")=="schedule"
            and env.get("GITHUB_REF")=="refs/heads/main"
            and env.get("GITHUB_RUN_ATTEMPT")=="1"
            and bool(env.get("GH_TOKEN")),
            "trusted read-only original central schedule required")
    sha=env.get("GITHUB_SHA");raw=env.get("GITHUB_RUN_ID","")
    require(type(raw) is str and re.fullmatch(r"[1-9][0-9]*",raw),
            "invalid current Publisher Run ID")
    run_id=int(raw)
    branch=get("pgextwin/build","branches/main")
    run=get("pgextwin/build",f"actions/runs/{run_id}")
    jobs=get("pgextwin/build",f"actions/runs/{run_id}/attempts/1/jobs?per_page=100")
    selected=select(candidates,fleet,jobs,run,branch,sha=sha,run_id=run_id)
    current=[]
    for row in selected:
        try:
            # A genuinely verified source can advance after intake. Exclude it
            # before Environment credentials; the Publisher repeats this gate.
            source_branch=get(row["repository"],"branches/main")
            source_run=get(row["repository"],f"actions/runs/{row['source_run']}")
            require(type(source_branch) is dict
                    and source_branch.get("name")=="main"
                    and source_branch.get("protected") is True
                    and (source_branch.get("commit") or {}).get("sha")==row["sha"]
                    and type(source_run) is dict
                    and type(source_run.get("id")) is int
                    and source_run["id"]==row["source_run"]
                    and type(source_run.get("run_attempt")) is int
                    and source_run["run_attempt"]==1
                    and source_run.get("event")=="push"
                    and source_run.get("path")==issuer.SOURCE
                    and source_run.get("head_sha")==row["sha"]
                    and source_run.get("head_branch")=="main"
                    and (source_run.get("repository") or {}).get("full_name")==row["repository"]
                    and source_run.get("status")=="completed"
                    and source_run.get("conclusion")=="success",
                    "original signed source moved or no longer authentic")
        except (Denied,source.Denied,OSError,ValueError,TypeError,KeyError,
                source.subprocess.TimeoutExpired):
            continue
        current.append(row)
    # Root Run timestamps can advance as unrelated jobs finish. Revalidate the
    # protected SHA/event/attempt/status, rather than treating those timestamps
    # as source identity or weakening any repository-specific proof.
    require(select(candidates,fleet,jobs,
                get("pgextwin/build",f"actions/runs/{run_id}"),
                get("pgextwin/build","branches/main"),sha=sha,run_id=run_id)
            ==selected,"live central identity changed during proof selection")
    return current

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--candidates-json",required=True)
    p.add_argument("--fleet",required=True)
    p.add_argument("--github-output",required=True)
    a=p.parse_args()
    try:
        require(len(a.candidates_json)<128*1024,"oversized original source matrix")
        rows=live(json.loads(a.candidates_json,object_pairs_hook=source.unique),
                  issuer.fleet_policy.read(a.fleet))
        with Path(a.github_output).open("a",encoding="utf-8") as out:
            out.write("publisher_matrix="+json.dumps(rows,separators=(",",":"))+"\n")
            out.write("has_verified_sources="+str(bool(rows)).lower()+"\n")
        print("INDEPENDENT_REPOSITORY_PROOFS_SELECTED="+str(len(rows))+
              "; no token or publication authority issued")
        return 0
    except (Denied,issuer.Denied,issuer.fleet_policy.Denied,source.Denied,
            OSError,ValueError,TypeError,KeyError,source.subprocess.TimeoutExpired):
        print("INDEPENDENT_PUBLISHER_SELECTION_DENY",file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
