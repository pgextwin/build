#!/usr/bin/env python3
"""Central genuine-schedule recovery of original approved native CI (READ-ONLY).

The locally emitted workflow_run can be SKIPPED when the original candidate
was awaiting GitHub approval. A later successful attempt does not necessarily
emit a fresh completed workflow_run. Do not rerun a green Windows workflow,
mutate the candidate or change its protected main (that would change the
synthetic merge SHA). Reconcile from independent protected build/main schedule.
Dynamic fleet is the sole membership source; never grant publication authority.
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
               endpoint.startswith("pulls/"))
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
    context=recovery.reconcile(repo,"schedule","refs/heads/main",target_main,
                               pulls,runs,lambda endpoint:native.gh_get(repo,endpoint))
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
                                date.today(),event="pull_request",
                                merge_sha=context["packagingMergeSha"],
                                pr_number=context["candidatePr"])
    require(outcome.get("status")=="VERIFIED"
            and all(x.get("status")=="SUCCESS" for x in outcome.get("majors",[])),
            "original ZIP/SPDX/Grype byte audit failed")
    return {"schemaVersion":1,
            "status":"CENTRAL_GENUINE_SCHEDULE_ORIGINAL_NATIVE_CI_BYTES_VERIFIED_NONPUBLISHING",
            "auditorRepository":"pgextwin/build","auditorEvent":"schedule",
            "auditorSourceSha":os.environ["GITHUB_SHA"],
            "targetMainSha":target_main,"targetRepository":repo,
            "native":context,"candidateAudit":outcome,
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
            verified.append((repo,record["native"]["candidateRunId"]))
        print("CENTRAL_SCHEDULE_NONPUBLISHING_NATIVE_AUDIT=",json.dumps(verified))
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"],"a",encoding="utf-8") as f:
                f.write("Central read-only genuine-schedule native CI recovery. No Release/WRITE.\n")
                for repo,run in verified:
                    f.write("- "+repo+" original native Run "+str(run)+": ZIP/SPDX/Grype verified\n")
        return 0
    except (Denied,ValueError,TypeError,KeyError,OSError,
            json.JSONDecodeError,subprocess.TimeoutExpired) as e:
        print("CENTRAL_NATIVE_AUDIT_FAIL_CLOSED:",str(e),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
