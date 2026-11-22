#!/usr/bin/env python3
"""Read-only selector for genuine owner-signed formal-source requests.

Never enters Publisher Environment, mints credentials or issues publishable
receipts. It requires the protected central source-kind publication
opt-in before the isolated Publisher downloads and verifies the original bytes.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
def load(name,script):
    spec=importlib.util.spec_from_file_location(name,ROOT/script)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj
admission=load("owner_source_request_authenticated_original","publisher-owner-source-admission.py")
policy=load("owner_source_request_protected_dual_policy","owner-source-publish-policy.py")
publication_policy=load("publication_policy","publication-policy.py")
issuer=policy.issuer

class Denied(ValueError):pass

def require(ok, reason):
    if not ok:raise Denied(reason)

def select(*,event,live,run,branch,env,fleet,central,owner_central,
           unattended,boundary):
    repo,source_run=admission.authenticate_request(
        event,live,run,branch,env,request_pattern=admission.PUBLISH_REQUEST)
    source_branch=admission.get(repo,"branches/main")
    source_sha=(source_branch.get("commit") or {}).get("sha")
    require(source_branch.get("protected") is True
            and type(source_sha) is str and admission.SHA.fullmatch(source_sha),
            "current signing source not protected")
    # No previous NONPUBLISHING proof is ever treated as a Release receipt.
    local=publication_policy.release_promotion_from(central,repo)
    owner_local=publication_policy.owner_source_from(owner_central,central,repo)
    policy.gate(fleet=fleet,central=central,local=local,unattended=unattended,
                boundary=boundary,owner_central=owner_central,
                owner_local=owner_local,repository=repo)
    require(admission.get(repo,"branches/main")==source_branch
            and admission.get("pgextwin/build","branches/main")==branch,
            "protected main changed during owner source selection")
    return {"schemaVersion":1,
            "status":"OWNER_SOURCE_KIND_READONLY_SELECTED_NOT_PUBLISHABLE",
            "sourceKind":admission.SOURCE_KIND,
            "repository":repo,"mainSha":source_sha,
            "sourceRunId":source_run,
            "publisherRequestCommentId":event["comment"]["id"],
            "publicationAuthorized":False,"publishableReceipt":False,
            "publisherWriteAuthorized":False,"PUBLISH":"DENY"}

def main():
    p=argparse.ArgumentParser()
    for key in ("fleet","central-policy","owner-central-policy","unattended",
                "publisher-boundary","output"):
        p.add_argument("--"+key,required=True)
    p.add_argument("--github-output")
    a=p.parse_args()
    try:
        env=os.environ
        require(bool(env.get("GH_TOKEN")) and bool(env.get("RUNNER_TEMP")),
                "missing authenticated read-only GitHub token")
        event=json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text("utf-8"),
                         object_pairs_hook=admission.unique)
        cid=(event.get("comment") or {}).get("id")
        require(type(cid) is int and cid>0,"original request comment missing")
        scratch=Path(env["RUNNER_TEMP"]).resolve()
        require(scratch.is_dir() and not scratch.is_symlink(),
                "untrusted Runner scratch")
        evidence=select(
            event=event,live=admission.get("pgextwin/build",f"issues/comments/{cid}"),
            run=admission.get("pgextwin/build",f"actions/runs/{env['GITHUB_RUN_ID']}"),
            branch=admission.get("pgextwin/build","branches/main"),
            env=env,fleet=issuer.fleet_policy.read(a.fleet),
            central=issuer.fleet_policy.read(a.central_policy),
            owner_central=issuer.fleet_policy.read(a.owner_central_policy),
            unattended=issuer.fleet_policy.read(a.unattended),
            boundary=issuer.fleet_policy.read(a.publisher_boundary))
        output=Path(a.output).resolve()
        require(output.parent==scratch and not output.is_symlink(),
                "untrusted selector output path")
        output.write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n","utf-8")
        if a.github_output:
            with Path(a.github_output).open("a",encoding="utf-8") as out:
                out.write("owner_source_selected=true\n")
                out.write("repository="+evidence["repository"]+"\n")
                out.write("source_run="+str(evidence["sourceRunId"])+"\n")
                out.write("main_sha="+evidence["mainSha"]+"\n")
        print("OWNER_SOURCE_REQUEST_SELECTED_READONLY; PUBLISH_DENY; NO RELEASE RECEIPT")
        return 0
    except Exception as exc:
        # Keep unauthenticated API response and token material out of logs.
        print("OWNER_SOURCE_PUBLISH_REQUEST_DENY ("+type(exc).__name__+
              "); no token, no Release, no publication",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
