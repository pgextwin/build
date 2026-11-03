#!/usr/bin/env python3
"""Dedicated isolated owner issue_comment signed-main formal Publisher.

A genuinely new protected source kind: NEVER coerce issue_comment into push.
The only entrypoint is a real Publisher Environment job. It re-downloads the
original signed owner source and runs real first+second Sigstore and ZIP/SPDX/
Grype before minting a single-repository App JWT token in the SAME job.
The prior read-only selector's JSON is never accepted as publication authority.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote

ROOT=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

owner=load("owner_formal_original","publisher-owner-source-admission.py")
selector=load("owner_formal_selector","publisher-owner-source-publish-request.py")
policy=load("owner_formal_policy","owner-source-publish-policy.py")
issuer=load("owner_formal_issuer","automatic-publisher-receipt-issuer.py")
formal=load("owner_formal_writer","fleet-publish-release.py")
scope=load("owner_formal_scoped_token","publisher-scoped-token.py")
probe=load("owner_formal_app_identity","probe-publisher-app.py")
tagplan=load("owner_formal_tag_inventory","automatic-release-tag-plan.py")
provenance=load("owner_formal_public_locator","automatic-release-provenance.py")
ident=issuer.ident
REPO=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
class Denied(ValueError):pass

def need(ok,why):
    if not ok:raise Denied(why)

def instant(value):
    need(type(value) is str and value.endswith("Z"),"missing UTC original time")
    return datetime.fromisoformat(value.replace("Z","+00:00"))

def authenticate(repo,run_id,sha,env):
    need(env.get("GITHUB_REPOSITORY")=="pgextwin/build"
         and env.get("GITHUB_EVENT_NAME")=="issue_comment"
         and env.get("GITHUB_REF")=="refs/heads/main"
         and env.get("GITHUB_RUN_ATTEMPT")=="1"
         and type(env.get("GH_TOKEN")) is str and len(env["GH_TOKEN"])>10
         and REPO.fullmatch(repo) is not None
         and type(run_id) is int and run_id>0
         and type(sha) is str and owner.SHA.fullmatch(sha) is not None,
         "untrusted owner Publisher runtime")
    event=json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text("utf-8"),
                     object_pairs_hook=owner.unique)
    cid=(event.get("comment") or {}).get("id")
    need(type(cid) is int and cid>0,"invalid owner request ID")
    central_branch=owner.get("pgextwin/build","branches/main")
    current=owner.get("pgextwin/build",f"actions/runs/{env['GITHUB_RUN_ID']}")
    target,source=owner.authenticate_request(
        event,owner.get("pgextwin/build",f"issues/comments/{cid}"),
        current,central_branch,env,request_pattern=owner.PUBLISH_REQUEST)
    need(repo==target and run_id==source
         and type(env.get("GITHUB_SHA")) is str
         and central_branch["commit"]["sha"]==env["GITHUB_SHA"],
         "original exact Run selector differs from immutable owner request")
    original=owner.get(repo,f"actions/runs/{run_id}")
    need(original.get("status")=="completed"
         and original.get("conclusion")=="success"
         and original.get("run_attempt")==1
         and original.get("head_sha")==sha
         and original.get("event")=="issue_comment"
         and original.get("path")==owner.SOURCE_WORKFLOW,
         "source original Run changed or was replayed")
    # A freshly created Publisher command may reference a successful original
    # signed Run, but not a stale or future original / edited request.
    signed_at=instant(original.get("updated_at"))
    requested_at=instant(event["comment"]["created_at"])
    central_at=instant(current.get("created_at"))
    need(signed_at<=requested_at<=central_at+timedelta(minutes=5)
         and central_at-requested_at<=timedelta(minutes=30)
         and requested_at-signed_at<=timedelta(days=7),
         "owner source/request freshness or replay window not satisfied")
    return event,central_branch,current,original,cid

def original_job(repo,publisher_id,central_sha):
    jobs=owner.get("pgextwin/build",
        f"actions/runs/{publisher_id}/attempts/1/jobs?per_page=100")
    items=jobs.get("jobs")
    need(type(jobs.get("total_count")) is int and type(items) is list
         and jobs["total_count"]==len(items) and 0<len(items)<100,
         "Publisher job inventory truncated or changed")
    matches=[j for j in items if j.get("name")==
             "Authenticate owner formal-source request and reverify original (DENY)"]
    need(len(matches)==1 and type(matches[0].get("id")) is int
         and matches[0].get("run_attempt")==1
         and matches[0].get("run_id")==publisher_id
         and matches[0].get("head_sha")==central_sha
         and matches[0].get("status")=="completed"
         and matches[0].get("conclusion")=="success",
         "separate same-Publisher-Run owner source admission not successful")
    return matches[0]["id"]

def package_and_grype(folder,manifest,lifecycle,proof):
    majors=ident.maintained_majors(manifest,lifecycle)
    expected_files=ident.expected_assets(manifest,majors)-{"SHA256SUMS.txt"}
    need(folder.is_dir() and not folder.is_symlink()
         and {p.name for p in folder.iterdir()}==expected_files
         and all(p.is_file() and not p.is_symlink() for p in folder.iterdir()),
         "missing/extra original signed ZIP/SPDX/Grype")
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
            for p in folder.iterdir()}
    need(type(proof.get("SHA256")) is dict and hashes==proof["SHA256"]
         and proof.get("maintainedMajors")==majors,
         "original/fresh per-major SHA256 mismatch")
    for m in majors:
        stem=ident.asset_stem(manifest,m)
        grype=owner.read_file(folder,stem+".vulnerabilities.json")
        result=owner.audit.vuln.review(grype,asset_stem=stem)
        need(type(result) is dict
             and result.get("status")=="NO_BLOCKING_FINDINGS"
             and type(result.get("blockingFindingCount")) is int
             and result["blockingFindingCount"]==0,
             "blocking Critical/High/Unknown Grype vulnerability")
    return hashes

def tag_from_live(repo,manifest,source_run):
    stem=ident.tag_stem(manifest)
    prefix=stem+"-windows."
    releases=tagplan.get_listing(repo,"releases?per_page=100")
    refs=tagplan.get_listing(repo,
        "git/matching-refs/tags/"+quote(prefix,safe=""),allow_missing=True)
    need(type(releases) is list and type(refs) is list,
         "unverifiable exact Release/tag inventory")
    existing=set()
    for item in releases:
        need(type(item) is dict and type(item.get("id")) is int
             and item["id"]>0 and type(item.get("tag_name")) is str
             and type(item.get("draft")) is bool,
             "unverifiable Release identity")
        text=item.get("body") or ""
        if provenance.PREFIX in text:
            record=provenance.decode(text)
            need(not (record.get("repository")==repo
                      and record.get("sourceRunId")==source_run),
                 "original source Run already published, replay forbidden")
        if item["tag_name"].startswith(prefix):
            existing.add(item["tag_name"])
    for item in refs:
        need(type(item) is dict and type(item.get("ref")) is str
             and item["ref"].startswith("refs/tags/"+prefix),
             "unverifiable exact matching tag ref")
        existing.add(item["ref"].removeprefix("refs/tags/"))
    seq=[]
    for val in existing:
        suffix=val[len(prefix):]
        need(re.fullmatch(r"[1-9][0-9]*",suffix) is not None,
             "malformed previous same-version Release tag")
        seq.append(int(suffix))
    tag=prefix+str(max(seq,default=0)+1)
    ident.validate_release_tag(manifest,tag)
    need(tag not in existing,"tag already exists")
    return tag

def recheck(repo,run_id,sha,manifest,lifecycle,root,initial,env,cid):
    # Re-authenticate actual source jobs, original signing comment and
    # original dual signatures rather than trusting the selector artifact.
    intent=owner.read_file(root/"intent","owner-main-intent.json")
    majors=ident.maintained_majors(manifest,lifecycle)
    owner.source_metadata(repo,sha,run_id,
        owner.get(repo,f"actions/runs/{run_id}"),
        owner.get(repo,f"actions/runs/{run_id}/attempts/1/jobs?per_page=100"),
        owner.get(repo,f"actions/runs/{run_id}/artifacts?per_page=100"),
        intent,owner.get(repo,f"issues/comments/{intent['commentId']}"),majors)
    first=owner.audit.audit(root/"signed",intent,manifest,lifecycle,
                            repo=repo,sha=sha,run_id=run_id,auditor="first")
    second=owner.audit.audit(root/"signed",intent,manifest,lifecycle,
                             repo=repo,sha=sha,run_id=run_id,auditor="second")
    actual_dual=owner.audit.join(first,second)
    need(actual_dual==owner.read_file(root/"dual","chat-owner-dual-sigstore.json")
         and first==owner.read_file(root/"first","chat-owner-audit-first.json")
         and second==owner.read_file(root/"second","chat-owner-audit-second.json")
         and initial.get("SHA256")==actual_dual["SHA256"],
         "new owner signed real Sigstore byte agreement changed")
    event,branch,current,original,check_cid=authenticate(repo,run_id,sha,env)
    need(check_cid==cid
         and owner.get(repo,"branches/main")["commit"]["sha"]==sha
         and owner.get("pgextwin/build","branches/main")==branch,
         "protected main or immutable owner request changed")
    return current

def main():
    parser=argparse.ArgumentParser()
    for key in ("repository","source-run","source-sha","fleet","central-policy",
                "owner-central-policy","owner-policy","unattended",
                "publisher-boundary","lifecycle","recovery","output"):
        parser.add_argument("--"+key,required=True)
    a=parser.parse_args()
    try:
        repo=a.repository
        run_id=int(a.source_run)
        sha=a.source_sha
        env=os.environ
        event,central_branch,central_run,source_run,cid=authenticate(repo,run_id,sha,env)
        fleet=issuer.fleet_policy.read(a.fleet)
        central=issuer.fleet_policy.read(a.central_policy)
        owner_central=issuer.fleet_policy.read(a.owner_central_policy)
        unattended=issuer.fleet_policy.read(a.unattended)
        boundary=issuer.fleet_policy.read(a.publisher_boundary)
        owner_policy=issuer.fleet_policy.read(a.owner_policy)
        lifecycle=issuer.fleet_policy.read(a.lifecycle)
        source_branch=owner.get(repo,"branches/main")
        need(source_branch.get("protected") is True
             and source_branch["commit"]["sha"]==sha,
             "source protected main no longer equals signed original")
        local=selector.protected_local(repo,sha,"release-promotion")
        owner_local=selector.protected_local(repo,sha,"owner-source-publication")
        policy.gate(fleet=fleet,central=central,local=local,unattended=unattended,
                    boundary=boundary,owner_central=owner_central,
                    owner_local=owner_local,repository=repo)
        issuer.owner_policy_gate(owner_policy)
        need(env.get("PUBLISHER_APP_ID")==str(issuer.APP)
             and env.get("PUBLISHER_INSTALLATION_ID")==str(issuer.INSTALLATION),
             "independent Publisher App identity variables missing")
        scratch=Path(env["RUNNER_TEMP"]).resolve()
        need(scratch.is_dir() and not scratch.is_symlink(),
             "untrusted Publisher temporary directory")
        proof=owner.admit(repo,run_id,scratch=scratch,fleet=fleet,
                          lifecycle=lifecycle)
        root=scratch/"original-owner-signed"
        manifest=owner.read_file(root/"manifest","extension.json") if (root/"manifest").exists() else None
        if manifest is None:
            contents=owner.get(repo,f"contents/config/extension.json?ref={sha}")
            import base64
            need(contents.get("encoding")=="base64"
                 and contents.get("type")=="file",
                 "original protected extension manifest unavailable")
            manifest=json.loads(base64.b64decode(
                contents["content"].replace("\n",""),validate=True),
                object_pairs_hook=owner.unique)
        need(manifest.get("name")==repo.split("/")[1],
             "source manifest name changed")
        expected=package_and_grype(root/"signed",manifest,lifecycle,proof)
        proof={**proof,"blockingGrypeFindings":0}
        tag=tag_from_live(repo,manifest,run_id)
        formal.REPO=repo
        formal.absent(tag)
        independent_id=original_job(repo,int(env["GITHUB_RUN_ID"]),env["GITHUB_SHA"])
        # Verify source a second time before private App key is even read.
        recheck(repo,run_id,sha,manifest,lifecycle,root,proof,env,cid)
        key=env.pop("PUBLISHER_PRIVATE_KEY")
        need(type(key) is str and bool(key),"Publisher App key unavailable")
        app_id=int(env["PUBLISHER_APP_ID"])
        installation=int(env["PUBLISHER_INSTALLATION_ID"])
        jwt=probe.jwt(key,app_id)
        app_identity=probe.api("GET","/app",jwt)
        installation_identity=probe.api("GET",
            "/app/installations/"+str(installation),jwt)
        with scope.single_repository_token(
                api=probe.api,jwt=probe.jwt,key=key,
                app=app_id,installation=installation,
                repository=repo,fleet=fleet,
                release_policy=issuer.MODE) as (token,minted,scoped):
            receipt=issuer.issue(
                proof=proof,lifecycle=lifecycle,manifest=manifest,
                fleet=fleet,central=central,local=local,
                unattended=unattended,boundary=boundary,
                schedule_run=central_run,central_branch=central_branch,
                signed_branch=source_branch,
                app_identity=app_identity,
                installation_identity=installation_identity,
                minted=minted,scoped=scoped,
                repository=repo,sha=sha,source_run=run_id,
                central_sha=env["GITHUB_SHA"],
                publisher_run=int(env["GITHUB_RUN_ID"]),
                event="issue_comment",ref=env["GITHUB_REF"],
                attempt=int(env["GITHUB_RUN_ATTEMPT"]),
                tag=tag,tag_absent=True,release_absent=True,
                actor=env["GITHUB_ACTOR"],owner_policy=owner_policy,
                request_comment_id=cid,source_kind=issuer.OWNER_KIND,
                source_signing_comment_id=proof["sourceCommentId"],
                owner_central=owner_central,owner_local=owner_local)
            need(issuer.typed.validate_receipt(
                receipt,repository=repo,commit=sha,actor=env["GITHUB_ACTOR"],
                event="issue_comment")=="issue_comment",
                "formal owner source-kind receipt is not valid")
            # A second independent real Sigstore/byte and unmodified original
            # GitHub Run check in this SAME isolated job, immediately before WRITE.
            package_and_grype(root/"signed",manifest,lifecycle,proof)
            recheck(repo,run_id,sha,manifest,lifecycle,root,proof,env,cid)
            need(original_job(repo,int(env["GITHUB_RUN_ID"]),env["GITHUB_SHA"])==
                 independent_id,"independent source proof changed before Release")
            formal.absent(tag)
            read_credential=env["GH_TOKEN"]
            try:
                env["GH_TOKEN"]=token
                formal.publish_preverified(
                    root/"signed",manifest,receipt,sha,expected,
                    Path(a.recovery),publish_run_id=int(env["GITHUB_RUN_ID"]))
            finally:
                env["GH_TOKEN"]=read_credential
        Path(a.output).write_text(json.dumps({
            "schemaVersion":1,"status":"PUBLISHED_VERIFIED",
            "sourceKind":issuer.OWNER_KIND,"repository":repo,
            "sourceRunId":run_id,"publisherRunId":int(env["GITHUB_RUN_ID"]),
            "releaseTag":tag,"publisherTokenRevoked":True},
            sort_keys=True,indent=2)+"\n","utf-8")
        print("OWNER_SIGNED_SOURCE_FORMAL_RELEASE_VERIFIED_AND_TOKEN_REVOKED")
        return 0
    except Exception as exc:
        print("OWNER_SIGNED_SOURCE_FORMAL_PUBLISHER_DENY ("+
              type(exc).__name__+"); API/token details suppressed",
              file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
