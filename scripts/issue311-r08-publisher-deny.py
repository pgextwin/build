#!/usr/bin/env python3
"""Issue #311 R08-02: actual App-original source -> Publisher DENY admission.

This job is **not** a credentialed Publisher and cannot authorize or create a
Release. It performs original authenticated GitHub GET against the completed
R08-01 cycle and proves the new App workflow_dispatch actor/source kind cannot
be laundered into the existing legacy schedule Publisher App/WRITE lane.

The crypto original-byte evidence was independently accepted as R08-01; this
is a separate read-only Publisher *boundary* proof, not a third Sigstore audit.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPOSITORY="pgextwin/orafce"
CENTRAL_REPO="pgextwin/build"
LOCAL_WORKFLOW=".github/workflows/issue311-request-local-prepare.yml"
CENTRAL_WORKFLOW=".github/workflows/issue311-r06-prepare-scan.yml"
FLEET_WORKFLOW=".github/workflows/issue311-coordinator-fleet-original.yml"
BOT="pgextwin-issue311-prepare-coord[bot]"
BOT_ID=350058024
APP_ID=5534389
SIGNER_APP_ID=15368
PUBLISHER_APP_ID=5451798
PUBLISHER_INSTALLATION_ID=174720074
SOURCE="APP_BOT_PREPARE_WORKFLOW_DISPATCH_SIGNED_BUILD_ONLY"
SHA40=re.compile(r"[a-f0-9]{40}\Z")
SHA64=re.compile(r"[a-f0-9]{64}\Z")
R08_JOBS={
    "Original protected PREPARE ZIP verification (NO RELEASE)",
    "R08 authenticated original App OIDC signing intent (NO PUBLISH)",
    "R07-01 Windows required summary",
    "R08 first independently verified real App OIDC Sigstore bytes (NO PUBLISH)",
    "R08 SECOND independent original-byte OIDC Sigstore verification (NO PUBLISH)",
    "R08 strict independent 2 Sigstore original-byte source agreement (PUBLISH_DENY)",
}
R08_ARTIFACTS={
    "issue311-app-local-prepare-original-receipt",
    "issue311-r08-app-oidc-intent-nonpublishing",
    "issue311-r08-signed-first-nonpublishing",
    "issue311-r08-signed-second-nonpublishing",
    "issue311-r08-app-oidc-dual-audit-nonpublishing",
    *{f"orafce-pg{major}-windows-x64" for major in range(14,19)}
}
class Denied(ValueError):
    pass

def need(condition,why):
    if not condition:
        raise Denied("R08_PUBLISHER_SOURCE_DENY: "+why)

def unique(pairs):
    result={}
    for k,v in pairs:
        need(k not in result,"duplicate JSON evidence key")
        result[k]=v
    return result

def parse(raw):
    return json.loads(raw,object_pairs_hook=unique)

def positive(value):
    return type(value) is int and value>0

def git_blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def assess(*, local, central, fleet, local_branch, state, state_blob,
           request, request_raw_sha, jobs, artifacts, boundary,
           central_run_id, fleet_run_id, local_run_id,
           central_sha, local_sha, source_kind):
    """Return a mandatory DENY, never a publication capability.

    Inputs MUST be authenticated independent GETs in live mode. Synthetic
    fixtures in CI only demonstrate hostile-denial policy, not real provenance.
    """
    need(source_kind==SOURCE,"old schedule/other source-kind forbidden")
    need(all(type(s) is str and SHA40.fullmatch(s) for s in
             (central_sha,local_sha,state_blob)) and
         all(positive(v) for v in (central_run_id,fleet_run_id,local_run_id)),
         "malformed immutable source identifiers")
    need(type(request) is dict and request.get("schemaVersion")==1
         and request.get("kind")=="pgextwin-execution-request"
         and request.get("mode")=="PREPARE"
         and request.get("allowFutureUpdates") is False
         and request.get("approval",{}).get("publicReleaseAuthorized") is False
         and request.get("approval",{}).get("publicationGrants")==[]
         and request.get("source",{}).get("centralMainSha")!=central_sha
         and type(request.get("targets")) is list
         and len(request["targets"])==17
         and len({x.get("repo") for x in request["targets"]})==17
         and {x.get("repo"):x.get("mainSha") for x in request["targets"]}.get(REPOSITORY)==local_sha
         and type(request_raw_sha) is str and SHA64.fullmatch(request_raw_sha),
         "new App source is not a unique nonpublishing immutable 17-request")
    need(type(central) is dict and central.get("id")==central_run_id
         and central.get("run_attempt")==1 and central.get("head_sha")==central_sha
         and central.get("path")==CENTRAL_WORKFLOW and central.get("event")=="push"
         and central.get("head_branch")=="main"
         and central.get("actor",{}).get("login")=="ShutenOishi"
         and central.get("status")=="completed" and central.get("conclusion")=="success",
         "central original not authenticated or not safe")
    need(type(fleet) is dict and fleet.get("id")==fleet_run_id
         and fleet.get("run_attempt")==1 and fleet.get("head_sha")==central_sha
         and fleet.get("path")==FLEET_WORKFLOW
         and fleet.get("event")=="workflow_run"
         and fleet.get("status")=="completed" and fleet.get("conclusion")=="success",
         "17-App genuine completed coordinator missing")
    need(type(local) is dict and local.get("id")==local_run_id
         and local.get("run_attempt")==1 and local.get("head_sha")==local_sha
         and local.get("path")==LOCAL_WORKFLOW
         and local.get("event")=="workflow_dispatch"
         and local.get("status")=="completed" and local.get("conclusion")=="success"
         and local.get("actor",{}).get("login")==BOT
         and local.get("actor",{}).get("id")==BOT_ID
         and local.get("triggering_actor",{}).get("login")==BOT,
         "real App actor ID/original Windows signer not trusted")
    need(type(local_branch) is dict and local_branch.get("protected") is True
         and local_branch.get("name")=="main"
         and local_branch.get("commit",{}).get("sha")==local_sha,
         "signed local HEAD drifted from protected main")
    need(type(jobs) is dict and type(jobs.get("jobs")) is list
         and jobs.get("total_count")==len(jobs["jobs"])
         and all(type(x) is dict for x in jobs["jobs"]), "incomplete job inventory")
    successes={j.get("name") for j in jobs["jobs"]
               if j.get("status")=="completed" and j.get("conclusion")=="success"}
    need(R08_JOBS.issubset(successes)
         and all(any(name.startswith(
             f"R07-01 authenticated App original Windows PG14-18 / PostgreSQL {m} / Windows x64")
             for name in successes) for m in range(14,19)),
         "missing App-original PG14-18/Sigstore dual-audit required job")
    need(type(artifacts) is dict and type(artifacts.get("artifacts")) is list
         and artifacts.get("total_count")==len(artifacts["artifacts"])
         and len(artifacts["artifacts"])==10
         and {x.get("name") for x in artifacts["artifacts"]}==R08_ARTIFACTS
         and all(positive(x.get("id")) and x.get("expired") is False
                 and x.get("digest") and re.fullmatch(r"sha256:[a-f0-9]{64}",x["digest"])
                 for x in artifacts["artifacts"]),
         "missing/ambiguous new App original audit and PG artifacts")
    need(type(state) is dict and state.get("schemaVersion")==1
         and state.get("revision")==2 and state.get("terminal")=="NO_UPDATE"
         and state.get("eventTransport")=="workflow_run.completed"
         and state.get("sourceRun")=={"id":fleet_run_id,"attempt":1}
         and state.get("sourceHeadSha")==central_sha
         and state.get("publisherAuthorized") is False
         and state.get("writeOutcomeUnknown") is False
         and type(state.get("targets")) is dict
         and len(state["targets"])==17 and
         set(state["targets"])=={x["repo"] for x in request["targets"]}
         and set(state["targets"].values())=={"SUCCESS"},
         "original 17-durable State missing/privileged/ambiguous or wrong cycle")
    need(type(boundary) is dict and boundary=={
        "schemaVersion":1,"mode":"ENFORCE",
        "publisherAppId":PUBLISHER_APP_ID,
        "publisherInstallationId":PUBLISHER_INSTALLATION_ID,
        "signerAppId":SIGNER_APP_ID}
         and len({APP_ID,SIGNER_APP_ID,PUBLISHER_APP_ID})==3,
         "Publisher App identity not isolated from prepare/signing actors")
    return {
        "schemaVersion":1,"status":"APP_R08_SIGNED_SOURCE_PUBLISH_DENY_ADMISSION_ONLY",
        "sourceKind":source_kind,"centralMainSha":central_sha,
        "centralRunId":central_run_id,"appFleetRunId":fleet_run_id,
        "signedLocalRunId":local_run_id,"localMainSha":local_sha,
        "stateGitBlobSha":state_blob,"requestRawSha256":request_raw_sha,
        "originalAppId":APP_ID,"originalAppBotId":BOT_ID,
        "signerAppId":SIGNER_APP_ID,"publisherAppId":PUBLISHER_APP_ID,
        "publisherAppSeparated":True,
        "realIndependentSourceMetadataGets":True,
        "cryptographicVerificationRepeatedByThisJob":False,
        "publisherSourceKindAuthorized":False,
        "publisherTokenRequested":False,"publisherWriteAuthorized":False,
        "publicationAuthorized":False,"publishableReceipt":False,
        "writeOutcomeUnknown":False,"runtimeEnabled":False,
        "releasePostAttempted":False,
        "decision":"PUBLISH_DENY","next":"separate formal Publisher source-kind authorization required",
    }

def api(path):
    need(os.environ.get("GH_TOKEN"),"read-only token required")
    need(re.fullmatch(r"repos/pgextwin/(build|orafce)/(actions/runs/[1-9][0-9]*(/jobs\?per_page=100|/artifacts\?per_page=100)?|branches/main|contents/\.github/execution-requests/r-20[0-9]{6}-r06prepare[a-z0-9-]{4,40}\.json\?ref=[a-f0-9]{40}|contents/checkpoints/request-lifecycle/r-20[0-9]{6}-r06appauto[1-9][0-9]*\.json\?ref=issue311-state)",path),
         "GET endpoint outside read-only fixed evidence allowlist")
    cp=subprocess.run(["gh","api","--method","GET",path],capture_output=True,
                      text=True,timeout=45,check=False)
    need(cp.returncode==0 and 0<len(cp.stdout)<10_000_000,
         "failed authenticated GitHub GET; no optimistic Publisher fallback")
    return parse(cp.stdout)

def decoded(obj):
    need(obj.get("encoding")=="base64" and type(obj.get("content")) is str,
         "Git Contents is not immutable bytes")
    raw=base64.b64decode(obj["content"].replace("\n",""),validate=True)
    need(git_blob(raw)==obj.get("sha"),"Git object blob SHA does not match original bytes")
    return raw,obj["sha"]

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--central-run",type=int,required=True)
    p.add_argument("--fleet-run",type=int,required=True)
    p.add_argument("--local-run",type=int,required=True)
    p.add_argument("--request-id",required=True)
    p.add_argument("--output",required=True)
    a=p.parse_args()
    try:
        need(os.environ.get("GITHUB_REPOSITORY")==CENTRAL_REPO
             and os.environ.get("GITHUB_EVENT_NAME")=="push"
             and os.environ.get("GITHUB_REF")=="refs/heads/main"
             and os.environ.get("GITHUB_RUN_ATTEMPT")=="1"
             and os.environ.get("GITHUB_ACTOR")=="ShutenOishi",
             "not original protected build postmerge read-only proof")
        central=api(f"repos/{CENTRAL_REPO}/actions/runs/{a.central_run}")
        fleet=api(f"repos/{CENTRAL_REPO}/actions/runs/{a.fleet_run}")
        local=api(f"repos/{REPOSITORY}/actions/runs/{a.local_run}")
        local_branch=api(f"repos/{REPOSITORY}/branches/main")
        jobs=api(f"repos/{REPOSITORY}/actions/runs/{a.local_run}/jobs?per_page=100")
        artifacts=api(f"repos/{REPOSITORY}/actions/runs/{a.local_run}/artifacts?per_page=100")
        raw,gitsha=decoded(api(f"repos/{CENTRAL_REPO}/contents/.github/execution-requests/{a.request_id}.json?ref={central['head_sha']}"))
        original=parse(raw)
        need(original.get("requestId")==a.request_id,"requestId path does not match")
        state_path=f"checkpoints/request-lifecycle/r-20261030-r06appauto{a.fleet_run}.json"
        state_raw,state_blob=decoded(api(
            f"repos/{CENTRAL_REPO}/contents/{state_path}?ref=issue311-state"))
        boundary=parse(Path("metadata/publisher-write-boundary.json").read_text("utf-8"))
        receipt=assess(
            local=local,central=central,fleet=fleet,local_branch=local_branch,
            state=parse(state_raw),state_blob=state_blob,
            request=original,request_raw_sha=hashlib.sha256(raw).hexdigest(),
            jobs=jobs,artifacts=artifacts,boundary=boundary,
            central_run_id=a.central_run,fleet_run_id=a.fleet_run,
            local_run_id=a.local_run,central_sha=central["head_sha"],
            local_sha=local["head_sha"],source_kind=SOURCE)
        Path(a.output).write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n",
                                   encoding="utf-8")
        print("R08_APP_ACTOR_SEPARATE_PUBLISHER_ADMISSION_DENY; NO_WRITE; NO_RELEASE")
        return 0
    except (Denied,KeyError,OSError,ValueError,TypeError,
            subprocess.TimeoutExpired) as exc:
        print("R08_APP_PUBLISHER_DENY: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
