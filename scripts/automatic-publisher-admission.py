#!/usr/bin/env python3
"""Independent scheduled-signed-source -> existing formal Publisher intake.

This is a READ-ONLY, nonpublishing prerequisite, NOT a signed Release receipt.
The source evidence must originate from a real same-job
verify-completed-signed-source.py invocation. The future credentialed Publisher
MUST independently repeat live proof and policy checks before any WRITE token.
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
def load(name, path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj
scope=load("scheduled_admission_scope","publisher-scoped-token.py")
identity=load("scheduled_admission_identity","fleet-release-identity.py")
SHA=re.compile(r"^[a-f0-9]{40}$")
HASH=re.compile(r"^[a-f0-9]{64}$")
SCHEDULE_WORKFLOW=".github/workflows/publisher-candidate-intake.yml"
SOURCE_WORKFLOW=".github/workflows/update-watch.yml"
BLOCKERS=(
    "CENTRAL_MANUAL_DISPATCH",
    "LOCAL_MANUAL_DISPATCH",
    "FLEET_MANUAL_ONLY",
    "UNATTENDED_OBSERVE_DENY",
    "INDEPENDENT_PUBLISHER_WRITE_POLICY_DENY",
    "INDEPENDENT_LIVE_PUBLISHER_AUTHORIZATION_REQUIRED",
)

class Denied(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Denied(reason)

def unique(items):
    value={}
    for name,item in items:
        require(name not in value,"duplicate JSON field")
        value[name]=item
    return value

def read(path):
    file=Path(path)
    require(file.is_file() and not file.is_symlink() and
            0 < file.stat().st_size < 1024*1024,"unsafe/missing input")
    obj=json.loads(file.read_text("utf-8-sig"),object_pairs_hook=unique)
    require(type(obj) is dict,"not a JSON object")
    return obj

def assess(source,proposal,manifest,fleet,central,local,unattended,boundary,
           schedule_run,*,repository,sha,source_run_id,central_sha,
           schedule_run_id,schedule_attempt,event,ref,central_branch):
    """Correlate separately authenticated source and scheduler; DENY issuance.

    A structurally valid untrusted JSON object does NOT prove Sigstore/GitHub.
    Caller must freshly re-download and verify original signed bytes in the
    same trusted job, never pass a previous build artifact as independent auth.
    """
    require(type(repository) is str and
            scope.REPO.fullmatch(repository) and
            type(sha) is str and SHA.fullmatch(sha) and
            type(central_sha) is str and SHA.fullmatch(central_sha) and
            type(source_run_id) is int and source_run_id>0 and
            type(schedule_run_id) is int and schedule_run_id>0 and
            type(schedule_attempt) is int and schedule_attempt==1 and
            event=="schedule" and ref=="refs/heads/main",
            "not an original completed signed source plus genuine schedule")
    require(type(central_branch) is dict and
            central_branch.get("name")=="main" and
            central_branch.get("protected") is True and
            (central_branch.get("commit") or {}).get("sha")==central_sha,
            "central schedule is not on the current protected main")
    require(type(schedule_run) is dict and
            type(schedule_run.get("id")) is int and
            schedule_run["id"]==schedule_run_id and
            type(schedule_run.get("run_attempt")) is int and
            schedule_run["run_attempt"]==1 and
            (schedule_run.get("repository") or {}).get("full_name")=="pgextwin/build" and
            schedule_run.get("head_sha")==central_sha and
            schedule_run.get("head_branch")=="main" and
            schedule_run.get("event")=="schedule" and
            schedule_run.get("path")==SCHEDULE_WORKFLOW and
            schedule_run.get("status")=="in_progress" and
            schedule_run.get("conclusion") is None,
            "unverified central schedule invocation")
    scope.valid_fleet(fleet,repository)
    require(type(manifest) is dict and manifest.get("name")==repository.split("/")[1],
            "untrusted signed source manifest")
    require(type(source) is dict and
            type(source.get("schemaVersion")) is int and
            source["schemaVersion"]==1 and
            source.get("status")=="REAL_COMPLETED_SIGNED_SOURCE_VERIFIED_NONPUBLISHING" and
            source.get("repository")==repository and
            source.get("mainMergeSha")==sha and
            type(source.get("sourceRunId")) is int and
            source["sourceRunId"]==source_run_id and
            type(source.get("sourceRunAttempt")) is int and
            source["sourceRunAttempt"]==1 and
            source.get("realSigstoreRechecked") is True and
            type(source.get("blockingGrypeFindings")) is int and
            source["blockingGrypeFindings"]==0 and
            all(source.get(x) is False for x in (
                "publisherTokenRequested","publicationAuthorized",
                "publishableReceipt","automaticReleaseEnabled")),
            "replayed/forged/incomplete independent real-signed source")
    majors=source.get("maintainedMajors")
    require(type(majors) is list and bool(majors) and
            len(majors)<=5 and
            all(type(m) is int and m in (14,15,16,17,18) for m in majors) and
            majors==sorted(set(majors)),
            "invalid maintained signed PostgreSQL matrix")
    try:
        pins=identity.sources(manifest)
        identity.validate_release_tag(manifest,proposal.get("releaseTagProposal"))
    except (identity.Denied,KeyError,TypeError,ValueError,AttributeError) as exc:
        raise Denied("invalid pinned source/tag proposal") from exc
    require(set(majors).issubset(pins),"unsigned PostgreSQL major")
    digests={}
    for asset in ("zip","spdx","grype"):
        values=source.get(asset+"Sha256ByMajor")
        require(type(values) is dict and set(values)=={str(m) for m in majors} and
                all(type(v) is str and HASH.fullmatch(v) for v in values.values()),
                "incomplete signed digest matrix")
        digests[asset]=values
    require(type(proposal) is dict and
            type(proposal.get("schemaVersion")) is int and
            proposal["schemaVersion"]==1 and
            proposal.get("status")=="PROPOSED_TAG_NONPUBLISHING" and
            proposal.get("repository")==repository and
            proposal.get("mainMergeSha")==sha and
            type(proposal.get("runId")) is int and
            proposal["runId"]==source_run_id and
            type(proposal.get("runAttempt")) is int and
            proposal["runAttempt"]==1 and
            proposal.get("publicationAuthorized") is False and
            proposal.get("publishableReceipt") is False and
            proposal.get("publisherWriteEnabled") is False and
            proposal.get("requiresIndependentLiveRecheckAndAtomicTagReservation") is True,
            "unauthenticated or unauthorized proposed Release tag")
    require(type(central) is dict and
            central.get("schemaVersion")==1 and
            central.get("releasePolicy")=="manual-dispatch" and
            type(central.get("allowedRepositories")) is list and
            len(central["allowedRepositories"])==len(fleet["entries"]) and
            set(central["allowedRepositories"])==
              {item["repository"] for item in fleet["entries"]},
            "central formal Publisher policy differs from protected registry")
    require(local=={"schemaVersion":1,"enabled":True,
                   "releasePolicy":"manual-dispatch"},
            "local formal Publisher policy invalid")
    require(type(unattended) is dict and unattended.get("schemaVersion")==1 and
            unattended.get("mode")=="OBSERVE" and
            unattended.get("defaultAction")=="DENY" and
            type(unattended.get("controls")) is dict and
            unattended["controls"].get("automaticFormalRelease") is False,
            "unexpected unattended release policy")
    require(type(boundary) is dict and
            boundary=={"schemaVersion":1,"mode":"DENY",
                       "publisherAppId":None,
                       "publisherInstallationId":None,
                       "signerAppId":15368},
            "privileged Publisher policy not explicitly DENY")
    return {
        "schemaVersion":1,
        "status":"SIGNED_SCHEDULE_PUBLISHER_ADMISSION_EVIDENCE_ONLY",
        "repository":repository,"mainMergeSha":sha,
        "sourceRunId":source_run_id,"sourceRunAttempt":1,
        "centralMainSha":central_sha,
        "scheduleRunId":schedule_run_id,"scheduleRunAttempt":1,
        "scheduleWorkflow":SCHEDULE_WORKFLOW,
        "signedSourceWorkflow":SOURCE_WORKFLOW,
        "releaseTagProposal":proposal["releaseTagProposal"],
        "maintainedMajors":majors,
        "sourcePins":[pins[m] for m in majors],
        "zipSha256ByMajor":digests["zip"],
        "spdxSha256ByMajor":digests["spdx"],
        "grypeSha256ByMajor":digests["grype"],
        "mustRepeatRealSigstoreAndCurrentPolicyInPrivilegedPublisher":True,
        "mustCheckTagAndReleaseAbsenceBeforeAtomicReservation":True,
        "publisherTokenRequested":False,
        "publicationAuthorized":False,
        "publishableReceipt":False,
        "publisherWriteAuthorized":False,
        "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO",
        "policyBlockers":list(BLOCKERS),
    }

def main():
    parser=argparse.ArgumentParser()
    for name in ("source","proposal","manifest","fleet","central-policy",
                 "local-policy","unattended","publisher-boundary",
                 "schedule-run","central-branch","output"):
        parser.add_argument("--"+name,required=True)
    p=parser.parse_args()
    try:
        require(os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build" and
                os.environ.get("GITHUB_EVENT_NAME")=="schedule" and
                os.environ.get("GITHUB_REF")=="refs/heads/main",
                "not the trusted central schedule job")
        result=assess(
            read(p.source),read(p.proposal),read(p.manifest),read(p.fleet),
            read(p.central_policy),read(p.local_policy),
            read(p.unattended),read(p.publisher_boundary),
            read(p.schedule_run),
            repository=os.environ.get("TARGET_REPOSITORY"),
            sha=os.environ.get("TARGET_SOURCE_SHA"),
            source_run_id=int(os.environ.get("TARGET_SOURCE_RUN","0")),
            central_sha=os.environ.get("GITHUB_SHA"),
            schedule_run_id=int(os.environ.get("GITHUB_RUN_ID","0")),
            schedule_attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT","0")),
            event=os.environ.get("GITHUB_EVENT_NAME"),
            ref=os.environ.get("GITHUB_REF"),
            central_branch=read(p.central_branch))
        Path(p.output).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
        print("SIGNED_SCHEDULE_PUBLISHER_ADMISSION_EVIDENCE_ONLY; PUBLISH_DENY")
        return 0
    except (Denied,scope.Denied,KeyError,ValueError,TypeError,OSError) as exc:
        print("SIGNED_SCHEDULE_PUBLISHER_DENY: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
