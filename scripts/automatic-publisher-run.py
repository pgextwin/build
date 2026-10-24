#!/usr/bin/env python3
"""Isolated protected-main Publisher: same-job source proof -> App -> formal writer.

Credentials belong ONLY to the dedicated Publisher Environment. Never accept
an uploaded publishable receipt. This executable recreates its own receipt from
fresh authenticated original run metadata, real Sigstore and current policies.
On current OBSERVE/manual-only/PUBLISH_DENY configuration it rejects BEFORE key
use; it never asks an operator to spoof workflow_dispatch or waive failing CI.
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
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m
issuer=load("auto_runtime_issuer","automatic-publisher-receipt-issuer.py")
source=load("auto_runtime_real_signed_source","verify-completed-signed-source.py")
scope=load("auto_runtime_token_lifecycle","publisher-scoped-token.py")
probe=load("auto_runtime_jwt","probe-publisher-app.py")
formal=load("auto_runtime_frozen_formal_writer","fleet-publish-release.py")
TAG=re.compile(r"^v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*$")

class Denied(ValueError):pass

def require(ok,message):
    if not ok:raise Denied(message)

def main():
    parser=argparse.ArgumentParser()
    for name in ("repository","sha","source-run","dist","manifest","lifecycle",
                 "original","second","proposal","fleet","central-policy",
                 "local-policy","unattended","publisher-boundary","recovery","output"):
        parser.add_argument("--"+name,required=True)
    a=parser.parse_args()
    try:
        require(os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build"
                and os.environ.get("GITHUB_EVENT_NAME")=="schedule"
                and os.environ.get("GITHUB_REF")=="refs/heads/main"
                and os.environ.get("GITHUB_RUN_ATTEMPT")=="1"
                and type(os.environ.get("GH_TOKEN")) is str
                and len(os.environ["GH_TOKEN"])>10,
                "not an original protected central schedule with read credentials")
        require(os.environ.get("PUBLISHER_APP_ID")==str(issuer.APP)
                and os.environ.get("PUBLISHER_INSTALLATION_ID")==str(issuer.INSTALLATION),
                "dedicated independent Publisher App variables missing")
        repository=a.repository
        sha=a.sha
        original_id=int(a.source_run)
        publisher_id=int(os.environ["GITHUB_RUN_ID"])
        central_sha=os.environ["GITHUB_SHA"]
        fleet=source.read(a.fleet)
        central=source.read(a.central_policy)
        local=source.read(a.local_policy)
        unattended=source.read(a.unattended)
        boundary=source.read(a.publisher_boundary)
        manifest=source.read(a.manifest)
        lifecycle=source.read(a.lifecycle)
        proposal=source.read(a.proposal)
        # First *unprivileged* gate; do not even access the private key until
        # all explicit protected policies are already switched by approved PR.
        issuer.policy_gate(fleet,central,local,unattended,boundary,repository)
        require(type(proposal.get("runId")) is int
                and proposal["runId"]==original_id
                and proposal.get("runAttempt")==1
                and proposal.get("repository")==repository
                and proposal.get("mainMergeSha")==sha
                and proposal.get("status")=="PROPOSED_TAG_NONPUBLISHING"
                and proposal.get("publicationAuthorized") is False
                and proposal.get("publishableReceipt") is False
                and proposal.get("publisherWriteEnabled") is False
                and proposal.get("requiresIndependentLiveRecheckAndAtomicTagReservation") is True,
                "original signed proposal not a nonpublishing exact-run witness")
        tag=proposal.get("releaseTagProposal")
        require(type(tag) is str and TAG.fullmatch(tag),
                "invalid exact proposed Release tag")
        # The in-process result is produced ONLY by the real verifier:
        # authenticated source branch/run/jobs/artifacts + actual bytes and
        # both gh attestation verify predicates for each maintained PG major.
        proof=source.verify_completed_source(
            Path(a.dist),manifest,lifecycle,source.read(a.original),
            source.read(a.second),fleet,
            repository=repository,sha=sha,run_id=original_id)
        central_branch=source.github("pgextwin/build","branches/main")
        signed_branch=source.github(repository,"branches/main")
        schedule_run=source.github("pgextwin/build",f"actions/runs/{publisher_id}")
        require(central_branch.get("commit",{}).get("sha")==central_sha,
                "current central protected main changed")
        formal.REPO=repository
        formal.absent(tag) # uses READ-only GitHub credential, denies 403/5xx
        # Key is read ONLY after original independent full proof and policies.
        key=os.environ.pop("PUBLISHER_PRIVATE_KEY")
        require(type(key) is str and bool(key),"publisher private key unavailable")
        app_id=int(os.environ["PUBLISHER_APP_ID"])
        installation=int(os.environ["PUBLISHER_INSTALLATION_ID"])
        jwt=probe.jwt(key,app_id)
        app_identity=probe.api("GET","/app",jwt)
        installation_identity=probe.api(
            "GET","/app/installations/"+str(installation),jwt)
        with scope.single_repository_token(
            api=probe.api,jwt=probe.jwt,key=key,
            app=app_id,installation=installation,
            repository=repository,fleet=fleet,
            release_policy=issuer.MODE) as (publisher_token,minted,scoped):
            receipt=issuer.issue(
                proof=proof,lifecycle=lifecycle,manifest=manifest,
                fleet=fleet,central=central,local=local,unattended=unattended,
                boundary=boundary,schedule_run=schedule_run,
                central_branch=central_branch,signed_branch=signed_branch,
                app_identity=app_identity,
                installation_identity=installation_identity,
                minted=minted,scoped=scoped,
                repository=repository,sha=sha,source_run=original_id,
                central_sha=central_sha,publisher_run=publisher_id,
                event=os.environ["GITHUB_EVENT_NAME"],
                ref=os.environ["GITHUB_REF"],
                attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
                tag=tag,tag_absent=True,release_absent=True,
                actor=os.environ.get("GITHUB_ACTOR",""))
            # Keep the central GET/attestation READ identity until all full
            # original source metadata and real signatures have been checked
            # AGAIN by the deployed formal Publisher preflight.
            expected=formal.check_assets(
                Path(a.dist),manifest,receipt,sha,original_id,lifecycle,
                verify_signatures=True,workflow_event="schedule")
            require(proof["zipSha256ByMajor"]=={
                str(m):expected[formal.ident.asset_stem(manifest,m)+".zip"]
                for m in proof["maintainedMajors"]},
                "separate formal Publisher ZIP byte digests differ")
            for obj,expected_sha in (
                (source.github("pgextwin/build","branches/main"),central_sha),
                (source.github(repository,"branches/main"),sha)):
                require(obj.get("protected") is True
                        and obj.get("commit",{}).get("sha")==expected_sha,
                        "protected source/central main changed before Release")
            current=source.github("pgextwin/build",f"actions/runs/{publisher_id}")
            require(type(current) is dict
                    and all(current.get(k)==schedule_run.get(k) for k in
                            ("id","run_attempt","event","path","head_sha",
                             "head_branch"))
                    and (current.get("repository") or {}).get("full_name")==
                        "pgextwin/build"
                    and current.get("status")=="in_progress"
                    and current.get("conclusion") is None,
                    "live schedule Run identity changed before Release")
            formal.absent(tag)
            # Absolutely NO GitHub WRITE without valid typed independent
            # receipt, repeated gh signatures, protected ref and tag absence.
            original_read_token=os.environ["GH_TOKEN"]
            try:
                os.environ["GH_TOKEN"]=publisher_token
                formal.publish_preverified(
                    Path(a.dist),manifest,receipt,sha,expected,
                    Path(a.recovery),publish_run_id=publisher_id)
            finally:
                os.environ["GH_TOKEN"]=original_read_token
        # Expiring token has been REVOKED, including when a write raises.
        Path(a.output).write_text(json.dumps({
            "schemaVersion":1,"status":"PUBLISHED_VERIFIED",
            "repository":repository,"mainMergeSha":sha,
            "sourceRunId":original_id,"publisherRunId":publisher_id,
            "tag":tag,"publisherTokenRevoked":True},sort_keys=True,indent=2)+"\n",
            encoding="utf-8")
        print("AUTOMATIC_SIGNED_RELEASE_PUBLISHED_AND_TOKEN_REVOKED")
        return 0
    except Exception as exc:
        # API/CLI exception bodies may contain credentials; never print them.
        name=type(exc).__name__
        print("AUTOMATIC_SIGNED_PUBLISHER_DENY ("+name+
              "); credential/API details suppressed",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
