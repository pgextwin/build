#!/usr/bin/env python3
"""Fail-closed typed scheduled Publisher receipt issuer (Issue #75).

Only call IN PROCESS in a protected Publisher Environment after authentic
GitHub GET, real original ZIP/SPDX/Grype+Sigstore verification and a freshly
scoped JWT-authenticated App token. JSON/PR artifacts alone are NEVER authority.
No entrypoint, secrets, network or Release mutations are provided here.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m
ident=load("scheduled_release_identity","fleet-release-identity.py")
typed=load("scheduled_release_receipt","release-authorization.py")
policy=load("scheduled_release_policy","unattended-policy.py")
SHA=re.compile(r"^[0-9a-f]{40}$")
HASH=re.compile(r"^[0-9a-f]{64}$")
REPO=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
MODE="automatic-signed-schedule"
APP=5451798
INSTALLATION=174720074
SCHEDULE=".github/workflows/publisher-candidate-intake.yml"
SOURCE=".github/workflows/update-watch.yml"

class Denied(ValueError): pass
def check(value,why):
    if not value: raise Denied(why)

def policy_gate(fleet,central,local,unattended,boundary,repository):
    """Manual-only/OBSERVE/DENY is categorically NOT implicit approval."""
    check(type(repository) is str and REPO.fullmatch(repository)
          and type(fleet) is dict and fleet.get("schemaVersion")==1
          and type(fleet.get("schemaVersion")) is int
          and fleet.get("releasePolicy")==MODE
          and type(fleet.get("entries")) is list and bool(fleet["entries"]),
          "future automatic signed fleet policy not approved")
    # Readiness, protected CI and the actual issuer must enforce the SAME
    # complete control schema. all(supplied_controls.values()) alone accepts
    # missing defenses, including a one-field automaticFormalRelease object.
    try:
        decision=policy.evaluate(unattended,fleet)
    except (policy.PolicyDenied,KeyError,TypeError,ValueError) as exc:
        raise Denied("incomplete or invalid shared unattended policy") from exc
    names=decision.get("eligibleRepositories",[])
    check(decision.get("status")=="POLICY_READY_RUNTIME_EVIDENCE_REQUIRED"
          and decision.get("automaticPublicationAuthorized") is False
          and repository in names,
          "complete registered automatic fleet not ready")
    check(type(central) is dict and central.get("schemaVersion")==1
          and type(central.get("schemaVersion")) is int
          and central.get("releasePolicy")==MODE
          and type(central.get("allowedRepositories")) is list
          and len(central["allowedRepositories"])==len(names)
          and set(central["allowedRepositories"])==set(names),
          "central Publisher auto-release policy not approved")
    check(type(local) is dict and type(local.get("schemaVersion")) is int
          and local.get("enabled") is True
          and local=={"schemaVersion":1,"enabled":True,"releasePolicy":MODE},
          "local automatic release not explicitly approved")
    check(type(boundary) is dict and type(boundary.get("schemaVersion")) is int
          and boundary=={
          "schemaVersion":1,"mode":"ENFORCE",
          "publisherAppId":APP,"publisherInstallationId":INSTALLATION,
          "signerAppId":15368},
          "independent Publisher policy/App mismatch")

def issue(*, proof, lifecycle, manifest, fleet, central, local, unattended,
          boundary, schedule_run, central_branch, signed_branch,
          app_identity, installation_identity, minted, scoped,
          repository, sha, source_run, central_sha, publisher_run,
          event, ref, attempt, tag, tag_absent, release_absent, actor):
    """In-process Release receipt: only after all genuinely independent gates.

    The caller must supply proof produced by real verify_completed_source()
    IN THIS JOB, not by reading a prior artifact containing equivalent JSON.
    Caller must also establish the live App issuer and token using JWT requests.
    """
    policy_gate(fleet,central,local,unattended,boundary,repository)
    check(type(sha) is str and SHA.fullmatch(sha)
          and type(central_sha) is str and SHA.fullmatch(central_sha)
          and type(source_run) is int and source_run>0
          and type(publisher_run) is int and publisher_run>0
          and source_run!=publisher_run
          and type(attempt) is int and attempt==1
          and event=="schedule" and ref=="refs/heads/main",
          "not original attempt1 central schedule plus distinct signed main/push")
    for branch,expected in ((central_branch,central_sha),(signed_branch,sha)):
        check(type(branch) is dict and branch.get("name")=="main"
              and branch.get("protected") is True
              and (branch.get("commit") or {}).get("sha")==expected,
              "current protected branch advanced/changed")
    check(type(schedule_run) is dict
          and type(schedule_run.get("id")) is int
          and schedule_run["id"]==publisher_run
          and type(schedule_run.get("run_attempt")) is int
          and schedule_run["run_attempt"]==1
          and (schedule_run.get("repository") or {}).get("full_name")=="pgextwin/build"
          and schedule_run.get("event")=="schedule"
          and schedule_run.get("path")==SCHEDULE
          and schedule_run.get("head_sha")==central_sha
          and schedule_run.get("head_branch")=="main"
          and schedule_run.get("status")=="in_progress"
          and schedule_run.get("conclusion") is None,
          "central schedule not authenticated or is a replay")
    check(type(proof) is dict and proof.get("schemaVersion")==1
          and proof.get("status")=="REAL_COMPLETED_SIGNED_SOURCE_VERIFIED_NONPUBLISHING"
          and proof.get("repository")==repository
          and proof.get("mainMergeSha")==sha
          and type(proof.get("sourceRunId")) is int
          and proof["sourceRunId"]==source_run
          and type(proof.get("sourceRunAttempt")) is int
          and proof["sourceRunAttempt"]==1
          and proof.get("realSigstoreRechecked") is True
          and type(proof.get("blockingGrypeFindings")) is int
          and proof["blockingGrypeFindings"]==0
          and all(proof.get(k) is False for k in (
              "publicationAuthorized","publishableReceipt",
              "publisherTokenRequested","automaticReleaseEnabled")),
          "original signed ZIP/SBOM/Grype cryptographic proof not established")
    check(type(manifest) is dict and manifest.get("name")==repository.split("/")[1],
          "source manifest/repository mismatch")
    try:
        majors=ident.maintained_majors(manifest,lifecycle)
        pins=ident.sources(manifest)
        ident.validate_release_tag(manifest,tag)
    except (ident.Denied,KeyError,TypeError,ValueError) as exc:
        raise Denied("invalid maintained PG versions/upstream/tag") from exc
    check(proof.get("maintainedMajors")==majors and bool(majors),
          "original signed PG major list mismatch")
    for kind in ("zip","spdx","grype"):
        hashes=proof.get(kind+"Sha256ByMajor")
        check(type(hashes) is dict and set(hashes)=={str(m) for m in majors}
              and all(type(d) is str and HASH.fullmatch(d) for d in hashes.values()),
              "missing signed "+kind+" digest evidence")
    check(tag_absent is True and release_absent is True,
          "existing/unverifiable GitHub tag or Release")
    check(type(app_identity) is dict and app_identity.get("id")==APP
          and app_identity.get("slug")=="pgextwin-publisher"
          and type(installation_identity) is dict
          and installation_identity.get("id")==INSTALLATION
          and installation_identity.get("app_id")==APP
          and (installation_identity.get("account") or {}).get("login")=="pgextwin"
          and installation_identity.get("repository_selection")=="all"
          and installation_identity.get("permissions")=={
              "contents":"write","metadata":"read"}
          and installation_identity.get("suspended_at") is None,
          "untrusted independent Publisher JWT/App issuer")
    check(type(minted) is dict
          and type(minted.get("token")) is str and len(minted["token"])>20
          and minted.get("repository_selection")=="selected"
          and minted.get("permissions")=={"contents":"write","metadata":"read"}
          and type(scoped) is dict and type(scoped.get("total_count")) is int
          and scoped["total_count"]==1
          and type(scoped.get("repositories")) is list
          and len(scoped["repositories"])==1
          and type(scoped["repositories"][0]) is dict
          and scoped["repositories"][0].get("full_name")==repository,
          "independent Publisher token scope unknown or expanded")
    receipt={
        "schemaVersion":1,"status":"VERIFIED_AUTOMATIC_SCHEDULE",
        "authorizationMode":"automatic-schedule",
        "repository":repository,"trustedCommit":sha,
        "extension":manifest["name"],"releaseTag":tag,
        "majors":majors,"sources":[pins[m] for m in majors],
        "publisherRepository":"pgextwin/build",
        "publisherWorkflow":SCHEDULE,
        "publisherRunId":publisher_run,"publisherRunAttempt":1,
        "publisherMainSha":central_sha,
        "signedSourceWorkflow":SOURCE,"sourceRunId":source_run,
        "sourceRunAttempt":1,"signedArtifactsVerified":True,
        "publicationAuthorized":True,"publishableReceipt":True,
        "publisherWriteAuthorized":True,"automaticReleaseEnabled":True,
        "approvalProvenance":"INDEPENDENT_LIVE_SCHEDULE_AND_SIGNED_SOURCE",
    }
    typed.validate_receipt(receipt,repository=repository,commit=sha,
                           actor=actor,event="schedule")
    return receipt
