#!/usr/bin/env python3
"""Issue #75 G3: pure synthetic future-tuple join, always nonpublishable.

NO entry point, network, token, file write, GitHub API, publisher or mutable
Release action. Inputs must be constructed by offline tests; acceptance is a
contract consistency check, NOT authenticated evidence or an authorization.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPOSITORY = "pgextwin/plpgsql_check"


class Denied(ValueError):
    """Malformed input or attempted promotion across an inert trust boundary."""


def require(value, reason):
    if not value:
        raise Denied(reason)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    require(spec is not None and spec.loader is not None,
            "existing trusted contract module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


approval_lib = load("issue75_g3_approval", "chat-pr-authorization.py")
jit_lib = load("issue75_g3_jit", "chat-pr-phase-d-prepublish.py")
receipt_lib = load("issue75_g3_receipt", "release-authorization.py")


def _manual_only(central, local, fleet):
    require(type(central) is dict and central.get("releasePolicy") == "manual-dispatch"
            and REPOSITORY in central.get("allowedRepositories", []),
            "central manual-dispatch policy changed")
    require(type(local) is dict and local.get("releasePolicy") == "manual-dispatch"
            and local.get("enabled") is True,
            "local manual-dispatch policy changed")
    require(type(fleet) is dict and fleet.get("releasePolicy") == "manual-only"
            and type(fleet.get("entries")) is list and bool(fleet["entries"])
            and all(type(e) is dict and e.get("releasePolicy") == "manual-only"
                    for e in fleet["entries"]),
            "fleet manual-only policy changed")


def _package_tuple(package, run, source, candidate, approval):
    """Validate only future *shape*, never provenance or signature validity."""
    require(type(candidate) is dict and type(package) is dict
            and type(run) is dict and type(source) is dict,
            "missing synthetic candidate/package/run/source")
    majors = candidate.get("majors")
    sources = candidate.get("sources")
    require(type(majors) is list and len(majors) > 0
            and all(type(m) is int and 14 <= m <= 19 for m in majors)
            and len(set(majors)) == len(majors)
            and type(sources) is list and len(sources) == len(majors),
            "incomplete candidate major/source matrix")
    major = (package.get("postgresql") or {}).get("major")
    require(type(major) is int and major in majors,
            "PACKAGE-INFO PostgreSQL major not in candidate")
    mapped = sources[majors.index(major)]
    require(type(mapped) is dict and all(
        type(mapped.get(k)) is str and mapped[k] == source.get(k)
        for k in ("commit", "ref", "version"))
        and approval_lib.full_sha(source.get("commit")),
        "PACKAGE-INFO source does not match SHA-pinned candidate")
    require(package.get("buildMode") == "release-attested"
            and (package.get("package") or {}).get("name") == REPOSITORY.split("/")[-1]
            and type(package.get("upstream")) is dict
            and all(package["upstream"].get(k) == source.get(k)
                    for k in ("repository", "commit", "ref", "version"))
            and (package.get("source") or {}).get("packagingRepository") == REPOSITORY
            and package["source"].get("packagingCommit") ==
            approval.get("authorizationCommit"),
            "PACKAGE-INFO identity or packaging commit mismatch")
    workflow = package.get("workflowRun")
    require(type(workflow) is dict
            and type(workflow.get("id")) is int and workflow["id"] > 0
            and type(workflow.get("attempt")) is int and workflow["attempt"] == 1
            and workflow.get("event") == "push"
            and workflow.get("ref") == "refs/heads/main",
            "PACKAGE-INFO future workflow identity inconsistent")
    require(type(run.get("id")) is int and run["id"] == workflow["id"]
            and run.get("event") == workflow["event"]
            and run.get("run_attempt") == workflow["attempt"]
            and run.get("head_branch") == "main"
            and run.get("head_sha") == approval.get("authorizationCommit")
            and run.get("status") == "completed"
            and run.get("conclusion") == "success",
            "independent future run fixture does not bind PACKAGE-INFO")
    return major


def verify_inert_g3(*, central, local, fleet, raw_authorization,
                    github_approval, candidate_receipt, jit_reader,
                    package_info, package_run, package_source):
    """Exercise existing B/C/D gates on fixtures and always return DENY context.

    No synthetic fixture can grant permission to invoke a publisher, even if
    the proposed future event, typed receipt and PACKAGE-INFO fully agree.
    """
    _manual_only(central, local, fleet)
    require(type(github_approval) is dict
            and github_approval.get("repository") == REPOSITORY
            and type(github_approval.get("event")) is dict,
            "future GitHub authorization fixture absent")
    event = github_approval["event"]
    require(type(event.get("sender")) is dict
            and approval_lib.human(event["sender"].get("login"))
            and type(event.get("after")) is str
            and approval_lib.full_sha(event["after"]),
            "invalid future main push actor/SHA")
    try:
        approval = approval_lib.verify_approval(
            raw_authorization, **github_approval)
        bound = approval_lib.bind_verified_receipt(candidate_receipt, approval)
        jit = jit_lib.verify_inert_prepublication_recheck(
            jit_reader, expected_main_sha=event["after"],
            expected_operator=approval["operator"])
    except (approval_lib.Denied, jit_lib.PhaseDDenied,
            TypeError, KeyError, IndexError, ValueError) as exc:
        raise Denied("existing authorization/candidate/JIT contract denied") from None
    require(jit.get("status") == "DRY_RUN_PHASE_D_RECHECK_ONLY"
            and jit.get("snapshotCount") == 2
            and jit.get("authorizationPr") == approval["authorizationPr"]
            and jit.get("candidatePr") == approval["candidatePr"]
            and jit.get("candidateRunId") == approval["candidateRunId"]
            and jit.get("decisionRunId") == approval["decisionRunId"]
            and jit.get("mainSha") == approval["authorizationCommit"]
            and jit.get("publishableReceipt") is False
            and jit.get("signedArtifactsVerified") is False
            and jit.get("publishingEnabled") is False,
            "G3 future fixture lacks stable independent two-round JIT")
    require(bound.get("status") == "DRY_RUN_CONTEXT_ONLY"
            and bound.get("authorizationMode") == "chat-pr-authorization"
            and bound.get("candidateGateStatus") == "VERIFIED_CHAT_PR_AUTHORIZATION"
            and bound.get("signedArtifactsVerified") is False
            and bound.get("publishableReceipt") is False
            and bound.get("publishingEnabled") is False,
            "identity-only typed context must remain nonpublishable")
    major = _package_tuple(package_info, package_run, package_source,
                           candidate_receipt, approval)
    # Prove the existing typed publisher entrypoint cannot consume this tuple.
    # NEVER call the actual publisher. A synthetic signature assertion or
    # status relabel must not make an inert context into an authorization.
    try:
        receipt_lib.validate_receipt(
            bound, repository=REPOSITORY,
            commit=approval["authorizationCommit"],
            actor=approval["operator"], event="push")
    except receipt_lib.Denied:
        pass
    else:
        raise Denied("typed publisher unexpectedly accepted inert receipt")
    return {
        "schemaVersion": 1,
        "status": "DRY_RUN_G3_DEFAULT_DENY_ONLY",
        "repository": REPOSITORY,
        "candidatePr": approval["candidatePr"],
        "authorizationPr": approval["authorizationPr"],
        "syntheticPackageMajor": major,
        "futureEventShape": "push",
        "futureReceiptType": "VERIFIED_CHAT_PR_AUTHORIZATION",
        "jitSnapshotCount": 2,
        "signedArtifactsVerified": False,
        "publishableReceipt": False,
        "publishingEnabled": False,
        "mutationsEnabled": False,
        "productionApproval": "BLOCKED_NOT_PRESENT",
        "publication": "DENY",
    }
