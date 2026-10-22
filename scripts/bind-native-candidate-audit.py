#!/usr/bin/env python3
"""Join exact real GitHub native-PR audit evidence; NEVER issue a PUBLISH receipt.

The main-runner caller MUST independently fetch ALL GitHub REST identities and
download the `candidate-audit-native-pr` ZIP from the exact verified artifact
ID. Both JSON files must be extracted from those bytes, not from an untrusted
candidate branch. This helper is deliberately pure and nonpublishing.
"""
from __future__ import annotations

from datetime import date
import importlib.util
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fleet_identity",ROOT/"fleet-release-identity.py")
ident = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ident)

HEX40=re.compile(r"^[0-9a-f]{40}$")
HEX64=re.compile(r"^[0-9a-f]{64}$")


class Denied(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise Denied(why)


def sha(s):
    return type(s) is str and HEX40.fullmatch(s) is not None


def unique(a):
    return type(a) is list and len(a)==len(set(a))


def join(*, context, audit, ext, lifecycle, ci_run, audit_run,
         artifact, repository, current_main_sha, today=None):
    """Independently bound *observations*, strictly never a publisher permit."""
    require(type(repository) is str and repository=="pgextwin/"+ext.get("name")
            and sha(current_main_sha), "invalid trusted repository/main")
    require(type(context) is dict and type(audit) is dict
            and context.get("schemaVersion")==1
            and audit.get("schemaVersion")==1
            and context.get("status")=="NATIVE_PR_CI_AUTHENTICATED_NOT_PUBLISHABLE"
            and audit.get("status")=="VERIFIED" and audit.get("originEvent")=="pull_request"
            and context.get("matrixResult")==audit.get("matrixResult")=="success",
            "native audit and context must both be successful immutable originals")
    for f in ("candidateAuditVerified", "signedArtifactsVerified",
              "publishableReceipt", "publicationAuthorized"):
        require(context.get(f) is False, "context was relabeled as a publication receipt")
    require(context.get("repository")==repository and audit.get("extension")==ext.get("name")
            and context.get("candidateRunId")==audit.get("runId")
            and context.get("candidateHeadSha")==audit.get("branchSha")
            and context.get("branch")==audit.get("branch")
            and sha(context.get("candidateHeadSha"))
            and sha(context.get("packagingMergeSha"))
            and type(context.get("candidateRunId")) is int
            and context["candidateRunId"]>0
            and type(context.get("candidatePr")) is int
            and context["candidatePr"]>0,
            "candidate audit provenance does not match the exact PR identity")
    require(type(ci_run) is dict and ci_run.get("id")==context["candidateRunId"]
            and ci_run.get("head_sha")==context["candidateHeadSha"]
            and ci_run.get("head_branch")==context["branch"]
            and ci_run.get("event")=="pull_request"
            and ci_run.get("name")=="Windows CI/CD"
            and ci_run.get("status")=="completed"
            and ci_run.get("conclusion")=="success"
            and (ci_run.get("head_repository") or {}).get("full_name")==repository,
            "candidate audit refers to incomplete/foreign Windows CI")
    require(type(audit_run) is dict and type(audit_run.get("id")) is int
            and audit_run["id"]>0
            and audit_run.get("name")=="Upstream candidate after verified central daily fleet scan"
            and audit_run.get("path")==".github/workflows/update-watch.yml"
            and audit_run.get("head_branch")=="main"
            and audit_run.get("head_sha")==current_main_sha
            and audit_run.get("event")=="workflow_run"
            and audit_run.get("status")=="completed"
            and audit_run.get("conclusion")=="success",
            "audit must belong to a real successful trusted-main workflow_run")
    require(type(artifact) is dict and type(artifact.get("id")) is int
            and artifact["id"]>0
            and artifact.get("name")=="candidate-audit-native-pr"
            and type(artifact.get("size_in_bytes")) is int
            and artifact["size_in_bytes"]>0
            and artifact.get("expired") is False
            and (artifact.get("workflow_run") or {}).get("id")==audit_run["id"],
            "missing or mismatched real GitHub audit artifact")
    try:
        majors=ident.maintained_majors(ext,lifecycle,today=today or date.today())
        sources=ident.sources(ext)
    except (ident.Denied,ValueError,KeyError,TypeError) as e:
        raise Denied("untrusted full-SHA pinned source manifest/lifecycle: "+str(e)) from e
    rows=audit.get("majors")
    require(type(rows) is list and len(rows)==len(majors)
            and [row.get("major") for row in rows if type(row) is dict]==majors,
            "wrong, missing, duplicate or unordered PostgreSQL evidence")
    digests=[]
    for row,major in zip(rows,majors):
        expected=sources[major]
        stem1=ident.asset_stem(ext,major)
        stem2=ext["name"]+"-"+expected["version"]+"-pg"+str(major)+"-windows-x64"
        suffixes=(".zip",".spdx.json",".vulnerabilities.json")
        triplet=(row.get("zip"),row.get("sbom"),row.get("grype"))
        allowed={tuple(stem+suf for suf in suffixes) for stem in (stem1,stem2)}
        require(row.get("status")=="SUCCESS"
                and row.get("sourceSha")==expected["commit"]
                and type(row.get("zipSha256")) is str
                and HEX64.fullmatch(row["zipSha256"])
                and triplet in allowed,
                "untrusted per-major source digest/ZIP/SPDX/Grype identities")
        digests.append({"major":major,"sourceSha":expected["commit"],
                        "zipSha256":row["zipSha256"]})
    return {"schemaVersion":1, "status":"BOUND_NATIVE_CANDIDATE_AUDIT_NONPUBLISHING",
            "repository":repository,"candidatePr":context["candidatePr"],
            "candidateHeadSha":context["candidateHeadSha"],
            "candidateCiRunId":context["candidateRunId"],
            "nativeAuditRunId":audit_run["id"],
            "nativeAuditArtifactId":artifact["id"],
            "candidateMergeSha":context["packagingMergeSha"],
            "mainShaAtAudit":current_main_sha,
            "majors":majors,"sourcesAndZipDigests":digests,
            "signedArtifactsVerified":False,"publishableReceipt":False,
            "publicationAuthorized":False}


if __name__=="__main__":
    raise SystemExit("Library only; no command-line publication endpoint")
