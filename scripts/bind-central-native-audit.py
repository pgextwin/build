#!/usr/bin/env python3
"""Bind a real central schedule receipt to original native PR bytes (NO PUBLISH).

Caller must independently GET the exact GitHub schedule run, its full job and
artifact inventories and original native CI; download the *actual* GitHub
artifact and parse the one target-repository JSON with duplicate-key rejection.
This pure function never substitutes a workflow_run, dispatch, or push event.
"""
from __future__ import annotations

from datetime import date
import importlib.util
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("central_receipt_identity",
    ROOT / "fleet-release-identity.py")
ident = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ident)

SHA = re.compile(r"^[a-f0-9]{40}$")
HASH = re.compile(r"^[a-f0-9]{64}$")
WORKFLOWS = {
    ".github/workflows/recover-native-pr-fleet.yml":
        "Independent approved attempt and original ZIP/SPDX/Grype audit (no Release)",
    ".github/workflows/fleet-upstream-watch.yml":
        "Independent original PR artifacts audit (genuine fleet schedule only; NO PUBLISH)",
}


class Denied(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise Denied(why)


def inventory(data, key):
    require(type(data) is dict and type(data.get("total_count")) is int
            and 0 <= data["total_count"] < 100
            and type(data.get(key)) is list
            and len(data[key]) == data["total_count"],
            "incomplete, truncated or unbounded GitHub " + key + " inventory")
    return data[key]


def join(*, receipt, schedule_run, jobs, artifacts, ci_run, ext,
         lifecycle, repository, parent_main_sha, today=None):
    """Return a nonpublishing bound candidate; never a signature or Release permit."""
    require(type(repository) is str and repository == "pgextwin/" + ext.get("name")
            and type(parent_main_sha) is str and SHA.fullmatch(parent_main_sha),
            "invalid immutable target source identity")
    require(type(schedule_run) is dict and type(schedule_run.get("id")) is int
            and schedule_run["id"] > 0
            and schedule_run.get("event") == "schedule"
            and schedule_run.get("status") == "completed"
            and schedule_run.get("conclusion") == "success"
            and schedule_run.get("head_branch") == "main"
            and type(schedule_run.get("head_sha")) is str
            and SHA.fullmatch(schedule_run["head_sha"])
            and schedule_run.get("path") in WORKFLOWS
            and type(schedule_run.get("run_attempt")) is int
            and schedule_run["run_attempt"] >= 1
            and (schedule_run.get("repository") or {}).get("full_name") == "pgextwin/build",
            "only genuine successful central main schedule may attest recovery")
    expected_job = WORKFLOWS[schedule_run["path"]]
    matches = [j for j in inventory(jobs, "jobs")
               if type(j) is dict and j.get("name") == expected_job]
    require(len(matches) == 1 and matches[0].get("run_id") == schedule_run["id"]
            and matches[0].get("status") == "completed"
            and matches[0].get("conclusion") == "success",
            "dedicated original-native schedule audit job not successful")
    selected = [a for a in inventory(artifacts, "artifacts")
                if type(a) is dict and a.get("name") ==
                "registered-original-native-pr-audits"]
    require(len(selected) == 1, "ambiguous or absent real schedule audit artifact")
    artifact = selected[0]
    require(type(artifact.get("id")) is int and artifact["id"] > 0
            and type(artifact.get("size_in_bytes")) is int
            and artifact["size_in_bytes"] > 0
            and artifact.get("expired") is False
            and (artifact.get("workflow_run") or {}).get("id") == schedule_run["id"]
            and (artifact.get("workflow_run") or {}).get("head_sha") ==
                schedule_run["head_sha"],
            "schedule receipt is not an unexpired exact-run GitHub artifact")
    require(type(receipt) is dict and receipt.get("schemaVersion") == 1
            and receipt.get("status") ==
                "CENTRAL_GENUINE_SCHEDULE_ORIGINAL_NATIVE_CI_BYTES_VERIFIED_NONPUBLISHING"
            and receipt.get("auditorRepository") == "pgextwin/build"
            and receipt.get("auditorEvent") == "schedule"
            and receipt.get("auditorSourceSha") == schedule_run["head_sha"]
            and receipt.get("targetRepository") == repository
            and receipt.get("targetMainSha") == parent_main_sha,
            "downloaded central schedule receipt not bound to protected parent")
    for key in ("signedArtifactsVerified", "publicationAuthorized", "publishableReceipt"):
        require(receipt.get(key) is False, "receipt illegally asserts publication authority")
    context, audit = receipt.get("native"), receipt.get("candidateAudit")
    require(type(context) is dict and type(audit) is dict
            and context.get("schemaVersion") == 1
            and context.get("status") == "NATIVE_PR_CI_AUTHENTICATED_NOT_PUBLISHABLE"
            and context.get("scheduleRecovery") is True
            and context.get("scheduleMainSha") == parent_main_sha
            and context.get("repository") == repository
            and context.get("matrixResult") == "success"
            and audit.get("schemaVersion") == 1
            and audit.get("status") == "VERIFIED"
            and audit.get("originEvent") == "pull_request"
            and audit.get("matrixResult") == "success"
            and audit.get("extension") == ext.get("name")
            and audit.get("runId") == context.get("candidateRunId")
            and audit.get("branchSha") == context.get("candidateHeadSha")
            and audit.get("branch") == context.get("branch"),
            "original PR provenance or independently audited byte record differs")
    for key in ("candidateAuditVerified", "signedArtifactsVerified",
                "publishableReceipt", "publicationAuthorized"):
        require(context.get(key) is False, "original native context claims authority")
    require(type(context.get("candidatePr")) is int and context["candidatePr"] > 0
            and type(context.get("candidateRunId")) is int
            and context["candidateRunId"] > 0
            and type(context.get("candidateHeadSha")) is str
            and SHA.fullmatch(context["candidateHeadSha"])
            and type(context.get("packagingMergeSha")) is str
            and SHA.fullmatch(context["packagingMergeSha"]),
            "invalid original PR or synthetic merge identity")
    require(type(ci_run) is dict
            and ci_run.get("id") == context["candidateRunId"]
            and ci_run.get("head_sha") == context["candidateHeadSha"]
            and ci_run.get("head_branch") == context.get("branch")
            and ci_run.get("event") == "pull_request"
            and ci_run.get("name") == "Windows CI/CD"
            and ci_run.get("status") == "completed"
            and ci_run.get("conclusion") == "success"
            and type(ci_run.get("run_attempt")) is int
            and ci_run["run_attempt"] >= 1
            and (ci_run.get("head_repository") or {}).get("full_name") == repository,
            "re-fetched original native PR CI is missing or substituted")
    try:
        majors = ident.maintained_majors(ext, lifecycle, today=today or date.today())
        sources = ident.sources(ext)
    except (ident.Denied, ValueError, KeyError, TypeError) as exc:
        raise Denied("immutable source manifest/lifecycle refused: " + str(exc)) from exc
    rows = audit.get("majors")
    require(type(rows) is list and len(rows) == len(majors)
            and [x.get("major") for x in rows if type(x) is dict] == majors,
            "PG-major byte audit incomplete, unordered or duplicated")
    digests = []
    for major, row in zip(majors, rows):
        pin = sources[major]
        stems = (ident.asset_stem(ext, major),
                 ext["name"] + "-" + pin["version"] +
                 "-pg" + str(major) + "-windows-x64")
        suffixes = (".zip", ".spdx.json", ".vulnerabilities.json")
        triplet = (row.get("zip"), row.get("sbom"), row.get("grype"))
        require(row.get("status") == "SUCCESS"
                and row.get("sourceSha") == pin["commit"]
                and type(row.get("zipSha256")) is str
                and HASH.fullmatch(row["zipSha256"])
                and triplet in {tuple(stem + suf for suf in suffixes)
                                for stem in stems},
                "original PG ZIP/SPDX/Grype SHA and protected pins disagree")
        digests.append({"major": major, "sourceSha": pin["commit"],
                        "zipSha256": row["zipSha256"]})
    return {
        "schemaVersion": 1, "status": "BOUND_NATIVE_CANDIDATE_AUDIT_NONPUBLISHING",
        "nativeAuditProvenance": "CENTRAL_GENUINE_SCHEDULE",
        "repository": repository, "candidatePr": context["candidatePr"],
        "candidateHeadSha": context["candidateHeadSha"],
        "candidateCiRunId": context["candidateRunId"],
        "candidateMergeSha": context["packagingMergeSha"],
        "nativeAuditRunId": schedule_run["id"],
        "nativeAuditArtifactId": artifact["id"],
        "mainShaAtAudit": parent_main_sha,
        "majors": majors, "sourcesAndZipDigests": digests,
        "signedArtifactsVerified": False, "publishableReceipt": False,
        "publicationAuthorized": False,
    }


if __name__ == "__main__":
    raise SystemExit("Pure evidence binder; no direct signing or publication endpoint")
