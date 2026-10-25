#!/usr/bin/env python3
"""Issue #75: strict native-candidate *postmerge* proof, NEVER a Release permit.

Join a real protected main-push/merged bot PR to an already bound, separately
authenticated, successful native PR artifact audit (build #221/#222).
All arguments are untrusted until a future trusted main-only GitHub runner
independently fetches them. This pure module has no network/write/CLI path.
"""
from __future__ import annotations

from datetime import date
import importlib.util
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fleet_identity", HERE / "fleet-release-identity.py")
ident = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ident)

SHA = re.compile(r"^[0-9a-f]{40}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
BRANCH = re.compile(r"^auto-candidate/([0-9a-f]{20})$")
HUMAN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
ALLOWED_ACTORS = frozenset({"ShutenOishi"})


_policy_spec=importlib.util.spec_from_file_location("shared_fleet_policy",HERE/"fleet-policy.py")
fleet_policy=importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(fleet_policy)

class Denied(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Denied(reason)


def full_sha(v):
    return type(v) is str and SHA.fullmatch(v) is not None


def verify(*, repository, event, commit, pr, pr_files, branch, checks,
           bound, manifest, lifecycle, fleet, today=None):
    """Return a strictly NONPUBLISHING merge witness, not a typed receipt.

    A prior native-audit binder must have downloaded exactly the original
    artifact by run ID and independently checked candidate ZIP/SPDX hashes.
    Neither that audit nor this function verifies signed Release attestations.
    """
    require(type(repository) is str and repository == "pgextwin/" + str(manifest.get("name"))
            and manifest.get("name") in ident.UPSTREAMS,
            "not one of the exact 17 audited extension repositories")
    try:
        names=fleet_policy.members(fleet,audited={"pgextwin/"+s for s in ident.UPSTREAMS})
        require(repository in names,"unknown candidate repository")
    except fleet_policy.Denied as exc:
        raise Denied("invalid audited candidate fleet") from exc
    require(type(event) is dict and event.get("ref") == "refs/heads/main"
            and (event.get("repository") or {}).get("full_name") == repository
            and event.get("created") is False and event.get("deleted") is False
            and full_sha(event.get("before")) and full_sha(event.get("after")),
            "must be one authenticated existing-main push")
    actor = (event.get("sender") or {}).get("login")
    require(type(actor) is str and HUMAN.fullmatch(actor) is not None
            and actor in ALLOWED_ACTORS,
            "merge actor must be the established human GitHub operator")
    require(type(event.get("commits")) is list and len(event["commits"]) == 1
            and (event["commits"][0] or {}).get("id") == event["after"],
            "main push contains unexpected commits")
    require(type(commit) is dict and commit.get("sha") == event["after"]
            and type(commit.get("parents")) is list and len(commit["parents"]) == 1
            and (commit["parents"][0] or {}).get("sha") == event["before"]
            and type(commit.get("files")) is list and len(commit["files"]) == 1,
            "unexpected merged main commit/parents/files")
    mf = commit["files"][0]
    require(type(mf) is dict and mf.get("filename") == "config/extension.json"
            and mf.get("status") == "modified" and full_sha(mf.get("sha")),
            "candidate merge is not a manifest-only change")
    require(type(pr) is dict and type(pr.get("number")) is int and pr["number"] > 0
            and pr.get("state") == "closed" and pr.get("merged") is True
            and pr.get("draft") is False and pr.get("merge_commit_sha") == event["after"]
            and (pr.get("head") or {}).get("repo", {}).get("full_name") == repository
            and (pr.get("base") or {}).get("repo", {}).get("full_name") == repository
            and (pr.get("base") or {}).get("ref") == "main"
            and (pr.get("user") or {}).get("login") == "github-actions[bot]"
            and (pr.get("merged_by") or {}).get("login") == actor
            and full_sha((pr.get("head") or {}).get("sha")),
            "merged PR identity not a genuine protected bot candidate")
    ref = (pr.get("head") or {}).get("ref")
    m = BRANCH.fullmatch(ref) if type(ref) is str else None
    require(m is not None and ("<!-- pgextwin-candidate:v1:" + m.group(1) + " -->")
            in (pr.get("body") or ""), "bot candidate marker/branch mismatch")
    require(type(pr_files) is list and len(pr_files) == 1
            and type(pr_files[0]) is dict
            and pr_files[0].get("filename") == "config/extension.json"
            and pr_files[0].get("status") == "modified"
            and pr_files[0].get("sha") == mf["sha"],
            "merged candidate manifest must be byte-identical to original PR")
    require(type(branch) is dict and branch.get("name") == "main"
            and branch.get("protected") is True
            and (branch.get("commit") or {}).get("sha") == event["after"],
            "main is not presently protected at exact merge SHA")
    required = ((branch.get("protection") or {}).get("required_status_checks") or {}).get("checks")
    require(type(required) is list and any(type(c) is dict
            and c.get("context") == "Windows required summary"
            and c.get("app_id") == 15368 for c in required),
            "exact protected App15368 Windows summary not required")
    require(type(checks) is dict and type(checks.get("total_count")) is int
            and 0 <= checks["total_count"] < 100
            and type(checks.get("check_runs")) is list
            and checks["total_count"] == len(checks["check_runs"]),
            "incomplete native PR check-run inventory")
    head = pr["head"]["sha"]
    matches = [c for c in checks["check_runs"] if type(c) is dict
               and c.get("name") == "Windows required summary"
               and c.get("head_sha") == head
               and c.get("status") == "completed"
               and c.get("conclusion") == "success"
               and (c.get("app") or {}).get("id") == 15368]
    require(len(matches) == 1, "ambiguous/missing original exact-head required Windows success")
    require(type(bound) is dict
            and bound.get("status") == "BOUND_NATIVE_CANDIDATE_AUDIT_NONPUBLISHING"
            and bound.get("repository") == repository
            and bound.get("candidatePr") == pr["number"]
            and bound.get("candidateHeadSha") == head
            and bound.get("mainShaAtAudit") == event["before"]
            and full_sha(bound.get("candidateMergeSha"))
            and type(bound.get("candidateCiRunId")) is int
            and bound["candidateCiRunId"] > 0
            and type(bound.get("nativeAuditRunId")) is int
            and bound["nativeAuditRunId"] > 0
            and type(bound.get("nativeAuditArtifactId")) is int
            and bound["nativeAuditArtifactId"] > 0,
            "original audit not independently bound to exact parent main, head and PR")
    for denial in ("signedArtifactsVerified", "publishableReceipt", "publicationAuthorized"):
        require(bound.get(denial) is False, "read-only audit illegally claims release authority")
    try:
        majors = ident.maintained_majors(manifest, lifecycle, today=today or date.today())
        pins = ident.sources(manifest)
        tag_stem = ident.tag_stem(manifest)
    except (ident.Denied, ValueError, TypeError, KeyError) as exc:
        raise Denied("merged immutable manifest source/lifecycle invalid: " + str(exc)) from exc
    digests = bound.get("sourcesAndZipDigests")
    require(type(digests) is list and len(digests) == len(majors)
            and bound.get("majors") == majors,
            "missing or duplicated immutable original native ZIP proofs")
    for item, major in zip(digests, majors):
        require(type(item) is dict and type(item.get("major")) is int
                and item["major"] == major
                and item.get("sourceSha") == pins[major]["commit"]
                and type(item.get("zipSha256")) is str
                and HASH.fullmatch(item["zipSha256"]) is not None,
                "merged upstream source SHA differs from independently audited ZIP")
    return {
        "schemaVersion": 1,
        "status": "MERGED_NATIVE_CANDIDATE_NONPUBLISHING",
        "repository": repository, "candidatePr": pr["number"],
        "candidateBranch": ref, "candidateHeadSha": head,
        "mainMergeSha": event["after"],
        "mainParentAtAudit": event["before"], "candidateCiRunId": bound["candidateCiRunId"],
        "nativeAuditRunId": bound["nativeAuditRunId"],
        "nativeAuditArtifactId": bound["nativeAuditArtifactId"],
        "maintainedMajors": majors, "releaseTagStem": tag_stem,
        "sourcesAndZipDigests": digests,
        "signedArtifactsVerified": False, "publishableReceipt": False,
        "publicationAuthorized": False, "automaticReleaseEnabled": False,
    }


if __name__ == "__main__":
    raise SystemExit("Read-only library only. No CLI publisher or release receipt issuer.")
