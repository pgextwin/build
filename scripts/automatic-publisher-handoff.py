#!/usr/bin/env python3
"""Evidence-only 17-extension signed candidate -> formal Publisher handoff.

Runs in the existing independent READ-only second-opinion GitHub job, AFTER
its real second gh attestation verification and byte/attempt comparison.
This is an exact-run nonpublishing manifest for a future separately authorized
Publisher; it is NEVER a publishable receipt or a grant of write privileges.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
SHA = re.compile(r"^[0-9a-f]{40}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
TAG = re.compile(r"^v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*$")
POLICY_BLOCKERS = frozenset({
    "CENTRAL_MANUAL_DISPATCH",
    "LOCAL_MANUAL_DISPATCH",
    "FLEET_MANUAL_ONLY",
    "UNATTENDED_OBSERVE_DENY",
    "INDEPENDENT_PUBLISHER_AUTHORIZATION_NOT_ESTABLISHED",
})
ASSETS = ("zip", "spdx", "grype")
DENIED = ("publishableReceipt", "publicationAuthorized",
          "automaticReleaseEnabled", "publisherWriteEnabled")


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON evidence key")
        result[key] = value
    return result


def read_json(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink(), "missing/symlink evidence file")
    obj = json.loads(p.read_text("utf-8-sig"), object_pairs_hook=unique)
    require(type(obj) is dict, "invalid evidence object")
    return obj


def handoff(first, second, opinion, bridge, tag, fleet, *,
            repository, main_sha, run_id, attempt, event, ref):
    """Join authentic independent proof *identities*, not grant authorization.

    The caller MUST have just rerun real gh attestation verification against
    freshly downloaded assets in the separate read-only job. Offline fixtures
    are only regression tests; this function cannot independently prove Sigstore.
    """
    require(type(repository) is str and REPO.fullmatch(repository)
            and type(main_sha) is str and SHA.fullmatch(main_sha)
            and type(run_id) is int and run_id > 0
            and type(attempt) is int and attempt == 1
            and event == "push" and ref == "refs/heads/main",
            "not original protected main/push signed candidate")
    require(type(fleet) is dict and type(fleet.get("schemaVersion")) is int
            and fleet["schemaVersion"] == 1
            and fleet.get("releasePolicy") == "manual-only"
            and type(fleet.get("entries")) is list
            and len(fleet["entries"]) == 17, "unknown fleet policy")
    rows = fleet["entries"]
    require(all(type(r) is dict and type(r.get("repository")) is str
                and REPO.fullmatch(r["repository"])
                and r.get("releasePolicy") == "manual-only"
                for r in rows)
            and len({r["repository"] for r in rows}) == 17
            and repository in {r["repository"] for r in rows},
            "non-17, duplicated or non-manual Publisher scope")
    require(type(first) is dict and type(second) is dict
            and first == second, "original and independent signed audits diverge")
    require(first.get("schemaVersion") == 1
            and type(first.get("schemaVersion")) is int
            and first.get("status") == "VERIFIED_SIGNED_CANDIDATE_NONPUBLISHING"
            and first.get("cryptographicVerification") == "REAL_GH_ATTESTATION_VERIFY"
            and first.get("signedArtifactsVerified") is True
            and first.get("repository") == repository
            and first.get("mainMergeSha") == main_sha
            and type(first.get("runId")) is int
            and first["runId"] == run_id
            and type(first.get("runAttempt")) is int
            and first["runAttempt"] == attempt
            and all(first.get(x) is False for x in DENIED[:3]),
            "original signed audit is not authentic-run bound or attempts PUBLISH")
    majors = first.get("maintainedMajors")
    require(type(majors) is list and len(majors) > 0 and len(majors) <= 5
            and all(type(m) is int and 14 <= m <= 18 for m in majors)
            and majors == sorted(set(majors)), "malformed PostgreSQL major matrix")
    keys = {str(m) for m in majors}
    for asset in ASSETS:
        values = first.get(asset + "Sha256ByMajor")
        require(type(values) is dict and set(values) == keys
                and all(type(v) is str and HASH.fullmatch(v)
                        for v in values.values()), "incomplete " + asset + " digests")
    risk = first.get("grypePolicyByMajor")
    require(type(risk) is dict and set(risk) == keys, "partial Grype policy")
    for major in keys:
        item = risk[major]
        require(type(item) is dict
                and item.get("status") == "NO_BLOCKING_FINDINGS"
                and type(item.get("blockingFindingCount")) is int
                and item["blockingFindingCount"] == 0
                and item.get("publicationAuthorized") is False
                and type(item.get("findingCountBySeverity")) is dict
                and all(type(item["findingCountBySeverity"].get(sev)) is int
                        and item["findingCountBySeverity"][sev] == 0
                        for sev in ("Critical", "High", "Unknown")),
                "blocking or incomplete Grype finding")
    require(type(opinion) is dict and opinion.get("schemaVersion") == 1
            and type(opinion.get("schemaVersion")) is int
            and opinion.get("status") == "INDEPENDENT_SIGNED_RECHECK_MATCH_NONPUBLISHING"
            and opinion.get("repository") == repository
            and opinion.get("mainMergeSha") == main_sha
            and type(opinion.get("runId")) is int
            and opinion["runId"] == run_id
            and type(opinion.get("runAttempt")) is int
            and opinion["runAttempt"] == attempt
            and opinion.get("maintainedMajors") == majors
            and opinion.get("assetByteDigestsMatch") is True
            and opinion.get("signedCandidateReverifiedBySeparateJob") is True
            and all(opinion.get(x) is False for x in DENIED)
            and all(opinion.get(k) == "NO_GO" for k in ("goB", "g4", "g5")),
            "independent cryptographic second opinion invalid")
    require(type(bridge) is dict and bridge.get("schemaVersion") == 1
            and type(bridge.get("schemaVersion")) is int
            and bridge.get("status") == "PUBLISH_DENY"
            and bridge.get("repository") == repository
            and bridge.get("mainMergeSha") == main_sha
            and type(bridge.get("runId")) is int
            and bridge["runId"] == run_id
            and type(bridge.get("runAttempt")) is int
            and bridge["runAttempt"] == attempt
            and bridge.get("maintainedMajors") == majors
            and all(bridge.get(k) == "NO_GO" for k in ("goB", "g4", "g5"))
            and all(bridge.get(x) is False for x in DENIED)
            and type(bridge.get("policyBlockers")) is list
            and len(bridge["policyBlockers"]) == len(POLICY_BLOCKERS)
            and set(bridge["policyBlockers"]) == POLICY_BLOCKERS,
            "Publisher effective policy not the expected explicit DENY")
    for asset in ASSETS:
        require(bridge.get(asset + "Sha256ByMajor") == first[asset + "Sha256ByMajor"],
                "signed " + asset + " differs from Publisher policy witness")
    require(bridge.get("grypePolicyByMajor") == risk,
            "signed Grype finding policy differs from Publisher witness")
    require(type(tag) is dict and type(tag.get("schemaVersion")) is int
            and tag["schemaVersion"] == 1
            and tag.get("status") == "PROPOSED_TAG_NONPUBLISHING"
            and tag.get("repository") == repository
            and tag.get("mainMergeSha") == main_sha
            and type(tag.get("runId")) is int and tag["runId"] == run_id
            and type(tag.get("runAttempt")) is int and tag["runAttempt"] == attempt
            and type(tag.get("releaseTagProposal")) is str
            and TAG.fullmatch(tag["releaseTagProposal"])
            and type(tag.get("releaseSequence")) is int
            and tag["releaseSequence"] > 0
            and tag["releaseTagProposal"].endswith(
                "-windows." + str(tag["releaseSequence"]))
            and tag.get("requiresIndependentLiveRecheckAndAtomicTagReservation") is True
            and all(tag.get(x) is False for x in DENIED if x in tag)
            and tag.get("publicationAuthorized") is False
            and tag.get("publishableReceipt") is False
            and tag.get("publisherWriteEnabled") is False,
            "unsigned, stale or unauthorized proposed Release tag")
    return {
        "schemaVersion": 1,
        "status": "SIGNED_PUBLISHER_HANDOFF_EVIDENCE_ONLY",
        "repository": repository, "mainMergeSha": main_sha,
        "runId": run_id, "runAttempt": attempt,
        "maintainedMajors": majors,
        "zipSha256ByMajor": first["zipSha256ByMajor"],
        "spdxSha256ByMajor": first["spdxSha256ByMajor"],
        "grypeSha256ByMajor": first["grypeSha256ByMajor"],
        "grypePolicyByMajor": risk,
        "independentSigstoreSecondOpinion": True,
        "tagProposal": tag["releaseTagProposal"],
        "mustRecheckLiveTagAndReleaseAbsence": True,
        "policyBlockers": sorted(POLICY_BLOCKERS),
        "publicationAuthorized": False, "publishableReceipt": False,
        "publisherWriteEnabled": False, "automaticReleaseEnabled": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
    }


def main():
    parser = argparse.ArgumentParser()
    for name in ("first", "second", "opinion", "bridge", "tag", "fleet", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        evidence = handoff(
            read_json(args.first), read_json(args.second),
            read_json(args.opinion), read_json(args.bridge),
            read_json(args.tag), read_json(args.fleet),
            repository=os.getenv("GITHUB_REPOSITORY"),
            main_sha=os.getenv("GITHUB_SHA"),
            run_id=int(os.getenv("GITHUB_RUN_ID", "0")),
            attempt=int(os.getenv("GITHUB_RUN_ATTEMPT", "0")),
            event=os.getenv("GITHUB_EVENT_NAME"),
            ref=os.getenv("GITHUB_REF"),
        )
        Path(args.output).write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n",
                                    encoding="utf-8")
        print("SIGNED_PUBLISHER_HANDOFF_EVIDENCE_ONLY; PUBLISH_DENY; no Release write")
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError) as exc:
        print("SIGNED_PUBLISHER_HANDOFF_DENY: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
