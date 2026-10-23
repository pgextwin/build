#!/usr/bin/env python3
"""Independent current-main/Run/tag recheck for 17-extension signed handoffs.

READ-ONLY. Run after the second *real* independent Sigstore job. A successful
recheck is NEVER Publisher WRITE authorization: the live production policies
remain manual-only, and the tag absence is only a point-in-time observation.
A future independent Publisher must verify bytes, policy, token, tag and Release
again immediately before its separately authorized create-only write.
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

REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
SHA = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*$")
FILES = {
    "metadata/automation-fleet.json",
    "metadata/release-promotion.json",
    "metadata/unattended-publication.json",
    "config/release-promotion.json",
}


class Denied(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Denied(message)


def object_json(raw):
    def unique(items):
        d = {}
        for key, value in items:
            require(key not in d, "duplicate JSON key")
            d[key] = value
        return d
    obj = json.loads(raw, object_pairs_hook=unique)
    require(type(obj) is dict, "expected JSON object")
    return obj


def blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def verified_live_file(content, path, local_bytes):
    """Require GitHub's committed blob to match immutable checked-out policy."""
    require(path in FILES and type(content) is dict
            and content.get("encoding") == "base64"
            and content.get("path") == path
            and type(content.get("content")) is str
            and type(content.get("sha")) is str
            and SHA.fullmatch(content["sha"])
            and type(local_bytes) is bytes and len(local_bytes) < 262144,
            "unsupported or missing GitHub policy blob")
    try:
        raw = base64.b64decode(content["content"], validate=False)
    except (ValueError, TypeError) as exc:
        raise Denied("invalid GitHub policy encoding") from exc
    require(raw == local_bytes and blob_sha(raw) == content["sha"],
            "live policy differs from pinned workflow policy")
    return object_json(raw.decode("utf-8"))


def assess(handoff, branch, run, fleet, central, local, unattended,
           *, repository, sha, run_id, attempt, event, ref,
           tag_absent, release_absent):
    """Pure attested-handoff consistency; ALWAYS returns PUBLISH_DENY."""
    require(type(repository) is str and REPO.fullmatch(repository)
            and type(sha) is str and SHA.fullmatch(sha)
            and type(run_id) is int and run_id > 0
            and type(attempt) is int and attempt == 1
            and event == "push" and ref == "refs/heads/main",
            "not the original protected main/push run")
    require(type(handoff) is dict
            and handoff.get("schemaVersion") == 1
            and type(handoff.get("schemaVersion")) is int
            and handoff.get("status") == "SIGNED_PUBLISHER_HANDOFF_EVIDENCE_ONLY"
            and handoff.get("repository") == repository
            and handoff.get("mainMergeSha") == sha
            and handoff.get("runId") == run_id
            and handoff.get("runAttempt") == attempt
            and handoff.get("independentSigstoreSecondOpinion") is True
            and all(handoff.get(k) is False for k in (
                "publishableReceipt", "publicationAuthorized",
                "publisherWriteEnabled", "automaticReleaseEnabled"))
            and all(handoff.get(k) == "NO_GO" for k in ("goB", "g4", "g5")),
            "nonpublishing signed second-opinion handoff absent or forged")
    tag = handoff.get("tagProposal")
    require(type(tag) is str and TAG.fullmatch(tag)
            and tag_absent is True and release_absent is True,
            "proposed tag/ref or formal Release is occupied/unverifiable")
    require(type(branch) is dict and branch.get("name") == "main"
            and branch.get("protected") is True
            and (branch.get("commit") or {}).get("sha") == sha,
            "source packaging main advanced or is not protected")
    require(type(run) is dict and run.get("id") == run_id
            and type(run.get("run_attempt")) is int
            and run["run_attempt"] == attempt
            and (run.get("repository") or {}).get("full_name") == repository
            and run.get("head_sha") == sha
            and run.get("head_branch") == "main"
            and run.get("event") == "push"
            and run.get("path") == ".github/workflows/update-watch.yml"
            and run.get("status") == "in_progress"
            and run.get("conclusion") is None,
            "authenticated original signed caller Run invalid")
    require(type(fleet) is dict and fleet.get("schemaVersion") == 1
            and fleet.get("releasePolicy") == "manual-only"
            and type(fleet.get("entries")) is list
            and len(fleet["entries"]) == 17,
            "central 17-extension manual-only policy changed")
    roster = [v.get("repository") for v in fleet["entries"] if type(v) is dict]
    require(len(roster) == 17 and len(set(roster)) == 17
            and repository in roster
            and all(type(x) is str and REPO.fullmatch(x) for x in roster)
            and all(v.get("mode") == "BUILD"
                    and v.get("candidateEnabled") is True
                    and v.get("releasePolicy") == "manual-only"
                    for v in fleet["entries"]),
            "incomplete or altered 17-extension fleet")
    require(type(central) is dict and central.get("schemaVersion") == 1
            and central.get("releasePolicy") == "manual-dispatch"
            and set(central.get("allowedRepositories", [])) == set(roster)
            and type(central.get("allowedRepositories")) is list
            and len(central["allowedRepositories"]) == 17,
            "central formal Release policy differs from expected DENY")
    require(local == {"schemaVersion": 1, "enabled": True,
                      "releasePolicy": "manual-dispatch"},
            "local formal Release policy is not manual-dispatch")
    require(type(unattended) is dict and unattended.get("schemaVersion") == 1
            and unattended.get("mode") == "OBSERVE"
            and unattended.get("defaultAction") == "DENY"
            and type(unattended.get("controls")) is dict
            and unattended["controls"].get("automaticFormalRelease") is False,
            "unattended policy unexpected or auto-release attempted")
    blockers = handoff.get("policyBlockers")
    require(type(blockers) is list and set(blockers) == {
            "CENTRAL_MANUAL_DISPATCH", "LOCAL_MANUAL_DISPATCH",
            "FLEET_MANUAL_ONLY", "UNATTENDED_OBSERVE_DENY",
            "INDEPENDENT_PUBLISHER_AUTHORIZATION_NOT_ESTABLISHED"},
            "signed handoff did not preserve exact five publication blockers")
    return {
        "schemaVersion": 1,
        "status": "LIVE_SIGNED_HANDOFF_RECHECK_NONPUBLISHING",
        "repository": repository, "mainMergeSha": sha,
        "runId": run_id, "runAttempt": attempt, "tagProposal": tag,
        "currentProtectedMainMatched": True,
        "originalPushRunActiveAndMatched": True,
        "tagAndReleaseAbsentAtObservation": True,
        "signedSecondOpinionWitnessed": True,
        "policyBlockers": sorted(blockers),
        "mustRecheckAndReserveTagInIndependentPublisher": True,
        "publicationAuthorized": False, "publishableReceipt": False,
        "publisherWriteEnabled": False, "automaticReleaseEnabled": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
    }


def github(repo, suffix, *, not_found=False):
    require(type(repo) is str and REPO.fullmatch(repo)
            and type(suffix) is str and "\n" not in suffix,
            "untrusted GitHub path")
    allowed = (
        suffix == "branches/main"
        or re.fullmatch(r"actions/runs/[1-9][0-9]*", suffix)
        or re.fullmatch(r"contents/(?:config/release-promotion\.json|metadata/(?:automation-fleet|release-promotion|unattended-publication)\.json)\?ref=(?:main|[a-f0-9]{40})", suffix)
        or re.fullmatch(r"releases/tags/v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*", suffix)
        or re.fullmatch(r"git/ref/tags/v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*", suffix)
    )
    require(allowed, "GitHub GET endpoint not allowlisted")
    args = ["gh", "api", "--method", "GET", "repos/" + repo + "/" + suffix]
    p = subprocess.run(args, capture_output=True, text=True,
                       check=False, timeout=40)
    if p.returncode:
        # The only accepted missing resource is an exact tag/ref under a
        # known public repo; any 401/403/5xx or other failure is DENY.
        if not_found and p.returncode != 0 and "(HTTP 404)" in p.stderr:
            return None
        raise Denied("independent GitHub GET unavailable")
    require(len(p.stdout) < 2 * 1024 * 1024,
            "oversized GitHub publisher preflight response")
    return object_json(p.stdout)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--handoff", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    try:
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        sha = os.environ.get("GITHUB_SHA", "")
        rid = int(os.environ.get("GITHUB_RUN_ID", "0"))
        attempt = int(os.environ.get("GITHUB_RUN_ATTEMPT", "0"))
        require(bool(os.environ.get("GH_TOKEN")), "read-only GitHub token missing")
        handoff = object_json(Path(args.handoff).read_text("utf-8"))
        branch = github(repo, "branches/main")
        run = github(repo, "actions/runs/" + str(rid))
        root = Path(__file__).resolve().parents[1]
        files = {}
        for name, origin, ref in (
            ("fleet", "pgextwin/build", "main"),
            ("central", "pgextwin/build", "main"),
            ("unattended", "pgextwin/build", "main"),
            ("local", repo, sha),
        ):
            path = {"fleet": "metadata/automation-fleet.json",
                    "central": "metadata/release-promotion.json",
                    "unattended": "metadata/unattended-publication.json",
                    "local": "config/release-promotion.json"}[name]
            local_path = (root / path if name != "local"
                          else Path("config/release-promotion.json"))
            files[name] = verified_live_file(
                github(origin, "contents/" + path + "?ref=" + ref),
                path, local_path.read_bytes())
        tag = handoff.get("tagProposal")
        require(type(tag) is str and TAG.fullmatch(tag), "invalid tag proposal")
        result = assess(
            handoff, branch, run, files["fleet"], files["central"],
            files["local"], files["unattended"],
            repository=repo, sha=sha, run_id=rid, attempt=attempt,
            event=os.environ.get("GITHUB_EVENT_NAME"),
            ref=os.environ.get("GITHUB_REF"),
            tag_absent=github(repo, "git/ref/tags/" + tag,
                              not_found=True) is None,
            release_absent=github(repo, "releases/tags/" + tag,
                                  not_found=True) is None)
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n", "utf-8")
        print("LIVE_SIGNED_HANDOFF_RECHECK_NONPUBLISHING; PUBLISH_DENY; NO WRITE")
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired) as e:
        print("LIVE_PUBLISHER_PREFLIGHT_DENY: " + str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
