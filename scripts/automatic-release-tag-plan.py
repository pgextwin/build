#!/usr/bin/env python3
"""Read-only, create-only-compatible tag proposal for 17 signed candidate Releases.

Never reserves a tag, creates a Release, grants publisher authority or requests a
write token. The actual Publisher MUST independently recheck live refs/releases
and atomically reserve the tag after authorization, signature and Grype checks.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "automatic_tag_identity", ROOT / "fleet-release-identity.py")
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def unique_json(raw):
    def unique(items):
        d = {}
        for k, v in items:
            require(k not in d, "ambiguous duplicate GitHub JSON field")
            d[k] = v
        return d
    return json.loads(raw, object_pairs_hook=unique)


def read_json(path):
    data = unique_json(Path(path).read_text(encoding="utf-8-sig"))
    require(type(data) is dict, "invalid local signed audit or manifest")
    return data


def get_listing(repo, path, *, allow_missing=False):
    require(type(repo) is str and REPO.fullmatch(repo)
            and type(path) is str and path.startswith(("releases?", "git/matching-refs/tags/")),
            "non-readonly GitHub inventory path")
    token = os.environ.get("GH_TOKEN")
    require(type(token) is str and bool(token), "missing scoped GitHub READ token")
    req = Request("https://api.github.com/repos/" + repo + "/" + path,
                  headers={"Authorization": "Bearer " + token,
                           "Accept": "application/vnd.github+json"})
    try:
        with urlopen(req, timeout=30) as response:
            require(response.status == 200, "unexpected GitHub inventory status")
            # Never plan from a truncated first page or a partial response.
            require(not re.search(r'\brel\s*=\s*"?next"?', response.headers.get("Link", ""), re.I),
                    "incomplete GitHub inventory pagination")
            data = response.read(8 * 1024 * 1024 + 1)
            require(len(data) <= 8 * 1024 * 1024, "oversized GitHub inventory")
            result = unique_json(data.decode("utf-8"))
    except HTTPError as e:
        if allow_missing and e.code == 404:
            return []
        raise Denied("authenticated GitHub inventory unavailable: HTTP " + str(e.code)) from e
    require(type(result) is list and len(result) < 100,
            "incomplete or paginated release/tag inventory")
    return result


def plan(audit, bridge, manifest, releases, refs, *, repo, sha, run_id, attempt):
    """Suggest a next tag from a fully enumerated live inventory; NEVER publish."""
    require(type(repo) is str and REPO.fullmatch(repo)
            and repo in {"pgextwin/" + n for n in identity.UPSTREAMS}
            and type(sha) is str and SHA.fullmatch(sha)
            and type(run_id) is int and run_id > 0
            and type(attempt) is int and attempt > 0,
            "unknown signed candidate execution identity")
    require(type(audit) is dict and type(bridge) is dict and type(manifest) is dict
            and audit.get("status") == "VERIFIED_SIGNED_CANDIDATE_NONPUBLISHING"
            and audit.get("cryptographicVerification") == "REAL_GH_ATTESTATION_VERIFY"
            and audit.get("signedArtifactsVerified") is True
            and audit.get("repository") == repo
            and audit.get("mainMergeSha") == sha
            and audit.get("runId") == run_id and type(audit.get("runId")) is int
            and audit.get("runAttempt") == attempt and type(audit.get("runAttempt")) is int
            and audit.get("publishableReceipt") is False
            and audit.get("publicationAuthorized") is False
            and audit.get("automaticReleaseEnabled") is False
            and bridge.get("status") == "PUBLISH_DENY"
            and bridge.get("repository") == repo
            and bridge.get("mainMergeSha") == sha
            and bridge.get("runId") == run_id and type(bridge.get("runId")) is int
            and bridge.get("runAttempt") == attempt and type(bridge.get("runAttempt")) is int
            and bridge.get("publicationAuthorized") is False
            and bridge.get("publisherWriteEnabled") is False
            and bridge.get("publishableReceipt") is False
            and bridge.get("goB") == bridge.get("g4") == bridge.get("g5") == "NO_GO"
            and type(bridge.get("policyBlockers")) is list
            and "INDEPENDENT_PUBLISHER_AUTHORIZATION_NOT_ESTABLISHED" in bridge["policyBlockers"]
            and manifest.get("name") == repo.split("/")[1],
            "signed audit/PUBLISH DENY identity and safety policy mismatch")
    require(type(releases) is list and type(refs) is list
            and len(releases) < 100 and len(refs) < 100,
            "incomplete release/tag inventory")
    try:
        stem = identity.tag_stem(manifest)
    except (identity.Denied, KeyError, TypeError, ValueError) as e:
        raise Denied("untrusted pinned upstream version identity") from e
    prefix = stem + "-windows."
    candidates = []
    seen_releases, seen_refs = set(), set()
    for item in releases:
        require(type(item) is dict and type(item.get("tag_name")) is str
                and type(item.get("id")) is int and item["id"] > 0
                and type(item.get("draft")) is bool,
                "ambiguous formal Release inventory")
        tag = item["tag_name"]
        require(tag not in seen_releases, "duplicate Release tags")
        seen_releases.add(tag)
        if tag.startswith(prefix):
            suffix = tag[len(prefix):]
            require(re.fullmatch(r"[1-9][0-9]*", suffix) is not None,
                    "malformed existing Windows Release sequence")
            candidates.append(int(suffix))
    for item in refs:
        require(type(item) is dict and type(item.get("ref")) is str
                and item["ref"].startswith("refs/tags/"),
                "malformed tag ref inventory")
        tag = item["ref"][len("refs/tags/"):]
        require(tag not in seen_refs, "duplicate tag refs")
        seen_refs.add(tag)
        require(tag.startswith(prefix), "GitHub matched-refs returned unrelated tag")
        suffix = tag[len(prefix):]
        require(re.fullmatch(r"[1-9][0-9]*", suffix) is not None,
                "malformed existing Windows tag ref sequence")
        candidates.append(int(suffix))
    proposed = prefix + str(max(candidates, default=0) + 1)
    try:
        identity.validate_release_tag(manifest, proposed)
    except (identity.Denied, ValueError) as e:
        raise Denied("proposed tag does not match fully pinned source") from e
    require(proposed not in seen_releases and proposed not in seen_refs,
            "new tag already reserved")
    return {
        "schemaVersion": 1, "status": "PROPOSED_TAG_NONPUBLISHING",
        "repository": repo, "mainMergeSha": sha,
        "runId": run_id, "runAttempt": attempt,
        "releaseTagProposal": proposed,
        "releaseSequence": max(candidates, default=0) + 1,
        "existingSameVersionReleases": sum(x.startswith(prefix) for x in seen_releases),
        "publicationAuthorized": False, "publishableReceipt": False,
        "publisherWriteEnabled": False,
        "requiresIndependentLiveRecheckAndAtomicTagReservation": True,
    }


def main():
    parser = argparse.ArgumentParser()
    for name in ("audit", "bridge", "manifest", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        repo, sha = os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_SHA", "")
        require(os.environ.get("GITHUB_EVENT_NAME") == "push"
                and os.environ.get("GITHUB_REF") == "refs/heads/main",
                "tag plan must be a genuine protected main/push")
        audit, bridge, manifest = (read_json(getattr(args, key))
                                   for key in ("audit", "bridge", "manifest"))
        stem = identity.tag_stem(manifest)
        releases = get_listing(repo, "releases?per_page=100")
        refs = get_listing(repo, "git/matching-refs/tags/" +
                           quote(stem + "-windows.", safe=""), allow_missing=True)
        result = plan(audit, bridge, manifest, releases, refs,
                      repo=repo, sha=sha,
                      run_id=int(os.environ.get("GITHUB_RUN_ID", "0")),
                      attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")))
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("PROPOSED_TAG_NONPUBLISHING; PUBLISH_DENY; no tag reserved")
        return 0
    except (Denied, identity.Denied, OSError, ValueError, TypeError, KeyError) as e:
        print("AUTOMATIC_TAG_PROPOSAL_DENY: " + str(e))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
