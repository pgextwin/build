#!/usr/bin/env python3
"""Observe current pinned-main version vs public Windows Release (NO PUBLISH).

This is an additional detection layer, NOT a signed source, byte verification,
Publisher receipt, Catalog acceptance or authorization. Fail closed on drift.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

from update_watch_lib import WatchError, github_get_json

SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
BIGM_REF = re.compile(r"^v[0-9]+\.[0-9]+-[0-9]{8}$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
BASE = "https://api.github.com/repos/"


class GapDenied(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise GapDenied(message)


def stem(repository, current):
    name = repository.split("/")[-1]
    require(type(current) is dict and bool(current), "missing pinned upstream version")
    if name == "pg_bigm":
        ref = current.get("ref")
        require(type(ref) is str and BIGM_REF.fullmatch(ref), "invalid pg_bigm dated release ref")
        return ref
    if "version" in current:
        version = current["version"]
    else:
        majors = sorted(int(k) for k in current if re.fullmatch(r"(?:1[4-8])", k))
        require(majors and len(majors) == len(current), "invalid per-PG version map")
        most_recent = current.get(str(majors[-1]))
        require(type(most_recent) is dict, "invalid per-PG latest version")
        version = most_recent.get("version")
    require(type(version) is str and VERSION.fullmatch(version), "invalid current version")
    return "v" + version


def report(fleet, scan, get):
    require(type(fleet) is dict and fleet.get("schemaVersion") == 1
            and type(fleet.get("entries")) is list, "invalid fleet registry")
    names = [e.get("repository") for e in fleet["entries"] if type(e) is dict]
    require(names and len(names) == len(fleet["entries"]) and len(set(names)) == len(names)
            and all(type(n) is str and REPO.fullmatch(n) for n in names),
            "unsafe fleet registry")
    require(type(scan) is dict and scan.get("schemaVersion") == 1
            and scan.get("scope") == "STABLE_UPSTREAM_GET_ONLY"
            and scan.get("publication") == "DENY"
            and scan.get("candidatePrCreated") is False
            and scan.get("fleetSize") == len(names)
            and type(scan.get("extensions")) is list
            and len(scan["extensions"]) == len(names),
            "scan must be original complete nonpublishing fleet observation")
    seen = {r.get("repository"): r for r in scan["extensions"] if type(r) is dict}
    require(len(seen) == len(names) and set(seen) == set(names),
            "partial, duplicate, or wrong fleet observation")
    rows = []
    for repo in names:
        source = seen[repo]
        status = "INDETERMINATE"
        public_tag = None
        current_stem = None
        try:
            require(source.get("status") in ("up-to-date", "update-available", "CENTRALLY_DISABLED"),
                    "unknown upstream observation")
            if source["status"] == "CENTRALLY_DISABLED":
                rows.append({"repository": repo, "status": "CENTRALLY_DISABLED",
                             "publicationVerified": False, "publicationAuthorized": False})
                continue
            current_sha = source.get("mainSha")
            require(type(current_sha) is str and SHA.fullmatch(current_sha),
                    "unbound source main SHA")
            branch = get(BASE + repo + "/branches/main")
            require(type(branch) is dict and branch.get("protected") is True
                    and (branch.get("commit") or {}).get("sha") == current_sha,
                    "protected main drift since upstream observation")
            if source["status"] == "update-available":
                status = "UPSTREAM_UPDATE_UNPREPARED"
            else:
                current_stem = stem(repo, source.get("current"))
                releases = get(BASE + repo + "/releases?per_page=100")
                require(type(releases) is list and len(releases) < 100
                        and all(type(r) is dict for r in releases),
                        "incomplete or malformed public release list")
                valid = [r for r in releases if r.get("draft") is False
                         and r.get("prerelease") is False
                         and type(r.get("tag_name")) is str
                         and re.fullmatch(re.escape(current_stem) + r"-windows\.[1-9][0-9]*",
                                          r["tag_name"])]
                if valid:
                    status = "CURRENT_VERSION_TAG_PRESENT_UNVERIFIED"
                    public_tag = valid[0]["tag_name"]
                else:
                    status = "CURRENT_VERSION_RELEASE_MISSING"
        except (GapDenied, WatchError, ValueError, TypeError, KeyError, OSError):
            status = "INDETERMINATE"
        rows.append({"repository": repo, "status": status,
                     "mainSha": source.get("mainSha"), "expectedStem": current_stem,
                     "observedTag": public_tag,
                     "publicationVerified": False, "publicationAuthorized": False})
    counts = {s: sum(r["status"] == s for r in rows)
              for s in sorted({r["status"] for r in rows})}
    return {"schemaVersion": 1, "observationOnly": True,
            "scope": "PROTECTED_MAIN_VS_PUBLIC_RELEASE_TAG_READ_ONLY",
            "publicationAuthorized": False, "verifiedPublishedBytes": False,
            "catalogVerified": False, "fleetSize": len(names),
            "releaseGaps": counts.get("CURRENT_VERSION_RELEASE_MISSING", 0),
            "indeterminate": counts.get("INDETERMINATE", 0),
            "counts": counts, "extensions": rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fleet", required=True)
    ap.add_argument("--scan", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--summary", required=True)
    args = ap.parse_args()
    try:
        require(os.environ.get("GITHUB_REPOSITORY") == "pgextwin/build"
                and os.environ.get("GITHUB_REF") == "refs/heads/main"
                and os.environ.get("GITHUB_EVENT_NAME") == "issue_comment",
                "only current owner Chat scan path permitted")
        token = os.environ.get("GH_TOKEN")
        require(type(token) is str and bool(token), "missing read-only GitHub token")
        fleet = json.loads(Path(args.fleet).read_text("utf-8"))
        scan = json.loads(Path(args.scan).read_text("utf-8"))
        result = report(fleet, scan, lambda url: github_get_json(url, token))
        Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", "utf-8")
        lines = ["## Protected-main versus public Windows Release tag (READ ONLY)", "",
                 "A matching tag is NOT proof of valid ZIP, signature, Attestation, Catalog or Website.",
                 "A missing tag is NOT publication permission.", "",
                 "| Extension | Status | Observed current-version tag |",
                 "| --- | --- | --- |"]
        for item in result["extensions"]:
            lines.append("| " + item["repository"].split("/")[-1] + " | "
                         + item["status"] + " | " + (item.get("observedTag") or "—") + " |")
        lines += ["", "Release-version gaps: " + str(result["releaseGaps"]),
                  "Indeterminate: " + str(result["indeterminate"]),
                  "PUBLISH=DENY; publication always requires separate signed-source and Publisher gates."]
        Path(args.summary).write_text("\n".join(lines) + "\n", "utf-8")
        print("FLEET_RELEASE_GAPS=" + str(result["releaseGaps"])
              + "; INDETERMINATE=" + str(result["indeterminate"]) + "; PUBLISH_DENY")
        return 2 if result["indeterminate"] else 0
    except (GapDenied, OSError, ValueError, TypeError, KeyError):
        print("FLEET_RELEASE_OBSERVATION_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
