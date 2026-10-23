#!/usr/bin/env python3
"""Fail-closed Grype finding policy for future unattended Windows Publisher.

Reads an *already authenticated* Grype JSON report; it cannot verify signatures,
authorize a Release, create tags, change policies, or contact GitHub. Only the
real signed-candidate verifier may supply its result to a future Publisher.
"""
from __future__ import annotations

from pathlib import PurePosixPath

SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
BLOCK = frozenset(("Critical", "High", "Unknown"))
FORBIDDEN = frozenset((
    "ignore", "exclude", "vex-documents", "vex-add", "only-fixed",
    "only-notfixed", "ignore-wontfix", "fail-on", "fail-on-severity",
))


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def settings(value):
    if type(value) is dict:
        for key, item in value.items():
            yield str(key).lower().replace("_", "-"), item
            yield from settings(item)
    elif type(value) is list:
        for item in value:
            yield from settings(item)


def review(report, *, asset_stem):
    """Classify unfiltered scanner findings, never grant a Publisher token."""
    require(type(asset_stem) is str and bool(asset_stem)
            and "/" not in asset_stem and "\\" not in asset_stem,
            "unsafe expected Windows asset identity")
    require(type(report) is dict, "Grype report not a JSON object")
    desc, source = report.get("descriptor"), report.get("source")
    require(type(desc) is dict and desc.get("name") == "grype"
            and desc.get("version") == "0.120.1", "unknown Grype scanner")
    require(type(source) is dict and source.get("type") == "file"
            and type(source.get("target")) is str
            and source["target"].replace("\\", "/").rstrip("/").split("/")[-1] == asset_stem,
            "Grype source is not the exact signed ZIP's SPDX SBOM")
    db = desc.get("db")
    require(type(db) is dict and type(db.get("status")) is dict
            and db["status"].get("valid") is True
            and all(type(db["status"].get(k)) is str and db["status"][k]
                    for k in ("schemaVersion", "built", "from"))
            and type(db.get("providers")) is dict and bool(db["providers"]),
            "Grype database authenticity/freshness prerequisites unavailable")
    config = desc.get("configuration")
    require(type(config) is dict, "Grype configuration missing")
    props = list(settings(config))
    require(any(k == "match-upstream-kernel-headers" for k, _ in props)
            and all(v is True for k, v in props
                    if k == "match-upstream-kernel-headers"),
            "unfiltered kernel header matcher not enabled")
    require(not any(k in FORBIDDEN and v not in (None, False, "", [], {})
                    for k, v in props),
            "filtered/ignored vulnerability evidence forbidden")
    matches, ignored = report.get("matches"), report.get("ignoredMatches", [])
    require(type(matches) is list and type(ignored) is list and not ignored,
            "missing Grype matches or hidden/suppressed vulnerabilities")
    counts = {name: 0 for name in SEVERITIES}
    for entry in matches:
        require(type(entry) is dict and type(entry.get("vulnerability")) is dict
                and type(entry["vulnerability"].get("id")) is str
                and bool(entry["vulnerability"]["id"])
                and type(entry.get("artifact")) is dict
                and type(entry["artifact"].get("name")) is str
                and bool(entry["artifact"]["name"]), "malformed Grype finding")
        severity = entry["vulnerability"].get("severity")
        require(type(severity) is str and severity in SEVERITIES,
                "unknown/missing vulnerability severity schema")
        details = entry.get("matchDetails")
        require(type(details) is list and bool(details)
                and all(type(v) is dict and type(v.get("matcher")) is str
                        and bool(v["matcher"]) for v in details),
                "missing vulnerability matcher evidence")
        counts[severity] += 1
    blocking = sum(counts[name] for name in BLOCK)
    return {
        "status": "BLOCKING_FINDINGS" if blocking else "NO_BLOCKING_FINDINGS",
        "blockingFindingCount": blocking,
        "findingCountBySeverity": counts,
        "publicationAuthorized": False,
    }
