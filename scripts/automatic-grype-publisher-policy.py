#!/usr/bin/env python3
"""Grype finding classification for the Windows Publisher evidence chain.

Reads an *already authenticated* Grype JSON report; it cannot verify signatures,
authorize a Release, create tags, change policies, or contact GitHub. Only the
real signed-candidate verifier may supply its result to a future Publisher.

E3 PR3 (per-route decision 6A): this module only *classifies* a report into a
recorded diagnostic verdict (status + per-severity counts). Callers record the
verdict; severity findings never deny publication by themselves.

E3 PR5 (audit M2): failures are separated into two kinds.
- Integrity failures raise Denied: the evidence does not bind to the exact
  signed ZIP (scanner identity, source target), is filtered/suppressed
  (ignore/VEX configuration, ignored matches), or is structurally malformed.
  Tampering, substitution and suppression stay refused.
- Diagnostic-validity failures return a DIAGNOSTIC_FAILED verdict instead:
  the vulnerability database block is missing or unusable (status not valid,
  schema/built/from missing, no providers), so the scan's matches cannot be
  trusted as a classification. The verdict carries zero counts, which means
  "not classified", never "no findings"; the status says so explicitly.
A producer diagnostic record (written by the signed build when Grype itself
could not produce a report) is classified the same way and returns its
recorded status (DIAGNOSTIC_FAILED or NOT_PERFORMED) with zero counts.
"""
from __future__ import annotations

from pathlib import PurePosixPath

SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
BLOCK = frozenset(("Critical", "High", "Unknown"))
FORBIDDEN = frozenset((
    "ignore", "exclude", "vex-documents", "vex-add", "only-fixed",
    "only-notfixed", "ignore-wontfix", "fail-on", "fail-on-severity",
))
DIAGNOSTIC_RECORD_NAME = "pgextwin-grype-diagnostic"
DIAGNOSTIC_STATUSES = ("DIAGNOSTIC_FAILED", "NOT_PERFORMED")
DB_UNAVAILABLE = "Grype database authenticity/freshness prerequisites unavailable"


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def zero_counts():
    return {name: 0 for name in SEVERITIES}


def diagnostic_verdict(status, reason, *, record=False, detail=None):
    verdict = {"status": status,
               "blockingFindingCount": 0,
               "findingCountBySeverity": zero_counts(),
               "publicationAuthorized": False,
               "diagnosticReason": reason}
    if record:
        verdict["diagnosticRecord"] = True
        verdict["diagnosticDetail"] = detail
    return verdict


def review_diagnostic_record(report, desc, *, asset_stem):
    """Classify a producer diagnostic record; anything mislabelled is Denied."""
    require(desc.get("name") == DIAGNOSTIC_RECORD_NAME
            and desc.get("diagnosticRecord") is True
            and desc.get("expectedScanner") == {"name": "grype",
                                                "version": "0.120.1"},
            "malformed Grype diagnostic record descriptor")
    source = report.get("source")
    require(type(source) is dict and source.get("type") == "file"
            and type(source.get("target")) is str
            and source["target"].replace("\\", "/").rstrip("/").split("/")[-1] == asset_stem,
            "Grype diagnostic record is not bound to the exact signed ZIP")
    status = report.get("status")
    detail = report.get("detail")
    require(status in DIAGNOSTIC_STATUSES
            and type(detail) is str and bool(detail)
            and report.get("matches") == []
            and report.get("ignoredMatches", []) == [],
            "malformed Grype diagnostic record body")
    return diagnostic_verdict(
        status,
        "producer recorded no Grype report for this asset",
        record=True, detail=detail)


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
    if type(desc) is dict and desc.get("diagnosticRecord") is True:
        return review_diagnostic_record(report, desc, asset_stem=asset_stem)
    require(type(desc) is dict and desc.get("name") == "grype"
            and desc.get("version") == "0.120.1", "unknown Grype scanner")
    require(type(source) is dict and source.get("type") == "file"
            and type(source.get("target")) is str
            and source["target"].replace("\\", "/").rstrip("/").split("/")[-1] == asset_stem,
            "Grype source is not the exact signed ZIP's SPDX SBOM")
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
    # Diagnostic validity (E3 PR5, audit M2): an unusable vulnerability
    # database means the scan produced no trustworthy classification. That
    # is recorded as DIAGNOSTIC_FAILED with zero counts and never denies;
    # the integrity checks above have already refused tampered, substituted
    # or filtered evidence, so reaching here means the report is bound to
    # this ZIP and unfiltered, only its database backing is unavailable.
    db = desc.get("db")
    if not (type(db) is dict and type(db.get("status")) is dict
            and db["status"].get("valid") is True
            and all(type(db["status"].get(k)) is str and db["status"][k]
                    for k in ("schemaVersion", "built", "from"))
            and type(db.get("providers")) is dict and bool(db["providers"])):
        return diagnostic_verdict("DIAGNOSTIC_FAILED", DB_UNAVAILABLE)
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
