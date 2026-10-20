#!/usr/bin/env python3
"""Pure, fail-closed release identity for the 14 pgextwin Windows extensions.

Not a publisher. This module does NOT authorize, create, or modify Releases.
The manual main-only gate must separately establish reviewed SHA-pinned sources,
candidate decisions/audits, attested build and operator PUBLISH confirmation.
"""
from __future__ import annotations
from datetime import date
import re

UPSTREAMS = {
    "pg_bigm": "pgbigm/pg_bigm",
    "pg_cron": "citusdata/pg_cron",
    "pg_hint_plan": "ossc-db/pg_hint_plan",
    "pgaudit": "pgaudit/pgaudit",
    "set_user": "pgaudit/set_user",
    "pg_repack": "reorg/pg_repack",
    "pg_ivm": "sraoss/pg_ivm",
    "pg_qualstats": "powa-team/pg_qualstats",
    "plpgsql_check": "okbob/plpgsql_check",
    "hypopg": "HypoPG/hypopg",
    "wal2json": "eulerto/wal2json",
    "pg_partman": "pgpartman/pg_partman",
    "pg_stat_monitor": "percona/pg_stat_monitor",
    "orafce": "orafce/orafce",
}
TAG_NAME = re.compile(r"^v[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]{8})?-windows\.[1-9][0-9]*$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA = re.compile(r"^[a-f0-9]{40}$")
ALLOWED_MAJORS = {14, 15, 16, 17, 18}

class Denied(ValueError):
    pass

def require(condition: bool, detail: str) -> None:
    if not condition:
        raise Denied(detail)

def configured_majors(ext: dict) -> list[int]:
    p = ext.get("postgresql", {})
    if isinstance(p.get("majors"), list):
        raw = p["majors"]
        require(all(type(n) is int for n in raw), "invalid PG major type")
        majors = sorted(raw)
    else:
        lo, hi = p.get("minMajor"), p.get("maxMajor")
        require(type(lo) is int and type(hi) is int and lo <= hi, "invalid PG range")
        majors = list(range(lo, hi + 1))
    require(bool(majors) and len(set(majors)) == len(majors)
            and set(majors).issubset(ALLOWED_MAJORS), "untrusted or duplicate PG majors")
    return majors

def maintained_majors(ext: dict, lifecycle: dict, today: date | None = None) -> list[int]:
    require(lifecycle.get("schemaVersion") == 1
            and isinstance(lifecycle.get("postgresql"), list), "invalid lifecycle")
    today = today or date.today()
    configured = set(configured_majors(ext))
    found: set[int] = set()
    maintained = []
    for item in lifecycle["postgresql"]:
        n = item.get("major")
        require(type(n) is int and n not in found, "invalid or duplicate lifecycle major")
        found.add(n)
        if n in configured and date.fromisoformat(item["eol"]) >= today:
            maintained.append(n)
    require(bool(maintained) and configured.issubset(found),
            "configured PG major absent from lifecycle")
    return sorted(maintained)

def sources(ext: dict, require_pins: bool = True) -> dict[int, dict]:
    name = ext.get("name")
    require(isinstance(name, str) and name in UPSTREAMS,
            "extension not in allowlisted fleet")
    upstream = ext.get("upstream")
    require(isinstance(upstream, dict)
            and upstream.get("repository") == UPSTREAMS[name],
            "upstream repository changed from audited allowlist")
    majors = configured_majors(ext)
    series = upstream.get("perPostgresql")
    require(series is None or isinstance(series, dict), "bad per-major configuration")
    if series is not None:
        require(set(series) == {str(x) for x in majors},
                "missing/unexpected per-major upstream identity")
    results = {}
    for m in majors:
        item = (series[str(m)] if series is not None else upstream)
        require(isinstance(item, dict), "invalid upstream source")
        ref, version, commit = item.get("ref"), item.get("version"), item.get("commit")
        require(isinstance(ref, str) and REF.fullmatch(ref),
                "unsafe/missing upstream ref")
        require(isinstance(version, str) and VERSION.fullmatch(version),
                "unsafe/missing source version")
        if require_pins:
            require(isinstance(commit, str) and SHA.fullmatch(commit),
                    "upstream source SHA must be fully pinned before formal release")
        elif commit is not None:
            require(isinstance(commit, str) and SHA.fullmatch(commit),
                    "malformed optional source pin")
        results[m] = {"major": m, "ref": ref, "version": version, "commit": commit}
    return results

def tag_stem(ext: dict, require_pins: bool = True) -> str:
    src = sources(ext, require_pins=require_pins)
    if ext["name"] == "pg_bigm":
        # Release convention is v1.2-20250903-windows.N, whereas the SQL
        # extension's semantic version is 1.2.
        ref = src[max(src)]["ref"]
        require(re.fullmatch(r"v[0-9]+\.[0-9]+-[0-9]{8}", ref) is not None,
                "pg_bigm release requires versioned dated source ref")
        return ref
    return "v" + src[max(src)]["version"]

def validate_release_tag(ext: dict, tag: str, require_pins: bool = True) -> None:
    require(isinstance(tag, str) and TAG_NAME.fullmatch(tag),
            "invalid or unsafe formal Windows Release tag")
    prefix = tag_stem(ext, require_pins=require_pins) + "-windows."
    require(tag.startswith(prefix)
            and re.fullmatch(r"[1-9][0-9]*", tag[len(prefix):]),
            "release tag does not match exact pinned current source identity")

def asset_stem(ext: dict, major: int, require_pins: bool = True) -> str:
    src = sources(ext, require_pins=require_pins)
    require(major in src, "PG major not configured")
    return f"{ext['name']}-{src[major]['ref']}-pg{major}-windows-x64"

def expected_assets(ext: dict, majors: list[int], require_pins: bool = True) -> set[str]:
    configured = sources(ext, require_pins=require_pins)
    require(majors == sorted(set(majors)) and bool(majors)
            and set(majors).issubset(configured), "missing/extra release major")
    assets = {"SHA256SUMS.txt"}
    for n in majors:
        stem = asset_stem(ext, n, require_pins=require_pins)
        assets.update({stem+".zip", stem+".spdx.json", stem+".vulnerabilities.json"})
    return assets
