#!/usr/bin/env python3
"""Issue #75: one bounded historical Microsoft MSU original-byte witness.

Nonexecuting, PR-only, no authenticating or publishing. This proves one exact
downloaded byte digest, never OS branch reachability or full runtime closure.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "issue75_kb_original", ROOT / "scripts/issue-75-kb-conditional-inert.py")
kb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kb)

PKG = ("KB3033929", "1.0.3",
       "51d28a163e4c9cfab2ea94c47d7308a88d578e18f6d4e0ac5c8286ee4ae9c91b")
SCRIPT = "Tools/ChocolateyInstall.ps1"
SCRIPT_SHA256 = "88f28af10bb556009d17a42cc42ae7d50f8b83c55d172cb3764e23a6a9420ecb"
URL = ("https://download.microsoft.com/download/C/8/7/"
       "C87AE67E-A228-48FB-8F02-B2A9A1238099/Windows6.1-KB3033929-x64.msu")
SHA256 = "5318587007edb6c8b29310ff18da479a162b486b9101a7de735f94a70dbc3b31"
MAX_MSU = 120_000_000
HOSTS = frozenset(("download.microsoft.com",
                   "download.windowsupdate.com",
                   "catalog.s.download.windowsupdate.com"))
PAIR = re.compile(
    r"(?im)^[ \t]*Url64[ \t]*=[ \t]*'(?P<url>https://[^'\r\n]+\.msu)'[ \t]*\r?\n"
    r"[ \t]*Checksum64[ \t]*=[ \t]*'(?P<digest>[a-fA-F0-9]{64})'[ \t]*$")


class Deny(ValueError):
    pass


def verify_url(url: str) -> str:
    p = urlsplit(url)
    if (p.scheme != "https" or p.hostname not in HOSTS or p.username is not None
            or p.password is not None or p.port not in (None, 443)
            or p.fragment or not p.path or p.path.startswith("//")):
        raise Deny("untrusted Microsoft original byte URL or redirect")
    return url


class LimitedRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        verify_url(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def get_msu(url: str, maximum: int = MAX_MSU) -> bytes:
    verify_url(url)
    opener = build_opener(LimitedRedirect())
    req = Request(url, method="GET", headers={
        "User-Agent": "pgextwin-issue75-msu-readonly/1", "Cache-Control": "no-cache"})
    with opener.open(req, timeout=60) as response:
        verify_url(response.geturl())
        if response.status != 200:
            raise Deny("Microsoft response not 200")
        data = response.read(maximum + 1)
    if len(data) < 100_000 or len(data) > maximum:
        raise Deny("missing, truncated or oversized MSU payload")
    return data


def source_pair(script: bytes) -> dict:
    if hashlib.sha256(script).hexdigest() != SCRIPT_SHA256:
        raise Deny("unapproved script original digest")
    text = script.decode("utf-8-sig")
    pairs = [(m.group("url"), m.group("digest").lower())
             for m in PAIR.finditer(text)]
    if pairs.count((URL, SHA256)) != 1:
        raise Deny("source URL/checksum adjacent pair absent or ambiguous")
    if any(u == URL and h != SHA256 for u, h in pairs):
        raise Deny("source reassigns approved MSU URL to a different digest")
    verify_url(URL)
    return {"url": URL, "expectedSHA256": SHA256,
            "sourceScriptSHA256": SCRIPT_SHA256,
            "lexicalAdjacentPair": True, "osBranchReachabilityProven": False}


def verified_payload(data: bytes, expected: str = SHA256) -> dict:
    if not (100_000 <= len(data) <= MAX_MSU and data.startswith(b"MSCF")):
        raise Deny("MSU CAB magic, size or bound mismatch")
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise Deny("Microsoft MSU real byte SHA256 mismatch")
    return {"sha256": digest, "bytes": len(data), "executed": False}


def observe(download_package=None, download_msu=None) -> dict:
    if download_package is None:
        download_package = kb.secondary.get
    if download_msu is None:
        download_msu = get_msu
    name, version, expected_pkg = PKG
    address = kb.secondary.SOURCE_PREFIX + name + "/" + version
    one = download_package(address, "nupkg", 25_000_000)
    two = download_package(address, "nupkg", 25_000_000)
    if one != two or hashlib.sha256(one).hexdigest() != expected_pkg:
        raise Deny("original nupkg double GET digest mismatch")
    kb.secondary.archive_inventory(one, name, version)
    with ZipFile(io.BytesIO(one)) as package:
        matches = [i for i in package.infolist() if i.filename.lower() == SCRIPT.lower()]
        if len(matches) != 1:
            raise Deny("unique historical PowerShell source required")
        pair = source_pair(package.read(matches[0]))
    first = download_msu(pair["url"])
    second = download_msu(pair["url"])
    if first != second:
        raise Deny("independent Microsoft MSU GET byte disagreement")
    original = verified_payload(first)
    return {
        "decision": "ONE_HISTORICAL_MSU_REAL_BYTES_SOURCE_ONLY",
        "package": {"name": name, "version": version,
                    "sha256": expected_pkg, "getCount": 2},
        "payload": {**pair, **original, "getCount": 2},
        "osBranchReachabilityProven": False,
        "runtimeDependencyClosureProven": False,
        "signerWriterIsolationProven": False,
        "signedPublisherPrewriteProven": False,
        "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
        "releaseAuthorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("static", "observe"), default="static")
    args = parser.parse_args()
    try:
        if args.mode == "observe":
            if not (os.getenv("GITHUB_EVENT_NAME") == "pull_request"
                    and os.getenv("GITHUB_HEAD_REF") == "issue-75-msu-original-bytes"
                    and os.getenv("GITHUB_REPOSITORY") == "pgextwin/build"
                    and os.getenv("GITHUB_JOB") == "issue75_msu_original"
                    and not os.getenv("GH_TOKEN")
                    and not os.getenv("GITHUB_TOKEN")):
                raise Deny("not isolated read-only PR job")
            result = observe()
        else:
            result = {"decision": "MSU_BOUND_SOURCE_STATIC_ONLY",
                      "payloadBytesVerified": 0, "runtimeDependencyClosureProven": False,
                      "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
                      "releaseAuthorized": False}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Deny, kb.Deny, kb.secondary.Deny, ValueError, OSError,
            UnicodeError, KeyError, TypeError) as exc:
        print(json.dumps({"decision": "DENY_MSU_ORIGINAL_BYTES",
                          "reason": str(exc)[:160],
                          "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
                          "releaseAuthorized": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
