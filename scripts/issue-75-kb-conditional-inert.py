#!/usr/bin/env python3
"""Issue #75: classify historical KB/WindowsUpdate script source without executing it.

Archive SHA256 means verified source bytes only. Literal URLs and checksums are
lexical candidates, never verified MSU bytes or an executable dependency closure.
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
from zipfile import ZipFile, BadZipFile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "issue75_secondary_source", ROOT / "scripts/issue-75-choco-secondary-readonly.py")
secondary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(secondary)

# Original archive SHA256 values, not script hashes or computed guesses.
# First five: successful source Runs 39039052934/39039490483.
# Last three: job successful under FAILED parent Run 39039716020;
# followed by a successful, independent further-package PR Run 39041869619.
PACKAGES = (
    ("chocolatey-core.extension", "1.3.3", "ed7a281f45a61150df0e1414651bca8501004c56deb43439c075f1ba58aff70a"),
    ("vcredist140", "14.23.27820", "aec3e2fa9a92dd7c158f8ecf51a541f13bcbe95933ace4ace5ec1d1681e9c9dd"),
    ("KB3033929", "1.0.3", "51d28a163e4c9cfab2ea94c47d7308a88d578e18f6d4e0ac5c8286ee4ae9c91b"),
    ("KB2919355", "1.0.20160915", "e4d1e19587bfc89a6dada9f15e8c64ae7db64a2b0628da45998ff300f8430f6a"),
    ("kb2999226", "1.0.20170509", "6f11999bf61b90ab5fcb992f0de266a6c897e91d96c3602cc3de3632df84e96a"),
    ("chocolatey-windowsupdate.extension", "1.0.2", "1cf1b09a1dc3c9094c05216b3a6eb32ad4f0372bb96066c21038b30c4372ebf4"),
    ("KB3035131", "1.0.1", "b13d656e223baa0b8b29979d585cb1b4dcf2e68d3daca73681fbd093abab1e4b"),
    ("KB2919442", "1.0.20160915", "8d1c0b79ec22343f6fe3a9a52d5072320b3265182ee273c453fef04e7b221cf3"),
)
URL = re.compile(r"https?://[^\s'\"<>\\)]+", re.I)
ASSIGN = re.compile(r"^\s*\$?(url64?|checksum64?|checksumtype64?)\s*=\s*(.*?)\s*$", re.I)
QUOTED = re.compile(r"^(['\"])(.*?)\1\s*(?:#.*)?$")
OS_KEY = re.compile(r"(?m)^\s*['\"](\d+\.\d+(?:-[\w]+)?)['\"]\s*=\s*@\{")
SHA = re.compile(r"^[0-9a-fA-F]{64}$")
CALL = re.compile(r"\b(Install-WindowsUpdate|Install-ChocolateyPackage|"
                  r"Invoke-WebRequest|Start-BitsTransfer|DownloadFile|"
                  r"Invoke-Expression|iex)\b", re.I)
ALLOWED_LITERAL_HOSTS = frozenset((
    "download.microsoft.com", "catalog.s.download.windowsupdate.com",
    "download.windowsupdate.com", "download.visualstudio.microsoft.com",
))

class Deny(ValueError):
    pass

def classify_script(raw: bytes) -> dict:
    if len(raw) > 150_000:
        raise Deny("oversized PowerShell source")
    text = raw.decode("utf-8-sig", errors="replace")
    urls, assignments, calls = [], [], []
    for number, line in enumerate(text.splitlines(), 1):
        for match in URL.finditer(line):
            candidate = match.group(0).rstrip(".,;]")
            parsed = urlsplit(candidate)
            literal = bool(
                QUOTED.fullmatch(line.strip().split("=", 1)[-1].strip())
            ) and "$" not in candidate and "`" not in candidate
            urls.append({
                "line": number, "url": candidate,
                "literalAssignment": literal,
                "allowlistedHost": parsed.scheme == "https"
                    and parsed.hostname in ALLOWED_LITERAL_HOSTS
                    and parsed.username is None and parsed.password is None
                    and parsed.port in (None, 443) and not parsed.fragment,
                "payloadBytesVerified": False,
            })
        m = ASSIGN.match(line)
        if m:
            key, value = m.group(1).lower(), m.group(2)
            quoted = QUOTED.fullmatch(value)
            value_text = quoted.group(2) if quoted else None
            is_digest = "checksum" in key and "type" not in key
            assignments.append({
                "line": number, "property": key,
                "literalSHA256": value_text.lower() if is_digest
                    and value_text and SHA.fullmatch(value_text) else None,
                "resolved": bool(quoted) and (
                    not is_digest or bool(value_text and SHA.fullmatch(value_text))),
            })
        calls.extend({"line": number, "name": m.group(1)}
                     for m in CALL.finditer(line))
    # No PowerShell interpretation; URL/checksum association and OS branch
    # reachability are explicitly unknown even for literal-looking assignments.
    return {
        "scriptSHA256": hashlib.sha256(raw).hexdigest(),
        "scriptBytes": len(raw),
        "osHashtableKeys": sorted(set(OS_KEY.findall(text))),
        "conditionalStatements": len(re.findall(r"(?im)^\s*(?:if|elseif|else)\b", text)),
        "externalURLCandidates": urls,
        "urlOrChecksumAssignments": assignments,
        "downloadOrExecutionHelperMentions": calls,
        "utf8ReplacementPresent": "\ufffd" in text,
        "osBranchReachabilityProven": False,
        "urlChecksumPairingProven": False,
        "conditionalExternalPayloadBytesVerified": False,
        "unresolvedDynamicOrIndirectBehavior": True,
    }

def observe(download=None) -> dict:
    if download is None:
        download = secondary.get
    rows = []
    for name, version, expected_sha in PACKAGES:
        address = secondary.SOURCE_PREFIX + name + "/" + version
        first = download(address, "nupkg", 25_000_000)
        second = download(address, "nupkg", 25_000_000)
        if first != second or hashlib.sha256(first).hexdigest() != expected_sha:
            raise Deny("approved historical nupkg original changed: " + name)
        basic = secondary.archive_inventory(first, name, version)
        scripts = []
        with ZipFile(io.BytesIO(first)) as archive:
            for item in archive.infolist():
                if item.filename.lower().endswith(".ps1") and not item.is_dir():
                    row = classify_script(archive.read(item))
                    row["path"] = item.filename
                    scripts.append(row)
        if {s["path"] for s in scripts} != {
            s["path"] for s in basic["scriptLiteralExternalDownloads"]
        }:
            raise Deny("unaccounted source scripts: " + name)
        rows.append({
            "name": name, "version": version,
            "actualArchiveSHA256": expected_sha,
            "originalArchiveBytes": len(first), "independentGETs": 2,
            "dependencies": basic["dependencies"],
            "scripts": scripts,
            "archiveBytesVerified": True, "sourceOnly": True,
        })
    return {
        "decision": "KB_CONDITIONAL_SOURCE_LEXICAL_INVENTORY_ONLY",
        "provenance": {
            "priorSourceRunsSuccess": [39039052934, 39039490483, 39041869619],
            "historicalFailedParentRunNotWaived": 39039716020,
        },
        "packages": rows,
        "packageArchivesDoubleGETSHA256": len(rows),
        "externalPayloadBytesVerifiedByThisProbe": 0,
        "runtimeDependencyClosureProven": False,
        "signedPublisherPrewriteProven": False,
        "writerCredentialIsolationProven": False,
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
                    and os.getenv("GITHUB_HEAD_REF") == "issue-75-kb-conditional-inert"
                    and os.getenv("GITHUB_REPOSITORY") == "pgextwin/build"
                    and os.getenv("GITHUB_JOB") == "issue75_kb_inert"
                    and not os.getenv("GH_TOKEN")
                    and not os.getenv("GITHUB_TOKEN")):
                raise Deny("not isolated PR-only read-only job")
            output = observe()
        else:
            output = {
                "decision": "KB_CONDITIONAL_SOURCE_STATIC_ONLY",
                "allowedOriginalArchives": len(PACKAGES),
                "externalPayloadBytesVerified": 0,
                "runtimeDependencyClosureProven": False,
                "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
                "releaseAuthorized": False,
            }
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except (Deny, secondary.Deny, OSError, ValueError, TypeError, KeyError,
            BadZipFile) as exc:
        print(json.dumps({
            "decision": "DENY_KB_CONDITIONAL_SOURCE",
            "reason": str(exc)[:120] if isinstance(exc, ValueError)
                      else type(exc).__name__,
            "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
            "releaseAuthorized": False,
        }, sort_keys=True))
        return 2

if __name__ == "__main__":
    sys.exit(main())
