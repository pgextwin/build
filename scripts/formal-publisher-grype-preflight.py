#!/usr/bin/env python3
"""Fail-closed common, read-only Grype guard for legacy manual Publishers.

Run BEFORE the frozen/approved Publisher executable writes any tag or draft.
This supplements (NEVER replaces) the original manual PUBLISH authorization,
exact attempt-bound Sigstore/SBOM proof and create-only Release verification.
No GitHub API, tokens, network, subprocess or write actions are used.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from zipfile import ZipFile, BadZipFile

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, HERE / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


identity = load("formal_grype_identity", "fleet-release-identity.py")
policy = load("formal_grype_policy", "automatic-grype-publisher-policy.py")
DIGEST = re.compile(r"^[0-9a-f]{64}$")


class Denied(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Denied(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "ambiguous duplicate JSON field")
        result[key] = value
    return result


def read_json(path):
    require(path.is_file() and not path.is_symlink(), "missing/unsafe evidence " + path.name)
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique)


def sha256(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(part)
    return hasher.hexdigest()


def verify(dist, extension, lifecycle, *, today=None):
    """Offline guard over exact immutable Release asset triplets.

    This is a negative security predicate, NEVER a Publisher receipt.
    Cryptographic attestation verification remains the old Publisher's job.
    """
    try:
        majors = identity.maintained_majors(extension, lifecycle, today=today)
        expected = identity.expected_assets(extension, majors) - {"SHA256SUMS.txt"}
    except (identity.Denied, KeyError, ValueError, TypeError) as exc:
        raise Denied("untrusted extension or lifecycle: " + str(exc)) from exc
    require(dist.is_dir() and not dist.is_symlink(), "untrusted asset directory")
    files = list(dist.iterdir())
    require(all(x.is_file() and not x.is_symlink() for x in files)
            and {x.name for x in files} == expected
            and len(files) == len(expected),
            "missing, duplicate or unexpected Windows Release assets")
    report = {}
    for major in majors:
        stem = identity.asset_stem(extension, major)
        zip_path = dist / (stem + ".zip")
        spdx_path = dist / (stem + ".spdx.json")
        grype_path = dist / (stem + ".vulnerabilities.json")
        with ZipFile(zip_path) as archive:
            require(archive.testzip() is None, "corrupt ZIP payload")
            require(archive.namelist().count("PACKAGE-INFO.json") == 1,
                    "missing or duplicate ZIP package identity")
        zip_hash = sha256(zip_path)
        spdx = read_json(spdx_path)
        require(type(spdx) is dict and spdx.get("spdxVersion") == "SPDX-2.3"
                and type(spdx.get("packages")) is list, "invalid SPDX root")
        roots = [p for p in spdx["packages"]
                 if type(p) is dict and p.get("name") == stem]
        require(len(roots) == 1, "missing/ambiguous ZIP-bound SPDX root")
        checks = roots[0].get("checksums")
        require(type(checks) is list, "missing SPDX SHA256 checksum")
        hashes = [c.get("checksumValue") for c in checks
                  if type(c) is dict and c.get("algorithm") == "SHA256"]
        require(len(hashes) == 1 and type(hashes[0]) is str
                and DIGEST.fullmatch(hashes[0].lower()) is not None
                and hashes[0].lower() == zip_hash,
                "SPDX source package digest differs from actual ZIP bytes")
        risk = read_json(grype_path)
        try:
            verdict = policy.review(risk, asset_stem=stem)
        except policy.Denied as exc:
            raise Denied("missing, filtered or forged Grype report: " + str(exc)) from exc
        require(verdict["status"] == "NO_BLOCKING_FINDINGS"
                and type(verdict["blockingFindingCount"]) is int
                and verdict["blockingFindingCount"] == 0
                and verdict["publicationAuthorized"] is False,
                "Critical/High/Unknown Grype findings: no formal Release")
        require(sha256(zip_path) == zip_hash,
                "Windows ZIP changed while inspecting vulnerability evidence")
        report[str(major)] = {"zipSha256": zip_hash,
                              "spdxSha256": sha256(spdx_path),
                              "grypeSha256": sha256(grype_path),
                              "blockingFindingCount": 0}
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--lifecycle", required=True)
    parser.add_argument("--dist", required=True)
    a = parser.parse_args()
    try:
        result = verify(Path(a.dist), read_json(Path(a.manifest)),
                        read_json(Path(a.lifecycle)))
        print("GRYPE_GUARD_PASSED_NONPUBLISHING " + json.dumps(result, sort_keys=True))
        return 0
    except (Denied, OSError, ValueError, KeyError, TypeError, BadZipFile) as exc:
        print("FORMAL_RELEASE_GRYPE_DENY " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
