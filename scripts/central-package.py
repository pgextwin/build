#!/usr/bin/env python3
"""Common build / packaging / K2 / K4 verification foundation for the
central monorepo (F21-04).

Provides the shared side of:
  * upstream pinned-SHA comparison (the declared commit in
    ``extensions/<name>/extension.json`` is the only source of truth),
  * deterministic ZIP packaging and SHA-256 generation,
  * the K2 byte-integrity handoff chain T0 -> T1 -> T2 -> T3 (the same
    ZIP bytes must be presented at every stage; any byte change breaks
    the recorded SHA-256 / size and is rejected),
  * the K4 per-version license original comparison, with the same entry
    semantics as ``scripts/verify-license-bytes.py`` (upstream-origin
    entries must match the upstream bytes at the pinned commit,
    packaging / build entries must match their pinned SHA-256, and at
    least one upstream-verified entry is required).

Actual pilot execution of these foundations is F2-2; this module is the
shared foundation plus its positive / negative tests.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}\Z")
SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")
GENERATED_SOURCES = ("upstream", "buildOutput")
STAGES = ("T0", "T1", "T2", "T3")
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def sha256_bytes(content):
    return hashlib.sha256(content).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pinned_commit(declared_commit, actual_commit):
    """Reject when the fetched upstream HEAD differs from the declaration."""
    if not isinstance(declared_commit, str) or not SHA40_RE.fullmatch(declared_commit):
        raise ValueError(f"Declared upstream commit is not a full SHA: {declared_commit!r}")
    if not isinstance(actual_commit, str) or not SHA40_RE.fullmatch(actual_commit):
        raise ValueError(f"Actual upstream commit is not a full SHA: {actual_commit!r}")
    if declared_commit.lower() != actual_commit.lower():
        raise ValueError(
            f"Upstream commit mismatch: declared {declared_commit} but fetched {actual_commit}."
        )


def write_deterministic_zip(entries, out_path):
    """Write a byte-reproducible ZIP from {arcname: bytes} and describe it."""
    if not entries:
        raise ValueError("Cannot package an empty entry set.")
    out_path = Path(out_path)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for arcname in sorted(entries):
            if arcname.startswith("/") or ".." in arcname.split("/"):
                raise ValueError(f"Invalid ZIP entry name: {arcname!r}")
            info = zipfile.ZipInfo(arcname, date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, entries[arcname])
    return {
        "fileName": out_path.name,
        "size": out_path.stat().st_size,
        "sha256": sha256_file(out_path),
    }


def read_zip_entries(zip_path):
    with zipfile.ZipFile(zip_path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def handoff_record(stage, extension, pg_major, zip_path, previous=None):
    """Record one K2 handoff point (T0..T3) for a packaged ZIP."""
    if stage not in STAGES:
        raise ValueError(f"Unknown handoff stage: {stage!r}")
    zip_path = Path(zip_path)
    record = {
        "schemaVersion": 1,
        "stage": stage,
        "extension": extension,
        "pgMajor": int(pg_major),
        "fileName": zip_path.name,
        "size": zip_path.stat().st_size,
        "sha256": sha256_file(zip_path),
        "previousStage": previous["stage"] if previous else None,
        "previousSha256": previous["sha256"] if previous else None,
    }
    return record


def verify_handoff_chain(records):
    """Verify a complete T0 -> T1 -> T2 -> T3 chain for one ZIP.

    Every stage must present the identical bytes (same SHA-256 and size)
    for the same extension / PostgreSQL major / file name, linked in
    order. Any byte tampering between stages changes the digest and is
    rejected here (K2).
    """
    if len(records) != len(STAGES):
        raise ValueError(
            f"Handoff chain must contain exactly {len(STAGES)} records, got {len(records)}."
        )
    first = records[0]
    for index, (record, stage) in enumerate(zip(records, STAGES)):
        if record.get("stage") != stage:
            raise ValueError(
                f"Handoff record {index} must be stage {stage}, got {record.get('stage')!r}."
            )
        for key in ("extension", "pgMajor", "fileName", "size", "sha256"):
            if record.get(key) != first.get(key):
                raise ValueError(
                    f"Handoff {stage} differs from T0 on '{key}': "
                    f"{record.get(key)!r} != {first.get(key)!r} (K2 byte integrity)."
                )
        expected_previous = records[index - 1] if index else None
        if record.get("previousStage") != (expected_previous["stage"] if expected_previous else None):
            raise ValueError(f"Handoff {stage} previousStage linkage is broken.")
        if record.get("previousSha256") != (expected_previous["sha256"] if expected_previous else None):
            raise ValueError(f"Handoff {stage} previousSha256 linkage is broken.")


def _validate_relative_path(path, label):
    if not isinstance(path, str) or not path or "\\" in path or path.startswith("/"):
        raise ValueError(f"Invalid {label} '{path}'.")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError(f"Invalid {label} '{path}'.")


def verify_license_entries(entries, upstream, packaging):
    """Verify license entries against upstream / packaging byte sources.

    ``upstream`` maps upstream paths to the bytes at the pinned commit;
    ``packaging`` maps repository paths to the packaging-side bytes.
    Entry semantics mirror scripts/verify-license-bytes.py. Returns the
    verified list (path, size, sha256 per entry).
    """
    if not isinstance(entries, list) or not entries:
        raise ValueError("License verification requires at least one license entry.")
    verified = []
    upstream_count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each license entry must be a JSON object.")
        origin = entry.get("origin")
        repository_path = entry.get("repositoryPath")
        _validate_relative_path(repository_path, "repositoryPath")

        if origin is None:
            unknown = set(entry) - {"repositoryPath", "upstreamPath", "upstreamStartMarker"}
            if unknown:
                raise ValueError(f"Unsupported license entry fields: {', '.join(sorted(unknown))}")
            upstream_path = entry.get("upstreamPath")
            _validate_relative_path(upstream_path, "upstreamPath")
            if upstream_path not in upstream:
                raise ValueError(f"Upstream license file not found at pinned commit: {upstream_path}")
            upstream_blob = upstream[upstream_path]
            expected = upstream_blob
            if "upstreamStartMarker" in entry:
                marker = entry["upstreamStartMarker"]
                if not isinstance(marker, str) or not marker:
                    raise ValueError("Expected a nonempty upstream license start marker.")
                offset = upstream_blob.find(marker.encode("utf-8"))
                if offset < 0:
                    raise ValueError(f"License range start not found in upstream '{upstream_path}'.")
                expected = upstream_blob[offset:]
            if repository_path not in packaging:
                raise ValueError(f"Packaging license file not found: {repository_path}")
            actual = packaging[repository_path]
            if actual != expected:
                raise ValueError(
                    f"License file '{repository_path}' differs from upstream "
                    f"'{upstream_path}' at the pinned commit (K4)."
                )
            verified.append({
                "repositoryPath": repository_path,
                "upstreamPath": upstream_path,
                "size": len(expected),
                "sha256": sha256_bytes(expected),
            })
            upstream_count += 1
        elif origin in ("packaging", "build"):
            expected_keys = (
                {"origin", "repositoryPath", "sha256"}
                if origin == "packaging"
                else {"origin", "repositoryPath", "generatedSource", "generatedPath", "sha256"}
            )
            if set(entry) != expected_keys:
                raise ValueError(f"Invalid fields for {origin} license entry '{repository_path}'.")
            expected_sha256 = entry["sha256"]
            if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
                raise ValueError(f"Invalid pinned license sha256 for '{repository_path}'.")
            if origin == "build":
                if entry["generatedSource"] not in GENERATED_SOURCES:
                    raise ValueError(f"Invalid generatedSource for build license '{repository_path}'.")
                _validate_relative_path(entry["generatedPath"], "generatedPath")
            if repository_path not in packaging:
                raise ValueError(f"Packaging license file not found: {repository_path}")
            actual = packaging[repository_path]
            digest = sha256_bytes(actual)
            if digest != expected_sha256:
                raise ValueError(
                    f"Packaging license file '{repository_path}' sha256 '{digest}' "
                    f"does not match pinned '{expected_sha256}' (K4)."
                )
            verified.append({
                "origin": origin,
                "repositoryPath": repository_path,
                "size": len(actual),
                "sha256": digest,
            })
        else:
            raise ValueError(f"Unsupported license origin: {origin!r}")

    if upstream_count < 1:
        raise ValueError(
            "License verification requires at least one upstream-verified license file (K4)."
        )
    return verified


def license_entries_for_major(license_block, pg_major):
    """Resolve the declaration license block to the entry list for a major."""
    if not isinstance(license_block, dict):
        raise ValueError("license must be an object.")
    if "perPostgresql" in license_block:
        per_major = license_block["perPostgresql"]
        key = str(pg_major)
        if key not in per_major:
            raise ValueError(f"No license entries declared for PostgreSQL {pg_major}.")
        return per_major[key]
    if "files" in license_block:
        return license_block["files"]
    if "upstreamPath" in license_block:
        upstream_path = license_block["upstreamPath"]
        return [{"repositoryPath": upstream_path, "upstreamPath": upstream_path}]
    raise ValueError("license block declares no upstreamPath, files, or perPostgresql form.")


def verify_declaration_licenses(license_block, pg_major, upstream, packaging):
    """K4 check of a declaration license block for one PostgreSQL major."""
    entries = license_entries_for_major(license_block, pg_major)
    return verify_license_entries(entries, upstream, packaging)


def _read_tree(root):
    root = Path(root)
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result[path.relative_to(root).as_posix()] = path.read_bytes()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    pin = sub.add_parser("pin", help="compare a declared commit with the fetched HEAD")
    pin.add_argument("--declared", required=True)
    pin.add_argument("--actual", required=True)

    digest = sub.add_parser("sha256", help="print the SHA-256 of a file")
    digest.add_argument("path", type=Path)

    licenses = sub.add_parser("verify-licenses", help="K4 check from two directory trees")
    licenses.add_argument("--license-json", type=Path, required=True,
                          help="JSON file holding the declaration license block")
    licenses.add_argument("--major", type=int, required=True)
    licenses.add_argument("--upstream-dir", type=Path, required=True)
    licenses.add_argument("--packaging-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "pin":
            verify_pinned_commit(args.declared, args.actual)
            print("PINNED_COMMIT_MATCH")
        elif args.command == "sha256":
            print(sha256_file(args.path))
        elif args.command == "verify-licenses":
            license_block = json.loads(args.license_json.read_text(encoding="utf-8"))
            verified = verify_declaration_licenses(
                license_block, args.major,
                _read_tree(args.upstream_dir), _read_tree(args.packaging_dir),
            )
            print(json.dumps({"verified": verified}, indent=2))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
