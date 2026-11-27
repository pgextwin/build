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
    packaging / build entries must match their pinned SHA-256, duplicate
    repository paths / build targets are rejected, and at least one
    upstream-verified entry is required),
  * the adapter execution-context boundary: ``build_adapter_environment``
    builds the only environment the common foundation may pass to
    extension-specific adapter / test code, and it never carries signing,
    Publisher, or local-auth credentials (CB70-12).

The ``verify-licenses`` CLI reads the fixed Git commit blobs
(``git cat-file blob HEAD:<path>``) from the upstream / packaging
repositories, exactly like ``verify-license-bytes.py``, so untracked or
modified worktree files and symbolic links cannot leak into the K4
comparison.

Actual pilot execution of these foundations is F2-2; this module is the
shared foundation plus its positive / negative tests.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
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
            # Same relative-path contract as license paths: backslash
            # separators (Windows Zip Slip), empty / "." / ".." segments
            # and absolute names are all rejected.
            _validate_relative_path(arcname, "ZIP entry name")
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
    index = STAGES.index(stage)
    if index == 0 and previous is not None:
        raise ValueError("The T0 handoff record must not have a previous record.")
    if index > 0:
        if previous is None:
            raise ValueError(
                f"The {stage} handoff record requires the {STAGES[index - 1]} record as previous."
            )
        if not isinstance(previous, dict) or previous.get("stage") != STAGES[index - 1]:
            raise ValueError(
                f"The {stage} handoff record's previous record must be stage {STAGES[index - 1]}."
            )
    if not isinstance(extension, str) or not extension:
        raise ValueError("Handoff record requires a nonempty extension name.")
    if isinstance(pg_major, bool) or not isinstance(pg_major, int) or pg_major < 1:
        raise ValueError("Handoff record requires a positive integer PostgreSQL major.")
    zip_path = Path(zip_path)
    size = zip_path.stat().st_size
    if size <= 0:
        raise ValueError("Handoff record requires a nonempty packaged ZIP.")
    record = {
        "schemaVersion": 1,
        "stage": stage,
        "extension": extension,
        "pgMajor": pg_major,
        "fileName": zip_path.name,
        "size": size,
        "sha256": sha256_file(zip_path),
        "previousStage": previous["stage"] if previous else None,
        "previousSha256": previous["sha256"] if previous else None,
    }
    return record


def _validate_handoff_record(record, stage):
    """Fail-closed shape validation for one handoff record (K2).

    A chain of well-linked but empty or malformed records (empty digest,
    zero size, wrong schema version) must never verify: every field the
    chain comparison relies on is type- and format-checked first.
    """
    if not isinstance(record, dict):
        raise ValueError(f"Handoff {stage} record is not a JSON object.")
    if record.get("stage") != stage:
        raise ValueError(
            f"Handoff record must be stage {stage}, got {record.get('stage')!r}."
        )
    schema_version = record.get("schemaVersion")
    if isinstance(schema_version, bool) or schema_version != 1:
        raise ValueError(f"Handoff {stage} schemaVersion must be 1, got {schema_version!r}.")
    for key in ("extension", "fileName"):
        value = record.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Handoff {stage} '{key}' must be a nonempty string.")
    pg_major = record.get("pgMajor")
    if isinstance(pg_major, bool) or not isinstance(pg_major, int) or pg_major < 1:
        raise ValueError(f"Handoff {stage} 'pgMajor' must be a positive integer.")
    size = record.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValueError(f"Handoff {stage} 'size' must be a positive integer.")
    digest = record.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ValueError(f"Handoff {stage} 'sha256' must be a 64-digit lowercase hex digest.")


def verify_handoff_chain(records, expected_sha256=None, expected_size=None):
    """Verify a complete T0 -> T1 -> T2 -> T3 chain for one ZIP.

    Every stage must present the identical bytes (same SHA-256 and size)
    for the same extension / PostgreSQL major / file name, linked in
    order. Any byte tampering between stages changes the digest and is
    rejected here (K2). When ``expected_sha256`` / ``expected_size`` are
    given (the digest and size measured immediately before packaging),
    the T0 record must match them, so a chain that is internally
    consistent but starts from tampered bytes is also rejected.
    """
    if not isinstance(records, list) or len(records) != len(STAGES):
        got = len(records) if isinstance(records, list) else type(records).__name__
        raise ValueError(
            f"Handoff chain must contain exactly {len(STAGES)} records, got {got}."
        )
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256)
    ):
        raise ValueError("expected_sha256 must be a 64-digit lowercase hex digest.")
    if expected_size is not None and (
        isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size <= 0
    ):
        raise ValueError("expected_size must be a positive integer.")
    first = records[0]
    for index, (record, stage) in enumerate(zip(records, STAGES)):
        _validate_handoff_record(record, stage)
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
    if expected_sha256 is not None and first["sha256"] != expected_sha256:
        raise ValueError(
            f"Handoff T0 sha256 '{first['sha256']}' does not match the pre-packaging "
            f"baseline '{expected_sha256}' (K2 byte integrity)."
        )
    if expected_size is not None and first["size"] != expected_size:
        raise ValueError(
            f"Handoff T0 size {first['size']} does not match the pre-packaging "
            f"baseline {expected_size} (K2 byte integrity)."
        )


def _validate_relative_path(path, label):
    if not isinstance(path, str) or not path or "\\" in path or path.startswith("/"):
        raise ValueError(f"Invalid {label} '{path}'.")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError(f"Invalid {label} '{path}'.")


# Adapter execution-context boundary (DESIGN 1.3, CB70-12). The common
# foundation invokes extension-specific adapter.ps1 / tests scripts only
# with an environment built here: a strict allowlist of non-secret build
# variables. Signing OIDC request tokens, the Actions runtime token,
# GITHUB_TOKEN / GH_TOKEN, Publisher variables, local-auth credentials,
# and anything token / secret / key shaped are never passed, so adapter
# code cannot reach signing, Publisher, or authorization material
# through the process environment.
ADAPTER_ENV_ALLOWLIST = frozenset({
    "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR",
    "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "HOMEDRIVE",
    "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES",
    "PROGRAMFILES(X86)", "PROGRAMW6432", "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE", "OS", "LANG", "LC_ALL", "TZ",
})
ADAPTER_ENV_FORBIDDEN_PREFIXES = (
    "ACTIONS_ID_TOKEN_REQUEST", "ACTIONS_RUNTIME", "PUBLISHER_", "LOCAL_AUTH_",
)
ADAPTER_ENV_FORBIDDEN_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "_KEY")


def _adapter_env_key_forbidden(key):
    upper = key.upper()
    if upper.startswith(ADAPTER_ENV_FORBIDDEN_PREFIXES):
        return True
    return any(marker in upper for marker in ADAPTER_ENV_FORBIDDEN_MARKERS)


def build_adapter_environment(base_env, extra_allowed=None):
    """Build the credential-free environment for adapter execution.

    Only allowlisted non-secret variables are copied from ``base_env``.
    ``extra_allowed`` names additional variables the caller explicitly
    wants passed; a credential-shaped name is a hard error (fail-closed)
    instead of a silent drop, so a caller can never smuggle a signing or
    Publisher credential into the adapter context by naming it.
    """
    env = {}
    for key, value in base_env.items():
        if key.upper() in ADAPTER_ENV_ALLOWLIST and not _adapter_env_key_forbidden(key):
            env[key] = value
    for key in extra_allowed or ():
        if _adapter_env_key_forbidden(key):
            raise ValueError(
                f"Credential-bearing environment variable must not be passed "
                f"to adapter code: {key}"
            )
        if key not in base_env:
            raise ValueError(
                f"Extra adapter environment variable is absent from the base environment: {key}"
            )
        env[key] = base_env[key]
    return env


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
    # Duplicate tracking with the same semantics as
    # verify-license-bytes.py / resolve-matrix.ps1: repository paths are
    # compared case-insensitively (Windows paths collide), an upstream
    # entry and a packaging / build entry may never share one repository
    # path, two upstream entries for one repository path must carry
    # identical bytes, and one build target may be generated only once.
    seen_upstream = {}
    seen_non_upstream = set()
    seen_generated = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each license entry must be a JSON object.")
        origin = entry.get("origin")
        repository_path = entry.get("repositoryPath")
        _validate_relative_path(repository_path, "repositoryPath")
        repository_key = repository_path.casefold()

        if origin is None:
            unknown = set(entry) - {"repositoryPath", "upstreamPath", "upstreamStartMarker"}
            if unknown:
                raise ValueError(f"Unsupported license entry fields: {', '.join(sorted(unknown))}")
            if repository_key in seen_non_upstream:
                raise ValueError(f"Duplicate license repositoryPath '{repository_path}'.")
            upstream_path = entry.get("upstreamPath")
            _validate_relative_path(upstream_path, "upstreamPath")
            if upstream_path not in upstream:
                raise ValueError(f"Upstream license file not found at pinned commit: {upstream_path}")
            upstream_blob = upstream[upstream_path]
            expected = upstream_blob
            provenance = {}
            if "upstreamStartMarker" in entry:
                marker = entry["upstreamStartMarker"]
                if not isinstance(marker, str) or not marker:
                    raise ValueError("Expected a nonempty upstream license start marker.")
                offset = upstream_blob.find(marker.encode("utf-8"))
                if offset < 0:
                    raise ValueError(f"License range start not found in upstream '{upstream_path}'.")
                expected = upstream_blob[offset:]
                provenance = {
                    "upstreamOffset": offset,
                    "upstreamSize": len(upstream_blob),
                    "upstreamSha256": sha256_bytes(upstream_blob),
                }
            if repository_path not in packaging:
                raise ValueError(f"Packaging license file not found: {repository_path}")
            actual = packaging[repository_path]
            if actual != expected:
                raise ValueError(
                    f"License file '{repository_path}' differs from upstream "
                    f"'{upstream_path}' at the pinned commit (K4)."
                )
            if repository_key in seen_upstream and seen_upstream[repository_key] != expected:
                raise ValueError(
                    f"Conflicting upstream bytes for license file '{repository_path}'."
                )
            seen_upstream[repository_key] = expected
            verified.append({
                "repositoryPath": repository_path,
                "upstreamPath": upstream_path,
                "size": len(expected),
                "sha256": sha256_bytes(expected),
                **provenance,
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
            if repository_key in seen_upstream or repository_key in seen_non_upstream:
                raise ValueError(f"Duplicate license repositoryPath '{repository_path}'.")
            extra = {}
            if origin == "build":
                if entry["generatedSource"] not in GENERATED_SOURCES:
                    raise ValueError(f"Invalid generatedSource for build license '{repository_path}'.")
                _validate_relative_path(entry["generatedPath"], "generatedPath")
                generated_key = (entry["generatedSource"], entry["generatedPath"].casefold())
                if generated_key in seen_generated:
                    raise ValueError(
                        f"Duplicate build license target "
                        f"'{entry['generatedSource']}:{entry['generatedPath']}'."
                    )
                seen_generated.add(generated_key)
                extra = {
                    "generatedSource": entry["generatedSource"],
                    "generatedPath": entry["generatedPath"],
                }
            if repository_path not in packaging:
                raise ValueError(f"Packaging license file not found: {repository_path}")
            actual = packaging[repository_path]
            digest = sha256_bytes(actual)
            if digest != expected_sha256:
                raise ValueError(
                    f"Packaging license file '{repository_path}' sha256 '{digest}' "
                    f"does not match pinned '{expected_sha256}' (K4)."
                )
            seen_non_upstream.add(repository_key)
            verified.append({
                "origin": origin,
                "repositoryPath": repository_path,
                "size": len(actual),
                "sha256": digest,
                **extra,
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
    if license_block.get("verifyAgainstUpstream") is not True:
        raise ValueError(
            "Central license verification requires verifyAgainstUpstream to be true; "
            "the central form does not allow opting out of the upstream comparison (K4)."
        )
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
        # Canonical mapping of resolve-matrix.ps1: the single upstreamPath
        # form is always packaged under the fixed repository path
        # "LICENSE", whatever the upstream file itself is named (for
        # example pgtap's README.md / COPYRIGHT originals).
        return [{"repositoryPath": "LICENSE", "upstreamPath": upstream_path}]
    raise ValueError("license block declares no upstreamPath, files, or perPostgresql form.")


def verify_declaration_licenses(license_block, pg_major, upstream, packaging):
    """K4 check of a declaration license block for one PostgreSQL major."""
    entries = license_entries_for_major(license_block, pg_major)
    return verify_license_entries(entries, upstream, packaging)


def _git_head_commit(repo):
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    if result.returncode:
        raise ValueError(f"Not a git repository with a HEAD commit: {repo}")
    return result.stdout.strip()


def _git_blob(repo, path, source):
    """Read one file as the blob recorded at HEAD of ``repo``.

    Mirrors verify-license-bytes.py: the comparison input is the fixed
    commit's blob, never the worktree file, so untracked files, local
    modifications, CRLF conversion, and symbolic links cannot leak in.
    """
    listing = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "HEAD", "--", path],
        capture_output=True, text=True,
    )
    if listing.returncode or not listing.stdout.strip():
        raise ValueError(f"Configured {source} license file was not found at HEAD: {path}")
    mode = listing.stdout.split(None, 1)[0]
    if mode == "120000":
        raise ValueError(f"Configured {source} license file is a symbolic link at HEAD: {path}")
    result = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "blob", f"HEAD:{path}"],
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(f"Configured {source} license file was not found at HEAD: {path}")
    return result.stdout


def verify_declaration_licenses_from_git(license_block, pg_major, upstream_repo, packaging_repo):
    """K4 check reading both sides from the fixed HEAD commit blobs.

    Returns the verified list plus the two commit SHAs the comparison is
    bound to (the same record shape as the verify-license-bytes.py
    verified list).
    """
    entries = license_entries_for_major(license_block, pg_major)
    upstream_paths = {
        entry["upstreamPath"] for entry in entries
        if isinstance(entry, dict) and entry.get("origin") is None
    }
    packaging_paths = {
        entry["repositoryPath"] for entry in entries if isinstance(entry, dict)
    }
    upstream = {path: _git_blob(upstream_repo, path, "upstream") for path in sorted(upstream_paths)}
    packaging = {
        path: _git_blob(packaging_repo, path, "packaging-repository")
        for path in sorted(packaging_paths)
    }
    verified = verify_license_entries(entries, upstream, packaging)
    return {
        "schemaVersion": 1,
        "upstreamCommit": _git_head_commit(upstream_repo),
        "packagingCommit": _git_head_commit(packaging_repo),
        "verified": verified,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    pin = sub.add_parser("pin", help="compare a declared commit with the fetched HEAD")
    pin.add_argument("--declared", required=True)
    pin.add_argument("--actual", required=True)

    digest = sub.add_parser("sha256", help="print the SHA-256 of a file")
    digest.add_argument("path", type=Path)

    licenses = sub.add_parser(
        "verify-licenses", help="K4 check from the HEAD blobs of two git repositories"
    )
    licenses.add_argument("--license-json", type=Path, required=True,
                          help="JSON file holding the declaration license block")
    licenses.add_argument("--major", type=int, required=True)
    licenses.add_argument("--upstream-dir", type=Path, required=True,
                          help="upstream git repository (read at HEAD)")
    licenses.add_argument("--packaging-dir", type=Path, required=True,
                          help="packaging git repository (read at HEAD)")

    args = parser.parse_args(argv)
    try:
        if args.command == "pin":
            verify_pinned_commit(args.declared, args.actual)
            print("PINNED_COMMIT_MATCH")
        elif args.command == "sha256":
            print(sha256_file(args.path))
        elif args.command == "verify-licenses":
            license_block = json.loads(args.license_json.read_text(encoding="utf-8"))
            document = verify_declaration_licenses_from_git(
                license_block, args.major, args.upstream_dir, args.packaging_dir,
            )
            print(json.dumps(document, indent=2))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
