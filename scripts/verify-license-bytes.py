#!/usr/bin/env python3
"""Verify and stage the license blobs from the two checked-out commits."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from tempfile import TemporaryDirectory


SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")
GENERATED_SOURCES = ("upstream", "buildOutput")


def validate_relative_path(path, label):
    if not isinstance(path, str) or not path or "\\" in path or path.startswith("/"):
        raise ValueError(f"Invalid {label} '{path}'.")
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError(f"Invalid {label} '{path}'.")


def read_blob(repo, path, source):
    result = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "blob", f"HEAD:{path}"],
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(f"Configured {source} license file was not found: {path}")
    return result.stdout


def output_path(root, path):
    target = root / path
    parent = target.parent.resolve()
    if not parent.is_relative_to(root):
        raise ValueError(f"Cannot write license file '{path}' outside '{root}'.")
    return parent / target.name


def write_bytes(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=path.parent) as directory:
        temporary_path = Path(directory) / "license"
        temporary_path.write_bytes(content)
        temporary_path.replace(path)


def verify_and_stage(args):
    license_files = json.loads(args.license_files.read_bytes())
    if not isinstance(license_files, list):
        raise ValueError("Expected a JSON array of license files.")

    upstream_dir = args.upstream_dir.resolve()
    packaging_dir = args.packaging_dir.resolve()
    stage_dir = args.stage_dir.resolve()
    staged_files = {}
    worktree_files = {}
    source_files = {}
    verified = []
    upstream_commit = None
    packaging_commit = None
    if args.verified_list:
        upstream_commit = subprocess.check_output(
            ["git", "-C", str(upstream_dir), "rev-parse", "HEAD"], text=True,
        ).strip()
        packaging_commit = subprocess.check_output(
            ["git", "-C", str(packaging_dir), "rev-parse", "HEAD"], text=True,
        ).strip()

    upstream_count = 0
    non_upstream_staged = set()
    seen_generated = set()

    for entry in license_files:
        if not isinstance(entry, dict):
            raise ValueError("Each license entry must be a JSON object.")
        origin = entry.get("origin")
        repository_path = entry["repositoryPath"]
        validate_relative_path(repository_path, "repositoryPath")

        if origin is None:
            unknown = set(entry) - {"repositoryPath", "upstreamPath", "upstreamStartMarker"}
            if unknown:
                raise ValueError(f"Unsupported license entry fields: {', '.join(sorted(unknown))}")
            upstream_path = entry["upstreamPath"]
            validate_relative_path(upstream_path, "upstreamPath")
            upstream_blob = read_blob(upstream_dir, upstream_path, "upstream")
            upstream = upstream_blob
            provenance = {}
            if "upstreamStartMarker" in entry:
                marker = entry["upstreamStartMarker"]
                if not isinstance(marker, str) or not marker:
                    raise ValueError("Expected a nonempty upstream license start marker.")
                offset = upstream_blob.find(marker.encode("utf-8"))
                if offset < 0:
                    raise ValueError(f"License range start not found in upstream '{upstream_path}'.")
                upstream = upstream_blob[offset:]
                provenance = {
                    "upstreamOffset": offset,
                    "upstreamSize": len(upstream_blob),
                    "upstreamSha256": hashlib.sha256(upstream_blob).hexdigest(),
                }
                if args.source_stage_dir:
                    source_path = output_path(args.source_stage_dir.resolve(), upstream_path)
                    source_files[source_path] = upstream_blob
            packaging = read_blob(packaging_dir, repository_path, "packaging-repository")
            digest = hashlib.sha256(upstream).hexdigest()
            if digest != hashlib.sha256(packaging).hexdigest() or upstream != packaging:
                raise ValueError(f"License file '{repository_path}' differs from upstream '{upstream_path}'.")

            staged_path = output_path(stage_dir, repository_path)
            if staged_path in non_upstream_staged:
                raise ValueError(f"Duplicate license staging path '{repository_path}'.")
            if staged_path in staged_files and staged_files[staged_path][0] != upstream:
                raise ValueError(f"Conflicting upstream bytes for license file '{repository_path}'.")
            staged_files.setdefault(staged_path, (upstream, digest, repository_path))
            verified.append({
                "upstreamPath": upstream_path,
                "repositoryPath": repository_path,
                "size": len(upstream),
                "sha256": digest,
                **provenance,
            })
            upstream_count += 1

            if args.restore_worktrees:
                worktree_files[output_path(upstream_dir, upstream_path)] = upstream_blob
                worktree_files[output_path(packaging_dir, repository_path)] = packaging
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

            extra = {}
            if origin == "build":
                generated_source = entry["generatedSource"]
                generated_path = entry["generatedPath"]
                if not isinstance(generated_source, str) or generated_source not in GENERATED_SOURCES:
                    raise ValueError(f"Invalid generatedSource for build license '{repository_path}'.")
                validate_relative_path(generated_path, "generatedPath")
                generated_key = (generated_source, generated_path.casefold())
                if generated_key in seen_generated:
                    raise ValueError(f"Duplicate build license target '{generated_source}:{generated_path}'.")
                seen_generated.add(generated_key)
                extra = {"generatedSource": generated_source, "generatedPath": generated_path}

            packaging = read_blob(packaging_dir, repository_path, "packaging-repository")
            digest = hashlib.sha256(packaging).hexdigest()
            if digest != expected_sha256:
                raise ValueError(
                    f"Packaging license file '{repository_path}' sha256 '{digest}' does not match pinned '{expected_sha256}'."
                )

            staged_path = output_path(stage_dir, repository_path)
            if staged_path in staged_files:
                raise ValueError(f"Duplicate license staging path '{repository_path}'.")
            staged_files[staged_path] = (packaging, digest, repository_path)
            non_upstream_staged.add(staged_path)
            verified.append({
                "origin": origin,
                "repositoryPath": repository_path,
                "size": len(packaging),
                "sha256": digest,
                **extra,
            })

            if args.restore_worktrees:
                worktree_files[output_path(packaging_dir, repository_path)] = packaging
        else:
            raise ValueError(f"Unsupported license origin: {origin!r}")

    if not license_files or upstream_count < 1:
        raise ValueError("License verification requires at least one upstream-verified license file.")

    # Check every pair before writing bytes for the packaging hooks.
    for path, (content, digest, repository_path) in staged_files.items():
        write_bytes(path, content)
        print(f"{digest}  {repository_path}")
    for path, content in source_files.items():
        write_bytes(path, content)
    for path, content in worktree_files.items():
        write_bytes(path, content)
    if args.verified_list:
        document = {
            "schemaVersion": 1,
            "upstreamCommit": upstream_commit,
            "packagingCommit": packaging_commit,
            "licenses": verified,
        }
        write_bytes(args.verified_list, (json.dumps(document, indent=2) + "\n").encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--license-files", type=Path, required=True)
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument("--packaging-dir", type=Path, required=True)
    parser.add_argument("--stage-dir", type=Path, required=True)
    parser.add_argument("--source-stage-dir", type=Path, help="stage whole source blobs for verified license ranges")
    parser.add_argument("--verified-list", type=Path, help="record the verified upstream blob identities")
    parser.add_argument(
        "--restore-worktrees", action="store_true",
        help="write verified bytes to the configured paths used by existing hooks",
    )
    args = parser.parse_args()
    try:
        verify_and_stage(args)
    except (KeyError, OSError, TypeError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
