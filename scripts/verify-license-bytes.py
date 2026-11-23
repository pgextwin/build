#!/usr/bin/env python3
"""Verify and stage the license blobs from the two checked-out commits."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory


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
    verified = []
    upstream_commit = None
    if args.verified_list:
        upstream_commit = subprocess.check_output(
            ["git", "-C", str(upstream_dir), "rev-parse", "HEAD"], text=True,
        ).strip()

    for entry in license_files:
        repository_path = entry["repositoryPath"]
        upstream_path = entry["upstreamPath"]
        upstream = read_blob(upstream_dir, upstream_path, "upstream")
        packaging = read_blob(packaging_dir, repository_path, "packaging-repository")
        digest = hashlib.sha256(upstream).hexdigest()
        if digest != hashlib.sha256(packaging).hexdigest() or upstream != packaging:
            raise ValueError(f"License file '{repository_path}' differs from upstream '{upstream_path}'.")

        staged_path = output_path(stage_dir, repository_path)
        if staged_path in staged_files and staged_files[staged_path][0] != upstream:
            raise ValueError(f"Conflicting upstream bytes for license file '{repository_path}'.")
        staged_files.setdefault(staged_path, (upstream, digest, repository_path))
        verified.append({
            "upstreamPath": upstream_path,
            "repositoryPath": repository_path,
            "size": len(upstream),
            "sha256": digest,
        })

        if args.restore_worktrees:
            worktree_files[output_path(upstream_dir, upstream_path)] = upstream
            worktree_files[output_path(packaging_dir, repository_path)] = packaging

    # Check every pair before writing bytes for the packaging hooks.
    for path, (content, digest, repository_path) in staged_files.items():
        write_bytes(path, content)
        print(f"{digest}  {repository_path}")
    for path, content in worktree_files.items():
        write_bytes(path, content)
    if args.verified_list:
        document = {"schemaVersion": 1, "upstreamCommit": upstream_commit, "licenses": verified}
        write_bytes(args.verified_list, (json.dumps(document, indent=2) + "\n").encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--license-files", type=Path, required=True)
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument("--packaging-dir", type=Path, required=True)
    parser.add_argument("--stage-dir", type=Path, required=True)
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
