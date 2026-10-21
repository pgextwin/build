#!/usr/bin/env python3
"""Issue #75: fail-closed, nonpublishing durable-store configuration preflight.

A filesystem path or successful fsync does NOT prove that the storage survives
host destruction, remount, or a separate principal's recovery. This module
performs NO writes, no credential access and no GitHub operations.
"""
import json
import os
import stat
import sys

DENY = {
    "classification": "NOT_PROVEN",
    "publicationAuthorized": False,
    "mutationAuthorized": False,
    "retryAuthorized": False,
    "goB": "NO_GO",
    "g4": "NO_GO",
    "g5": "NO_GO",
}

def inspect_mount(path):
    result = dict(DENY)
    result["reason"] = "external durability and custody evidence unavailable"
    if not isinstance(path, str) or not os.path.isabs(path):
        result["reason"] = "absolute private mount path required"
        return result
    if os.path.normpath(path) != path or os.path.realpath(path) != path:
        result["reason"] = "noncanonical path or symlink denied"
        return result
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace and os.path.isabs(workspace):
        root = os.path.realpath(workspace)
        if os.path.commonpath((root, path)) == root:
            result["reason"] = "GitHub workspace is not a durable store"
            return result
    if path.startswith(("/tmp/", "/var/tmp/", "/run/", "/dev/shm/")) or path in (
        "/tmp", "/var/tmp", "/run", "/dev/shm"
    ):
        result["reason"] = "ephemeral path denied"
        return result
    try:
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700:
            result["reason"] = "owner-only directory required"
            return result
        if st.st_uid != os.geteuid():
            result["reason"] = "directory owner mismatch"
            return result
    except (OSError, ValueError):
        result["reason"] = "directory unavailable"
        return result
    result["classification"] = "LOCAL_CUSTODY_ONLY_NOT_DURABILITY_PROOF"
    result["reason"] = "local directory custody checked; independent crash/restart and remote write authorization absent"
    return result

def main():
    path = sys.argv[1] if len(sys.argv) == 2 else ""
    print(json.dumps(inspect_mount(path), sort_keys=True))
    return 0 if len(sys.argv) == 2 else 2

if __name__ == "__main__":
    raise SystemExit(main())
