#!/usr/bin/env python3
"""Issue #75: isolated filesystem PREWRITE seal, not a Publisher journal.

Can create and re-read a single fsync-backed, create-only local record, on a
trusted owner-only POSIX directory. Never performs GitHub/network/token writes.
No runtime with durable private storage is deployed; this primitive alone does
not meet GO B/G4/G5, enable retry, or authorize Tag/Release mutations.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat

TARGETS = frozenset((
    "pgextwin/pgtap", "pgextwin/pg_variables", "pgextwin/pg_store_plans",
))
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z")
MAX_RECORD = 16384
FIELDS = frozenset((
    "schemaVersion", "requestId", "repository", "sourceSha",
    "signerWorkflowSha", "tag", "runId", "attempt", "assetHashes",
))

class Deny(ValueError):
    pass

def need(condition):
    if not condition:
        raise Deny("trusted nonpublishing prewrite seal incomplete")

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result

def validated(record):
    need(type(record) is dict and set(record) == FIELDS)
    need(type(record["schemaVersion"]) is int and record["schemaVersion"] == 1)
    need(type(record["requestId"]) is str and SHA256.fullmatch(record["requestId"]))
    need(type(record["repository"]) is str and record["repository"] in TARGETS)
    need(type(record["sourceSha"]) is str and SHA40.fullmatch(record["sourceSha"]))
    need(type(record["signerWorkflowSha"]) is str and
         SHA40.fullmatch(record["signerWorkflowSha"]))
    need(type(record["tag"]) is str and TAG.fullmatch(record["tag"]))
    need(type(record["runId"]) is int and record["runId"] > 0)
    need(type(record["attempt"]) is int and 1 <= record["attempt"] <= 1000)
    assets = record["assetHashes"]
    need(type(assets) is dict and 2 <= len(assets) <= 32)
    need(any(name.endswith(".zip") for name in assets))
    need(any(name.endswith(".spdx.json") for name in assets))
    for name, digest in assets.items():
        need(type(name) is str and ASSET.fullmatch(name) and
             type(digest) is str and SHA256.fullmatch(digest))
    raw = (json.dumps(record, sort_keys=True, separators=(",",":"),
                      ensure_ascii=True) + "\n").encode("ascii")
    need(len(raw) <= MAX_RECORD)
    return raw

def _directory(path):
    need(type(path) is str and os.path.isabs(path))
    # Reject a symlink at any ancestor, not only at the final component.
    need(os.path.realpath(path) == os.path.normpath(path))
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace and os.path.isabs(workspace):
        need(os.path.commonpath((os.path.realpath(path),
                                 os.path.realpath(workspace))) !=
             os.path.realpath(workspace))
    try:
        before = os.lstat(path)
        need(stat.S_ISDIR(before.st_mode) and
             stat.S_IMODE(before.st_mode) == 0o700 and
             before.st_uid == os.geteuid())
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        current = os.fstat(fd)
        need((current.st_dev, current.st_ino) ==
             (before.st_dev, before.st_ino))
        need(stat.S_ISDIR(current.st_mode) and
             stat.S_IMODE(current.st_mode) == 0o700 and
             current.st_uid == os.geteuid())
        return fd
    except Exception:
        try:
            os.close(fd)
        except (OSError, UnboundLocalError):
            pass
        raise Deny("private durable directory custody not proven") from None

def _name(request_id):
    need(type(request_id) is str and SHA256.fullmatch(request_id))
    return request_id + ".json"

def seal(path, record):
    """Create-once/fsync record. Uncertain writes remain quarantined.

    A successful return proves only local filesystem operations; caller must
    independently prove a truly durable trusted private filesystem. No action
    after this function is authorized by its return value.
    """
    raw = validated(record)
    directory = _directory(path)
    fd = None
    try:
        fd = os.open(_name(record["requestId"]),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            n = os.write(fd, raw[offset:])
            need(type(n) is int and n > 0)
            offset += n
        os.fsync(fd)
        os.fsync(directory)
    except Exception:
        # Never unlink a possibly partially persisted reservation. Another
        # attempt must see O_EXCL failure and treat it as UNKNOWN_QUARANTINE.
        raise Deny("prewrite seal missing/duplicate/uncertain: quarantine") from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)
    return {
        "classification": "LOCAL_CREATE_ONLY_SEAL_NOT_PUBLICATION_AUTHORITY",
        "requestId": record["requestId"],
        "recordSha256": hashlib.sha256(raw).hexdigest(),
        "publicationAuthorized": False, "mutationAuthorized": False,
        "retryAuthorized": False, "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
    }

def inspect(path, request_id):
    """Nonpublishing inspection: duplicate JSON/symlink/extra bytes deny."""
    directory = _directory(path)
    fd = None
    try:
        fd = os.open(_name(request_id),
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory)
        mode = os.fstat(fd)
        need(stat.S_ISREG(mode.st_mode) and stat.S_IMODE(mode.st_mode) == 0o600)
        need(mode.st_uid == os.geteuid() and mode.st_nlink == 1)
        raw = os.read(fd, MAX_RECORD + 1)
        need(0 < len(raw) <= MAX_RECORD and raw.endswith(b"\n"))
        record = json.loads(raw.decode("ascii"), object_pairs_hook=unique)
        need(validated(record) == raw and record["requestId"] == request_id)
        return {
            "classification": "LOCAL_READ_ONLY_SEAL_NO_REMOTE_VERIFICATION",
            "recordSha256": hashlib.sha256(raw).hexdigest(),
            "publicationAuthorized": False, "mutationAuthorized": False,
            "retryAuthorized": False, "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO",
        }
    except Exception:
        raise Deny("prewrite seal read untrusted: quarantine") from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)
