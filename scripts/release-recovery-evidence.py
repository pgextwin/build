#!/usr/bin/env python3
"""Issue #75 PRE-G4: inert, read-only recovery evidence classifier.

This module is deliberately NOT called by the fleet publisher. It performs no
I/O and never authorizes retry, tag mutation, draft edit, deletion or publish.
Actual publisher persistence and recovery writes require a separate G4 GO.
"""
import re

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Exact Wave3 scope only; this is a read-only classifier, never a Publisher.
WAVE3_REPOS = frozenset((
    "pgextwin/pgtap", "pgextwin/pg_variables",
    "pgextwin/pg_store_plans",
))
TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
STAGES = frozenset({
    "TAG_RESERVED", "DRAFT_STAGED", "DRAFT_VERIFIED",
    "PUBLISHED_AUDIT_PENDING", "PUBLISHED_VERIFIED",
})


def _result(consistent, reason):
    return {
        "classification": "CONSISTENT_READ_ONLY" if consistent else "UNKNOWN_QUARANTINE",
        "reason": reason,
        "publicationAuthorized": False,
        "retryAuthorized": False,
        "mutationAuthorized": False,
        "permittedActions": ["MANUAL_READ_ONLY_TRIAGE"],
    }


def _valid_record(record):
    if type(record) is not dict or type(record.get("schemaVersion")) is not int:
        return False
    # Current deployed schemaVersion=1 lacks sufficient identity fields; deny.
    if (record["schemaVersion"] != 2 or type(record.get("state")) is not str
            or record["state"] not in STAGES):
        return False
    tag, commit = record.get("tag"), record.get("commit")
    # A stage name, tag and runId alone cannot bind a crash/replay to the
    # exact original nonpublishing prewrite attempt. These fields mirror the
    # existing local seal's immutable (requestId, repository, runId, attempt).
    # Remote run/attempt authenticity is STILL NOT independently proven here.
    request_id = record.get("requestId")
    attempt = record.get("attempt")
    repo = record.get("repository")
    if (type(tag) is not str or not TAG.fullmatch(tag)
            or type(commit) is not str or not SHA40.fullmatch(commit)
            or type(repo) is not str or repo not in WAVE3_REPOS
            or type(request_id) is not str or not SHA256.fullmatch(request_id)
            or type(attempt) is not int or not 1 <= attempt <= 1000
            or type(record.get("runId")) is not int or record["runId"] <= 0):
        return False
    reservation = record.get("reservation")
    if (type(reservation) is not dict
            or type(reservation.get("httpStatus")) is not int
            or reservation["httpStatus"] != 201
            or reservation.get("outcome") != "CREATED"
            or reservation.get("ref") != "refs/tags/" + tag
            or reservation.get("objectSha") != commit):
        return False
    inventory = record.get("assetInventory")
    if (type(inventory) is not dict or not inventory
            or any(type(name) is not str or not name or "/" in name
                   or type(sha) is not str or not SHA256.fullmatch(sha)
                   for name, sha in inventory.items())):
        return False
    release_id = record.get("releaseId")
    if record["state"] == "TAG_RESERVED":
        return release_id is None
    return type(release_id) is int and release_id > 0


def _valid_snapshot(record, snapshot):
    if (type(snapshot) is not dict or snapshot.get("complete") is not True
            or type(snapshot.get("httpStatus")) is not int
            or snapshot["httpStatus"] != 200):
        return False
    tag_ref = snapshot.get("tagRef")
    if (type(tag_ref) is not dict
            or tag_ref.get("ref") != "refs/tags/" + record["tag"]
            or tag_ref.get("objectSha") != record["commit"]):
        return False
    release = snapshot.get("release")
    if record["state"] == "TAG_RESERVED":
        # An unexpectedly present partial Draft is UNKNOWN, never free for reuse.
        return release is None
    if (type(release) is not dict
            or type(release.get("id")) is not int
            or release["id"] != record["releaseId"]
            or release.get("tag_name") != record["tag"]
            or release.get("target_commitish") != record["commit"]):
        return False
    expected_draft = record["state"] in {"DRAFT_STAGED", "DRAFT_VERIFIED"}
    if release.get("draft") is not expected_draft:
        return False
    assets = release.get("assets")
    if type(assets) is not list or len(assets) != len(record["assetInventory"]):
        return False
    names, ids = set(), set()
    for asset in assets:
        if (type(asset) is not dict or type(asset.get("id")) is not int
                or asset["id"] <= 0 or type(asset.get("name")) is not str
                or asset.get("state") != "uploaded"):
            return False
        name = asset["name"]
        if name in names or asset["id"] in ids:
            return False
        names.add(name)
        ids.add(asset["id"])
        sha = record["assetInventory"].get(name)
        if sha is None or asset.get("digest") != "sha256:" + sha:
            return False
    return names == set(record["assetInventory"])


def classify_recovery_evidence(record, snapshots):
    """Classify two supplied *read-only* snapshots; NEVER grant a write.

    Caller must obtain separate authenticated, complete GET observations and
    archive raw responses. This pure function cannot attest their origin.
    Missing/forged original requestId, Wave3 repository, runId or run attempt,
    a lost POST response, 422, 429, timeout, partial Draft, lost recovery write,
    missing Release ID, inconsistent ref/assets or replay is UNKNOWN/quarantined.
    Two caller-supplied snapshots do NOT authenticate GitHub or permit writes.
    """
    if not _valid_record(record):
        return _result(False, "missing or invalid persisted immutable evidence")
    if (type(snapshots) is not list or len(snapshots) != 2
            or snapshots[0] is snapshots[1]):
        return _result(False, "two separately captured read-only observations required")
    if snapshots[0] != snapshots[1]:
        return _result(False, "remote state changed or observations disagree")
    if not all(_valid_snapshot(record, snapshot) for snapshot in snapshots):
        return _result(False, "remote tag/Release ID/assets incomplete or inconsistent")
    return _result(True, "consistent observations only; manual triage, no resume")
