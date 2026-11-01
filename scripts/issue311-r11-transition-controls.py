#!/usr/bin/env python3
"""R11 legacy/new writer and schedule migration audit; no writes or cron changes.

This is a bounded, *read-only* crosswalk over the authenticated original R11
inventory. A transition candidate is never a verified deletion authorization.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

EXTENSIONS = (
    "pg_bigm", "pg_cron", "pg_hint_plan", "pgaudit", "set_user",
    "pg_repack", "pg_ivm", "pg_qualstats", "plpgsql_check", "orafce",
    "hypopg", "wal2json", "pg_partman", "pg_stat_monitor", "pgtap",
    "pg_variables", "pg_store_plans",
)
CENTRAL = ("build", "catalog", "website")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TRANSIENT = {429, 502, 503, 504}
REJECT = {401, 403, 404, 409, 422}

def need(condition, reason):
    if not condition:
        raise ValueError("R11_TRANSITION_DENY " + reason)

def unique(pairs):
    out = {}
    for k, v in pairs:
        need(k not in out, "duplicate JSON key")
        out[k] = v
    return out

def scope_for(path, repo):
    """Functional buckets are candidate classifications, never acceptance."""
    text = path.lower()
    if repo in EXTENSIONS:
        need(path == ".github/workflows/update-watch.yml",
             "unexpected extension scheduled workflow")
        return ["DETECT", "ISSUE", "CANDIDATE_PR", "NATIVE_CI",
                "SIGNATURE_REEVALUATION"]
    labels = []
    for token, name in (
        ("fleet", "FLEET_SCAN"), ("watch", "DETECT"),
        ("candidate", "CANDIDATE_PR"), ("recover", "FINITE_RECOVERY"),
        ("sign", "SIGNATURE_REEVALUATION"), ("publisher", "PUBLISH_GATE"),
        ("release", "RELEASE_GATE"), ("catalog", "CATALOG"),
        ("website", "WEBSITE"), ("postgresql", "POSTGRESQL_SCAN"),
    ):
        if token in text:
            labels.append(name)
    return labels or ["UNCLASSIFIED_HOLD"]

def writer_resource(repo, kind, namespace, sha):
    """Exact repository + mutable API resource, not a concurrency-group guess."""
    need(type(repo) is str and repo.startswith("pgextwin/") and
         repo.split("/")[1] in EXTENSIONS + CENTRAL, "unregistered repo")
    need(kind in {"issues", "pulls", "actions", "contents", "releases"},
         "unknown writer resource class")
    need(type(namespace) is str and re.fullmatch(r"[A-Za-z0-9_./-]{1,160}", namespace)
         and ".." not in namespace and not namespace.startswith("/"),
         "unscoped writer namespace")
    need(type(sha) is str and SHA40.fullmatch(sha), "unbound writer code")
    return {"repository":repo, "kind":kind, "namespace":namespace, "codeSha":sha}

def classify_writer_pair(legacy, new):
    for obj in (legacy, new):
        need(type(obj) is dict and set(obj) ==
             {"repository", "kind", "namespace", "codeSha"}, "unbound resource record")
        need(writer_resource(**dict(repo=obj["repository"],kind=obj["kind"],
                                   namespace=obj["namespace"],sha=obj["codeSha"])),
             "invalid writer resource")
    a = (legacy["repository"], legacy["kind"], legacy["namespace"])
    b = (new["repository"], new["kind"], new["namespace"])
    return "SHARED_FENCE_REQUIRED" if a == b else "DISJOINT_EXACT_RESOURCE"

def fenced_writer_preflight(legacy, successor, persisted, attempt, now):
    """Pure shared-resource fence check before ANY GitHub API write.

    Caller must independently authenticate the persisted state, its Git blob
    identity, the actual Writer, and the expected HEAD. Passing this check
    never authorizes PUT, attests a live HTTP 409, or replaces GitHub CAS.
    Legacy writers must also invoke the same fence; merely having this function
    in the successor cannot stop an unfenced legacy credential.
    """
    from datetime import datetime, timezone

    need(classify_writer_pair(legacy, successor) == "SHARED_FENCE_REQUIRED",
         "fence only applies to an exact shared resource")
    need(type(persisted) is dict and set(persisted) == {
         "schemaVersion", "repository", "kind", "namespace", "requestId",
         "sourceSha", "revision", "generation", "leaseOwner", "expiresAt",
         "gitBlobSha", "consumedAttemptKeys", "terminal", "writeOutcomeUnknown",
         "publisherAuthorized", "runtimeEnabled"}, "untrusted fence schema")
    need(persisted["schemaVersion"] == 1 and
         (persisted["repository"], persisted["kind"], persisted["namespace"]) ==
         (successor["repository"], successor["kind"], successor["namespace"]),
         "fence resource mismatch")
    need(type(persisted["requestId"]) is str and
         re.fullmatch(r"r-[0-9]{8}-[a-z0-9-]{8,56}", persisted["requestId"]),
         "unbound request")
    need(type(persisted["sourceSha"]) is str and
         SHA40.fullmatch(persisted["sourceSha"]) and
         type(persisted["gitBlobSha"]) is str and
         SHA40.fullmatch(persisted["gitBlobSha"]), "invalid source/CAS blob")
    need(type(persisted["revision"]) is int and persisted["revision"] >= 0 and
         type(persisted["generation"]) is int and persisted["generation"] >= 1,
         "invalid durable revision/generation")
    need(type(persisted["leaseOwner"]) is str and
         re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", persisted["leaseOwner"]),
         "invalid persisted owner")
    need(persisted["terminal"] is False and
         persisted["writeOutcomeUnknown"] is False and
         persisted["publisherAuthorized"] is False and
         persisted["runtimeEnabled"] is False, "terminal/unknown/publication denied")
    keys = persisted["consumedAttemptKeys"]
    need(type(keys) is list and len(keys) <= 200 and
         all(type(k) is str and re.fullmatch(r"[a-zA-Z0-9._:-]{1,100}", k) for k in keys)
         and len(set(keys)) == len(keys), "invalid replay index")
    need(type(attempt) is dict and set(attempt) == {
         "requestId", "sourceSha", "owner", "generation", "expectedRevision",
         "expectedBlobSha", "attemptKey"}, "unbound attempt")
    need(type(attempt["attemptKey"]) is str and
         re.fullmatch(r"[a-zA-Z0-9._:-]{1,100}", attempt["attemptKey"]) and
         attempt["attemptKey"] not in keys, "replayed or invalid attempt")
    need(attempt["requestId"] == persisted["requestId"] and
         attempt["sourceSha"] == persisted["sourceSha"] and
         attempt["sourceSha"] == successor["codeSha"],
         "request/source/head changed")
    need(attempt["owner"] == persisted["leaseOwner"] and
         type(attempt["generation"]) is int and
         attempt["generation"] == persisted["generation"],
         "late or displaced writer")
    need(type(attempt["expectedRevision"]) is int and
         attempt["expectedRevision"] == persisted["revision"] and
         type(attempt["expectedBlobSha"]) is str and
         attempt["expectedBlobSha"] == persisted["gitBlobSha"],
         "stale durable CAS expectation")
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() == timezone.utc.utcoffset(now), "trusted UTC required")
    try:
        expiry = datetime.fromisoformat(persisted["expiresAt"].replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("R11_TRANSITION_DENY malformed persisted expiry") from exc
    need(expiry.tzinfo is not None and expiry.utcoffset() ==
         timezone.utc.utcoffset(expiry) and now < expiry, "expired writer lease")
    return {"result": "ELIGIBLE_PREFLIGHT_ONLY", "writeAuthorized": False,
            "liveRaceProven": False, "githubCASStillRequired": True,
            "expectedRevision": persisted["revision"],
            "expectedBlobSha": persisted["gitBlobSha"],
            "generation": persisted["generation"],
            "attemptKey": attempt["attemptKey"]}


def bounded_unknown_ack_get(observations, expected_blob_sha):
    """No PUT/POST capability. At most three GET observations after one write.

    404 never proves a lost PUT was not committed; transient errors cannot
    authorize retry. Each observation must be a real original GET supplied
    by a separately authenticated caller, not self-attested success.
    """
    need(type(expected_blob_sha) is str and SHA40.fullmatch(expected_blob_sha),
         "invalid expected Git blob")
    need(type(observations) is list and 1 <= len(observations) <= 3,
         "GET budget must be 1..3")
    for i, sample in enumerate(observations):
        need(type(sample) is dict and set(sample) == {"method","status","blobSha"}
             and sample["method"] == "GET" and type(sample["status"]) is int,
             "non-GET or untrusted recovery observation")
        status = sample["status"]
        blob = sample["blobSha"]
        if status == 200:
            need(type(blob) is str and SHA40.fullmatch(blob),
                 "200 without original Git blob")
            need(i == len(observations)-1, "extra reads after terminal GET")
            return "MATCHED_NO_REWRITE" if blob == expected_blob_sha else "QUARANTINE_CONFLICT"
        need(blob is None, "unexpected body on failure")
        if status in REJECT:
            need(i == len(observations)-1, "reads after permanent denial")
            return "QUARANTINE_PERMANENT"
        need(status in TRANSIENT, "unsupported/ambiguous status")
    return "QUARANTINE_BOUNDED_UNKNOWN"

def crosswalk(original):
    need(type(original) is dict and original.get("schemaVersion") == 1 and
         original.get("kind") == "ISSUE311_R11_AUTHENTICATED_SCHEDULE_INVENTORY" and
         original.get("nonpublishing") is True and
         original.get("runtimeEnabled") is False and
         original.get("publicationAuthorized") is False and
         original.get("writerUsed") is False and
         original.get("scheduleRemoved") is False and
         original.get("migrationAccepted") is False and
         original.get("legacyScheduleMustRemain") is True,
         "not safe immutable original inventory")
    ex, central = original.get("extensions"), original.get("central")
    need(type(ex) is list and type(central) is list and
         [x.get("repository") for x in ex] == ["pgextwin/"+x for x in EXTENSIONS] and
         [x.get("repository") for x in central] == ["pgextwin/"+x for x in CENTRAL],
         "incomplete/reordered 20-repo inventory")
    rows = []
    for row in ex:
        repo = row["repository"].split("/")[1]
        s = row.get("schedule")
        expected = ["30 * * * *", "41 * * * *"] if repo == "hypopg" else ["30 * * * *"]
        need(type(row.get("mainSha")) is str and SHA40.fullmatch(row["mainSha"])
             and type(row.get("gitBlobSha")) is str and SHA40.fullmatch(row["gitBlobSha"])
             and row.get("workflow") == ".github/workflows/update-watch.yml"
             and type(s) is dict and s.get("cron") == expected
             and s.get("migrationAccepted") is False and
             s.get("pushPreserved") is True and
             s.get("workflowRunPreserved") is True and
             s.get("scheduleDependentAuthorize") is True, "extension schedule unsafe")
        rows.append({"repository":row["repository"],"workflow":row["workflow"],
                     "gitBlobSha":row["gitBlobSha"],"legacyCron":expected,
                     "functions":scope_for(row["workflow"], repo),
                     "replacementAccepted":False,"writerFenceAccepted":False,
                     "recoveryAccepted":False,"retirementAuthorized":False})
    for row in central:
        repo = row["repository"].split("/")[1]
        schedules = row.get("scheduleWorkflows")
        need(type(row.get("mainSha")) is str and SHA40.fullmatch(row["mainSha"])
             and row.get("migrationAccepted") is False and type(schedules) is list,
             "central inventory invalid")
        for s in schedules:
            need(type(s) is dict and type(s.get("path")) is str and
                 s["path"].startswith(".github/workflows/") and
                 s["path"].endswith((".yml",".yaml")) and
                 type(s.get("gitBlobSha")) is str and SHA40.fullmatch(s["gitBlobSha"])
                 and type(s.get("cron")) is list and len(s["cron"]) > 0 and
                 all(type(v) is str and len(v) > 0 for v in s["cron"]) and
                 s.get("migrationAccepted") is False, "central schedule source invalid")
            rows.append({"repository":row["repository"],"workflow":s["path"],
                         "gitBlobSha":s["gitBlobSha"],"legacyCron":s["cron"],
                         "functions":scope_for(s["path"], repo),
                         "replacementAccepted":False,"writerFenceAccepted":False,
                         "recoveryAccepted":False,"retirementAuthorized":False})
    names = [(r["repository"], r["workflow"]) for r in rows]
    need(len(names) == len(set(names)) and len(rows) >= 17, "schedule mapping collision")
    return {"schemaVersion":1,"scope":"R11_484_485_486_487_NONPUBLISHING",
            "authenticatedOriginalInventoryRequired":True,
            "originalEvidenceKind":original["kind"],
            "canonicalParsedInventorySha256":hashlib.sha256(
                (json.dumps(original,sort_keys=True,separators=(",",":"),
                            ensure_ascii=True)+"\n").encode()).hexdigest(),
            "repositoryCount":20,"scheduleCount":len(rows),
            "legacySchedulesRetained":True,"publisherAuthorized":False,
            "runtimeEnabled":False,"allRetirementDeniedUntilIndependentProof":True,
            "writerOverlapStatus":"SHARED_MUTABLE_RESOURCES_REQUIRE_FENCE",
            "unknownAckPolicy":"ONE_PUT_MAX_THREE_GET_NO_REWRITE",
            "rows":rows}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory",required=True)
    parser.add_argument("--output",required=True)
    parser.add_argument("--verify",action="store_true")
    a = parser.parse_args()
    raw = Path(a.inventory).read_bytes()
    original = json.loads(raw,object_pairs_hook=unique)
    expected = (json.dumps(crosswalk(original),sort_keys=True,
                           ensure_ascii=True,indent=2)+"\n").encode()
    target = Path(a.output)
    if a.verify:
        need(target.read_bytes() == expected,"crosswalk changed between original and reader")
        print("R11_INDEPENDENT_CROSSWALK_MATCH",hashlib.sha256(expected).hexdigest())
    else:
        target.write_bytes(expected)
        print("R11_CROSSWALK_PENDING_NO_CRON_REMOVAL",
              hashlib.sha256(expected).hexdigest())

if __name__ == "__main__":
    main()
