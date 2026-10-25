#!/usr/bin/env python3
"""Offline review templates, NEVER activation, CI proof or publication authority.

Inputs are minimized authenticated GET records supplied by the caller. Hashes
detect corruption, not authenticity. Re-GET heads/files/protection before any
future protected PR; this program has no network, credential or apply path.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "migration_plan_issuer", ROOT / "automatic-publisher-receipt-issuer.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
spec = importlib.util.spec_from_file_location("migration_catalog_contract", ROOT / "catalog-downstream-policy.py")
downstream = importlib.util.module_from_spec(spec)
spec.loader.exec_module(downstream)
SHA = re.compile(r"[0-9a-f]{40}\Z")
TARGET = "__APPROVED_PROTECTED_POLICY_SHA__"
SIGNER = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
CENTRAL = tuple("metadata/" + n for n in (
    "automation-fleet.json", "release-promotion.json",
    "unattended-publication.json", "publisher-write-boundary.json"))
DOWNSTREAM = "metadata/manual-release-downstream.json"
LOCAL = (".github/workflows/update-watch.yml", "config/release-promotion.json",
         "config/candidate-build.json", "config/extension.json")
SUPPORT = frozenset(("operator-update-auto.yml", "check-extension-updates.yml",
    "candidate-update.yml", "verify-native-pr-candidate.yml",
    "automatic-postmerge-audit-readonly.yml", "verify-signed-candidate-readonly.yml"))
CALL = re.compile(r"^    uses: pgextwin/build/\.github/workflows/([a-z-]+\.yml)@([0-9a-f]{40})$", re.M)

class Denied(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Denied(reason)

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result

def parse(text):
    return json.loads(text, object_pairs_hook=unique)

def blob(content):
    raw = content.encode("utf-8")
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def branch(record, repository):
    need(type(record) is dict and record.get("repository") == repository
         and record.get("branch") == "main" and record.get("protected") is True
         and type(record.get("sha")) is str and SHA.fullmatch(record["sha"]),
         "invalid or unprotected main snapshot")
    checks = record.get("requiredChecks")
    need(type(checks) is list and bool(checks), "required checks absent")
    seen = set()
    for item in checks:
        need(type(item) is dict and set(item) == {"context", "app_id"}
             and type(item["context"]) is str and 0 < len(item["context"]) <= 250
             and all(ord(c) >= 32 for c in item["context"])
             and type(item["app_id"]) is int and item["app_id"] > 0,
             "malformed required check")
        pair = (item["context"], item["app_id"])
        need(pair not in seen, "duplicate required check")
        seen.add(pair)
    required = "resolver" if repository == "pgextwin/build" else "Windows required summary"
    need((required, 15368) in seen, "required original App15368 check absent")
    return {k: record[k] for k in ("repository", "branch", "sha", "protected", "requiredChecks")}

def files(record, paths):
    supplied = record.get("files")
    need(type(supplied) is dict and set(supplied) == set(paths), "incomplete or unexpected file inventory")
    result = {}
    for path in paths:
        item = supplied[path]
        need(type(item) is dict and set(item) == {"blobSha", "content"}
             and type(item["content"]) is str and 0 < len(item["content"]) < 262144
             and type(item["blobSha"]) is str and SHA.fullmatch(item["blobSha"])
             and blob(item["content"]) == item["blobSha"], "file Git blob digest mismatch")
        result[path] = item["content"]
    return result

def encode(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"

def change(path, before, after, *, template=False):
    lines = difflib.unified_diff(before.splitlines(keepends=True),
        after.splitlines(keepends=True), fromfile="a/" + path, tofile="b/" + path)
    patch = "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
                    for line in lines)
    need(bool(patch), "empty migration change")
    return {"path": path, "beforeBlobSha": blob(before),
            "templateBlobSha" if template else "proposedBlobSha": blob(after),
            "requiresPolicyShaBinding": template, "diff": patch}

def plan(snapshot, heads):
    need(type(snapshot) is dict and set(snapshot) == {"schemaVersion", "kind", "central", "extensions"}
         and type(snapshot["schemaVersion"]) is int and snapshot["schemaVersion"] == 1
         and snapshot["kind"] == "pgextwin-publication-migration-snapshot/v1",
         "invalid migration snapshot")
    need(type(heads) is dict and set(heads) == {"schemaVersion", "kind", "heads"}
         and type(heads["schemaVersion"]) is int and heads["schemaVersion"] == 1
         and heads["kind"] == "pgextwin-publication-migration-heads/v1"
         and type(heads["heads"]) is list, "invalid head observation")
    central = snapshot["central"]
    central_branch = branch(central, "pgextwin/build")
    original = files(central, CENTRAL + (DOWNSTREAM,))
    objects = [parse(original[path]) for path in CENTRAL]
    need(gate.deployment_policy(*objects)["staticPublisherReady"] is False,
         "planner requires the pre-activation policy bundle")
    old_downstream = parse(original[DOWNSTREAM])
    downstream.validate(old_downstream, *objects[:2])
    registered = gate.fleet_policy.members(objects[0])
    need("pgextwin/build" not in registered, "Publisher cannot be a source extension")
    rows = snapshot["extensions"]
    need(type(rows) is list and len(rows) == len(registered), "incomplete fleet snapshot")
    inventory = {}
    for row in rows:
        need(type(row) is dict and row.get("repository") in registered
             and row["repository"] not in inventory, "unknown or duplicate extension")
        inventory[row["repository"]] = branch(row, row["repository"])
    observed = {}
    for row in heads["heads"]:
        need(type(row) is dict and type(row.get("repository")) is str
             and row["repository"] not in observed, "duplicate head observation")
        observed[row["repository"]] = branch(row, row["repository"])
    need(observed == dict(inventory, **{"pgextwin/build": central_branch}),
         "stale main, protection or required-check observation; refresh authenticated GET")
    proposed = deepcopy(objects)
    proposed[0]["releasePolicy"] = gate.MODE
    for row in proposed[0]["entries"]:
        row["releasePolicy"] = gate.MODE
        row["reason"] = ("Protected automatic signed schedule policy; candidates remain nonpublishing; "
                         "live source, CI, Sigstore, scoped App and create-only gates remain required")
    proposed[1]["releasePolicy"] = gate.MODE
    proposed[2]["mode"] = "UNATTENDED"
    proposed[2]["controls"] = {key: True for key in proposed[2]["controls"]}
    proposed[2]["notes"] = ("Approved declaration still requires independent live source, CI, "
                            "Sigstore, scoped Publisher and downstream verification; static policy is not authority.")
    proposed[3].update(mode="ENFORCE", publisherAppId=gate.APP,
                       publisherInstallationId=gate.INSTALLATION)
    need(gate.deployment_policy(*proposed)["staticPublisherReady"] is True,
         "projected central bundle is inconsistent")
    central_changes = [change(path, original[path], encode(obj))
                       for path, obj in zip(CENTRAL, proposed)]
    central_changes.append(change(DOWNSTREAM, original[DOWNSTREAM],
        encode(downstream.automatic_template(old_downstream, *proposed[:2]))))
    extensions = []
    for row in sorted(rows, key=lambda r: r["repository"]):
        repo = row["repository"]
        source = files(row, LOCAL)
        local = parse(source[LOCAL[1]])
        need(local == {"schemaVersion": 1, "enabled": True, "releasePolicy": "manual-dispatch"}
             and type(local.get("schemaVersion")) is int, "unexpected local release policy")
        candidate = parse(source[LOCAL[2]])
        need(type(candidate) is dict and candidate.get("releasePolicy") == "manual-only" and candidate.get("enabled") is True
             and type(candidate.get("schemaVersion")) is int and candidate["schemaVersion"] == 1,
             "candidate-only policy changed")
        manifest = parse(source[LOCAL[3]])
        need(type(manifest) is dict and manifest.get("name") == repo.split("/")[1], "manifest identity differs")
        workflow = source[LOCAL[0]]
        matches = list(CALL.finditer(workflow))
        expected = SUPPORT | {"build-extension-attested.yml"}
        need(len(matches) == len(expected) and {m[1] for m in matches} == expected
             and len(re.findall(r"^\s*uses:", workflow, re.M)) == len(matches),
             "unknown, duplicate, mutable or malformed workflow caller")
        need(next(m[2] for m in matches if m[1] == "build-extension-attested.yml") == SIGNER,
             "audited immutable signer pin changed")
        refs = {m[1]: m[2] for m in matches}
        updated = CALL.sub(lambda m: m[0] if m[1] not in SUPPORT else
                          m[0][:-40] + TARGET, workflow)
        local["releasePolicy"] = gate.MODE
        extensions.append({**inventory[repo], "supportPinsBefore": refs,
            "preservedFiles": {p: blob(source[p]) for p in LOCAL[2:]},
            "changes": [change(LOCAL[0], workflow, updated, template=True),
                        change(LOCAL[1], source[LOCAL[1]], encode(local))]})
    return {"schemaVersion": 1, "status": "REVIEW_TEMPLATES_POLICY_SHA_UNBOUND",
        "publicationAuthorized": False, "publishableReceipt": False, "applyEnabled": False,
        "liveEvidenceVerified": False, "sourceRecheckRequired": True,
        "snapshotSha256": digest(snapshot), "headObservationSha256": digest(heads),
        "targetPolicySha": None, "targetPlaceholder": TARGET,
        "registeredExtensionCount": len(extensions),
        "central": {**central_branch, "changes": central_changes}, "extensions": extensions,
        "requiredOrder": [
            "Complete genuine signed-candidate capability proof and effective authorization review, including every declared control and downstream rollout prerequisites.",
            "Refresh authenticated source/protection/file GETs; regenerate all templates if anything changed.",
            "Only after authorization, protected central PR for the four Publisher policies plus the consistent fifth Catalog downstream declaration; original App15368 CI and genuine postmerge must succeed.",
            "Fetch that actual protected merge SHA and exact automatic policy bytes; a bare SHA or this plan cannot bind authority.",
            "Materialize support-caller pins at that approved policy SHA; preserve signer, detector input, manifest and candidate-only policy.",
            "Protected local policy/caller PRs, all existing required checks and genuine postmerge; never bypass extra repository checks.",
            "Requalify a fresh original manifest-only candidate main/push on each new main; previous-main signed Runs are invalidated by migration.",
            "Genuine central schedule: independent fresh ZIP/SPDX/Grype/Sigstore proof, live issuer/App scope, vacant tag/Release, create-only publish, HTTP401 token revocation.",
            "Re-download public assets, verify Catalog original protected PR/merge, actual CLI bytes and public Website evidence separately."
        ]}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--heads", required=True)
    args = parser.parse_args()
    try:
        result = plan(gate.fleet_policy.read(args.snapshot), gate.fleet_policy.read(args.heads))
        print(encode(result), end="")
        return 0
    except (ValueError, TypeError, KeyError, OSError, StopIteration):
        print("MIGRATION_PLAN_DENY; refresh and review inputs; no authority issued", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
