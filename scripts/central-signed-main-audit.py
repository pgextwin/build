#!/usr/bin/env python3
"""Bind the verified claims table to the central workflow run from GitHub's REST API."""

import argparse
import importlib
from pathlib import Path
import sys

auth = importlib.import_module("central-signing-auth")
verify = importlib.import_module("verify-central-attestation-claims")
require = auth.require
obj = auth.object_or_empty
BAD_CLAIMS = "AUDIT_CLAIMS_NOT_VERIFIED"


def referenced_workflow(entries, pin):
    name = f"{auth.REPOSITORY}/{auth.REUSABLE}"
    code = "AUDIT_REFERENCED_WORKFLOW_MISMATCH"
    require(isinstance(entries, list) and len(entries) == 1, code)
    entry = obj(entries[0])
    require(entry.get("path") in (name, f"{name}@{pin}") and entry.get("sha") == pin, code)
    # REST returns a SHA in path for pinned references. If ref is present,
    # it must identify the same SHA as both path and sha.
    if "ref" in entry:
        require(entry["ref"] == pin, code)
    return entry


def verify_report(report, intent):
    require(isinstance(report, dict) and report.keys() == {
        "schema_version", "intent", "subject", "verified", "claims",
    } and type(report["schema_version"]) is int and report["schema_version"] == 1
        and report["verified"] is True and verify.same_json(report["intent"], intent), BAD_CLAIMS)
    subject = obj(report["subject"])
    name = subject.get("name")
    digest = obj(subject.get("digest"))
    require(subject.keys() == {"name", "digest"} and isinstance(name, str)
            and Path(name).name == name and "\\" not in name
            and name.startswith(f'{intent["extension_name"]}-') and name.endswith(".zip")
            and digest.keys() == {"sha256"} and auth.matches(auth.DIGEST, digest["sha256"]),
            BAD_CLAIMS)
    predicates = obj(report["claims"])
    require(predicates.keys() == {verify.SLSA, verify.SPDX}, BAD_CLAIMS)
    for kind, rows in predicates.items():
        skipped = {20, 21} if kind == verify.SLSA else {18, 19}
        require(isinstance(rows, list) and len(rows) == 21, BAD_CLAIMS)
        for number, row in enumerate(rows, 1):
            row = obj(row)
            if number in skipped:
                require(row == verify.inapplicable(number), BAD_CLAIMS)
            else:
                require(row.keys() == {"number", "claim", "expected", "actual", "status"}
                        and type(row["number"]) is int and row["number"] == number
                        and row["status"] == "match", BAD_CLAIMS)
        for number, (claim, expected, _) in enumerate(verify.certificate_expectations(intent), 4):
            require(rows[number - 1] == verify.row(number, f"certificate.{claim}", expected, expected),
                    BAD_CLAIMS, claim)
        require(rows[16]["expected"] == [subject], BAD_CLAIMS)


def audit(run, intent, report):
    auth.validate_intent(intent)
    run = obj(run)
    require(run.get("path") in (auth.CALLER, f"{auth.CALLER}@{auth.REF}"), "AUDIT_RUN_PATH_MISMATCH")
    require(obj(run.get("repository")).get("full_name") == auth.REPOSITORY,
            "AUDIT_RUN_REPOSITORY_MISMATCH")
    require(run.get("head_sha") == intent["head_sha"] and run.get("head_branch") == "main",
            "AUDIT_RUN_HEAD_SHA_MISMATCH")
    require(run.get("event") == intent["authentic_event"], "AUDIT_RUN_EVENT_MISMATCH")
    actor = obj(run.get("actor"))
    require(actor.get("login") == intent["actor_login"], "AUDIT_RUN_ACTOR_MISMATCH")
    if intent["authentic_event"] == "issue_comment":
        require(type(actor.get("id")) is int and actor["id"] == auth.OWNER_ID
                and actor.get("type") == "User", "AUDIT_RUN_ACTOR_MISMATCH")
    require(type(run.get("id")) is int and run["id"] == intent["run_id"], "AUDIT_RUN_ID_MISMATCH")
    require(type(run.get("run_attempt")) is int and run["run_attempt"] == intent["run_attempt"],
            "AUDIT_RUN_ATTEMPT_MISMATCH")
    reusable = referenced_workflow(run.get("referenced_workflows"), intent["reusable_pin_sha"])
    verify_report(report, intent)
    return {
        "schema_version": 1,
        "publishing_allowed": False,
        "run": {
            "repository": auth.REPOSITORY, "path": auth.CALLER, "head_sha": run["head_sha"],
            "head_branch": run["head_branch"], "event": run["event"], "actor": actor,
            "id": run["id"], "run_attempt": run["run_attempt"],
            "run_invocation_uri": auth.run_uri(run["id"], run["run_attempt"]),
            "referenced_workflows": [reusable],
        },
        "verification": report,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run-json", "intent", "claims-report", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()

    try:
        intent = auth.load_intent(args.intent)
        run = auth.read_json(args.run_json, "AUDIT_RUN_JSON_INVALID")
        report = auth.read_json(args.claims_report, BAD_CLAIMS)
        result = audit(run, intent, report)
        auth.write_json(args.output, result)
        print(f'Central claims verified for {result["run"]["run_invocation_uri"]}')
    except (ValueError, OSError, TypeError) as error:
        return auth.report_error(error, BAD_CLAIMS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
