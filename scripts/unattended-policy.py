#!/usr/bin/env python3
"""Step 22 central unattended-mode safety contract (NOT a publication authority).

This validator deliberately performs no GitHub writes and issues no Release token.
A policy passing this check is a necessary, NEVER sufficient, condition for an
unattended publisher: runtime evidence and scoped App checks are separate gates.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REQUIRED_CONTROLS = {
    "automaticCandidateMerge",
    "automaticFormalRelease",
    "automaticCatalogMerge",
    "automaticWebsiteVerification",
    "requireDedicatedMergeApp",
    "requireFreshCandidateAudit",
    "requirePinnedUpstreamCommit",
    "requireBuildProvenance",
    "requireSbomAttestation",
    "requireBlockingVulnerabilityPolicy",
    "requireImmutableTags",
    "quarantineOnAmbiguity",
}
AUTOMATIC_CONTROLS = {
    "automaticCandidateMerge", "automaticFormalRelease", "automaticCatalogMerge"
}
REQUIRED_MAJOR_VERSIONS = [15, 16, 17, 18]
PILOT = "pgextwin/plpgsql_check"
SCHEDULE = "0 0 * * *"


class PolicyDenied(ValueError):
    """Safety contract could not be established."""


def require(condition, reason):
    if not condition:
        raise PolicyDenied(reason)


def evaluate(policy, fleet):
    require(type(policy) is dict and set(policy) ==
            {"schemaVersion", "mode", "defaultAction", "scheduleUtc",
             "pilotRepository", "requiredMajorVersions", "controls", "notes"},
            "unknown or missing unattended policy fields")
    require(policy["schemaVersion"] == 1 and
            policy["mode"] in {"OBSERVE", "UNATTENDED"} and
            policy["defaultAction"] == "DENY", "invalid mode/default-deny settings")
    require(policy["scheduleUtc"] == SCHEDULE and
            policy["pilotRepository"] == PILOT and
            policy["requiredMajorVersions"] == REQUIRED_MAJOR_VERSIONS,
            "unsupported pilot, PostgreSQL majors or schedule")
    require(isinstance(policy["notes"], str) and bool(policy["notes"]),
            "missing explanatory rollout notes")
    controls = policy["controls"]
    require(type(controls) is dict and set(controls) == REQUIRED_CONTROLS,
            "incomplete/unrecognized unattended controls")
    require(all(type(v) is bool for v in controls.values()),
            "all safety controls must be booleans")
    require(type(fleet) is dict and fleet.get("schemaVersion") == 1 and
            fleet.get("scheduleUtc") == SCHEDULE and
            fleet.get("releasePolicy") == "manual-only",
            "fleet identity or release safety policy changed")
    entries = fleet.get("entries")
    require(type(entries) is list and len(entries) == 9,
            "expected exactly nine existing fleet members")
    names = [x.get("repository") for x in entries if type(x) is dict]
    require(len(names) == 9 and len(set(names)) == 9 and PILOT in names,
            "fleet repository registry contains duplicates or omissions")
    require(all(x.get("scheduleUtc") == SCHEDULE and
                x.get("mode") in {"WATCH", "BUILD", "OFF"} and
                x.get("releasePolicy") == "manual-only" for x in entries),
            "fleet controls are incompatible with Step 22 safe rollout")
    pilot = next(x for x in entries if x["repository"] == PILOT)
    require(pilot["mode"] == "BUILD" and pilot["candidateEnabled"] is True,
            "only the existing BUILD pilot may be evaluated")
    require(all((x["mode"] == "BUILD") == (x["candidateEnabled"] is True)
                for x in entries),
            "candidate BUILD mode and explicit opt-in must agree")
    if policy["mode"] == "OBSERVE":
        require(not any(controls[key] for key in AUTOMATIC_CONTROLS),
                "observe-only mode cannot enable mutating automation")
        return {"schemaVersion": 1, "status": "OBSERVE_ONLY",
                "repository": PILOT, "automaticPublicationAuthorized": False,
                "reason": "Manual approval and publishing remain mandatory."}
    # A BUILD entry is not authorization to publish. Preserve the Step 22
    # single-repository unattended pilot constraint independently from the
    # Step 23 nine-repository manual-only candidate queue.
    require(all(x["mode"] != "BUILD" and x["candidateEnabled"] is False
                for x in entries if x["repository"] != PILOT),
            "unattended mode forbids non-pilot BUILD targets")
    require(all(controls.values()),
            "unattended mode requires every defense-in-depth control")
    # Never issue an authorization token. Only independently validated
    # candidate, fresh attestation, source/license, Grype and scoped App
    # evidence may open a separate future runtime execution gate.
    return {"schemaVersion": 1, "status": "POLICY_READY_RUNTIME_EVIDENCE_REQUIRED",
            "repository": PILOT, "automaticPublicationAuthorized": False,
            "reason": "Static configuration cannot authorize a Release."}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--policy", required=True)
    p.add_argument("--fleet", required=True)
    p.add_argument("--output")
    p.add_argument("--require-unattended", action="store_true")
    a = p.parse_args()
    try:
        policy = json.loads(Path(a.policy).read_text(encoding="utf-8"))
        fleet = json.loads(Path(a.fleet).read_text(encoding="utf-8"))
        decision = evaluate(policy, fleet)
        if a.output:
            Path(a.output).write_text(json.dumps(decision, indent=2) + "\n",
                                      encoding="utf-8")
        print(json.dumps(decision))
        if a.require_unattended and decision["status"] != "POLICY_READY_RUNTIME_EVIDENCE_REQUIRED":
            raise PolicyDenied("unattended operation is not enabled")
        return 0
    except (PolicyDenied, OSError, ValueError, KeyError, TypeError) as err:
        print("UNATTENDED POLICY DENIED: " + str(err), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
