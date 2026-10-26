#!/usr/bin/env python3
"""Step 22 central unattended-mode safety contract (NOT a publication authority).

This validator deliberately performs no GitHub writes and issues no Release token.
A policy passing this check is a necessary, NEVER sufficient, condition for an
unattended publisher: runtime evidence and scoped App checks are separate gates.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
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
# Schema 1 is the frozen historical contract. Schema 2 describes the existing
# connected-Chat candidate route and the separate dedicated Catalog App truthfully.
# Neither route's declaration proves a real merge or grants Release authority.
EXPLICIT_IDENTITY_CONTROLS = (REQUIRED_CONTROLS - {"requireDedicatedMergeApp"}) | {
    "requireTrustedCandidateMergeIdentity", "requireDedicatedCatalogMergeApp"
}
POLICY_FIELDS = {"schemaVersion", "mode", "defaultAction", "scheduleUtc",
                 "pilotRepository", "requiredMajorVersions", "controls", "notes"}
_identity_spec = importlib.util.spec_from_file_location(
    "unattended_candidate_identity", Path(__file__).with_name("candidate-merge-identity.py"))
candidate_identity = importlib.util.module_from_spec(_identity_spec)
_identity_spec.loader.exec_module(candidate_identity)
AUTOMATIC_CONTROLS = {
    "automaticCandidateMerge", "automaticFormalRelease", "automaticCatalogMerge"
}
REQUIRED_MAJOR_VERSIONS = [15, 16, 17, 18]
PILOT = "pgextwin/plpgsql_check"
SCHEDULE = "0 * * * *"
REPOSITORY = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")


class PolicyDenied(ValueError):
    """Safety contract could not be established."""


def require(condition, reason):
    if not condition:
        raise PolicyDenied(reason)


def policy_controls(policy):
    require(type(policy) is dict and type(policy.get("schemaVersion")) is int
            and policy["schemaVersion"] in (1, 2), "invalid policy schema")
    explicit = policy["schemaVersion"] == 2
    require(set(policy) == POLICY_FIELDS | ({"candidateMergeIdentity"} if explicit else set()),
            "unknown or missing unattended policy fields")
    controls = policy["controls"]
    require(type(controls) is dict and set(controls) ==
            (EXPLICIT_IDENTITY_CONTROLS if explicit else REQUIRED_CONTROLS),
            "incomplete/unrecognized unattended controls")
    require(all(type(v) is bool for v in controls.values()),
            "all safety controls must be booleans")
    if explicit:
        require(controls["requireTrustedCandidateMergeIdentity"] is True
                and controls["requireDedicatedCatalogMergeApp"] is True,
                "both explicit merge identity defenses are mandatory")
        try:
            candidate_identity.validate(policy["candidateMergeIdentity"])
        except candidate_identity.Denied as exc:
            raise PolicyDenied("untrusted candidate merge identity declaration") from exc
    return controls


def with_explicit_merge_identities(policy):
    """Return a strict review copy; preserve mode and every automation switch.

    This pure conversion neither saves metadata nor issues a receipt, token,
    App proof or automatic-publication grant. Catalog's separate actual
    requireDedicatedMergeApp policy and scoped runtime checks stay unchanged.
    """
    controls = policy_controls(policy)
    proposed = deepcopy(policy)
    if policy["schemaVersion"] == 1:
        require(controls["requireDedicatedMergeApp"] is True,
                "historical identity guard cannot be disabled during conversion")
        proposed["schemaVersion"] = 2
        del proposed["controls"]["requireDedicatedMergeApp"]
        proposed["controls"].update(requireTrustedCandidateMergeIdentity=True,
                                     requireDedicatedCatalogMergeApp=True)
        proposed["candidateMergeIdentity"] = candidate_identity.declaration()
    policy_controls(proposed)
    return proposed


def evaluate(policy, fleet):
    controls = policy_controls(policy)
    require(policy["mode"] in {"OBSERVE", "UNATTENDED"} and
            policy["defaultAction"] == "DENY", "invalid mode/default-deny settings")
    require(policy["scheduleUtc"] == SCHEDULE and
            policy["pilotRepository"] == PILOT and
            policy["requiredMajorVersions"] == REQUIRED_MAJOR_VERSIONS,
            "unsupported pilot, PostgreSQL majors or schedule")
    require(isinstance(policy["notes"], str) and bool(policy["notes"]),
            "missing explanatory rollout notes")
    require(type(fleet) is dict and type(fleet.get("schemaVersion")) is int and
            fleet["schemaVersion"] == 1 and
            fleet.get("scheduleUtc") == SCHEDULE and
            fleet.get("releasePolicy") in ("manual-only", "automatic-signed-schedule"),
            "fleet identity or release safety policy changed")
    fleet_mode=fleet["releasePolicy"]
    require(policy["mode"] != "OBSERVE" or fleet_mode == "manual-only",
            "OBSERVE cannot silently accept the scheduled Publisher release policy")
    entries = fleet.get("entries")
    # The protected registry is the membership source of truth. Adding a
    # registered repository must not require editing a second fixed roster.
    # This static check never grants it Release authority: central/local
    # opt-in, authentic signed source and scoped App gates remain separate.
    require(type(entries) is list and bool(entries)
            and all(type(x) is dict for x in entries),
            "missing or malformed registered fleet")
    names = [x.get("repository") for x in entries]
    require(all(type(name) is str and REPOSITORY.fullmatch(name) for name in names)
            and len(set(names)) == len(names) and PILOT in names,
            "fleet repository registry has invalid identities, duplicates or no canary")
    require(all(x.get("scheduleUtc") == SCHEDULE and
                x.get("mode") in {"WATCH", "BUILD", "OFF"} and
                type(x.get("candidateEnabled")) is bool and
                x.get("releasePolicy") == fleet_mode for x in entries),
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
    # An explicitly protected automatic signed schedule mode is allowed only
    # in UNATTENDED with full controls. This STATIC policy does not authorize
    # a Release; separate original Sigstore and independent Publisher App
    # checks are still mandatory. Legacy manual-only mode stays supported
    # as an observational migration dry run.
    require(fleet_mode == "manual-only" or
            (fleet_mode == "automatic-signed-schedule" and
             policy["mode"] == "UNATTENDED"),
            "scheduled release mode is not independently controlled")
    # The historical one-repository pilot restriction is no longer an
    # authorization gate: all registered candidates use the same protected
    # BUILD lane. Requiring other members to turn OFF would disable a proven
    # safe stage without improving signing or Publisher authenticity.
    # Require a COMPLETE fleet here; static policy still never authorizes
    # a Release or bypasses runtime/provenance/Signer/Publisher checks.
    require(all(x["mode"] == "BUILD" and x["candidateEnabled"] is True
                for x in entries),
            "unattended mode requires the complete registered BUILD fleet")
    require(all(controls.values()),
            "unattended mode requires every defense-in-depth control")
    # Never issue an authorization token. Only independently validated
    # candidate, fresh attestation, source/license, Grype and scoped App
    # evidence may open a separate future runtime execution gate.
    return {"schemaVersion": 1, "status": "POLICY_READY_RUNTIME_EVIDENCE_REQUIRED",
            "repository": PILOT, "eligibleRepositories": sorted(names),
            "automaticPublicationAuthorized": False,
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
