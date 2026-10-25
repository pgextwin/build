#!/usr/bin/env python3
"""Central Catalog declaration contract; read-only, NEVER publication authority.

Matches Catalog's two explicit downstream modes. The Catalog controller must
still independently verify its local opt-in, original App CI, public signed
Release and exact record-only PR. This validator cannot enable that controller.
"""
from __future__ import annotations
from copy import deepcopy
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("catalog_downstream_fleet", Path(__file__).with_name("fleet-policy.py"))
fleet_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fleet_policy)
FIELDS = {"schemaVersion", "enabled", "mode", "releasePolicy", "automaticFormalRelease",
          "automaticCatalogMerge", "allowedExtensions", "requiredCatalogWorkflow",
          "requirePublishedPublicRelease", "requireBuildProvenanceAttestation",
          "requireSbomAttestation", "requireExactSHA256", "requireExactHeadRequiredChecks",
          "requireDedicatedMergeApp", "denyUnknownOrDuplicate", "notes"}
SAFE_FLAGS = {"requirePublishedPublicRelease", "requireBuildProvenanceAttestation",
              "requireSbomAttestation", "requireExactSHA256", "requireExactHeadRequiredChecks",
              "requireDedicatedMergeApp", "denyUnknownOrDuplicate"}

def validate(value, fleet, central):
    rows = fleet_policy.central_policy(fleet, central)
    need = fleet_policy.require
    names = {repo.split("/")[1] for repo in rows}
    need(type(value) is dict and set(value) == FIELDS
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and all(type(value[k]) is bool for k in ("enabled", "automaticFormalRelease", "automaticCatalogMerge"))
         and value["requiredCatalogWorkflow"] == "validate.yml"
         and all(value[k] is True for k in SAFE_FLAGS)
         and type(value["notes"]) is str and bool(value["notes"]),
         "invalid Catalog downstream controls")
    allowed = value["allowedExtensions"]
    need(type(allowed) is list and bool(allowed) and all(type(n) is str for n in allowed)
         and len(allowed) == len(set(allowed)) and set(allowed) <= names,
         "unknown, duplicate or incomplete Catalog source identities")
    automatic = fleet["releasePolicy"] == fleet_policy.AUTOMATIC
    need(value["releasePolicy"] == (fleet_policy.AUTOMATIC if automatic else "manual-dispatch")
         and value["mode"] == ("POST_VERIFIED_RELEASE_ONLY" if automatic else "POST_MANUAL_RELEASE_ONLY")
         and value["automaticFormalRelease"] is automatic
         and value["enabled"] == value["automaticCatalogMerge"],
         "Catalog downstream mode and central deployment disagree")
    need(not automatic or value["enabled"] is True, "automatic downstream opt-in missing")
    need(not value["enabled"] or set(allowed) == names, "enabled Catalog declaration requires the complete registered fleet")
    return {"schemaVersion": 1, "status": "STATIC_CATALOG_POLICY_ONLY",
            "catalogMergeDeclared": value["enabled"], "publicationAuthorized": False,
            "publishableReceipt": False, "catalogWriteAuthorized": False}

def automatic_template(value, automatic_fleet, automatic_central):
    """Construct a proposed review object; does not persist or activate it."""
    proposed = deepcopy(value)
    proposed.update(enabled=True, mode="POST_VERIFIED_RELEASE_ONLY",
        releasePolicy=fleet_policy.AUTOMATIC, automaticFormalRelease=True,
        automaticCatalogMerge=True,
        allowedExtensions=sorted(repo.split("/")[1] for repo in fleet_policy.members(automatic_fleet)),
        notes="Explicit downstream declaration only; Catalog local/App opt-ins, public signed Release verification and exact-head protected PR checks remain mandatory.")
    validate(proposed, automatic_fleet, automatic_central)
    return proposed
