#!/usr/bin/env python3
"""Protected dual-opt-in for distinct owner main-signing Release sources.

This is a pure, fail-closed policy prerequisite, NOT a Release issuer.
It cannot make a NONPUBLISHING source proof or JSON into authorization.
The existing automatic-signed-schedule gates remain mandatory.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location(
    "owner_source_existing_publisher_issuer",
    ROOT/"automatic-publisher-receipt-issuer.py")
issuer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(issuer)

SOURCE_KIND="OWNER_ISSUE_COMMENT_MAIN_SIGNING"
OWNER="ShutenOishi"
OWNER_ID=27071164
class Denied(ValueError):pass

def require(ok, why):
    if not ok:raise Denied(why)

def gate(*,fleet,central,local,unattended,boundary,
         owner_central,owner_local,repository):
    """Only explicit protected central AND local opt-in; no implicit fallback."""
    try:
        issuer.policy_gate(fleet,central,local,unattended,boundary,repository)
    except (issuer.Denied,KeyError,ValueError,TypeError) as exc:
        raise Denied("existing signed Publisher policy not satisfied") from exc
    require(type(owner_central) is dict and
            set(owner_central)=={"schemaVersion","sourceKind","mode",
                                 "allowedRepositories","ownerLogin","ownerId"} and
            type(owner_central.get("schemaVersion")) is int and
            owner_central["schemaVersion"]==1 and
            owner_central.get("sourceKind")==SOURCE_KIND and
            owner_central.get("mode")=="ENFORCE" and
            owner_central.get("ownerLogin")==OWNER and
            type(owner_central.get("ownerId")) is int and
            owner_central["ownerId"]==OWNER_ID and
            type(owner_central.get("allowedRepositories")) is list,
            "distinct central owner-source publication opt-in missing")
    allowed=owner_central["allowedRepositories"]
    names=set(issuer.fleet_policy.members(fleet))
    require(bool(allowed) and len(allowed)==len(set(allowed))
            and all(type(x) is str and x in names for x in allowed)
            and repository in allowed,
            "source-kind central allowlist absent, duplicated or outside fleet")
    expected={"schemaVersion":1,"enabled":True,"sourceKind":SOURCE_KIND,
              "releasePolicy":issuer.MODE}
    require(type(owner_local) is dict and
            owner_local==expected and
            type(owner_local.get("schemaVersion")) is int and
            type(owner_local.get("enabled")) is bool,
            "distinct protected local owner-source publication opt-in missing")
    return {"schemaVersion":1,"sourceKind":SOURCE_KIND,
            "status":"STATIC_SOURCE_KIND_POLICY_READY_RUNTIME_PROOF_REQUIRED",
            "repository":repository,"publicationAuthorized":False,
            "publishableReceipt":False}
