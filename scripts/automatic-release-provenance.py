#!/usr/bin/env python3
"""Immutable identity marker for independently authenticated automatic Releases.

A marker in Release notes is an untrusted *locator* for Catalog's independent
GitHub GET of BOTH source main/push and central scheduled Publisher Runs. Never
interpret the marker alone as proof, signature, App consent or Release authority.
"""
from __future__ import annotations
import json
import re

PREFIX="<!-- PGEXTWIN_AUTOMATIC_SIGNED_PROVENANCE_V1="
SUFFIX=" -->"
HEX40=re.compile(r"^[a-f0-9]{40}$")
TAG=re.compile(r"^v[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]{8})?-windows\.[1-9][0-9]*$")
REPO=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
FIELDS={
    "schemaVersion","authorizationMode","repository","releaseTag",
    "packagingCommit","sourceRunId","sourceRunAttempt",
    "sourceWorkflow","publisherRepository","publisherRunId",
    "publisherRunAttempt","publisherMainSha","publisherWorkflow",
    "publisherAppId","approvalProvenance",
}
class Denied(ValueError): pass

def require(ok,reason):
    if not ok: raise Denied(reason)

def claim(receipt):
    """Return only public locators, never a token, approver or authorization."""
    require(type(receipt) is dict
            and receipt.get("authorizationMode")=="automatic-schedule"
            and receipt.get("status")=="VERIFIED_AUTOMATIC_SCHEDULE"
            and receipt.get("approvalProvenance")==
                "INDEPENDENT_LIVE_SCHEDULE_AND_SIGNED_SOURCE",
            "no independently typed automatic Publisher receipt")
    result={
        "schemaVersion":1,
        "authorizationMode":"automatic-schedule",
        "repository":receipt.get("repository"),
        "releaseTag":receipt.get("releaseTag"),
        "packagingCommit":receipt.get("trustedCommit"),
        "sourceRunId":receipt.get("sourceRunId"),
        "sourceRunAttempt":receipt.get("sourceRunAttempt"),
        "sourceWorkflow":receipt.get("signedSourceWorkflow"),
        "publisherRepository":receipt.get("publisherRepository"),
        "publisherRunId":receipt.get("publisherRunId"),
        "publisherRunAttempt":receipt.get("publisherRunAttempt"),
        "publisherMainSha":receipt.get("publisherMainSha"),
        "publisherWorkflow":receipt.get("publisherWorkflow"),
        "publisherAppId":5451798,
        "approvalProvenance":receipt.get("approvalProvenance"),
    }
    validate(result)
    return result

def validate(value):
    require(type(value) is dict and set(value)==FIELDS
            and type(value.get("schemaVersion")) is int
            and value["schemaVersion"]==1
            and value.get("authorizationMode")=="automatic-schedule"
            and type(value.get("repository")) is str and REPO.fullmatch(value["repository"])
            and type(value.get("releaseTag")) is str and TAG.fullmatch(value["releaseTag"])
            and type(value.get("packagingCommit")) is str and HEX40.fullmatch(value["packagingCommit"])
            and type(value.get("sourceRunId")) is int and value["sourceRunId"]>0
            and type(value.get("sourceRunAttempt")) is int and value["sourceRunAttempt"]==1
            and value.get("sourceWorkflow")==".github/workflows/update-watch.yml"
            and value.get("publisherRepository")=="pgextwin/build"
            and type(value.get("publisherRunId")) is int and value["publisherRunId"]>0
            and value["publisherRunId"]!=value["sourceRunId"]
            and type(value.get("publisherRunAttempt")) is int and value["publisherRunAttempt"]==1
            and type(value.get("publisherMainSha")) is str and HEX40.fullmatch(value["publisherMainSha"])
            and value.get("publisherWorkflow")==".github/workflows/publisher-candidate-intake.yml"
            and type(value.get("publisherAppId")) is int and value["publisherAppId"]==5451798
            and value.get("approvalProvenance")=="INDEPENDENT_LIVE_SCHEDULE_AND_SIGNED_SOURCE",
            "invalid automatic signed Publisher public Run locator")
    return value

def encode(receipt):
    value=claim(receipt)
    return PREFIX+json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True)+SUFFIX

def decode(body):
    """Strict, unique marker; parse only as a locator, never release authority."""
    require(type(body) is str and len(body)<1000000,"missing/oversized public notes")
    lines=[s for s in body.splitlines() if s.startswith(PREFIX)]
    require(len(lines)==1 and lines[0].endswith(SUFFIX),
            "missing, duplicate or malformed automatic Publisher locator")
    raw=lines[0][len(PREFIX):-len(SUFFIX)]
    def unique(rows):
        obj={}
        for k,v in rows:
            require(k not in obj,"duplicate evidence key")
            obj[k]=v
        return obj
    try: result=json.loads(raw,object_pairs_hook=unique)
    except (ValueError,TypeError) as exc:
        raise Denied("malformed Publisher locator JSON") from exc
    return validate(result)
