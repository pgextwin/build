#!/usr/bin/env python3
"""Issue #75 Windows 11 host option assessment from identity-free LOCAL facts.

No Windows command is run by this Python file. The separately provided
read-only PowerShell JSON is SELF-REPORTED and can be forged: assessment is a
hardware/host-signal triage only, NOT an attestation or a Secret approval.
Imports prior 32+13-blob, 15-control, five-rollback private preboot gates.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
MAX_BYTES=4096
EDITIONS={
    "Professional","ProfessionalN","Enterprise","EnterpriseS",
    "Education","EducationN","Core","CoreSingleLanguage","UNKNOWN"
}
TRI={"YES","NO","UNKNOWN"}
HV={"ENABLED","DISABLED","UNKNOWN"}

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

old=load("scripts/issue-75-external-writer-preboot.py",
         "issue75_previous_external_preboot")

class Deny(ValueError):
    pass

def need(value):
    if not value:
        raise Deny("invalid or untrusted local Windows 11 capability report")

def strict(obj,keys):
    need(type(obj) is dict and set(obj)==set(keys))

def parse(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES and b"\0" not in raw)
    try:
        doc=json.loads(raw.decode("utf-8"),
                       object_pairs_hook=old.old.gui.existing.old.unique)
    except (UnicodeError,ValueError):
        raise Deny("untrusted or duplicate JSON") from None
    need(type(doc) is dict)
    return doc

FIELDS={
    "schemaVersion","evidenceKind","observation","windowsBuild",
    "windowsEdition","hyperVFeature","firmwareVirtualization","cpuSlat",
    "physicalMemoryAtLeast8GiB","systemDriveFreeAtLeast40GiB",
    "systemDriveEncryptionProtected","allFirewallProfilesEnabled",
    "machineIdentityIncluded","credentialAccessAttempted",
    "systemSettingsChanged","privateWriterRuntimeProven",
    "publicationAuthorized"
}
def assess(report):
    strict(report,FIELDS)
    need(type(report["schemaVersion"]) is int and report["schemaVersion"]==1)
    need(report["evidenceKind"]=="ISSUE75_LOCAL_WINDOWS_HOST_FACTS_UNATTESTED")
    need(report["observation"] in (
        "SYNTHETIC_CI_FIXTURE_NOT_REAL",
        "LOCAL_WINDOWS_POWERSHELL_UNATTESTED"))
    build=report["windowsBuild"]
    need(type(build) is int and 0<=build<=999999)
    edition=report["windowsEdition"]
    need(type(edition) is str and edition in EDITIONS)
    need(report["hyperVFeature"] in HV)
    for key in ("firmwareVirtualization","cpuSlat",
                "physicalMemoryAtLeast8GiB",
                "systemDriveFreeAtLeast40GiB",
                "systemDriveEncryptionProtected",
                "allFirewallProfilesEnabled"):
        need(type(report[key]) is str and report[key] in TRI)
    for field in ("machineIdentityIncluded","credentialAccessAttempted",
                  "systemSettingsChanged","privateWriterRuntimeProven",
                  "publicationAuthorized"):
        need(report[field] is False)

    original=old.inspect(old.read(old.EVIDENCE.read_bytes()))
    need(original["sourceBlobCount"]==45 and
         original["credentialProbeAllowed"] is False and
         original["publicationAuthorized"] is False)
    windows11=build>=22000
    edition_hv=edition in {
        "Professional","ProfessionalN","Enterprise","EnterpriseS",
        "Education","EducationN"}
    hardware=(report["firmwareVirtualization"]=="YES" and
              report["cpuSlat"]=="YES" and
              report["physicalMemoryAtLeast8GiB"]=="YES" and
              report["systemDriveFreeAtLeast40GiB"]=="YES")
    if windows11 and edition_hv and hardware:
        route="LOCAL_HYPERV_VIRTUALIZATION_CANDIDATE_ONLY"
    elif windows11 and edition in {"Core","CoreSingleLanguage"} and hardware:
        route="LOCAL_THIRD_PARTY_HYPERVISOR_LICENSE_REVIEW"
    else:
        route="INSUFFICIENT_OR_UNKNOWN_LOCAL_VM_CAPABILITIES"
    security_signal=(
        report["systemDriveEncryptionProtected"]=="YES" and
        report["allFirewallProfilesEnabled"]=="YES")
    return {
        "classification":"WINDOWS_LOCAL_HOST_FACTS_UNATTESTED",
        "origin":report["observation"],
        "hostVirtualizationTriage":route,
        "windows11BuildDetected":windows11,
        "hostDiskEncryptionAndFirewallReported":security_signal,
        "hypervEnabledReported":report["hyperVFeature"]=="ENABLED",
        "localVMOnlyForNoSecretPilot":True,
        "cloudQuoteKnown":False,
        "existingDedicatedHostProven":False,
        "secretVaultAndAccessBoundaryProven":False,
        "actualSignerOIDCProven":False,
        "realWriterPrincipalProven":False,
        "privateWriterRuntimeProven":False,
        "credentialNonPropagationProven":False,
        "privilegedExecutionAllowed":False,
        "publicationAuthorized":False,
        "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO"}

def denied():
    return {"classification":"DENY_UNTRUSTED_WINDOWS_HOST_FACTS",
            "privilegedExecutionAllowed":False,
            "publicationAuthorized":False,
            "privateWriterRuntimeProven":False,
            "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO"}

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=("analyze","require-private"),required=True)
    parser.add_argument("--facts",type=Path,required=True)
    args=parser.parse_args(argv)
    out=denied();rc=2
    try:
        need(args.facts.is_file() and args.facts.stat().st_size<=MAX_BYTES)
        out=assess(parse(args.facts.read_bytes()))
        if args.mode=="analyze":
            rc=0
        else:
            # A Windows CLI, 0700 folder, encrypted disk, paid VM or
            # self-asserted JSON can never prove an authenticated workload.
            out=denied()
    except Exception:
        out=denied()
    print(json.dumps(out,sort_keys=True))
    return rc

if __name__=="__main__":
    sys.exit(main())
