#!/usr/bin/env python3
"""Issue #75: combine existing connector evidence with user-submitted Work GUI.

The Work GUI report is independently sourced from the *current GitHub App*
connection but is not independently reauthenticated by this CI job.
A reported absence in pgextwin must NEVER imply absence outside pgextwin.
No network, token, workflows, OIDC, App POST/DELETE or GitHub mutations.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT/"evidence/issue-75/work-gui-private-runtime-inventory-20261018.json"
MAX_BYTES = 8192

def load(filename, alias):
    spec=importlib.util.spec_from_file_location(alias, ROOT/filename)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

existing=load("scripts/issue-75-private-runtime-readiness.py",
              "issue75_connected_readiness")

class Deny(ValueError):
    pass

def require(value):
    if not value:
        raise Deny("missing or forged reported Work GUI negative baseline")

def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    require(b"\0" not in raw)
    try:
        out=json.loads(raw.decode("utf-8"),
                       object_pairs_hook=existing.old.unique)
    except (ValueError, UnicodeError):
        raise Deny("ambiguous or unreadable GUI report") from None
    require(type(out) is dict)
    return out

def inspect(data):
    require(type(data) is dict and set(data) == {
        "schemaVersion","evidenceKind","observedDate","provenance",
        "pgextwin","unknowns","privateExecutor",
        "goB","g4","g5","publicationAuthorized"})
    require(type(data["schemaVersion"]) is int and data["schemaVersion"]==1)
    require(data["evidenceKind"]=="ISSUE75_REPORTED_GUI_RUNTIME_NEGATIVE")
    require(data["observedDate"]=="2026-10-18")
    require(data["provenance"]==
            "USER_SUPPLIED_WORK_GUI_GET_ONLY_REPORT_NOT_INDEPENDENTLY_REFETCHED")
    require(data["pgextwin"] == {
        "repositories":18,"privateRepositories":0,
        "buildEnvironments":0,"plpgsqlCheckEnvironments":0,
        "buildSelfHostedRunners":0,"plpgsqlCheckSelfHostedRunners":0,
        "organizationCustomRunners":0})
    require(all(type(v) is int for v in data["pgextwin"].values()))
    require(data["unknowns"] == [
        "externalPrivateExecutor", "separateSignerIdentity",
        "independentWriterIdentity", "AppInstallationScopes",
        "secretIsolation", "crossJobCredentialNonPropagation"])
    require(data["privateExecutor"]=="NOT_PROVEN")
    require(all(data[key]=="NO_GO" for key in ("goB","g4","g5")))
    require(data["publicationAuthorized"] is False)

    # The old source and Role contract is preserved, not overwritten by GUI
    # testimony: 32+13 pinned Git Blobs and 2026-10-18 connector GET state.
    old=existing.validate(existing.read(existing.RECORD.read_bytes()))
    require(old["privateRuntimeReadiness"]=="NOT_PROVEN" and
            old["publicationAuthorized"] is False and
            old["observedConnectedOrgRepos"]==18)
    return {
        "schemaVersion":1,
        "decision":"GUI_REPORTED_PGEXTWIN_RUNTIME_ABSENCES_EXTERNAL_UNKNOWN",
        "guiEvidenceProvenance":"REPORTED_NOT_REAUTHENTICATED",
        "withinPgextwinPrivateRepo":"REPORTED_ABSENT",
        "withinPgextwinEnvironments":"REPORTED_ABSENT",
        "withinPgextwinSelfHostedRunners":"REPORTED_ABSENT",
        "externalPrivateRuntime":"UNOBSERVABLE",
        "independentAppPermissions":"UNOBSERVABLE",
        "realPrincipalSeparation":"NOT_PROVEN",
        "credentialNonPropagation":"NOT_PROVEN",
        "privateRuntimeReadiness":"NOT_PROVEN",
        "liveCredentialTestsAllowed":False,
        "publicationAuthorized":False,
        "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO"}

def deny():
    return {"schemaVersion":1,
            "decision":"DENY_GUI_RUNTIME_PROOF_UNTRUSTED",
            "privateRuntimeReadiness":"NOT_PROVEN",
            "liveCredentialTestsAllowed":False,
            "publicationAuthorized":False,
            "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO"}

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=("static","require-real"),required=True)
    parser.add_argument("--report",type=Path,default=GUI)
    args=parser.parse_args(argv)
    output=deny()
    status=2
    try:
        require(args.report.is_file() and args.report.stat().st_size<=MAX_BYTES)
        output=inspect(parse(args.report.read_bytes()))
        if args.mode=="static":
            status=0
        else:
            # Even a correct Work GUI source report is not an authenticated
            # live credential, an approved private runner or a GO permit.
            output=deny()
    except Exception:
        output=deny()
    print(json.dumps(output,sort_keys=True))
    return status

if __name__=="__main__":
    sys.exit(main())
