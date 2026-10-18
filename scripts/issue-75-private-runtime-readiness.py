#!/usr/bin/env python3
"""Issue #75: conservative GET-only connected private-runtime readiness.

Existing GitHub App repo visibility is NOT organization ownership, private
Actions environment/secret access, trusted runner isolation, or a Writer
installation principal. Static verification can PASS only the recorded NO-GO
facts. No GET/mint/network/process, credentials, Release or mutation here.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
RECORD=ROOT/"evidence/issue-75/connected-private-runtime-readiness-20261018.json"
MAX_BYTES=16_384

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

old=load("scripts/issue-75-real-principal-acceptance.py","issue75_prior_credential_gate")
custody=load("scripts/issue-75-active-principal-custody-readonly.py","issue75_prior_source_custody")
private_signer=load("scripts/issue-75-private-signer-verify.py","issue75_private_dormant_signer")
private_writer=load("scripts/issue-75-private-writer-app-probe.py","issue75_private_dormant_writer")

class Deny(ValueError):pass
def need(ok):
    if not ok:raise Deny("insufficient privately isolated runtime evidence")

def exact(d,keys):
    need(type(d) is dict and set(d)==set(keys))
    return d

def read(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES)
    need(b"\0" not in raw)
    try:
        d=json.loads(raw.decode("utf-8"),object_pairs_hook=old.unique)
    except (ValueError,UnicodeError,old.Deny) as exc:
        raise Deny("invalid private-runtime metadata") from None
    need(type(d) is dict)
    return d

def validate(d):
    exact(d,{"schemaVersion","evidenceKind","observedDate","source",
             "fixedIdentities","connectedInstallations","repositorySnapshots",
             "readOnlySettings","riskAssessment"})
    need(type(d["schemaVersion"]) is int and d["schemaVersion"]==1)
    need(d["evidenceKind"]=="ISSUE75_CONNECTED_GITHUB_PRIVATE_RUNTIME_GET_ONLY_INVENTORY")
    need(d["observedDate"]=="2026-10-18")
    need(type(d["source"]) is str and
         d["source"].startswith("Connected GitHub App: installation repository listings"))
    exact(d["fixedIdentities"],{"buildMain","pilotMain","publisherPin","signerPin",
                                "priorNegativeRun","priorAcceptanceMerge"})
    fixed=d["fixedIdentities"]
    need(fixed=={
        "buildMain":"7900eb697284c6cf5aec69d05ce347120a803265",
        "pilotMain":custody.PILOT_SHA,
        "publisherPin":custody.PUBLISHER_PIN,
        "signerPin":custody.SIGNER_PIN,
        "priorNegativeRun":39104746046,
        "priorAcceptanceMerge":"0992112792feb832c320a983380e47f7f1650209"})
    expect_install={
        "count":2,"pgextwinRepositoriesVisible":18,
        "pgextwinVisiblePrivate":0,"pgextwinVisiblePublic":18,
        "otherConnectedPublicRepositories":6,"otherConnectedPrivateRepositories":0,
        "allRepositoriesSelected":True,
        "completeness":"CONNECTED_INSTALLATION_VISIBILITY_ONLY"}
    need(d["connectedInstallations"]==expect_install and
         type(d["connectedInstallations"]["count"]) is int)
    exact(d["repositorySnapshots"],{"build","plpgsql_check"})
    need(d["repositorySnapshots"]=={
        "build":{"visibility":"public","protectedMain":True,
                 "reportedCallerAdmin":True,
                 "workflowWitnessGitBlob":"0e16dd2ec65ee22e71c30b2d234a475c03e2d7ba"},
        "plpgsql_check":{"visibility":"public","protectedMain":True,
                "promoteGitBlob":custody.PUBLISHER_SOURCE_BLOB,
                "productionSignerOIDCDeclared":True,
                "productionWriterUsesGithubToken":True}})
    need(d["readOnlySettings"]=={
        "environmentListing":"CONNECTOR_ENDPOINT_ALLOWLIST_DENIED",
        "actionsPolicyListing":"CONNECTOR_ENDPOINT_ALLOWLIST_DENIED",
        "orgActionsPolicy":"CONNECTOR_ENDPOINT_ALLOWLIST_DENIED",
        "buildBranchProtectionDetails":"HTTP403_RESOURCE_NOT_ACCESSIBLE_BY_INTEGRATION",
        "buildRulesetListing":"AVAILABLE_EMPTY_LIST",
        "plpgsqlCheckRulesetListing":"AVAILABLE_EMPTY_LIST",
        "orgMembershipListing":"EMPTY_AS_OBSERVED_BY_CONNECTION",
        "privateEnvironmentPoliciesAuthenticated":False,
        "privateRunnerIsolationAuthenticated":False,
        "secretsExistenceOrAccessAuthenticated":False,
        "separateSignerWriterCredentialStoresAuthenticated":False,
        "gitHubAppWriterInstallationAuthenticated":False})
    need(d["riskAssessment"]=={
        "privateExecutorAvailability":"NOT_PROVEN",
        "privilegedPrivateSignerCanRun":"NOT_PROVEN",
        "privilegedPrivateWriterCanRun":"NOT_PROVEN",
        "credentialNonPropagation":"NOT_PROVEN",
        "independentGitHubAppWriterPrincipal":"NOT_PROVEN",
        "publicCISecretBearingProbeAllowed":False,
        "liveTokenMintOrPublishAllowed":False,
        "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO","formalRelease":"DENY",
        "needExternalGUISettingsGET":True})
    # The previously accepted signer/Writer denial contract is independent
    # and its frozen original 32+13 Git Blob roots are reused, not rewritten.
    old.verify_existing_roots()
    base=old.validate(old.read_record(old.RECORD.read_bytes()))
    need(base["realPrincipalAcceptance"]=="NOT_PROVEN" and
         base["publicationAuthorized"] is False)
    need(private_signer.SIGNER_SHA==custody.SIGNER_PIN and
         private_writer.REPO=="pgextwin/plpgsql_check")
    return {
        "schemaVersion":1,
        "decision":"CONNECTED_SCOPE_ASSESSED_PRIVATE_EXECUTOR_NOT_PROVEN",
        "observedConnectedOrgRepos":18,
        "observedConnectedOrgPrivateRepos":0,
        "environmentAndOrgPolicyGet":"UNAVAILABLE_ON_CONNECTION",
        "privateEnvironmentProven":False,
        "writerSignerIdentitySeparationProven":False,
        "realSignerOIDCProven":False,
        "realWriterInstallationProven":False,
        "realCredentialNonPropagationProven":False,
        "permittedLiveMint":False,
        "privateRuntimeReadiness":"NOT_PROVEN",
        "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO",
        "publicationAuthorized":False}

def denied():
    return {"schemaVersion":1,
            "decision":"DENY_UNKNOWN_PRIVATE_RUNTIME_ISOLATION",
            "privateRuntimeReadiness":"NOT_PROVEN",
            "permittedLiveMint":False,
            "publicationAuthorized":False,
            "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO"}

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=("static","require-private"),required=True)
    parser.add_argument("--inventory",type=Path,default=RECORD)
    args=parser.parse_args(argv)
    result=denied()
    exit_status=2
    try:
        need(args.inventory.is_file() and args.inventory.stat().st_size<=MAX_BYTES)
        result=validate(read(args.inventory.read_bytes()))
        if args.mode=="static":
            exit_status=0
        else:
            # A public user-supplied JSON cannot certify a private environment
            # or a separately authorized Writer/Signer token principal.
            result=denied()
    except Exception:
        result=denied()
    print(json.dumps(result,sort_keys=True))
    return exit_status

if __name__=="__main__":
    sys.exit(main())
