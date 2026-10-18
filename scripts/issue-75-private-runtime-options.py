#!/usr/bin/env python3
"""Issue #75: offline private-runtime option *design* admission; never an approval.

Reuses the existing GET-only Work GUI negative classifier (and the original
32+13 immutable Git blobs). All newly proposed infrastructure, credentials,
budget and privilege changes require independent authorization and execution.
No network, subprocess, token, Sigstore signing, Release or GitHub mutation.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
EVIDENCE=ROOT/"evidence/issue-75/private-runtime-options-contract-20261018.json"
MAX_BYTES=12000

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

gui=load("scripts/issue-75-work-gui-readiness.py","issue75_existing_gui_gate")
signer=load("scripts/issue-75-private-signer-verify.py","issue75_existing_private_signer")
writer=load("scripts/issue-75-private-writer-app-probe.py","issue75_existing_private_writer")

class Deny(ValueError):pass
def need(c):
    if not c:raise Deny("private executor proof or authorization unavailable")
def exact(d,keys):
    need(type(d) is dict and set(d)==set(keys))
def no_go():
    return {"decision":"DENY_PRIVATE_INFRASTRUCTURE_AND_PRINCIPAL_UNPROVEN",
            "scope":"NONPRIVILEGED_DESIGN_ONLY",
            "recommendedPath":"EXTERNAL_ISOLATED_WRITER",
            "privateExecutorReady":False,
            "realSignerOIDCProven":False,
            "separateWriterPrincipalProven":False,
            "credentialNonPropagationProven":False,
            "privilegedProbeAllowed":False,
            "newBudgetOrPlanApproved":False,
            "publicationAuthorized":False,
            "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO"}

def read(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES)
    need(b"\0" not in raw)
    try:
        out=json.loads(raw.decode("utf-8"),object_pairs_hook=gui.existing.old.unique)
    except (ValueError,UnicodeError):
        raise Deny("invalid options contract") from None
    need(type(out) is dict)
    return out

def evaluate(doc):
    exact(doc,{"schemaVersion","evidenceKind","baseline","options",
               "requiredControlStates","rollout","controls"})
    need(type(doc["schemaVersion"]) is int and doc["schemaVersion"]==1)
    need(doc["evidenceKind"]=="ISSUE75_PRIVATE_EXECUTOR_OPTION_GATE_DENY_ONLY")
    need(type(doc["baseline"]) is dict)
    base=doc["baseline"]
    need(base=={
        "buildProtectedMainBefore":"cbe61b34ade29115d9c359402e8117a9caba3c08",
        "workGuiDecision":"GUI_REPORTED_PGEXTWIN_RUNTIME_ABSENCES_EXTERNAL_UNKNOWN",
        "workGuiProvenance":"REPORTED_NOT_REAUTHENTICATED",
        "originalGitBlobs":32,"additionalGitBlobs":13,
        "publisherPin":"455f0ccc667697f600700a6e64bcfd6c57b6a977",
        "signerPin":"5756b3c5136a8bf4db710016cfe97555f0a71c6d"
    })
    need(all(type(base[k]) is int for k in ("originalGitBlobs","additionalGitBlobs")))
    previous=gui.inspect(gui.parse(gui.GUI.read_bytes()))
    need(previous["decision"]==base["workGuiDecision"])
    need(previous["guiEvidenceProvenance"]==base["workGuiProvenance"])
    need(previous["liveCredentialTestsAllowed"] is False)
    need(signer.SIGNER_SHA==base["signerPin"])
    need(writer.REPO=="pgextwin/plpgsql_check")

    options=doc["options"]
    need(type(options) is list and len(options)==3)
    ids=("EXTERNAL_ISOLATED_WRITER","GITHUB_PRIVATE_ORG",
         "PUBLIC_ENVIRONMENT_SECRETS")
    recommendations=("PREFERRED_FOR_DESIGN_ONLY","CONDITIONAL_ONLY",
                     "REJECT_AS_PRIVATE_ISOLATION")
    paths=("PUBLIC_PROTECTED_READER_SIGNER_PLUS_PRIVATE_OUT_OF_BAND_WRITER",
           "PAID_ORG_PRIVATE_REPO_AND_SEPARATE_APPROVED_CREDENTIAL_EXECUTORS",
           "PUBLIC_REPO_ENVIRONMENT_WITH_PRIVILEGED_SECRET")
    for i,opt in enumerate(options):
        exact(opt,{"id","recommendation","existingInfrastructure",
                   "architecture","publicSignerOidcProven",
                   "privateWriterSeparatePrincipalProven","privateRuntimeAvailable",
                   "manualCostChangeRequired","costFloor",
                   "privilegedExecutionAuthorized","go"})
        need(opt["id"]==ids[i] and
             opt["recommendation"]==recommendations[i] and
             opt["architecture"]==paths[i])
        need(opt["existingInfrastructure"]==
             ("NOT_PROVEN" if i==0 else "REPORTED_ABSENT"))
        need(opt["manualCostChangeRequired"]==
             ("REQUIRES_PLAN_REVIEW" if i==1 else "UNKNOWN"))
        need(opt["costFloor"]=="UNQUOTED")
        for key in ("publicSignerOidcProven","privateWriterSeparatePrincipalProven",
                    "privateRuntimeAvailable","privilegedExecutionAuthorized"):
            need(opt[key] is False)
        need(opt["go"]=="NO_GO")
    states=doc["requiredControlStates"]
    expected_names={
        "executionOwnerAndPrivateTenancy","isolatedWriterRunnerAndStorage",
        "protectedImmutableSourceAndApp15368",
        "signerGithubIssuedOidcAndSigstoreVerification",
        "pinnedSignerCheckoutCredentialNonPersistence",
        "independentWriterAppIssuerInstallationAndRepositoryScope",
        "shortLivedWriterTokenRevokeVerified","readerWriterDistinctCredentialStores",
        "forbiddenCrossJobArtifactOutputCacheLeaksDenied",
        "credentialNonPropagationIndependentAudit",
        "trustedGhBinaryRunnerAndSigstoreRootsPinned",
        "actualRealSignedPublisherPositivePrewrite","schemaV2RecoveryPositive",
        "authorizedBudgetAndPrivatePlan","approvedChangeAndRollbackGate"}
    exact(states,expected_names)
    for k,v in states.items():
        need(v==("PARTIAL_SOURCE_ONLY" if k=="protectedImmutableSourceAndApp15368"
                 else "NOT_DEPLOYED" if k=="pinnedSignerCheckoutCredentialNonPersistence"
                 else "NOT_PROVEN"))
    phases=doc["rollout"]
    need(type(phases) is list and len(phases)==5)
    phase_names=("A_DESIGN","B_PRIVATE_HOST","C_SIGNER_REAL",
                 "D_WRITER_MINT_REVOKE_TEST","E_PUBLISHER_POSITIVE_PREWRITE")
    states=("YES_NONPRIVILEGED","NO_AUTHORIZATION","NO_TRUST_EVIDENCE",
            "NO_APPROVAL","NO_GO")
    for i,step in enumerate(phases):
        exact(step,{"phase","ready","operation","rollback","credentials"})
        need(step["phase"]==phase_names[i] and step["ready"]==states[i])
        need(type(step["operation"]) is str and len(step["operation"])>15)
        need(type(step["rollback"]) is str and len(step["rollback"])>15)
        need(step["credentials"]==
             ("NONE" if i==0 else "NOT_YET_AVAILABLE" if i==1
              else "NONE_IN_PUBLIC_CI" if i==2
              else "PRIVATE_ONLY" if i==3 else "NO_NEW_PUBLIC_SECRET"))

    c=doc["controls"]
    exact(c,{"actualNewPrivateHostProvisioned","actualNewAppInstalled",
             "secretProvisioned","permissionsChanged","branchProtectionChanged",
             "budgetChanged","publisherPinChanged","signerPinChanged",
             "tagsOrReleasesChanged","liveOidcOrWriterMintRun",
             "goB","g4","g5","publicationAuthorized"})
    for key in c:
        need(c[key]=="NO_GO" if key in ("goB","g4","g5") else c[key] is False)

    result=no_go()
    result.update({"decision":"NONPRIVILEGED_OPTIONS_CONTRACT_PASS_NO_LIVE_APPROVAL",
                   "alternativesChecked":3,
                   "unprovenControls":len(expected_names),
                   "rollbackStepsDefined":5,
                   "previousGuiState":"REPORTED_ABSENT_IN_ORG_EXTERNAL_UNKNOWN"})
    return result

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("static","require-execution"),required=True)
    p.add_argument("--plan",type=Path,default=EVIDENCE)
    args=p.parse_args(argv)
    out=no_go();code=2
    try:
        need(args.plan.is_file() and args.plan.stat().st_size<=MAX_BYTES)
        out=evaluate(read(args.plan.read_bytes()))
        if args.mode=="static":code=0
        else:out=no_go()
    except Exception:out=no_go()
    print(json.dumps(out,sort_keys=True))
    return code

if __name__=="__main__":
    sys.exit(main())
