#!/usr/bin/env python3
"""Issue #75 external private Writer preboot: no secrets, no network, no mint.

Reuses immutable 32+13 Git Blob source evidence, 15 unsafe/unproven control
states and five rollback phases. Can independently inspect *local directory
permissions* and arithmetically bound a hypothetical vendor quote. Neither
observation proves private tenancy, actual App custody or a granted budget.
"""
from __future__ import annotations
import argparse
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

ROOT=Path(__file__).resolve().parents[1]
EVIDENCE=ROOT/"evidence/issue-75/external-writer-preboot-deny-20261018.json"
MAX_BYTES=12000

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

old=load("issue75_options", "scripts/issue-75-private-runtime-options.py")
class Deny(ValueError):pass
def need(ok):
    if not ok:raise Deny("external Writer private preboot is not accepted")
def exact(d, keys):
    need(type(d) is dict and set(d)==set(keys))
def read(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES and b"\0" not in raw)
    try:
        obj=json.loads(raw.decode("utf-8"),object_pairs_hook=old.gui.existing.old.unique)
    except (ValueError,UnicodeError):
        raise Deny("invalid credentialless preboot data") from None
    need(type(obj) is dict)
    return obj

NAMES=("SOURCE_SHA_AND_RUN_ATTEMPT","SIGNED_PROVENANCE_NO_BEARER",
       "SCRUBBED_JIT_METADATA")
EDGES=(("READER","SIGNER"),("SIGNER","WRITER"),("WRITER","AUDITOR"))
SAFE_META=("sourceSha","sourceRepo","runId","attempt","signerWorkflowSha",
    "signedZipSha256","sigstoreRootSha256","toolSha256","writerAppId",
    "installationId","targetRepositoryId","scopeClass","tokenTtlSeconds",
    "revoked","independentAuditRef")
NO_CREDENTIALS=("privateKey","appJwt","installationToken","oidcToken",
    "authorizationHeader","credentialDigest","envDump","cacheSecret",
    "debugTrace")

def inspect(manifest):
    exact(manifest,{"schemaVersion","kind","reference","identities","flows",
                    "workspace","writerApp","cost","jit","controls"})
    need(type(manifest["schemaVersion"]) is int and manifest["schemaVersion"]==1)
    need(manifest["kind"]=="ISSUE75_EXTERNAL_WRITER_PREBOOT_DESIGN_ONLY")
    baseline=manifest["reference"]
    need(baseline=={
        "buildBefore":"bb0023f344bede8940fb3e2fa8e6d0541457c0f8",
        "immutableSourceLedgerOriginal":32,
        "immutableSourceLedgerAdditional":13,
        "signerPin":"5756b3c5136a8bf4db710016cfe97555f0a71c6d",
        "publisherPin":"455f0ccc667697f600700a6e64bcfd6c57b6a977",
        "path":"EXTERNAL_ISOLATED_WRITER","priorControls":15,
        "priorRollbackPhases":5})
    for field in ("immutableSourceLedgerOriginal","immutableSourceLedgerAdditional",
                  "priorControls","priorRollbackPhases"):
        need(type(baseline[field]) is int)
    prior=old.evaluate(old.read(old.EVIDENCE.read_bytes()))
    need(prior["decision"]=="NONPRIVILEGED_OPTIONS_CONTRACT_PASS_NO_LIVE_APPROVAL"
         and prior["unprovenControls"]==baseline["priorControls"]
         and prior["rollbackStepsDefined"]==baseline["priorRollbackPhases"]
         and old.signer.SIGNER_SHA==baseline["signerPin"])

    roles=manifest["identities"]
    exact(roles,{"reader","signer","writer"})
    need(roles=={
        "reader":{"realm":"GITHUB_PROTECTED_MAIN_GET_ONLY",
                  "hasWriterKey":False,"hasSignerToken":False},
        "signer":{"realm":"GITHUB_PROTECTED_MAIN_OIDC_SIGN_ONLY",
                  "hasWriterKey":False,"hasReaderToken":False},
        "writer":{"realm":"EXTERNAL_PRIVATE_NOT_PROVISIONED",
                  "hasGithubActionsOidc":False,"hasReaderToken":False}})
    flows=manifest["flows"]
    need(type(flows) is list and len(flows)==3)
    for i,entry in enumerate(flows):
        exact(entry,{"from","to","payload"})
        need((entry["from"],entry["to"])==EDGES[i]
             and entry["payload"]==NAMES[i])
        # This describes a proposed taint-free message DAG only; public
        # JSON never validates actual runtime nonpropagation.
    workspace=manifest["workspace"]
    exact(workspace,{"provider","privateHostId","privateStoreId",
                     "trustRootSha256","runnerImageSha256","workDir","observedLive"})
    need(workspace=={
        "provider":"NOT_SELECTED","privateHostId":None,"privateStoreId":None,
        "trustRootSha256":None,"runnerImageSha256":None,"workDir":None,
        "observedLive":False})
    app=manifest["writerApp"]
    exact(app,{"status","appId","installationId","repository","repositoryId",
               "requestedScopes","mintTestApproved"})
    need(app=={"status":"NOT_INSTALLED","appId":None,
             "installationId":None,"repository":"pgextwin/plpgsql_check",
             "repositoryId":1410581312,"requestedScopes":["contents:write"],
             "mintTestApproved":False})
    costs=manifest["cost"]
    exact(costs,{"quoteStatus","currency","vendor","quoteId",
                 "monthlyLimitJPY","approvedBudgetJPY","approvalState"})
    need(costs=={"quoteStatus":"NOT_QUOTED","currency":"JPY",
                "vendor":None,"quoteId":None,"monthlyLimitJPY":None,
                "approvedBudgetJPY":None,"approvalState":"NOT_APPROVED"})
    jit=manifest["jit"]
    exact(jit,{"requiredMetadata","forbiddenMaterial","independentRuntimeEvidence"})
    need(jit["requiredMetadata"]==list(SAFE_META) and
         jit["forbiddenMaterial"]==list(NO_CREDENTIALS) and
         jit["independentRuntimeEvidence"] is False)
    need(set(SAFE_META).isdisjoint(set(NO_CREDENTIALS)))
    controls=manifest["controls"]
    exact(controls,{"noNewPrivateInfrastructure","noNewAppOrSecret",
        "noNewPermissionsOrBudget","noNewReleaseOrTag","privateRunnerApproved",
        "writerIdentityVerified","signerIdentityVerified",
        "runtimeNonPropagationVerified","liveExecutionAllowed",
        "goB","g4","g5","publicationAuthorized"})
    for k in controls:
        expected=("NO_GO" if k in ("goB","g4","g5") else
                  True if k.startswith("noNew") else False)
        need(controls[k] is expected if type(expected) is bool
             else controls[k]==expected)

    return {"classification":"CREDENTIALLESS_PREBOOT_GRAPH_VALID_NO_PRIVATE_RUNTIME",
            "sourceBlobCount":baseline["immutableSourceLedgerOriginal"]+
                              baseline["immutableSourceLedgerAdditional"],
            "allowedCrossBoundaryDataFlows":len(flows),
            "sanitizedJitKeys":len(SAFE_META),
            "knownProvider":False,"quotedCosts":False,
            "readiness":"NOT_PROVEN","actualCrossJobIsolationProven":False,
            "actualSignerOidcProven":False,"actualWriterAppProven":False,
            "costApproved":False,"credentialProbeAllowed":False,
            "publicationAuthorized":False,"goB":"NO_GO","g4":"NO_GO","g5":"NO_GO"}

def inspect_private_dir(path):
    """Read-only OS stat, not a trusted enclave/runner isolation attestation."""
    need(isinstance(path,Path) and path.is_absolute())
    try:
        info=path.lstat()
        need(stat.S_ISDIR(info.st_mode) and not path.is_symlink())
        need(info.st_mode & 0o077 == 0 and info.st_mode & 0o700 == 0o700)
        if hasattr(os,"getuid"):need(info.st_uid==os.getuid())
        need(path.resolve(strict=True)==path)
        need(ROOT not in path.parents and path!=ROOT)
    except (OSError,RuntimeError):
        raise Deny("local workspace inspection failed") from None
    return {"localDirectoryMode":"PRIVATE_OWNER_ONLY",
            "localDirectoryPermissionsChecked":True,
            "privateExecutionTenancyAuthenticated":False,
            "actualCredentialIsolationProven":False,
            "credentialProbeAllowed":False}

def parse_rate(text):
    need(type(text) is str and 1<=len(text)<=16)
    need(all(x in "0123456789." for x in text)
         and text.count(".")<=1 and text not in ("","."))
    try:v=Decimal(text)
    except InvalidOperation:raise Deny("invalid quote rate") from None
    need(v.is_finite() and 0<=v<=Decimal("10000000") and
         -v.as_tuple().exponent<=4)
    return v

def estimate_quote(q):
    """Compute upper bound from OPERATOR-SUPPLIED rates, never a price lookup."""
    exact(q,{"currency","status","rateJPY","limit",
             "bufferPercent","approval","reference"})
    need(q["currency"]=="JPY" and q["status"]=="USER_SUPPLIED_NOT_VERIFIED"
         and q["approval"]=="NOT_APPROVED")
    need(type(q["reference"]) is str and
         1<=len(q["reference"])<=70 and
         all(x.isalnum() or x in "-_:. " for x in q["reference"]))
    rates=q["rateJPY"]
    exact(rates,{"computeHour","storageGBMonth","egressGB","monthlyFixed"})
    limits=q["limit"]
    exact(limits,{"computeHours","storageGBMonths","egressGB"})
    need(all(type(x) is int and 0<=x<=10000 for x in limits.values()))
    need(type(q["bufferPercent"]) is int and
         0<=q["bufferPercent"]<=100)
    total=(parse_rate(rates["computeHour"])*limits["computeHours"]+
           parse_rate(rates["storageGBMonth"])*limits["storageGBMonths"]+
           parse_rate(rates["egressGB"])*limits["egressGB"]+
           parse_rate(rates["monthlyFixed"]))
    bounded=(total*(100+q["bufferPercent"])/100).quantize(
        Decimal("1"),rounding=ROUND_CEILING)
    need(bounded<=1000000000)
    return {"maximumEstimatedMonthlyJPY":int(bounded),
            "quoteSource":"USER_SUPPLIED_UNVERIFIED",
            "rateOrCurrencyAuthenticated":False,
            "provisioningBudgetApproved":False,
            "credentialProbeAllowed":False}

def denied():
    return {"classification":"DENY_EXTERNAL_WRITER_PREBOOT_UNVERIFIED",
            "readiness":"NOT_PROVEN","credentialProbeAllowed":False,
            "publicationAuthorized":False,
            "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO"}

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--mode",required=True,
                   choices=("static","local-dir","require-live"))
    p.add_argument("--manifest",type=Path,default=EVIDENCE)
    p.add_argument("--workspace",type=Path)
    p.add_argument("--quote",type=Path)
    args=p.parse_args(argv)
    out=denied();code=2
    try:
        need(args.manifest.is_file() and args.manifest.stat().st_size<=MAX_BYTES)
        out=inspect(read(args.manifest.read_bytes()))
        if args.quote is not None:
            need(args.quote.is_file() and args.quote.stat().st_size<=MAX_BYTES)
            out["costBound"]=estimate_quote(read(args.quote.read_bytes()))
        if args.mode=="local-dir":
            need(args.workspace is not None and args.workspace.is_absolute())
            out["workspaceCheck"]=inspect_private_dir(args.workspace)
            code=0
        elif args.mode=="static":
            need(args.workspace is None)
            code=0
        else:
            # Local OS mode and hypothetical pricing are not runtime/identity
            # attestations, and cannot approve secrets or a GitHub App mint.
            out=denied()
    except Exception:
        out=denied()
    print(json.dumps(out,sort_keys=True))
    return code

if __name__=="__main__":
    sys.exit(main())
