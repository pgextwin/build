#!/usr/bin/env python3
"""Second, independent original-byte/Sigstore evidence agreement (NO PUBLISH).

Both JSON inputs must be produced by separate original GitHub jobs that each
ran real gh attestation verify on separately downloaded Windows signed files.
This shape join alone is NEVER cryptographic proof or Publisher admission.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "merged_dual_audit_identity", ROOT / "scripts/fleet-release-identity.py")
ident = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ident)
SHA = re.compile(r"^[a-f0-9]{40}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")
SOURCE = "MERGED_BOT_SCHEDULED_REQUALIFICATION_SIGNED_BUILD"
STATUS = "VERIFIED_MERGED_SCHEDULED_OIDC_NONPUBLISHING"

class Denied(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Denied(reason)

def unique(pairs):
    out={}
    for key,value in pairs:
        need(key not in out, "duplicate audit evidence key")
        out[key]=value
    return out

def load(path):
    p=Path(path)
    need(p.is_file() and not p.is_symlink() and 0<p.stat().st_size<2_000_000,
         "missing/unsafe signed audit JSON")
    v=json.loads(p.read_text("utf-8-sig"),object_pairs_hook=unique)
    need(type(v) is dict, "signed audit must be object")
    return v

def verify(first, second, manifest, lifecycle, *, repository, sha, run_id):
    need(type(repository) is str and repository.startswith("pgextwin/")
         and type(sha) is str and SHA.fullmatch(sha)
         and type(run_id) is int and run_id>0, "malformed root source")
    need(type(manifest) is dict and manifest.get("name")==repository.split("/")[1],
         "protected packaging manifest not identical to claimed repo")
    try:
        majors=ident.maintained_majors(manifest,lifecycle)
    except (ident.Denied,TypeError,ValueError,KeyError) as e:
        raise Denied("unsupported or incomplete maintained major roster") from e
    need(type(majors) is list and bool(majors), "empty actual PG roster")
    immutable=("schemaVersion","status","sourceKind","repository","mainMergeSha",
        "candidatePr","candidateHead","originalFleetScheduleRun",
        "originalNativeWindowsRun","originalRequiredCheck",
        "runId","runAttempt","maintainedMajors",
        "zipSha256ByMajor","spdxSha256ByMajor","grypeSha256ByMajor",
        "grypePolicyByMajor","cryptographicVerification","signedArtifactsVerified",
        "publishableReceipt","publicationAuthorized","publisherSourceKindAuthorized",
        "automaticReleaseEnabled")
    for name,item,job in (("first",first,"signed_audit_first"),
                          ("second",second,"signed_audit_second")):
        need(item.get("auditorJob")==job and item.get("schemaVersion")==1
             and item.get("status")==STATUS and item.get("sourceKind")==SOURCE
             and item.get("repository")==repository and item.get("mainMergeSha")==sha
             and item.get("runId")==run_id and item.get("runAttempt")==1
             and type(item.get("candidatePr")) is int and item["candidatePr"]>0
             and type(item.get("originalFleetScheduleRun")) is int
             and item["originalFleetScheduleRun"]>0
             and type(item.get("originalNativeWindowsRun")) is int
             and item["originalNativeWindowsRun"]>0
             and item.get("maintainedMajors")==majors
             and item.get("cryptographicVerification")=="REAL_GH_ATTESTATION_VERIFY"
             and item.get("signedArtifactsVerified") is True
             and all(item.get(k) is False for k in (
                 "publishableReceipt","publicationAuthorized",
                 "publisherSourceKindAuthorized","automaticReleaseEnabled")),
             "not an independently completed genuine signed "+name+" audit")
        need(type(item.get("candidateHead")) is str and SHA.fullmatch(item["candidateHead"]),
             "missing candidate HEAD in "+name+" audit")
        for field in ("zipSha256ByMajor","spdxSha256ByMajor","grypeSha256ByMajor"):
            digests=item.get(field)
            need(type(digests) is dict and set(digests)=={str(m) for m in majors}
                 and all(type(d) is str and DIGEST.fullmatch(d) for d in digests.values()),
                 "missing/extra unsigned or invalid "+field+" in "+name)
        risks=item.get("grypePolicyByMajor")
        need(type(risks) is dict and set(risks)=={str(m) for m in majors},
             "Grype risk-policy matrix incomplete for "+name)
    need(all(first.get(k)==second.get(k) for k in immutable),
         "independent authentic original artifacts/signatures/source disagree")
    return {"schemaVersion":1,
        "status":"TWO_INDEPENDENT_REAL_SIGSTORE_AUDITS_NONPUBLISHING",
        "sourceKind":SOURCE,"repository":repository,"currentProtectedMain":sha,
        "runId":run_id,"runAttempt":1,
        "auditorJobs":["signed_audit_first","signed_audit_second"],
        "originalCandidatePr":first["candidatePr"],
        "originalFleetScheduleRun":first["originalFleetScheduleRun"],
        "maintainedMajors":majors,"zipSha256ByMajor":first["zipSha256ByMajor"],
        "signedArtifactsVerified":True,"independentSigstoreAudits":2,
        "publisherSourceKindAuthorized":False,"publicationAuthorized":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("first","second","manifest","lifecycle","output"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    try:
        need(os.environ.get("GITHUB_EVENT_NAME")=="schedule"
             and os.environ.get("GITHUB_REF")=="refs/heads/main"
             and os.environ.get("GITHUB_RUN_ATTEMPT")=="1"
             and os.environ.get("GITHUB_JOB")=="dual_audit_join",
             "requires exact genuine completed first+second schedule dependencies")
        output=verify(load(a.first),load(a.second),load(a.manifest),load(a.lifecycle),
                      repository=os.environ["GITHUB_REPOSITORY"],
                      sha=os.environ["GITHUB_SHA"],
                      run_id=int(os.environ["GITHUB_RUN_ID"]))
        Path(a.output).write_text(json.dumps(output,indent=2)+"\n","utf-8")
        print("INDEPENDENT_SIGSTORE_AUDITS=2; SIGNED_BYTES_MATCH; PUBLISH_DENY")
        return 0
    except (Denied,ident.Denied,KeyError,TypeError,ValueError,OSError) as exc:
        print("INDEPENDENT_SCHEDULED_SIGSTORE_DENY: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
