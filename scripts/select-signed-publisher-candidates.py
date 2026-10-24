#!/usr/bin/env python3
"""Safely choose a dynamic fleet subset for NONPUBLISHING completed-run recheck.

A read-only intake report is never a formal Release or Publisher authorization.
This selector has no GitHub calls, Secrets, tokens or writer.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("selector_fleet_scope", ROOT/"publisher-scoped-token.py")
scope=importlib.util.module_from_spec(spec);spec.loader.exec_module(scope)
SHA=re.compile(r"^[0-9a-f]{40}$")

class Denied(ValueError): pass

def require(ok,msg):
    if not ok:raise Denied(msg)

def unique(pairs):
    obj={}
    for k,v in pairs:
        require(k not in obj,"duplicate JSON field")
        obj[k]=v
    return obj

def select(report,fleet):
    require(type(report) is dict and type(report.get("schemaVersion")) is int
            and report["schemaVersion"]==1
            and report.get("status")=="NONPUBLISHING_PUBLISHER_INTAKE"
            and all(report.get(k) is False for k in (
                "publishableReceipt","publicationAuthorized",
                "publisherWriteAuthorized","verifiedSignedReleaseArtifacts")),
            "not a nonpublishing authenticated intake report")
    require(type(fleet) is dict and type(fleet.get("entries")) is list
            and bool(fleet["entries"]), "missing protected fleet")
    names=[r.get("repository") for r in fleet["entries"] if type(r) is dict]
    require(len(names)==len(fleet["entries"]) and len(set(names))==len(names),
            "untrusted protected fleet roster")
    for name in names:
        scope.valid_fleet(fleet,name)
    rows=report.get("rows")
    require(type(rows) is list and len(rows)==len(names)
            and type(report.get("repositoryCount")) is int
            and report["repositoryCount"]==len(names)
            and all(type(r) is dict for r in rows)
            and {r.get("repository") for r in rows}==set(names),
            "intake does not cover exactly all protected members")
    eligible=[]
    for row in rows:
        require(row.get("publicationAuthorized") is False
                and row.get("publisherTokenRequested") is False,
                "intake attempted to supply Release authorization or token")
        if row.get("status")=="SIGNED_RUN_FOUND_REVERIFICATION_REQUIRED":
            repo,sha,run_id=row["repository"],row.get("mainSha"),row.get("candidateRunId")
            require(type(sha) is str and SHA.fullmatch(sha)
                    and type(run_id) is int and run_id>0
                    and row.get("needsRealSigstoreReverification") is True,
                    "signed intake has invalid immutable source identity")
            eligible.append({"repository":repo,"name":repo.split("/")[1],
                             "sha":sha,"source_run":run_id})
        else:
            require(row.get("status") in (
                "NO_ORIGINAL_SIGNED_PUSH_ON_CURRENT_MAIN",
                "ORIGINAL_PUSH_NOT_SUCCESSFULLY_ATTESTED",
                "SIGNED_JOB_CHAIN_INCOMPLETE",
                "SIGNED_AUDIT_ARTIFACTS_INCOMPLETE","INDETERMINATE"),
                "unknown/forged intake verdict")
    return eligible

def main():
    ap=argparse.ArgumentParser()
    for name in ("intake","fleet","github-output"):
        ap.add_argument("--"+name,required=True)
    a=ap.parse_args()
    try:
        report=json.loads(Path(a.intake).read_text(),object_pairs_hook=unique)
        fleet=json.loads(Path(a.fleet).read_text(),object_pairs_hook=unique)
        rows=select(report,fleet)
        with open(a.github_output,"a",encoding="utf-8") as file:
            file.write("candidate_matrix="+json.dumps(rows,separators=(",",":"))+"\n")
            file.write("has_candidates="+str(bool(rows)).lower()+"\n")
        print("READ_ONLY_ORIGINAL_SIGNED_SOURCE_RECHECK="+str(len(rows))+"; PUBLISH_DENY")
        return 0
    except (Denied,scope.Denied,ValueError,KeyError,TypeError,OSError) as e:
        print("INDEPENDENT_RECHECK_SELECTION_DENY: "+str(e),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
