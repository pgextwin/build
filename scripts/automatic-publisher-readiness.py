#!/usr/bin/env python3
"""Read-only central policy switch: skip credentialed Publisher unless opted in.

This has no authority to issue a Release receipt. The isolated Publisher MUST
repeat every central/local/source/App/expiry/branch/tag check after startup.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location(
    "auto_publisher_readiness_issuer",ROOT/"automatic-publisher-receipt-issuer.py")
issuer=importlib.util.module_from_spec(spec);spec.loader.exec_module(issuer)

def ready(fleet,central,unattended,boundary):
    if any((
        fleet.get("releasePolicy")!=issuer.MODE,
        central.get("releasePolicy")!=issuer.MODE,
        unattended.get("mode")!="UNATTENDED",
        boundary.get("mode")!="ENFORCE",
    )):
        return False
    names=[r.get("repository") for r in fleet.get("entries",[]) if type(r) is dict]
    if not names:
        return False
    for name in names:
        issuer.policy_gate(fleet,central,{"schemaVersion":1,
                           "enabled":True,"releasePolicy":issuer.MODE},
                           unattended,boundary,name)
    return True

def main():
    p=argparse.ArgumentParser()
    for field in ("fleet","central-policy","unattended","publisher-boundary",
                  "github-output"):
        p.add_argument("--"+field,required=True)
    a=p.parse_args()
    try:
        paths=[a.fleet,a.central_policy,a.unattended,a.publisher_boundary]
        objs=[]
        for path in paths:
            file=Path(path)
            if file.is_symlink() or not file.is_file():
                raise ValueError("untrusted static Publisher policy")
            objs.append(json.loads(file.read_text("utf-8")))
        permitted=ready(*objs)
        with Path(a.github_output).open("a",encoding="utf-8") as out:
            out.write("publisher_ready="+str(permitted).lower()+"\n")
        print("PUBLISHER_STATIC_READINESS="+str(permitted).lower()+
              "; no authorization or credential minted")
        return 0
    except (KeyError,ValueError,OSError,TypeError,issuer.Denied) as exc:
        print("PUBLISHER_STATIC_READINESS_DENY: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
