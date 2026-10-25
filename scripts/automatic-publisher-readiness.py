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
    return issuer.deployment_policy(fleet,central,unattended,boundary)["staticPublisherReady"]

def main():
    p=argparse.ArgumentParser()
    for field in ("fleet","central-policy","unattended","publisher-boundary"):
        p.add_argument("--"+field,required=True)
    p.add_argument("--github-output")
    a=p.parse_args()
    try:
        paths=[a.fleet,a.central_policy,a.unattended,a.publisher_boundary]
        objs=[issuer.fleet_policy.read(path) for path in paths]
        decision=issuer.deployment_policy(*objs)
        permitted=decision["staticPublisherReady"]
        if a.github_output:
            with Path(a.github_output).open("a",encoding="utf-8") as out:
                out.write("publisher_ready="+str(permitted).lower()+"\n")
        print(json.dumps(decision,sort_keys=True))
        print("PUBLISHER_STATIC_READINESS="+str(permitted).lower()+
              "; no authorization or credential minted")
        return 0
    except (KeyError,ValueError,OSError,TypeError,issuer.Denied) as exc:
        print("PUBLISHER_STATIC_READINESS_DENY: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
