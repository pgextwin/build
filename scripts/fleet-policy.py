#!/usr/bin/env python3
"""Shared NONPUBLISHING fleet/central-policy contract; never Release authority.

Candidate policy/decision records keep their legacy manual-only marker: that
means a candidate cannot publish. The fleet's formal-release mode is separate.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

MANUAL="manual-only"
AUTOMATIC="automatic-signed-schedule"
REPO=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")

class Denied(ValueError): pass

def require(ok,why):
    if not ok: raise Denied(why)

def members(fleet,*,require_build=True,audited=None):
    require(type(fleet) is dict and type(fleet.get("schemaVersion")) is int
            and fleet["schemaVersion"]==1
            and fleet.get("releasePolicy") in (MANUAL,AUTOMATIC)
            and type(fleet.get("entries")) is list and bool(fleet["entries"]),
            "invalid or unsupported protected fleet")
    rows={}
    for row in fleet["entries"]:
        require(type(row) is dict and type(row.get("repository")) is str
                and REPO.fullmatch(row["repository"])
                and row["repository"] not in rows
                and row.get("releasePolicy")==fleet["releasePolicy"]
                and row.get("mode") in ("OFF","WATCH","BUILD")
                and type(row.get("candidateEnabled")) is bool
                and row["candidateEnabled"]==(row["mode"]=="BUILD"),
                "invalid, duplicate or mixed-policy fleet member")
        require(not require_build or row["mode"]=="BUILD",
                "complete BUILD opt-in is required")
        rows[row["repository"]]=row
    if audited is not None:
        require(set(rows)==set(audited),"incomplete audited source registry")
    return rows

def central_policy(fleet,central,*,audited=None):
    rows=members(fleet,audited=audited)
    expected=AUTOMATIC if fleet["releasePolicy"]==AUTOMATIC else "manual-dispatch"
    require(type(central) is dict and type(central.get("schemaVersion")) is int
            and central["schemaVersion"]==1 and central.get("releasePolicy")==expected
            and type(central.get("allowedRepositories")) is list
            and all(type(r) is str for r in central["allowedRepositories"])
            and len(central["allowedRepositories"])==len(rows)
            and set(central["allowedRepositories"])==set(rows),
            "central/fleet release mode or complete membership differs")
    return rows

def read(path):
    def unique(pairs):
        obj={}
        for k,v in pairs:
            require(k not in obj,"duplicate policy JSON key")
            obj[k]=v
        return obj
    p=Path(path)
    require(p.is_file() and not p.is_symlink() and 0<p.stat().st_size<5*1024*1024,
            "unsafe or missing policy JSON")
    obj=json.loads(p.read_text("utf-8-sig"),object_pairs_hook=unique)
    require(type(obj) is dict,"policy must be a JSON object")
    return obj

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--fleet",required=True)
    parser.add_argument("--github-output",required=True)
    a=parser.parse_args()
    try:
        fleet=read(a.fleet)
        members(fleet)
        with Path(a.github_output).open("a",encoding="utf-8") as out:
            out.write("manual_only="+str(fleet["releasePolicy"]==MANUAL).lower()+"\n")
        print("FLEET_POLICY_VERIFIED; publicationAuthorized=false")
        return 0
    except (Denied,OSError,ValueError,TypeError,KeyError):
        print("FLEET_POLICY_DENY",file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
