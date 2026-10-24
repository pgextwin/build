#!/usr/bin/env python3
"""Shared read-only original signed Run artifact download; never a receipt.

Both the public intake proof job and isolated Publisher MUST independently GET
original signed ZIP/SPDX/Grype + first/second signed audits. An artifact's name
is not proof: both callers run real gh Sigstore and immutable run checks AFTER.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys

REPO=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
class Denied(ValueError): pass

def check(ok,reason):
    if not ok: raise Denied(reason)

def download(repository,run_id,directory,*,call=None):
    check(type(repository) is str and REPO.fullmatch(repository)
          and type(run_id) is int and run_id>0
          and type(directory) is Path and not directory.is_symlink()
          and type(os.environ.get("RUNNER_TEMP")) is str
          and type(os.environ.get("GH_TOKEN")) is str
          and bool(os.environ["GH_TOKEN"]),
          "unsafe original signed artifact source")
    base=Path(os.environ["RUNNER_TEMP"]).resolve()
    folder=directory.resolve()
    check(folder!=base and folder.is_relative_to(base),
          "signed asset directory escapes runner scratch")
    name=repository.split("/")[1]
    paths={k:folder/k for k in ("original","second","signed-raw","signed-dist")}
    check(not any(p.exists() or p.is_symlink() for p in paths.values()),
          "stale/duplicate downloaded artifacts exist")
    for p in paths.values():p.mkdir(parents=True,exist_ok=False)
    cmd=call or subprocess.run
    for filter_kind,filter_value,path in (
        ("--name","automatic-signed-candidate-audit-nonpublishing",paths["original"]),
        ("--name","independent-signed-publisher-preflight-nonpublishing",paths["second"]),
        ("--pattern",name+"-pg*-windows-x64",paths["signed-raw"]),
    ):
        result=cmd(["gh","run","download",str(run_id),"--repo",repository,
                    filter_kind,filter_value,"--dir",str(path)],
                   capture_output=True,text=True,timeout=180,check=False)
        check(result.returncode==0,
              "authenticated original signed Run download unavailable")
    incoming=paths["signed-raw"]
    check(all(not p.is_symlink() for p in incoming.rglob("*")),
          "signed artifacts contain linked/unsafe tree")
    files=[p for p in incoming.rglob("*") if p.is_file()]
    check(bool(files) and len({p.name for p in files})==len(files),
          "signed PG asset tree missing or duplicated")
    for p in files:
        check(p.name.startswith(name+"-")
              and p.name.endswith((".zip",".spdx.json",".vulnerabilities.json"))
              and p.stat().st_size>0 and p.stat().st_size<1024*1024*1024,
              "unexpected signed ZIP/SPDX/Grype artifact member")
        shutil.copyfile(p,paths["signed-dist"]/p.name)
    for expected,path in (
        ("automatic-signed-candidate-audit.json",paths["original"]),
        ("independent-signed-candidate-audit.json",paths["second"]),
    ):
        check((path/expected).is_file() and
              not (path/expected).is_symlink(),
              "missing independent original signed audit JSON")
    return paths

def main():
    ap=argparse.ArgumentParser()
    for arg in ("repository","run-id","directory"):
        ap.add_argument("--"+arg,required=True)
    a=ap.parse_args()
    try:
        result=download(a.repository,int(a.run_id),Path(a.directory))
        print("ORIGINAL_SIGNED_ARTIFACTS_REDOWNLOADED="+
              str(len(list(result["signed-dist"].iterdir())))+
              "; NO_PUBLISH; no signed proof until real Sigstore verification")
        return 0
    except (Denied,ValueError,KeyError,TypeError,OSError,
            subprocess.TimeoutExpired) as exc:
        print("ORIGINAL_SIGNED_DOWNLOAD_DENY: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
