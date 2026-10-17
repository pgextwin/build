#!/usr/bin/env python3
"""Issue #75: inert CPython 3.13 wheel candidate, reproducible offline download.

Never installs or runs a wheel, touches Signer/Publisher, or promotes a Release.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
LOCK=ROOT/"evidence/issue-75/python-wheel-lock-candidate-20261017.json"
SOURCE=ROOT/"evidence/issue-75/external-public-byte-observed-39034789275.json"
EXPECTED_SOURCE_GIT_BLOB="c5acb7920a5d9871eacef54a01a92ae71677a24f"
SHA64=re.compile(r"[0-9a-f]{64}\Z")
class Deny(ValueError):pass
def need(x): 
    if not x:raise Deny("inert wheel lock rejected")
def load(path):
    data=path.read_bytes();need(len(data)<60000)
    def unique(pairs):
        d={}
        for k,v in pairs:
            need(k not in d);d[k]=v
        return d
    return json.loads(data.decode(),object_pairs_hook=unique)
def git_blob(data):return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
def validated(lock,raw_source):
    need(git_blob(raw_source)==EXPECTED_SOURCE_GIT_BLOB)
    source=json.loads(raw_source)
    need(type(lock) is dict and lock.get("schemaVersion")==1 and lock.get("kind")=="ISSUE75_OFFLINE_WHEEL_LOCK_CANDIDATE_NONDEPLOYED")
    need(lock.get("source")=={"runId":39034789275,"runAttempt":1,
         "headSha":"f32e43d55e5613e6b985b1f37e883800e6f2127c",
         "evidenceBlob":EXPECTED_SOURCE_GIT_BLOB})
    need(lock.get("pythonTarget")=="3.13" and lock.get("arch")=="x64" and lock.get("onlyBinary") is True)
    need(lock.get("boundary")=={"offlineWheelCandidateValidated":False,
        "signerPipInstallModified":False,"wheelHashesPinnedInSigner":False,
        "fullyReproducibleSigner":False,"goB":"NO_GO","g4":"NO_GO",
        "g5":"NO_GO","publicationAuthorized":False})
    pkgs=lock.get("packages")
    need(type(pkgs) is dict and len(pkgs)==8 and
         {"attrs","jsonschema","jsonschema-specifications","meson","ninja",
          "referencing","rpds-py","typing-extensions"}==set(pkgs))
    seen={"ubuntu":{}, "windows":{}}
    for name,v in pkgs.items():
        need(re.fullmatch(r"[a-z][a-z0-9-]{1,40}",name)!=None)
        need(type(v) is dict and set(v)=={"version","platforms"} and
             re.fullmatch(r"[0-9]+(?:\.[0-9]+)*",v["version"])!=None)
        need(type(v["platforms"]) is dict and set(v["platforms"])==set(seen))
        for platform in seen:
            f=v["platforms"][platform]
            need(type(f) is dict and set(f)=={"filename","sha256"} and
                 re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl",f["filename"])!=None and
                 SHA64.fullmatch(f["sha256"])!=None)
            stem=f["filename"].split("-")
            need(len(stem)>=5 and stem[0].replace("_","-").lower()==name and
                 stem[1]==v["version"])
            need(f["filename"] not in seen[platform])
            seen[platform][f["filename"]]=f["sha256"]
    for platform in seen:
        need(seen[platform]==source["observations"][platform]["wheelInventory"]["wheels"])
    return seen
def requirements(lock,platform):
    need(platform in ("ubuntu","windows"))
    lines=["# Candidate only; never injected into the active Signer.",
           "--only-binary=:all:"]
    for name in sorted(lock["packages"]):
        p=lock["packages"][name]
        lines.append(f'{name}=={p["version"]} --hash=sha256:{p["platforms"][platform]["sha256"]}')
    return "\n".join(lines)+"\n"
def check_wheelhouse(folder,expected):
    files=list(Path(folder).iterdir())
    need(len(files)==8)
    got={}
    for file in files:
        need(file.is_file() and not file.is_symlink() and file.name in expected)
        h=hashlib.sha256()
        with file.open("rb") as inp:
            for chunk in iter(lambda:inp.read(1024*1024),b""):h.update(chunk)
        need(h.hexdigest()==expected[file.name])
        got[file.name]=h.hexdigest()
    need(got==expected)
def offline_probe(lock,seen,platform):
    # Binary-only pip download, never install or execute package content.
    # Online acquisition pinned by digest, then no-index offline re-resolution.
    need(os.environ.get("GITHUB_EVENT_NAME")=="pull_request" and
         os.environ.get("GITHUB_HEAD_REF")=="issue-75-edb-installer-wheel-lock" and
         os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build" and
         os.environ.get("GITHUB_JOB")=="issue75_wheel_lock_probe")
    need(not os.environ.get("GH_TOKEN") and not os.environ.get("GITHUB_TOKEN"))
    target="manylinux2014_x86_64" if platform=="ubuntu" else "win_amd64"
    clean=os.environ.copy()
    for name in list(clean):
        if name.startswith("PIP_") or name in ("GH_TOKEN","GITHUB_TOKEN","ACTIONS_RUNTIME_TOKEN"):
            clean.pop(name,None)
    clean["PIP_NO_INPUT"]="1"
    with tempfile.TemporaryDirectory(prefix="pgextwin-inert-wheel-") as dirname:
        base=Path(dirname); req=base/"hash-candidate.txt";req.write_text(requirements(lock,platform))
        online=base/"downloaded";offline=base/"offline";online.mkdir();offline.mkdir()
        args=[sys.executable,"-m","pip","--isolated","download","--no-deps",
              "--no-cache-dir","--disable-pip-version-check","--no-input",
              "--only-binary=:all:","--require-hashes","--platform",target,
              "--python-version","3.13","--implementation","cp","--abi","cp313"]
        for is_offline,dest in ((False,online),(True,offline)):
            extra=(["--no-index","--find-links",str(online)] if is_offline else
                   ["--index-url","https://pypi.org/simple"])
            ret=subprocess.run(args+extra+["--dest",str(dest),"-r",str(req)],
                env=clean,capture_output=True,text=True,stdin=subprocess.DEVNULL,
                check=False,timeout=180)
            need(ret.returncode==0)
            check_wheelhouse(dest,seen[platform])
    return True
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=("static","ubuntu","windows"),default="static")
    mode=ap.parse_args().mode
    result={"decision":"DENY_OFFLINE_WHEEL_CANDIDATE","goB":"NO_GO","g4":"NO_GO",
            "g5":"NO_GO","publicationAuthorized":False}
    try:
        lock=load(LOCK);seen=validated(lock,SOURCE.read_bytes())
        result.update(decision="HASHED_WHEEL_LOCK_CANDIDATE_ONLY",
                      packageCount=len(lock["packages"]),platforms=2,
                      wheelFiles=16,signerModified=False,
                      offlineWheelReadbackProven=False)
        if mode!="static":
            offline_probe(lock,seen,mode)
            result.update(decision="OFFLINE_WHEELHOUSE_REPRODUCED_NO_GO",
                          platform=mode,offlineWheelReadbackProven=True)
        print(json.dumps(result,sort_keys=True));return 0
    except (Deny,OSError,KeyError,ValueError,TypeError,subprocess.TimeoutExpired):
        print(json.dumps(result,sort_keys=True));return 2
if __name__=="__main__":sys.exit(main())
