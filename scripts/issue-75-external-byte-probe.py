#!/usr/bin/env python3
"""Issue #75: bounded public-byte observations only; never a dependency approval.

Offline contract (--mode static) + opt-in PR-only unsigned public downloads:
Git action bundle/lockfile source-bytes, platform-specific PyPI binary wheels,
Chocolatey nupkg archives. No token, no installs, no GitHub writes, no release.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET
from zipfile import ZipFile, BadZipFile

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "evidence/issue-75/external-byte-probe-plan-20261017.json"
ROOT_RECORD = ROOT / "evidence/issue-75/action-roots-signer-hardening-20261017.json"
PG = ROOT / "metadata/postgresql.json"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
EXPECTED_BUNDLES = {
 "actions/checkout": [("dist/index.js","06ae5d221b3dc83259d396ec60027972181e51b9",1452503)],
 "actions/setup-python": [("dist/setup/index.js","6ac18cd5ee65fee78ba70a0af27c6c5425113622",3573880)],
 "actions/upload-artifact": [("dist/upload/index.js","a36d775b02159bad1b24bf1ac3a314bc456a6fb5",4450352)],
 "actions/download-artifact": [("dist/index.js","d7aade707a79a3bc4130f2605987cbbf2ecfac6c",4425394)],
 "actions/attest": [("dist/index.js","ae6dd7873447202be6e0a3f99a5472e31fe86b6e",4868977)],
 "actions/create-github-app-token": [("dist/main.cjs","20b90dce8c14c24222d6552fac6a4d5e2866a7d6",945857),
                                    ("dist/post.cjs","8e50446c010d08891cf91a3f7f06f343b7e44997",889303)],
}
PIP_REQUIREMENTS = ["jsonschema>=4,<5", "meson==1.8.3", "ninja==1.11.1.4"]
PIP_TARGETS = {"action-python": ("manylinux2014_x86_64","ubuntu-latest"),
               "chocolatey-python": ("win_amd64","windows-latest")}
ALLOWED_HOSTS = frozenset({"raw.githubusercontent.com","community.chocolatey.org",
                           "packages.chocolatey.org","globalcdn.nuget.org"})
class Deny(ValueError):
    pass
def need(x, why):
    if not x: raise Deny(why)
def load(path):
    raw = path.read_bytes()
    need(len(raw) < 160000, "oversize manifest")
    def pairs(items):
        d={}
        for k,v in items:
            need(k not in d, "duplicate JSON field")
            d[k]=v
        return d
    return json.loads(raw.decode("utf-8"),object_pairs_hook=pairs)
def gitblob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def verify_gitblob(raw,sha,size=None):
    need(type(raw) is bytes and SHA40.fullmatch(sha or "") is not None,
         "invalid Git blob evidence")
    if size is not None: need(len(raw)==size,"wrong downloaded file size")
    need(gitblob(raw)==sha, "raw bytes do not match immutable Git blob")
    return hashlib.sha256(raw).hexdigest()
def inspect(plan,root,pg):
    need(type(plan) is dict and plan.get("schemaVersion")==1 and
         plan.get("kind")=="ISSUE75_PUBLIC_EXTERNAL_BYTES_NO_PUBLISH_PROBE",
         "unrecognized public-byte evidence contract")
    base=plan.get("baseline")
    need(type(base) is dict and base == {
       "actionRootRecord":"evidence/issue-75/action-roots-signer-hardening-20261017.json",
       "actionRootRecordSourceCommit":"050adfaacba003b60c769e900b3b1f311c094b72",
       "postgresqlMetadataBlob":"44efa0bd070f75e67fbc31fd07820b2e0fad560d",
       "signerPin":"5756b3c5136a8bf4db710016cfe97555f0a71c6d",
       "ubuntuImageVersion":"20261012.334.1","ubuntuImageOs":"ubuntu24",
       "windowsImageVersion":"20261007.264.1","windowsImageOs":"win25-vs2026"},
       "baseline action, lifecycle or signer root drift")
    need(type(root) is dict and root.get("schemaVersion")==1 and
         root.get("kind")=="ISSUE75_SIGNER_CHECKOUT_ACTION_ROOTS_OFFLINE_NO_GO",
         "unknown prior immutable Action record")
    acts=plan.get("actions")
    need(type(acts) is dict and set(acts)==set(EXPECTED_BUNDLES)==set(root["actions"]),
         "missing/added action bundle")
    for name, bundles in EXPECTED_BUNDLES.items():
        r=root["actions"][name]; o=acts[name]
        need(type(o) is dict and set(o)=={"commit","files"} and
             o["commit"]==r["commit"] and type(o["files"]) is list,
             "action root/record drift")
        required={(path,sha,size,"action_bundle") for path,sha,size in bundles}
        required.add(("package-lock.json",r["lockBlob"],None,"lockfile"))
        got=set()
        for f in o["files"]:
            need(type(f) is dict and set(f)==
                 ({"kind","path","gitBlob"} if f.get("kind")=="lockfile"
                  else {"kind","path","gitBlob","size"}),
                 "invalid action file schema")
            tup=(f["path"],f["gitBlob"],f.get("size"),f["kind"])
            need(tup in required and tup not in got,"new/missing action file identity")
            got.add(tup)
        need(got==required,"incomplete action byte source inventory")
    py=plan.get("python")
    need(type(py) is dict and py=={
        "requirements":PIP_REQUIREMENTS,
        "platforms":[
          {"os":"ubuntu-latest","pipPlatform":"manylinux2014_x86_64",
           "pythonVersion":"3.13","implementation":"cp","abi":"cp313"},
          {"os":"windows-latest","pipPlatform":"win_amd64",
           "pythonVersion":"3.13","implementation":"cp","abi":"cp313"}],
        "wheelHashesPinnedInSigner":False,"pipIndex":"https://pypi.org/simple",
        "twoIndependentDownloadSets":True}, "Python wheel scope or floating semantics changed")
    chocolatey=plan.get("chocolatey")
    need(type(pg) is dict and pg.get("schemaVersion")==1 and
         type(pg.get("postgresql")) is list and len(pg["postgresql"])==5,
         "lifecycle PG package metadata unreadable")
    expected=[{"name":e["chocolateyPackage"],"version":e["chocolateyVersion"]}
              for e in pg["postgresql"]]
    need(type(chocolatey) is dict and chocolatey=={
        "packages":expected,
        "requestPrefix":"https://community.chocolatey.org/api/v2/package/",
        "twoIndependentDownloads":True,
        "nupkgHashesPinnedInSigner":False,
        "installerBinaryHashesVerified":False},
        "Chocolatey version/source or verification assertion drift")
    classification=plan.get("classification")
    need(type(classification) is dict and classification =={
         "observationsOnly":True,"actionTreeOrBlobNotExecutableAttestation":True,
         "publishedReleasesVerified":False,
         "signerRuntimeDependenciesLocked":False,
         "readerSignerWriterIsolationProven":False,
         "signedPublisherPositivePrewriteProven":False,
         "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO","publicationAuthorized":False},
         "forged external byte closure GO B acceptance")
    return {"decision":"BOUNDED_PUBLIC_BYTE_PLAN_ONLY","actionRoots":len(acts),
            "actionBundles":sum(len(v) for v in EXPECTED_BUNDLES.values()),
            "actionLockfiles":len(acts),"pipDependencyHashesPinned":False,
            "chocolateyPackageHashesPinned":False,
            "runnerImagePinned":False,"goB":"NO_GO","g4":"NO_GO",
            "g5":"NO_GO","publicationAuthorized":False}

def allow_url(url, allowed=ALLOWED_HOSTS):
    u=urlsplit(url)
    need(u.scheme=="https" and u.hostname in allowed and
         not u.username and not u.password and (u.port is None or u.port==443)
         and not u.fragment, "external download URL not allowlisted")
    return url

def fetch_bytes(url,max_size):
    allow_url(url)
    need(type(max_size) is int and 0<max_size<=30_000_000,
         "unsafe download limit")
    req=Request(url,headers={"User-Agent":"pgextwin-issue75-inert-byte-audit/1",
                             "Cache-Control":"no-cache"}, method="GET")
    with urlopen(req,timeout=40) as response:
        allow_url(response.geturl())
        need(response.status==200,"public binary GET failed")
        raw=response.read(max_size+1)
    need(0<len(raw)<=max_size,"empty/oversize download")
    return raw

def download_actions(plan):
    records=[]
    for repo,data in sorted(plan["actions"].items()):
        for f in data["files"]:
            url=f"https://raw.githubusercontent.com/{repo}/{data['commit']}/{f['path']}"
            maximum=(f.get("size",5000000)+1) if f["kind"]=="action_bundle" else 5000000
            maximum=min(maximum,12000000)
            one=fetch_bytes(url,maximum)
            two=fetch_bytes(url,maximum)
            sha1=verify_gitblob(one,f["gitBlob"],f.get("size"))
            sha2=verify_gitblob(two,f["gitBlob"],f.get("size"))
            need(sha1==sha2,"inconsistent duplicate public action GET")
            records.append({"repository":repo,"path":f["path"],"bytes":len(one),
                            "gitBlobVerified":True,"sha256":sha1,
                            "GETs":2,"executableAttestation":False})
    return records

def inspect_nupkg(raw,name,version):
    need(len(raw)<30_000_000 and raw[:2]==b"PK","untrusted nupkg zip")
    with ZipFile(io.BytesIO(raw)) as archive:
        candidates=[i for i in archive.infolist()
                    if i.filename.lower().endswith(".nuspec") and "/" not in i.filename]
        need(len(candidates)==1 and candidates[0].file_size<200_000,
             "missing/ambiguous nupkg identity")
        e=ET.fromstring(archive.read(candidates[0]))
        def field(key):
            return [n.text for n in e.iter() if n.tag.split("}")[-1]==key]
        need(field("id")==[name] and field("version")==[version],
             "nupkg package identity mismatch")
        installers=[x for x in archive.infolist()
                    if x.filename.lower().endswith("chocolateyinstall.ps1")]
        need(len(installers)<=2, "ambiguous chocolatey install scripts")
        externalInstallers=bool(installers)
    return externalInstallers

def download_chocolatey(plan):
    output=[]
    for entry in plan["chocolatey"]["packages"]:
        name,version=entry["name"],entry["version"]
        need(re.fullmatch(r"postgresql1[4-8]",name)!=None and
             re.fullmatch(r"\d+\.\d+\.\d+",version)!=None,
             "untrusted Chocolatey package identifier")
        url=plan["chocolatey"]["requestPrefix"]+name+"/"+version
        first=fetch_bytes(url,25_000_000)
        second=fetch_bytes(url,25_000_000)
        need(hashlib.sha256(first).digest()==hashlib.sha256(second).digest(),
             "Chocolatey download bytes differ between independent GETs")
        is_installer=inspect_nupkg(first,name,version)
        output.append({"name":name,"version":version,"nupkgBytes":len(first),
                       "nupkgSHA256":hashlib.sha256(first).hexdigest(),
                       "GETs":2,"nupkgIdentityVerified":True,
                       "containsInstallScript":is_installer,
                       "postgresqlInstallerSHA256Verified":False})
    return output

def wheel_inventory(folder):
    root=Path(folder)
    entries=sorted(root.iterdir(),key=lambda p:p.name)
    need(2<=len(entries)<=50, "incomplete/oversize wheel set")
    result={}
    total=0
    for file in entries:
        need(file.is_file() and not file.is_symlink() and file.suffix==".whl"
             and re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl",file.name),
             "unexpected pip artifact")
        need(file.stat().st_size<50_000_000,"oversize wheel")
        raw=file.read_bytes()
        total+=len(raw)
        need(total<120_000_000,"oversize total downloaded wheel set")
        with ZipFile(io.BytesIO(raw)) as wheel:
            need(any(n.endswith(".dist-info/WHEEL") for n in wheel.namelist()),
                 "invalid wheel archive")
        result[file.name]=hashlib.sha256(raw).hexdigest()
    return result

def download_wheels(plan, mode):
    platform,os_name=PIP_TARGETS[mode]
    results=[]
    with tempfile.TemporaryDirectory(prefix="issue75-pip-public-bytes-") as tmp:
        for attempt in (1,2):
            dest=Path(tmp)/str(attempt)
            dest.mkdir()
            args=[sys.executable,"-m","pip","--isolated","download",
                  "--no-cache-dir","--disable-pip-version-check","--no-input",
                  "--only-binary=:all:","--index-url","https://pypi.org/simple",
                  "--platform",platform,"--python-version","3.13",
                  "--implementation","cp","--abi","cp313",
                  "--dest",str(dest),*PIP_REQUIREMENTS]
            env=os.environ.copy()
            for name in ("GH_TOKEN","GITHUB_TOKEN","ACTIONS_RUNTIME_TOKEN",
                         "PIP_INDEX_URL","PIP_EXTRA_INDEX_URL","PIP_TRUSTED_HOST"):
                env.pop(name,None)
            env["PIP_NO_INPUT"]="1"
            proc=subprocess.run(args,env=env,stdin=subprocess.DEVNULL,
                                capture_output=True,text=True,timeout=150,
                                check=False)
            need(proc.returncode==0,"public PyPI binary-only wheel resolution unavailable")
            results.append(wheel_inventory(dest))
    need(results[0]==results[1],"PyPI wheel resolution or bytes drift between runs")
    return {"platform":platform,"pythonTarget":"cp313",
            "independentDownloadSets":2,"wheels":results[0],
            "hashesLockedBySigner":False}

def runner(mode,plan):
    os_name="ubuntu" if mode=="action-python" else "windows"
    image=os.environ.get("ImageOS","UNKNOWN")
    version=os.environ.get("ImageVersion","UNKNOWN")
    need(bool(re.fullmatch(r"[A-Za-z0-9._-]{1,100}",image)) and
         bool(re.fullmatch(r"[A-Za-z0-9._-]{1,100}",version)),
         "invalid runner version")
    return {"runner":os_name,"imageOS":image,"imageVersion":version,
            "baselineImageVersion":plan["baseline"][os_name+"ImageVersion"],
            "changedSincePriorProbe":(
                image!=plan["baseline"][os_name+"ImageOs"] or
                version!=plan["baseline"][os_name+"ImageVersion"]),
            "imageDigestPinned":False}
def main(argv=None):
    p=argparse.ArgumentParser(description="Nonpublishing Action/PyPI/choco SHA256 observation")
    p.add_argument("--mode",choices=["static","action-python","chocolatey-python"],
                   default="static")
    mode=p.parse_args(argv).mode
    out={"decision":"DENY_PUBLIC_BYTE_PROBE","goB":"NO_GO","g4":"NO_GO",
         "g5":"NO_GO","publicationAuthorized":False}
    try:
        plan,root,pg=load(PLAN),load(ROOT_RECORD),load(PG)
        out=inspect(plan,root,pg)
        if mode!="static":
            need(os.environ.get("GITHUB_EVENT_NAME")=="pull_request" and
                 os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build" and
                 os.environ.get("GITHUB_HEAD_REF")=="issue-75-external-byte-closure-probe" and
                 os.environ.get("GITHUB_JOB")=="issue75_public_byte_probe",
                 "non-isolated job identity")
            need(not any(os.environ.get(k) for k in ("GH_TOKEN","GITHUB_TOKEN")),
                 "unexpected explicit credentials")
            out["runner"]=runner(mode,plan)
            if mode=="action-python":
                out["actionFiles"]=download_actions(plan)
            else:
                out["chocolateyArchives"]=download_chocolatey(plan)
            out["wheelInventory"]=download_wheels(plan,mode)
            out["decision"]="PUBLIC_BYTES_DOUBLE_HASHED_SOURCE_ONLY_NO_GO"
        print(json.dumps(out,sort_keys=True))
        return 0
    except (Deny,OSError,ValueError,TypeError,KeyError,UnicodeError,
            subprocess.TimeoutExpired,BadZipFile,ET.ParseError) as exc:
        # Do not reveal server errors, resolved URLs, environment or download bodies.
        print(json.dumps({"decision":"DENY_PUBLIC_BYTE_PROBE","reasonCode":
                          "MISSING_MISMATCHED_OR_UNAVAILABLE_PUBLIC_BYTE_EVIDENCE",
                          "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO",
                          "publicationAuthorized":False},sort_keys=True))
        return 2
if __name__=="__main__":sys.exit(main())
