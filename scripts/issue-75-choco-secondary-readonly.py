#!/usr/bin/env python3
"""Issue #75: inert read-only Chocolatey transitive package byte inventory.

Never runs Chocolatey/PowerShell/EXE, never installs, no auth or GitHub write.
Only actual downloaded bytes may be called SHA256-verified.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
import re
import sys
import subprocess
from urllib.parse import urlsplit
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from zipfile import ZipFile, BadZipFile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PARENT=ROOT/"evidence/issue-75/edb-pg14-18-exe-byte-observations-20261017.json"
PARENT_BLOB="cd820757fde0ae7fdd7d0e728b7076ef7d1dff10"
PACKAGES=(("chocolatey-core.extension","1.3.3"),
          ("vcredist140","14.23.27820"))
KB_PACKAGES=(("KB3033929","1.0.3"),("KB2919355","1.0.20160915"),
             ("kb2999226","1.0.20170509"))
ORIGINAL=ROOT/"evidence/issue-75/choco-secondary-observed-39039052934.json"
ORIGINAL_BLOB="244c016b7056761825dbf4a8bb3e77758cf40dbb"
SHA256=re.compile(r"[a-f0-9]{64}\Z")
SOURCE_PREFIX="https://community.chocolatey.org/api/v2/package/"
# Simple literal assignments. Do not interpret or execute PowerShell.
PROPERTIES=re.compile(r"(?im)^\s*(Url64|Url|Checksum64|Checksum|ChecksumType64|ChecksumType)\s*=\s*(['\"])(.*?)\2\s*(?:#.*)?$")
class Deny(ValueError): pass
def need(ok,why):
    if not ok:raise Deny(why)
def gitblob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def immutable_parent():
    data=PARENT.read_bytes()
    if gitblob(data)!=PARENT_BLOB:
        import subprocess
        p=subprocess.run(["git","show","HEAD:"+PARENT.relative_to(ROOT).as_posix()],
                         cwd=ROOT,capture_output=True,check=False,timeout=10)
        need(p.returncode==0,"parent Git blob unavailable")
        data=p.stdout
    need(gitblob(data)==PARENT_BLOB,"parent immutable proof changed")
    j=json.loads(data)
    need(j["verifiedInstallerCount"]==5 and j["acceptance"]["goB"]=="NO_GO" and
         j["acceptance"]["chocolateyDependencyBytesClosed"] is False,
         "previously approved root changed")
    for source in j["sources"]:
        need(len(source["sourcePackages"])==5,"five PostgreSQL package roots required")
        for pkg in source["sourcePackages"]:
            need(pkg["declaredChocolateyDependencies"]==[
                {"id":PACKAGES[0][0],"version":PACKAGES[0][1]},
                {"id":PACKAGES[1][0],"version":PACKAGES[1][1]}],
                "unexpected declared Chocolatey dependency")
    return j

def host_allowed(url,category):
    u=urlsplit(url)
    need(u.scheme=="https" and u.username is None and u.password is None and
         u.port in (None,443) and not u.fragment,"unsafe URL")
    if category=="nupkg":
        need(u.hostname in ("community.chocolatey.org","packages.chocolatey.org",
                            "globalcdn.nuget.org"),"unknown Chocolatey CDN")
    else:
        need(u.hostname=="download.visualstudio.microsoft.com",
             "unexpected Microsoft redistributable URL")
    return url

class StrictRedirect(HTTPRedirectHandler):
    def __init__(self, category):
        self.category=category
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        host_allowed(newurl,self.category)
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def get(url,category,maximum=25_000_000):
    host_allowed(url,category)
    req=Request(url,headers={"User-Agent":"pgextwin-issue75-readonly-sha256/1",
                             "Cache-Control":"no-cache"},method="GET")
    with build_opener(StrictRedirect(category)).open(req,timeout=45) as resp:
        host_allowed(resp.geturl(),category)
        need(resp.status==200,"bad HTTP result")
        raw=resp.read(maximum+1)
    need(0<len(raw)<=maximum,"missing/oversized public response")
    return raw

def parse_literals(text):
    """Conservative interpretation: collect literal URLs/hashes only."""
    pairs={}
    for key,quote,val in PROPERTIES.findall(text):
        k=key.lower()
        need(k not in pairs,"duplicate URL/checksum field")
        pairs[k]=val.strip()
    urls={}
    for url_key,digest_key,type_key in (
        ("url","checksum","checksumtype"),
        ("url64","checksum64","checksumtype64")):
        if url_key in pairs or digest_key in pairs:
            u=pairs.get(url_key)
            h=pairs.get(digest_key,"").lower()
            need(u and SHA256.fullmatch(h)!=None and
                 pairs.get(type_key,"").lower()=="sha256",
                 "unfixed or dynamically computed external installer checksum")
            host_allowed(u,"microsoft")
            need(u.endswith(".exe") and "/VC_redist." in u,"unexpected payload")
            urls[url_key]={"url":u,"sha256":h}
    return urls

def archive_inventory(raw,name,version):
    need(raw[:2]==b"PK" and len(raw)<=25_000_000,"bad nupkg")
    result={"name":name,"version":version,
            "archiveSHA256":hashlib.sha256(raw).hexdigest(),
            "archiveBytes":len(raw),"files":[],"dependencies":[],
            "scriptLiteralExternalDownloads":[],
            "scriptInspectionIsNotExecution":True,
            "fullPackageRuntimeDependencyClosure":False}
    with ZipFile(io.BytesIO(raw)) as zip:
        files=zip.infolist()
        need(0<len(files)<150 and
             sum(f.file_size for f in files)<55_000_000,
             "oversized expanded archive")
        nuspec=[f for f in files if f.filename.lower().endswith(".nuspec") and
                "/" not in f.filename]
        need(len(nuspec)==1,"ambiguous nuspec")
        ns=ET.fromstring(zip.read(nuspec[0]))
        tag=lambda e:e.tag.split("}")[-1]
        ids=[e.text for e in ns.iter() if tag(e)=="id"]
        versions=[e.text for e in ns.iter() if tag(e)=="version"]
        need(ids==[name] and versions==[version],"package id/version mismatch")
        for node in ns.iter():
            if tag(node)=="dependency":
                result["dependencies"].append({
                    "id":node.get("id",""),"version":node.get("version","")})
        need(len(result["dependencies"])<=20,"dependency explosion")
        for item in files:
            fn=item.filename
            need(not fn.startswith("/") and not "\\" in fn and
                 ".." not in fn.split("/") and len(fn)<300,
                 "zip path traversal")
            if item.is_dir():continue
            need(item.file_size<=15_000_000 and
                 item.compress_size<=15_000_000,"suspicious embedded byte limit")
            contents=zip.read(item)
            file_info={"path":fn,"bytes":len(contents),
                       "sha256":hashlib.sha256(contents).hexdigest()}
            result["files"].append(file_info)
            if fn.lower().endswith(".ps1"):
                need(len(contents)<150_000,"oversize PowerShell source")
                txt=contents.decode("utf-8-sig",errors="replace")
                literals=parse_literals(txt)
                result["scriptLiteralExternalDownloads"].append({
                    "path":fn,"scriptSHA256":file_info["sha256"],
                    "literalDownloadURLs":literals,
                    "containsDynamicPowerShell":True})
    return result

def double_read_package(name,version,download=get):
    need((name,version) in PACKAGES+KB_PACKAGES,"not allowlisted")
    url=SOURCE_PREFIX+name+"/"+version
    first=download(url,"nupkg",25_000_000)
    second=download(url,"nupkg",25_000_000)
    need(first==second,"public Chocolatey package changed between independent GETs")
    res=archive_inventory(first,name,version)
    res["independentGETs"]=2
    return res

def witness():
    need(os.environ.get("GITHUB_EVENT_NAME")=="pull_request" and
         os.environ.get("GITHUB_HEAD_REF")=="issue-75-choco-secondary-closure" and
         os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build" and
         os.environ.get("GITHUB_JOB")=="issue75_secondary_chocolatey_readonly",
         "wrong PR-only job")
    need(not os.environ.get("GH_TOKEN") and not os.environ.get("GITHUB_TOKEN"),
         "explicit credentials present")
    immutable_parent()
    packages=[double_read_package(*x) for x in PACKAGES]
    return {"decision":"TWO_CHOCOLATEY_PACKAGES_DOUBLE_HASHED_SOURCE_ONLY",
            "packages":packages,
            "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO",
            "runtimeClosureProven":False,"releaseAuthorized":False}

def original_observation():
    raw=ORIGINAL.read_bytes()
    if gitblob(raw)!=ORIGINAL_BLOB:
        p=subprocess.run(["git","show","HEAD:"+ORIGINAL.relative_to(ROOT).as_posix()],
                         cwd=ROOT,capture_output=True,check=False,timeout=12)
        need(p.returncode==0,"original Git Blob unavailable")
        raw=p.stdout
    need(gitblob(raw)==ORIGINAL_BLOB,"immutable two-package ledger changed")
    data=json.loads(raw)
    need(data.get("kind")=="ISSUE75_SECONDARY_NUPKG_REAL_BYTES_SOURCE_ONLY" and
         data.get("source")=={
           "repository":"pgextwin/build","runId":39039052934,"runAttempt":1,
           "headSha":"f2425a5523ad3a2e94d3ceea528b1d054c906de3",
           "jobId":117414622859,"runConclusion":"success",
           "url":"https://github.com/pgextwin/build/actions/runs/39039052934"},
         "invalid two-package source Run")
    need(data.get("boundary")=={
         "nupkgBytesVerified":2,"vcRedistExeBytesVerified":0,
         "kbDependencyPackagesVerified":0,"allRuntimeDependencyBytesVerified":False,
         "scriptExecuted":False,"publisherVerified":False,
         "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO",
         "formalReleaseAuthorized":False},"forged dependency acceptance")
    need(len(data.get("packages",[]))==2 and
         [(p["name"],p["version"]) for p in data["packages"]]==list(PACKAGES),
         "missing secondary package record")
    expected=[{"id":name,"version":version} for name,version in KB_PACKAGES]
    need(data["packages"][0]["dependencies"]==[] and
         data["packages"][1]["dependencies"]==[
           {"id":PACKAGES[0][0],"version":PACKAGES[0][1]},*expected],
         "unexpected further declared KB dependencies")
    return data

def actual_vcredist_bytes(package):
    candidates=[v for s in package["scriptLiteralExternalDownloads"]
                for v in [s["literalDownloadURLs"]]
                if "url" in v and "url64" in v]
    need(len(candidates)==1,"Microsoft EXE dynamic or missing URL/checksum")
    vc=candidates[0]
    results=[]
    for arch,key in (("x86","url"),("x64","url64")):
        row=vc[key]
        need(row["url"].endswith("VC_redist."+arch+".exe") and
             SHA256.fullmatch(row["sha256"]) is not None,
             "Microsoft EXE expected arch/digest mismatch")
        # Two truly independent HTTPS public GETs, each bounded at 45MB.
        a=get(row["url"],"microsoft",45_000_000)
        b=get(row["url"],"microsoft",45_000_000)
        need(len(a)>1_000_000 and a==b,"VC_redist EXE changed or too small")
        digest=hashlib.sha256(a).hexdigest()
        need(digest==row["sha256"],"actual VC_redist EXE SHA256 mismatch")
        results.append({"architecture":arch,"sha256":digest,"bytes":len(a),
                        "expectedSHA256":row["sha256"],"url":row["url"],
                        "GETs":2,"verified":True,"executed":False})
    return results

def observe_closure():
    immutable_parent()
    original=original_observation()
    packages=[double_read_package(*x) for x in PACKAGES]
    need(packages==original["packages"],"secondary archive or script changed since original Run")
    kb=[double_read_package(*x) for x in KB_PACKAGES]
    vc=actual_vcredist_bytes(packages[1])
    return {"decision":"MICROSOFT_TWO_EXE_AND_THREE_KB_ARCHIVES_SOURCE_ONLY_NO_GO",
            "originalRun":39039052934,"packages":packages,
            "kbPackages":kb,"vcRedistributableEXEs":vc,
            "vcExeVerified":2,"kbNupkgVerified":3,
            "kbExternalInstallerBytesVerified":False,
            "unreviewedScriptRuntimeSemantics":True,"goB":"NO_GO",
            "g4":"NO_GO","g5":"NO_GO","releaseAuthorized":False}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=("static","observe","closure"),default="static")
    mode=parser.parse_args().mode
    try:
        immutable_parent()
        if mode=="observe":out=witness()
        elif mode=="closure":out=observe_closure()
        else:out={"decision":"SECONDARY_PACKAGE_SOURCE_CONTRACT_ONLY",
                  "parents":5,"packages":2,"goB":"NO_GO","g4":"NO_GO","g5":"NO_GO",
                  "runtimeClosureProven":False,"releaseAuthorized":False}
        print(json.dumps(out,sort_keys=True))
        return 0
    except (Deny,OSError,ValueError,TypeError,KeyError,UnicodeError,
            BadZipFile,ET.ParseError) as exc:
        reason=(str(exc) if isinstance(exc,Deny) else type(exc).__name__)
        print(json.dumps({"decision":"DENY_SECONDARY_PACKAGE_SOURCE",
                          "reasonCode":reason[:100],
                          "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO",
                          "releaseAuthorized":False},sort_keys=True))
        return 2
if __name__=="__main__":sys.exit(main())
