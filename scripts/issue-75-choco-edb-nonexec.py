#!/usr/bin/env python3
"""Issue #75: read untrusted Chocolatey nupkg scripts as data, never execute.

Optional bounded public EDB download is a negative/inert witness only. No
Chocolatey install, no PowerShell invocation, no Signer/Writer/Release.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
from urllib.parse import urlsplit, urljoin
from urllib.request import Request, build_opener, HTTPRedirectHandler
from zipfile import ZipFile
ROOT=Path(__file__).resolve().parents[1]
OBS=ROOT/"evidence/issue-75/external-public-byte-observed-39034789275.json"
PG=ROOT/"metadata/postgresql.json"
SOURCE=ROOT/"scripts/issue-75-external-byte-probe.py"
spec=importlib.util.spec_from_file_location("public_byte_readonly",SOURCE)
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
SHA64=re.compile(r"[a-fA-F0-9]{64}\Z")
SIMPLE=re.compile(r"(?im)^\s*(url64|checksum64|checksumtype64|filetype)\s*=\s*(['\"])(.*?)\2\s*(?:#.*)?$")
EDB=re.compile(r"https://get\.enterprisedb\.com/postgresql/postgresql-(1[4-8])\.(\d+)-(\d+)-windows-x64\.exe\Z")
RECEIPT=ROOT/"evidence/issue-75/edb-pg14-18-exe-byte-observations-20261017.json"
RECEIPT_BLOB="cd820757fde0ae7fdd7d0e728b7076ef7d1dff10"
class Deny(ValueError):pass
def need(condition,why):
    if not condition:raise Deny(why)
def inspect_installer_script(raw,name,version):
    need(type(raw) is bytes and len(raw)<100000,"oversize installer source")
    need(b"\0" not in raw,"NUL script")
    script=raw.decode("utf-8-sig")
    kv={}
    for key,quote,value in SIMPLE.findall(script):
        k=key.lower()
        need(k not in kv,"duplicate literal property")
        kv[k]=value
    need(set(kv)=={"url64","checksum64","checksumtype64","filetype"},
         "not fully static 64-bit installer configuration")
    need(kv["checksumtype64"].lower()=="sha256" and
         kv["filetype"].lower()=="exe" and
         SHA64.fullmatch(kv["checksum64"]) is not None,
         "bad installer checksum/format")
    need("Install-ChocolateyPackage @packageArgs" in script,
         "unexpected install entrypoint")
    match=EDB.fullmatch(kv["url64"])
    need(match is not None,"not an exact EDB x64 URL")
    need(name=="postgresql"+match.group(1) and
         version.split(".")[0:2]==[match.group(1),match.group(2)],
         "EDB major/minor not bound to installed Chocolatey package")
    # Extraction does not assess all PowerShell behavior. All scripts remain
    # untrusted data; unknown dynamic operations cannot be run or whitelisted.
    return {"package":name,"version":version,"url64":kv["url64"],
            "checksum64":kv["checksum64"].lower(),
            "checksumType64":"sha256","fileType":"exe",
            "scriptSHA256":hashlib.sha256(raw).hexdigest(),
            "installerBytesSHA256Verified":False,
            "scriptWasExecuted":False,"unreviewedPowerShellBehavior":True}
def package_data(raw,name,version,expected_sha):
    need(hashlib.sha256(raw).hexdigest()==expected_sha,
         "nupkg changed from successful immutable CI witness")
    with ZipFile(io.BytesIO(raw)) as archive:
        files=[f for f in archive.infolist()
               if f.filename.lower().endswith("/chocolateyinstall.ps1")]
        need(len(files)==1 and files[0].file_size<=100000,
             "not exactly one bounded Chocolatey install script")
        namepath=files[0].filename.lower()
        need(namepath.startswith("tools/") and
             not any(x in namepath for x in ("../","\\","//")),
             "untrusted executable path in package")
        doc=archive.read(files[0])
        ns=[f for f in archive.infolist() if f.filename.endswith(".nuspec")]
        need(len(ns)==1 and ns[0].file_size<100000,"invalid nuspec evidence")
        import xml.etree.ElementTree as ET
        root=ET.fromstring(archive.read(ns[0]))
        deps=[]
        for e in root.iter():
            if e.tag.split("}")[-1]=="dependency":
                deps.append({"id":e.attrib.get("id",""),"version":e.attrib.get("version","")})
        need(len(deps)<20,"ambiguous transitive Chocolatey requirements")
    parsed=inspect_installer_script(doc,name,version)
    parsed["nupkgSHA256"]=expected_sha
    parsed["declaredChocolateyDependencies"]=deps
    return parsed
def inspect_five(fetch):
    record=base.load(OBS)
    old=record["observations"]["windows"]["chocolateyArchives"]
    need(len(old)==5 and record["boundaries"]["goB"]=="NO_GO",
         "original closed-world archive ledger drift")
    proof=[]
    for row in old:
        name,version=row["name"],row["version"]
        need(re.fullmatch(r"postgresql1[4-8]",name)!=None and
             re.fullmatch(r"\d+\.\d+\.\d+",version)!=None and
             row["GETs"]==2 and row["nupkgIdentityVerified"] is True,
             "original nupkg source unresolved")
        raw=fetch("https://community.chocolatey.org/api/v2/package/"+name+"/"+version,
                  1000000)
        need(len(raw)==row["nupkgBytes"],"original package length mismatch")
        proof.append(package_data(raw,name,version,row["nupkgSHA256"]))
    need(len(proof)==5 and len({x["package"] for x in proof})==5,
         "PG14..18 declared source incomplete")
    return proof

def verify_receipt(raw):
    # No claims about the original signed Publisher or actual installation.
    # This is an exact-source record of two independent successful PR Runs.
    need(base.gitblob(raw)==RECEIPT_BLOB,"EDB complete evidence Git Blob drift")
    data=json.loads(raw)
    need(type(data) is dict and data.get("schemaVersion")==1 and
         data.get("kind")=="ISSUE75_EDB_PG14_TO_18_EXE_BYTES_OBSERVED_READONLY_NO_GO",
         "EDB receipt kind")
    sources=data.get("sources")
    need(type(sources) is list and len(sources)==2,"missing source run")
    for row,run,sha,job in zip(sources,(39038000517,39038162434),
                               ("18826c6c6938df9323b8f0086b4fef6a044357bb",
                                "0a6649933e4ad313d3f0ce7cc84510a7a5e1a04e"),
                               (117411610495,117412082965)):
        need(row["source"]=={"runId":run,"attempt":1,"head":sha,"jobId":job,
                            "runConclusion":"success","jobConclusion":"success"},
             "original run-identity mismatch")
        need(len(row["sourcePackages"])==5,"missing nupkg source root")
    need(sources[0]["sourcePackages"]==sources[1]["sourcePackages"],
         "nupkg scripts differ between original successful runs")
    proofs=[item for row in sources for item in row["downloadedInstallers"]]
    need(data.get("verifiedInstallerCount")==5 and len(proofs)==5 and
         len({x["package"] for x in proofs})==5 and
         data.get("verifiedExeTotalBytes")==sum(x["bytesRead"] for x in proofs),
         "installer byte count drift")
    expected={e["package"]:e for e in sources[0]["sourcePackages"]}
    for item in proofs:
        pkg=expected[item["package"]]
        need(item["checksumFromChocolatey"]==pkg["checksum64"] and
             item["computedSHA256"]==pkg["checksum64"] and
             item["installerURL"]==pkg["url64"] and
             item["verified"] is True and item["status"]=="MATCH" and
             200000000<item["bytesRead"]<=420000000,
             "forged actual EDB EXE checksum match")
    need(data.get("acceptance")=={
        "actualPG14To18InstallerBytesMatchedChocolatey":True,
        "installedPostgresByThisAudit":False,
        "executedPowerShell":False,"executedExe":False,
        "postgresqlRuntimeClosureProven":False,
        "chocolateyDependencyBytesClosed":False,
        "signerPinsModified":False,
        "signedPublisherPrewriteProven":False,
        "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO","releaseAuthorized":False},
        "forged runtime/publish acceptance")
    return data
def read_receipt():
    raw=RECEIPT.read_bytes()
    if base.gitblob(raw)!=RECEIPT_BLOB:
        # core.autocrlf on Windows may change checkout worktree bytes; Git
        # object is authoritative, no network access or credential required.
        cmd=["git","show","HEAD:"+RECEIPT.relative_to(ROOT).as_posix()]
        p=subprocess.run(cmd,cwd=ROOT,capture_output=True,check=False,timeout=12)
        need(p.returncode==0,"Git receipt object unavailable")
        raw=p.stdout
    return verify_receipt(raw)

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        return None
def bounded_installer_get(row, maximum=420_000_000):
    """One stream probe, max 420MB, allowlisted redirect target; never run EXE."""
    need(row["checksumType64"]=="sha256" and
         SHA64.fullmatch(row["checksum64"]) is not None and
         EDB.fullmatch(row["url64"]) is not None, "no trusted EDB checksum")
    url=row["url64"]
    opener=build_opener(NoRedirect())
    redirects=0
    total=0
    result={"package":row["package"],"installerURL":url,
            "checksumFromChocolatey":row["checksum64"],
            "bytesRead":0,"verified":False,"status":"NOT_OBSERVED"}
    try:
        for _ in range(4):
            host=urlsplit(url).hostname or ""
            need(urlsplit(url).scheme=="https" and
                 (host=="get.enterprisedb.com" or host.endswith(".s3.amazonaws.com")
                  or host in {"s3.amazonaws.com","downloads.enterprisedb.com"}),
                 "unallowlisted EDB redirect")
            req=Request(url,method="GET",headers={"User-Agent":"pgextwin-issue75-inert-edb-audit/1"})
            try:
                stream=opener.open(req,timeout=45)
                break
            except urllib.error.HTTPError as e:
                if e.code not in (301,302,303,307,308):raise
                location=e.headers.get("Location")
                need(bool(location),"missing redirect location")
                redirects+=1
                url=urljoin(url,location)
        else:raise Deny("excessive redirects")
        with stream as body:
            h=hashlib.sha256()
            while True:
                data=body.read(1024*1024)
                if not data:break
                total+=len(data)
                need(total<=maximum,"installer byte budget exceeded")
                h.update(data)
        result["bytesRead"]=total
        need(total>1_000_000,"unexpectedly short installer")
        result["computedSHA256"]=h.hexdigest()
        result["verified"]=h.hexdigest()==row["checksum64"]
        result["status"]="MATCH" if result["verified"] else "CHECKSUM_MISMATCH"
        need(result["verified"],"untrusted EDB installer content")
    except (OSError,TimeoutError,urllib.error.URLError,Deny):
        if result["status"]=="CHECKSUM_MISMATCH":
            raise Deny("EDB_SHA256_MISMATCH")
        if result["status"]=="NOT_OBSERVED":result["status"]="UNAVAILABLE_OR_BOUNDED"
        # Resource/network obstacles are honestly NOT_PROVEN; digest mismatches
        # cannot become success and MUST fail the job.
        if total>0 and result["status"]=="UNAVAILABLE_OR_BOUNDED":
            result["bytesRead"]=total
    result["redirectCount"]=redirects
    return result

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=("static","inspect","canary","remaining"),default="static")
    args=ap.parse_args()
    out={"decision":"DENY_INSTALLER_SOURCE","goB":"NO_GO","g4":"NO_GO",
         "g5":"NO_GO","publicationAuthorized":False}
    try:
        receipt=read_receipt()
        out["recordedExeMatches"]=receipt["verifiedInstallerCount"]
        out["recordedExeBytes"]=receipt["verifiedExeTotalBytes"]
        if args.mode=="static":
            # Immutable two-Run record; no live download or trust upgrade.
            need(EDB.fullmatch("https://get.enterprisedb.com/postgresql/postgresql-14.24-1-windows-x64.exe") is not None,"EDB URL parser")
            out["decision"]="RECORDED_FIVE_INSTALLER_BYTES_SOURCE_ONLY"
        else:
            need(os.environ.get("GITHUB_EVENT_NAME")=="pull_request" and
                 os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build" and
                 os.environ.get("GITHUB_HEAD_REF")=="issue-75-edb-installer-wheel-lock" and
                 os.environ.get("GITHUB_JOB")=="issue75_choco_script_probe",
                 "not the isolated PR-only job")
            need(not os.environ.get("GH_TOKEN") and not os.environ.get("GITHUB_TOKEN"),
                 "credentials observed")
            data=inspect_five(base.fetch_bytes)
            need(data==receipt["sources"][0]["sourcePackages"],
                 "new nupkg script no longer matches verified receipt")
            out.update(decision="CHOCOLATEY_SCRIPT_LITERAL_SHA256_ONLY",
                       sourcePackages=data,sourceScriptCount=len(data),
                       installerByteVerifiedCount=0)
            if args.mode=="canary":
                out["canary"]=bounded_installer_get(data[0])
                out["installerByteVerifiedCount"]=int(out["canary"]["verified"])
                if out["canary"]["verified"]:
                    out["decision"]="ONE_EDB_INSTALLER_SOURCE_AND_BYTES_MATCH_NO_GO"
            if args.mode=="remaining":
                out["remainingInstallers"]=[bounded_installer_get(row) for row in data[1:]]
                out["installerByteVerifiedCount"]=sum(int(x["verified"]) for x in out["remainingInstallers"])
                if out["installerByteVerifiedCount"]==4:
                    out["decision"]="FOUR_EDB_INSTALLER_BYTES_MATCH_NO_GO"
                else:
                    out["decision"]="INCOMPLETE_EDB_INSTALLER_BYTES_NO_GO"
        print(json.dumps(out,sort_keys=True));return 0
    except (Deny,OSError,ValueError,TypeError,KeyError,UnicodeError):
        print(json.dumps(out,sort_keys=True));return 2
if __name__=="__main__":sys.exit(main())
