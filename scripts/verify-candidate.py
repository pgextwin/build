#!/usr/bin/env python3
"""Verify real per-PG Windows candidate artifacts, never a Release."""
import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from zipfile import ZipFile

SHA = re.compile(r"^[0-9a-f]{40}$")
OWNED = re.compile(r"^auto-candidate/([0-9a-f]{20})$")

def eligible(ext, lifecycle, today):
    pg = ext["postgresql"]
    configured = {int(m) for m in pg["majors"]} if "majors" in pg else set(range(int(pg["minMajor"]), int(pg["maxMajor"]) + 1))
    if lifecycle.get("schemaVersion") != 1 or not isinstance(lifecycle.get("postgresql"), list):
        raise ValueError("invalid PostgreSQL lifecycle")
    result = sorted({int(x["major"]) for x in lifecycle["postgresql"]
                     if int(x["major"]) in configured and date.fromisoformat(x["eol"]) >= today})
    if not result:
        raise ValueError("no eligible PostgreSQL major")
    return result

def one(folder, ext, major, runid, branch_sha, branch):
    files=list(folder.iterdir())
    zips=list(folder.glob("*.zip"))
    sboms=list(folder.glob("*.spdx.json"))
    reports=list(folder.glob("*.vulnerabilities.json"))
    if len(zips)!=1 or len(sboms)!=1 or len(reports)!=1 or len(files)!=3:
        raise ValueError("missing or unexpected ZIP, SPDX or Grype artifact")
    with ZipFile(zips[0]) as z:
        if z.namelist().count("PACKAGE-INFO.json") != 1:
            raise ValueError("missing embedded root PACKAGE-INFO.json")
        pkg=json.loads(z.read("PACKAGE-INFO.json").decode("utf-8-sig"))
    source=ext["upstream"].get("perPostgresql",{}).get(str(major),ext["upstream"])
    if not SHA.fullmatch(str(source.get("commit",""))):
        raise ValueError("missing immutable upstream SHA for major")
    checks=[
        (pkg.get("buildMode"),"normal"),
        (pkg.get("package",{}).get("name"),ext["name"]),
        (pkg.get("postgresql",{}).get("major"),major),
        (pkg.get("upstream",{}).get("repository"),ext["upstream"]["repository"]),
        (pkg.get("upstream",{}).get("ref"),source["ref"]),
        (pkg.get("upstream",{}).get("version"),str(source["version"])),
        (pkg.get("upstream",{}).get("commit"),source["commit"]),
        (pkg.get("source",{}).get("packagingRepository"),"pgextwin/"+ext["name"]),
        (pkg.get("source",{}).get("packagingCommit"),branch_sha),
        (pkg.get("workflowRun",{}).get("id"),runid),
        (pkg.get("workflowRun",{}).get("event"),"workflow_dispatch"),
        (pkg.get("workflowRun",{}).get("ref"),"refs/heads/"+branch)
    ]
    if any(actual!=expected for actual,expected in checks):
        raise ValueError("package identity / SHA / major / run does not match candidate manifest")
    spdx=json.loads(sboms[0].read_text(encoding="utf-8-sig"))
    grype=json.loads(reports[0].read_text(encoding="utf-8-sig"))
    if not isinstance(spdx,dict) or spdx.get("spdxVersion")!="SPDX-2.3":
        raise ValueError("invalid SPDX")
    if not isinstance(grype,dict) or not isinstance(grype.get("matches"),list):
        raise ValueError("invalid Grype JSON")
    return {"major":major,"status":"SUCCESS","sourceSha":source["commit"],
            "zipSha256":hashlib.sha256(zips[0].read_bytes()).hexdigest(),
            "zip":zips[0].name,"sbom":sboms[0].name,"grype":reports[0].name}

def audit(root, ext, lifecycle, runid, branch_sha, branch, matrix_result, today):
    if not SHA.fullmatch(branch_sha) or not OWNED.fullmatch(branch):
        raise ValueError("invalid candidate commit or branch")
    majors=eligible(ext,lifecycle,today)
    items=[]
    for major in majors:
        folder=root/(ext["name"]+"-pg"+str(major)+"-windows-x64")
        try:
            if not folder.is_dir():
                raise ValueError("missing PG-major Actions artifact")
            items.append(one(folder,ext,major,runid,branch_sha,branch))
        except (ValueError,OSError,KeyError,TypeError) as e:
            items.append({"major":major,"status":"FAILED","error":str(e)})
    status="VERIFIED" if matrix_result=="success" and all(x["status"]=="SUCCESS" for x in items) else "FAILED"
    return {"schemaVersion":1,"extension":ext["name"],"runId":runid,"branch":branch,
            "branchSha":branch_sha,"matrixResult":matrix_result,"status":status,"majors":items}

def gh(*argv):
    p=subprocess.run(["gh",*argv],text=True,capture_output=True)
    if p.returncode:
        raise ValueError("GitHub CLI call failed: "+p.stderr[:300])
    return p.stdout

def comment(report,repo,path):
    m=OWNED.fullmatch(report["branch"])
    if not m or repo!="pgextwin/"+report["extension"]:
        raise ValueError("untrusted PR/repository identifier")
    prs=json.loads(gh("pr","list","--repo",repo,"--head",report["branch"],
                     "--state","open","--limit","100","--json","number,body"))
    marker="<!-- pgextwin-candidate:v1:"+m.group(1)+" -->"
    if len(prs)!=1 or marker not in str(prs[0].get("body") or ""):
        raise ValueError("no unique automation-owned candidate PR")
    lines=["<!-- pgextwin-candidate-run:"+str(report["runId"])+" -->",
           "## "+report["status"]+" Windows candidate",
           "- Run: https://github.com/"+repo+"/actions/runs/"+str(report["runId"]),
           "- Windows matrix: "+report["matrixResult"],"",
           "| PG major | Result | Upstream SHA | ZIP SHA-256 / Error |",
           "| --- | --- | --- | --- |"]
    for item in report["majors"]:
        detail=(item.get("zipSha256") or item.get("error","unknown")).replace("|","/").replace("\n"," ")[:200]
        lines.append("| "+str(item["major"])+" | "+item["status"]+" | "+item.get("sourceSha","-")+" | "+detail+" |")
    lines+=["","All major CI jobs must succeed, including Test Contract, metadata, SPDX and Grype steps.",
            "Normal candidate CI has no release attestation and cannot publish Releases."]
    Path(path).write_text("\n".join(lines)+"\n",encoding="utf-8")
    gh("pr","comment",str(prs[0]["number"]),"--repo",repo,"--body-file",str(path))

def main():
    p=argparse.ArgumentParser()
    for field in ("extension","lifecycle","repo","branch","sha","matrix-result","output"):
        p.add_argument("--"+field,required=True)
    p.add_argument("--run-id",required=True,type=int)
    args=p.parse_args()
    report={"schemaVersion":1,"status":"FAILED","extension":"unknown","runId":args.run_id,
            "branch":args.branch,"branchSha":args.sha,"matrixResult":args.matrix_result,"majors":[]}
    try:
        ext=json.loads(Path(args.extension).read_text(encoding="utf-8"))
        lifecycle=json.loads(Path(args.lifecycle).read_text(encoding="utf-8"))
        report["extension"]=ext["name"]
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            gh("run","download",str(args.run_id),"--repo",args.repo,"--dir",temp)
            report=audit(Path(temp),ext,lifecycle,args.run_id,args.sha,args.branch,
                         args.matrix_result,date.today())
    except (ValueError,OSError,KeyError,TypeError) as e:
        report["error"]=str(e)
        print("Candidate audit FAILED CLOSED: "+str(e),file=sys.stderr)
    Path(args.output).write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report))
    return 0 if report["status"]=="VERIFIED" else 2

if __name__=="__main__":
    raise SystemExit(main())
