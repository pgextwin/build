#!/usr/bin/env python3
"""Step 21 create-only formal Release, fully checked before public publication.

A reserved tag or partial draft is quarantined. Reruns MUST fail closed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
from zipfile import ZipFile

REPO = "pgextwin/plpgsql_check"
SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"

class Denied(ValueError): pass

def check(x, message):
    if not x: raise Denied(message)

def run(*args):
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode:
        raise Denied("command failed: " + " ".join(args[:3]) + " " + p.stderr[:250])
    return p.stdout

def digest(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda: f.read(1024 * 1024), b""): h.update(c)
    return h.hexdigest()

def get(path):
    req = Request("https://api.github.com/repos/" + REPO + "/" + path,
                  headers={"Authorization":"Bearer " + os.environ["GH_TOKEN"],
                           "Accept":"application/vnd.github+json"})
    try:
        with urlopen(req, timeout=25) as resp:
            check(resp.status == 200, "ambiguous GitHub response")
            return json.load(resp)
    except HTTPError as e:
        if e.code == 404: return None
        raise Denied("GitHub API failed HTTP " + str(e.code)) from e

def absent(tag):
    for path in ("releases/tags/","git/ref/tags/"):
        check(get(path+quote(tag,safe="")) is None, "existing tag/release forbidden")

def check_assets(folder, ext, receipt, commit, run_id, verify_signatures=True):
    check(receipt.get("status") == "VERIFIED_APPROVED" and receipt["repository"] == REPO
          and receipt["trustedCommit"] == commit
          and ext["name"] == receipt["extension"]
          and ext["upstream"]["version"] == receipt["version"]
          and ext["upstream"]["commit"] == receipt["upstreamCommit"]
          and ext["upstream"]["ref"] == receipt["upstreamRef"]
          and isinstance(receipt.get("majors"), list)
          and receipt["majors"] == sorted(set(receipt["majors"]))
          and bool(receipt["majors"])
          and all(m in (14,15,16,17,18) for m in receipt["majors"]),
          "promotion receipt/source mismatch")
    required = set()
    for m in receipt["majors"]:
        stem = ext["name"]+"-v"+receipt["version"]+"-pg"+str(m)+"-windows-x64"
        files = [stem+s for s in (".zip",".spdx.json",".vulnerabilities.json")]
        required.update(files)
        with ZipFile(folder/files[0]) as z:
            check(z.namelist().count("PACKAGE-INFO.json") == 1, "missing package identity")
            pkg = json.loads(z.read("PACKAGE-INFO.json").decode("utf-8-sig"))
        check(pkg.get("buildMode") == "release-attested"
              and pkg["package"]["name"] == ext["name"]
              and pkg["postgresql"]["major"] == m
              and pkg["upstream"]["commit"] == receipt["upstreamCommit"]
              and pkg["upstream"]["ref"] == receipt["upstreamRef"]
              and pkg["source"]["packagingRepository"] == REPO
              and pkg["source"]["packagingCommit"] == commit
              and pkg["workflowRun"]["id"] == run_id
              and pkg["workflowRun"]["event"] == "workflow_dispatch"
              and pkg["workflowRun"]["ref"] == "refs/heads/main", "package/SHA/run mismatch")
        check(json.loads((folder/files[1]).read_text(encoding="utf-8-sig"))["spdxVersion"] == "SPDX-2.3",
              "invalid SPDX")
        check(isinstance(json.loads((folder/files[2]).read_text(encoding="utf-8-sig"))["matches"],list),
              "invalid Grype")
        if verify_signatures:
            run("gh","attestation","verify",str(folder/files[0]),"--repo",REPO,"--signer-workflow",SIGNER)
            run("gh","attestation","verify",str(folder/files[0]),"--repo",REPO,
                "--signer-workflow",SIGNER,"--predicate-type","https://spdx.dev/Document/v2.3")
    check({p.name for p in folder.iterdir() if p.is_file()} == required, "partial/extra major assets")
    return {name:digest(folder/name) for name in required}

def check_remote(tag, expected, draft):
    release=get("releases/tags/"+quote(tag,safe=""))
    check(release and release.get("draft") is draft and release["tag_name"] == tag,
          "release state mismatch")
    assets={a["name"]:a for a in release["assets"]}
    check(set(assets) == set(expected) and all(a["state"] == "uploaded" for a in assets.values()),
          "partial or unexpected published assets")
    for name,expected_sha in expected.items():
        with tempfile.TemporaryDirectory() as d:
            run("gh","release","download",tag,"--repo",REPO,"--pattern",name,"--dir",d)
            check(digest(Path(d)/name) == expected_sha, "remote SHA mismatch: " + name)

def main():
    p=argparse.ArgumentParser()
    for n in ("receipt","manifest","tag","dist","recovery"):
        p.add_argument("--"+n,required=True)
    a=p.parse_args()
    stage="STARTED"
    try:
        check(os.environ.get("GITHUB_REPOSITORY")==REPO
              and os.environ.get("GITHUB_REF")=="refs/heads/main"
              and os.environ.get("GITHUB_EVENT_NAME")=="workflow_dispatch", "untrusted publishing origin")
        receipt=json.loads(Path(a.receipt).read_text())
        ext=json.loads(Path(a.manifest).read_text())
        check(a.tag==receipt["releaseTag"],"tag does not match approval")
        commit=os.environ["GITHUB_SHA"]
        folder=Path(a.dist)
        expected=check_assets(folder,ext,receipt,commit,int(os.environ["GITHUB_RUN_ID"]))
        absent(a.tag)
        (folder/"SHA256SUMS.txt").write_text("".join(
            value+"  "+name+"\n" for name,value in sorted(expected.items())),encoding="ascii")
        expected["SHA256SUMS.txt"]=digest(folder/"SHA256SUMS.txt")
        notes=Path(a.recovery).with_suffix(".md")
        notes.write_text("# "+ext["name"]+" Windows x64\n\n"
            +"Unofficial binaries built from reviewed upstream SHA "+receipt["upstreamCommit"]
            +". PG15–18 tested; SPDX SBOM, Grype report, signed provenance, signed SBOM and SHA256SUMS included.\n"
            +"非公式Windows x64バイナリです。PG15〜18と検証可能な証明を含みます。\n",encoding="utf-8")
        def state(s):
            nonlocal stage
            stage=s
            Path(a.recovery).write_text(json.dumps(
                {"schemaVersion":1,"state":stage,"tag":a.tag,"runId":int(os.environ["GITHUB_RUN_ID"]),
                 "commit":commit},indent=2)+"\n")
        state("PREFLIGHT_OK")
        # Exclusive tag reservation: a second concurrent writer cannot create the same tag.
        run("gh","api","-X","POST","repos/"+REPO+"/git/refs",
            "-f","ref=refs/tags/"+a.tag,"-f","sha="+commit)
        state("TAG_RESERVED")
        run("gh","release","create",a.tag,
            *[str(folder/name) for name in sorted(expected)],
            "--repo",REPO,"--verify-tag","--draft","--target",commit,
            "--title",a.tag,"--notes-file",str(notes))
        state("DRAFT_STAGED")
        check_remote(a.tag,expected,True)
        state("DRAFT_VERIFIED")
        # Edits ONLY a new, verified draft produced by this run; never prior published releases.
        run("gh","release","edit",a.tag,"--repo",REPO,"--draft=false")
        state("PUBLISHED_AUDIT_PENDING")
        check_remote(a.tag,expected,False)
        state("PUBLISHED_VERIFIED")
        print("Formal Release verified: "+a.tag)
        return 0
    except (Denied,KeyError,ValueError,OSError,TypeError,IndexError,HTTPError) as e:
        print("RELEASE DENIED at "+stage+": "+str(e),file=sys.stderr)
        return 2

if __name__=="__main__": sys.exit(main())
