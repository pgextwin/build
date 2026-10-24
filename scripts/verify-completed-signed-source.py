#!/usr/bin/env python3
"""Independent REAL verification of completed signed main/push candidate bytes.

Central READ-ONLY Publisher prerequisite. This is NOT a release authorization:
the caller must obtain original Actions artifacts using authenticated GitHub
downloads, and a separately authorized Publisher must recheck policy/tag/bytes
before any scoped WRITE token. Never import this as a receipt issuer.
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
from zipfile import ZipFile, BadZipFile

ROOT = Path(__file__).resolve().parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

guard = load("completed_signed_source_guard", "issue-75-publisher-preflight.py")
ident = load("completed_signed_source_identity", "fleet-release-identity.py")
independent = load("completed_signed_source_opinion", "independent-signed-publisher-preflight.py")
grype_policy = load("completed_signed_source_grype", "automatic-grype-publisher-policy.py")
scope = load("completed_signed_source_scope", "publisher-scoped-token.py")
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")

class Denied(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Denied(why)

def unique(pairs):
    out={}
    for k,v in pairs:
        require(k not in out, "duplicate JSON evidence field")
        out[k]=v
    return out

def read(path):
    p=Path(path)
    require(p.is_file() and not p.is_symlink() and p.stat().st_size < 5*1024*1024,
            "missing, linked or oversized evidence JSON")
    obj=json.loads(p.read_text("utf-8-sig"), object_pairs_hook=unique)
    require(type(obj) is dict, "non-object evidence")
    return obj

def command(*args):
    """Only real authenticated GitHub GET and Sigstore verify are supported."""
    require(args[:3] == ("gh","api","--method")
            and len(args)==5 and args[3]=="GET"
            or args[:3] == ("gh","attestation","verify"),
            "untrusted or mutating CLI command")
    run=subprocess.run(args,capture_output=True,text=True,check=False,timeout=180)
    require(run.returncode == 0 and 0 < len(run.stdout) < 4*1024*1024,
            "independent GitHub GET or gh attestation verification failed")
    return run.stdout

def github(repository, route):
    require(type(repository) is str and REPO.fullmatch(repository)
            and (route=="branches/main"
                 or re.fullmatch(r"actions/runs/[1-9][0-9]*",route)
                 or re.fullmatch(r"actions/runs/[1-9][0-9]*/attempts/1/jobs\?per_page=100",route)
                 or re.fullmatch(r"actions/runs/[1-9][0-9]*/artifacts\?per_page=100",route)),
            "untrusted GitHub resource")
    return json.loads(command("gh","api","--method","GET",
                              "repos/"+repository+"/"+route),
                      object_pairs_hook=unique)

def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda:file.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def verify_completed_source(folder, manifest, lifecycle, first, second, fleet, *,
                            repository, sha, run_id, attempt=1, get=github,
                            verify=command):
    """Real Sigstore + exact bytes + Grype + authenticated completed Run (NO PUBLISH).

    The default `verify` executes real gh attestation verification, not a
    caller-provided JSON assertion. Injected callbacks serve offline unit tests
    only. Do not convert this result into formal Publisher admission.
    """
    require(type(repository) is str and REPO.fullmatch(repository)
            and type(sha) is str and SHA.fullmatch(sha)
            and type(run_id) is int and run_id>0
            and type(attempt) is int and attempt==1
            and type(manifest) is dict and manifest.get("name")==repository.split("/")[1],
            "invalid protected signed source identity")
    scope.valid_fleet(fleet,repository)
    branch=get(repository,"branches/main")
    require(type(branch) is dict and branch.get("name")=="main"
            and branch.get("protected") is True
            and type(branch.get("commit")) is dict
            and branch["commit"].get("sha")==sha,
            "source main is not protected or has advanced")
    run_path=f"actions/runs/{run_id}"
    jobs_path=run_path+"/attempts/1/jobs?per_page=100"
    assets_path=run_path+"/artifacts?per_page=100"
    original=guard.validate_completed_push_snapshot(
        get(repository,run_path),get(repository,jobs_path),
        get(repository,assets_path),repo=repository,sha=sha,
        run_id=run_id,attempt=attempt)
    require(type(folder) is Path and folder.is_dir() and not folder.is_symlink(),
            "signed ZIP directory unavailable")
    try:
        majors=ident.maintained_majors(manifest,lifecycle)
        pins=ident.sources(manifest)
        files=ident.expected_assets(manifest,majors)-{"SHA256SUMS.txt"}
    except (ident.Denied,KeyError,ValueError,TypeError) as exc:
        raise Denied("protected PostgreSQL source identity invalid") from exc
    require({p.name for p in folder.iterdir()} == files
            and all(p.is_file() and not p.is_symlink()
                    and 0<p.stat().st_size<1024*1024*1024 for p in folder.iterdir()),
            "partial/extra/linked or oversized signed artifacts")
    try:
        proof=independent.compare(first,second,repo=repository,sha=sha,
                                  run_id=run_id,attempt=attempt,
                                  manifest=manifest,lifecycle=lifecycle,
                                  event="push",ref="refs/heads/main")
    except (independent.Denied,ident.Denied,TypeError,KeyError,ValueError) as exc:
        raise Denied("original and independent signed audit mismatch") from exc
    require(proof.get("signedCandidateReverifiedBySeparateJob") is True
            and proof.get("publicationAuthorized") is False,
            "independent signed audit not correctly denied for publication")
    hashes={name:digest(folder/name) for name in files}
    for major in majors:
        stem=ident.asset_stem(manifest,major)
        zp=folder/(stem+".zip")
        sp=folder/(stem+".spdx.json")
        gp=folder/(stem+".vulnerabilities.json")
        source=pins[major]
        try:
            with ZipFile(zp) as z:
                members=[i for i in z.infolist() if i.filename=="PACKAGE-INFO.json"]
                require(len(members)==1 and members[0].file_size<256000,
                        "missing/duplicate/oversized package identity")
                pkg=json.loads(z.read(members[0]).decode("utf-8-sig"),
                               object_pairs_hook=unique)
        except (BadZipFile,UnicodeError,KeyError,OSError) as exc:
            raise Denied("invalid signed ZIP package") from exc
        guard.validate_pkg(pkg,major=major,repo=repository,
                           packaging_sha=sha,upstream_sha=source["commit"],
                           run_id=run_id,attempt=attempt,event="push")
        require(pkg.get("buildMode")=="release-attested"
                and pkg.get("package",{}).get("name")==manifest["name"]
                and pkg.get("upstream")=={
                    "repository":manifest["upstream"]["repository"],
                    "ref":source["ref"],"version":source["version"],
                    "commit":source["commit"]},
                "signed source SHA/ref/version does not match protected manifest")
        sbom=json.loads(sp.read_text("utf-8-sig"),object_pairs_hook=unique)
        risks=json.loads(gp.read_text("utf-8-sig"),object_pairs_hook=unique)
        require(type(sbom) is dict and sbom.get("spdxVersion")=="SPDX-2.3",
                "invalid original signed SPDX")
        try:
            policy=grype_policy.review(risks,asset_stem=stem)
        except (grype_policy.Denied,TypeError,KeyError,ValueError) as exc:
            raise Denied("unfiltered Grype policy evidence invalid") from exc
        require(policy["status"]=="NO_BLOCKING_FINDINGS"
                and policy["blockingFindingCount"]==0
                and first["grypePolicyByMajor"][str(major)]==policy,
                "Critical/High/Unknown risk or Grype evidence changed")
        for suffix,kind in (("zip","zip"),("spdx","spdx"),("grype","grype")):
            file_path=folder/(stem+{
                "zip":".zip","spdx":".spdx.json","grype":".vulnerabilities.json"}[suffix])
            require(first[suffix+"Sha256ByMajor"][str(major)]==hashes[file_path.name],
                    "original and independently downloaded "+kind+" digest differ")
        for kind in (guard.PROVENANCE,guard.SPDX):
            output=verify("gh","attestation","verify",str(zp),
                "--repo",repository,
                "--signer-workflow","pgextwin/build/"+guard.SIGNER_PATH,
                "--signer-digest",guard.SIGNER_SHA,"--source-digest",sha,
                "--source-ref","refs/heads/main","--predicate-type",kind,
                "--format","json")
            guard.verified_claims(output,predicate=kind,repo=repository,
                packaging_sha=sha,run_id=run_id,attempt=attempt,
                zip_name=zp.name,zip_digest=hashes[zp.name],sbom=sbom,
                event="push",config_path=guard.PUSH_PATH)
            require(digest(zp)==hashes[zp.name] and digest(sp)==hashes[sp.name],
                    "signed bytes changed during real Sigstore verification")
    require({name:digest(folder/name) for name in files}==hashes,
            "ZIP/SPDX/Grype changed during re-verification")
    final_branch=get(repository,"branches/main")
    require(final_branch==branch and final_branch["commit"]["sha"]==sha,
            "source protected main changed during independent proof")
    final=guard.validate_completed_push_snapshot(
        get(repository,run_path),get(repository,jobs_path),
        get(repository,assets_path),repo=repository,sha=sha,
        run_id=run_id,attempt=attempt)
    require(original==final,"original signed Run/jobs/artifacts changed")
    return {"schemaVersion":1,
            "status":"REAL_COMPLETED_SIGNED_SOURCE_VERIFIED_NONPUBLISHING",
            "repository":repository,"mainMergeSha":sha,
            "sourceRunId":run_id,"sourceRunAttempt":attempt,
            "maintainedMajors":majors,
            "zipSha256ByMajor":first["zipSha256ByMajor"],
            "spdxSha256ByMajor":first["spdxSha256ByMajor"],
            "grypeSha256ByMajor":first["grypeSha256ByMajor"],
            "realSigstoreRechecked":True,"blockingGrypeFindings":0,
            "publisherTokenRequested":False,"publishableReceipt":False,
            "publicationAuthorized":False,"automaticReleaseEnabled":False}

def main():
    p=argparse.ArgumentParser()
    for name in ("repository","sha","run-id","dist","manifest",
                 "lifecycle","original","second","fleet","output"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    try:
        require(os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build"
                and os.environ.get("GITHUB_REF")=="refs/heads/main"
                and os.environ.get("GITHUB_EVENT_NAME") in ("schedule","push")
                and os.environ.get("GH_TOKEN"),
                "not trusted central read-only runtime")
        result=verify_completed_source(
            Path(a.dist),read(a.manifest),read(a.lifecycle),
            read(a.original),read(a.second),read(a.fleet),
            repository=a.repository,sha=a.sha,run_id=int(a.run_id))
        Path(a.output).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n","utf-8")
        print("INDEPENDENT_COMPLETED_SIGNED_SOURCE_VERIFIED; PUBLISH_DENY")
        return 0
    except (Denied,guard.Deny,independent.Denied,scope.Denied,
            OSError,ValueError,TypeError,KeyError,
            subprocess.TimeoutExpired) as exc:
        print("COMPLETED_SIGNED_SOURCE_DENY: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
