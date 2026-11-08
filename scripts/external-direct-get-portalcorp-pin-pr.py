#!/usr/bin/env python3
"""Create-only exact portalcorp pgvector PG16 signed metadata App PR; never ZIP."""
import base64
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "issue112_original_signed_pin_pr", ROOT/"scripts/external-direct-get-public-pin-pr.py")
old=importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
SOURCE="portalcorp_pgvector"
EXPECTED={
    "sourceGroup":"external","extension":"vector","pgMajor":"16",
    "sourceRepo":"portalcorp/pgvector_compiled","repositoryId":835861704,
    "releaseTag":"v0.16.105","releaseId":182821763,
    "assetName":"pgvector-x86_64-pc-windows-msvc-pg16.zip","assetId":203009337,
    "originalBytes":163732,
    "originalSha256":"a9c63a3e51c09c18f192277a28be3fb021f3872a7cc2d23e4ca06e10f2c99571",
    "originalProviderUrl":"https://github.com/portalcorp/pgvector_compiled/releases/download/v0.16.105/pgvector-x86_64-pc-windows-msvc-pg16.zip",
    "licenseUrl":"https://github.com/portalcorp/pgvector_compiled/blob/v0.16.105/LICENSE",
    "approvedOperation":old.OPERATION,"downloadAuthorized":True,"mirrorAuthorized":False
}
def require(ok,why):
    old.require(ok,why)

def verify_portalcorp_manifest(doc,build_sha,catalog_sha,runid,now):
    require(type(doc) is dict and set(doc)==old.TOP_KEYS,
            "wrong portalcorp signed manifest shape")
    exact={
        "schemaVersion":"pgextwin-external-direct-get-admission/v1",
        "sourceKind":"EXTERNAL_GITHUB_RELEASE_ASSET",
        "issuerRepository":old.BUILD,"issuerCommit":build_sha,
        "catalogCommit":catalog_sha,"issuerEvent":"workflow_dispatch",
        "issuerRunId":runid,"issuerRunAttempt":1,
        "ownerActor":"ShutenOishi","ownerId":27071164,
        "publisherEnvironment":old.ENVIRONMENT,"publisherAppId":5609317,
        "approvedOperation":old.OPERATION,"downloadAuthorized":True,
        "mirrorAuthorized":False,"redistributionAuthorized":False
    }
    require(all(type(doc.get(k)) is type(v) and doc[k]==v for k,v in exact.items()),
            "unreviewed issuer event, App or source commit")
    issued,expires=old.parse_utc(doc["issuedAt"]),old.parse_utc(doc["expiresAt"])
    require(expires-issued==timedelta(hours=6) and issued<=now<expires,
            "six-hour portalcorp owner admission expired")
    rows=doc["records"]
    require(type(rows) is list and len(rows)==1
            and type(rows[0]) is dict and set(rows[0])==old.ROW_KEYS,
            "unexpected portalcorp signed source cohort")
    row=rows[0]
    require(all(type(row.get(k)) is type(v) and row[k]==v for k,v in EXPECTED.items()),
            "wrong exact source/ZIP/hash/provider/rights")
    require("PostgreSQL 16" in row["targetEnvironment"]
            and "Windows x64" in row["targetEnvironment"]
            and all(type(row[k]) is str and len(row[k])>=60 for k in
                    ("targetEnvironment","noticeTreatment","dependencyTreatment"))
            and "https://github.com/pgvector/pgvector/blob/v0.8.0/LICENSE"
                in row["noticeTreatment"],
            "unreviewed user-visible rights and bounded runtime")
    return expires

def path_for(runid,name):
    require(type(runid) is int and 0<runid<10**15
            and name in ("external-get-admission.json","attestation.json"),
            "unapproved create-only path")
    return f"external/signed-direct-get/{SOURCE}/run-{runid}/{name}"

def make_pr(api,token,runid,catalog_sha,files,expires):
    base="/repos/pgextwin/catalog"
    branch=f"issue112-portalcorp-signed-get-run-{runid}"
    current=api("GET",base+"/branches/main",token)
    require(current.get("protected") is True
            and current.get("commit",{}).get("sha")==catalog_sha,
            "protected Catalog changed before signed PR")
    api("POST",base+"/git/refs",token,{
        "ref":"refs/heads/"+branch,"sha":catalog_sha})
    for name in ("external-get-admission.json","attestation.json"):
        dest=path_for(runid,name)
        route=base+"/contents/"+dest
        raw=files[name]
        api("PUT",route,token,{
            "message":"chore(#112): stage original signed portalcorp PG16 metadata "+name,
            "branch":branch,"content":base64.b64encode(raw).decode("ascii")})
        readback=api("GET",route+"?ref="+branch,token)
        require(readback.get("type")=="file" and readback.get("path")==dest
                and base64.b64decode(readback.get("content",""))==raw,
                "signed PR bytes not readback unchanged")
    again=api("GET",base+"/branches/main",token)
    require(again.get("protected") is True
            and again.get("commit",{}).get("sha")==catalog_sha
            and datetime.now(timezone.utc)<expires,
            "Catalog moved or source-specific signature expired before PR")
    pr=api("POST",base+"/pulls",token,{
        "title":f"feat(#112): genuine portalcorp PG16 original GET-only Run {runid}",
        "head":branch,"base":"main","draft":False,
        "body":"Original owner workflow_dispatch on protected Build/main, authentic "
               "Environment review twice, same-Run independent Sigstore, immutable "
               "provider original ZIP SHA256 and real Windows PG16 SQL. Metadata only. "
               "Public availability is subject to protected Catalog merge and original "
               "postmerge Windows/public CLI E2E. Signature expiry six hours; expired "
               "means GET_DENY. Packaging repo MIT license plus upstream pgvector "
               "PostgreSQL license disclosed. No binary mirror, redistribution, install "
               "or Oracle/community pgvector P3 hold modification. Refs pgextwin/build#112."})
    require(type(pr.get("number")) is int and pr["number"]>0
            and pr.get("head",{}).get("ref")==branch
            and pr.get("base",{}).get("ref")=="main",
            "App source-specific Catalog PR was not created")
    return pr["number"]

def main():
    try:
        env=dict(os.environ)
        event=json.loads(Path(env["GITHUB_EVENT_PATH"]).read_bytes(),
                         object_pairs_hook=old.no_duplicates)
        runid=env["GITHUB_RUN_ID"]
        base="repos/pgextwin/build/actions/runs/"+runid
        build,catalog,verified_run=old.check_run_context(
            env,event,
            branch=old.gh_read("repos/pgextwin/build/branches/main"),
            run=old.gh_read(base),jobs=old.gh_read(base+"/jobs?per_page=100"),
            approvals=old.gh_read(base+"/approvals"),
            catalog=old.gh_read("repos/pgextwin/catalog/branches/main"),
            expected_extension=SOURCE)
        files=old.read_exact(env["SIGNED_METADATA_DIR"])
        doc=json.loads(files["external-get-admission.json"],
                       object_pairs_hook=old.no_duplicates)
        expires=verify_portalcorp_manifest(doc,build,catalog,verified_run,
                                           datetime.now(timezone.utc))
        old.verify_sigstore(env["SIGNED_METADATA_DIR"],build)
        helpers=old.load_module("portalcorp_exact_app",old.APP_MODULE)
        private=env.pop("EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY")
        with helpers.scoped_catalog_token(
                helpers.shared._existing.api,helpers.shared._existing.jwt,private) as token:
            number=make_pr(helpers.shared._existing.api,token,
                           verified_run,catalog,files,expires)
        print(f"PORTALCORP_SIGNED_PIN_CATALOG_PR={number} APP_REVOKED=TRUE ZIP_UPLOAD=NONE MIRROR=DENY")
    except Exception:
        print("PORTALCORP_SIGNED_PIN_PR_DENY; no source tokens or ZIPs leaked",file=sys.stderr)
        raise SystemExit(1)

if __name__=="__main__":
    main()
