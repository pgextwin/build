#!/usr/bin/env python3
"""Review exact portalcorp pgvector PG16 original bytes for genuine owner-signed GET only.

Authenticated provider identity, independent real Windows runtime evidence, original
SHA256/ZIP/PE and source-license disclosures are required. This is not upstream
reproducible-build or binary-signature verification. No ZIP publication or mirror.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("issue112_original_issuer", ROOT / "scripts/external-direct-get-issuer.py")
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
SOURCE = "portalcorp/pgvector_compiled"
REPO_ID = 835861704
TAG = "v0.16.105"
TAG_COMMIT = "76256aa2eeda43a8ccb017f3e4431a4a921d3374"
RELEASE_ID = 182821763
ASSET_ID = 203009337
ASSET_NAME = "pgvector-x86_64-pc-windows-msvc-pg16.zip"
ASSET_SHA = "a9c63a3e51c09c18f192277a28be3fb021f3872a7cc2d23e4ca06e10f2c99571"
ASSET_SIZE = 163732
RUNTIME_RUN = 42530859120
RUNTIME_HEAD = "9d4aaf0c0e7dc6b79cc572e95eb57b745807676a"
INTAKE = "config/issue112-portalcorp-pg16-original-get-intake-v1.json"

def require(ok, why):
    old.require(ok, why)

def verify_original(path, catalog):
    p=Path(path)
    require(p.is_file() and not p.is_symlink() and p.stat().st_size == ASSET_SIZE,
            "wrong original ZIP file or size")
    payload=p.read_bytes()
    require(hashlib.sha256(payload).hexdigest() == ASSET_SHA,
            "wrong independent provider-original SHA256")
    sys.path.insert(0, str(catalog / "scripts"))
    from issue112_portalcorp_windows_private import audit_existing_zip
    proof=audit_existing_zip(payload)
    require(proof["zipMembers"] == 48, "original ZIP member inventory changed")
    with zipfile.ZipFile(io.BytesIO(payload)) as z:
        names=z.namelist()
        prefix="pgvector-x86_64-pc-windows-msvc-pg16/"
        dll=[x for x in names if x.endswith("/lib/vector.dll")]
        controls=[x for x in names if x.endswith("/share/extension/vector.control")]
        require(len(dll)==1 and len(controls)==1, "wrong pgvector archive layout")
        binary=z.read(dll[0])
        require(binary[:2] == b"MZ" and len(binary)>128, "not a Windows DLL")
        pe_off=struct.unpack_from("<I", binary, 0x3c)[0]
        require(pe_off+6 <= len(binary)
                and binary[pe_off:pe_off+4] == b"PE\0\0"
                and struct.unpack_from("<H", binary, pe_off+4)[0] == 0x8664,
                "not a PE AMD64 original")
        control=z.read(controls[0])
        require(b"0.8.0" in control and len(control)<4096,
                "not pinned pgvector v0.8.0")
    return {"bytes":len(payload), "sha256":ASSET_SHA, "zipMembers":48}

def validate_source(catalog, branch, repo, ref, release, runtime, jobs):
    catalog_sha=subprocess.run(["git","-C",str(catalog),"rev-parse","HEAD"],
          capture_output=True,check=True,timeout=30).stdout.decode().strip()
    require(branch.get("protected") is True
            and branch.get("commit",{}).get("sha")==catalog_sha
            and old.SHA40.fullmatch(catalog_sha), "Catalog checked-out protected main drift")
    sys.path.insert(0, str(catalog / "scripts"))
    from external_direct_link_review import strict_read
    from external_direct_get_intake import validate_intake
    intake=strict_read(catalog / INTAKE)
    rows=validate_intake(intake)
    require(len(rows)==1, "unreviewed extra source")
    row=rows[0]
    expected={
        "extension":"vector", "upstreamVersion":"0.8.0", "pgMajor":"16",
        "sourceRepo":SOURCE, "repositoryId":REPO_ID,
        "releaseTag":TAG, "releaseId":RELEASE_ID, "assetId":ASSET_ID,
        "assetName":ASSET_NAME, "originalBytes":ASSET_SIZE,
        "originalSha256":ASSET_SHA,
        "originalProviderUrl":f"https://github.com/{SOURCE}/releases/download/{TAG}/{ASSET_NAME}",
        "licenseUrl":f"https://github.com/{SOURCE}/blob/{TAG}/LICENSE",
        "licenseSpdx":"MIT AND PostgreSQL", "providerType":"community",
    }
    require(all(type(row.get(k)) is type(v) and row[k]==v for k,v in expected.items()),
            "unreviewed portalcorp release/asset/rights identity")
    require("https://github.com/pgvector/pgvector/blob/v0.8.0/LICENSE"
            in row["noticeTreatment"]
            and "transitive" in row["dependencyTreatment"]
            and row["downloadAuthorized"] is False
            and row["mirrorAuthorized"] is False
            and intake["authorizationIssuer"] == "NONE",
            "source notice, scope or unsigned permission changed")
    require(repo.get("id")==REPO_ID and repo.get("full_name")==SOURCE
            and ref.get("object",{}).get("type")=="commit"
            and ref.get("object",{}).get("sha")==TAG_COMMIT
            and release.get("id")==RELEASE_ID
            and release.get("tag_name")==TAG
            and release.get("draft") is False
            and release.get("prerelease") is False,
            "untrusted provider release, tag or repository")
    assets=release.get("assets")
    require(type(assets) is list and 1<=len(assets)<=100, "unbounded provider assets")
    found=[a for a in assets if a.get("id")==ASSET_ID or a.get("name")==ASSET_NAME]
    require(len(found)==1 and found[0].get("id")==ASSET_ID
            and found[0].get("name")==ASSET_NAME
            and found[0].get("size")==ASSET_SIZE
            and found[0].get("state")=="uploaded"
            and found[0].get("digest") in (None, "sha256:"+ASSET_SHA)
            and found[0].get("browser_download_url")==expected["originalProviderUrl"],
            "provider original ZIP metadata does not match independent pin")
    require(runtime.get("id")==RUNTIME_RUN and runtime.get("event")=="push"
            and runtime.get("run_attempt")==1
            and runtime.get("status")=="completed" and runtime.get("conclusion")=="success"
            and runtime.get("head_branch")=="main" and runtime.get("head_sha")==RUNTIME_HEAD
            and runtime.get("path")==".github/workflows/issue112-external-zip-pilot.yml"
            and runtime.get("repository",{}).get("full_name")=="pgextwin/catalog",
            "not genuine original Catalog main Windows PG16 qualification")
    matches=[j for j in jobs.get("jobs",[]) if j.get("name")=="portalcorp-pg16-native"]
    require(len(matches)==1 and matches[0].get("conclusion")=="success"
            and matches[0].get("run_id")==RUNTIME_RUN,
            "not independently validated real EDB PG16 native SQL")
    return catalog_sha,row

def manifest(build, runid, catalog_sha, row, proof, now):
    require(old.SHA40.fullmatch(build) and old.SHA40.fullmatch(catalog_sha)
            and type(runid) is int and runid>0
            and proof=={"bytes":ASSET_SIZE,"sha256":ASSET_SHA,"zipMembers":48},
            "invalid original ZIP proof or issuer")
    n=now.astimezone(timezone.utc).replace(microsecond=0)
    return {
        "schemaVersion":"pgextwin-external-direct-get-admission/v1",
        "sourceKind":"EXTERNAL_GITHUB_RELEASE_ASSET",
        "issuerRepository":old.BUILD, "issuerCommit":build, "catalogCommit":catalog_sha,
        "issuerEvent":"workflow_dispatch", "issuerRunId":runid, "issuerRunAttempt":1,
        "ownerActor":old.OWNER, "ownerId":old.OWNER_ID,
        "publisherEnvironment":"external-direct-provider-publisher",
        "publisherAppId":old.APP_ID, "approvedOperation":old.OPERATION,
        "issuedAt":n.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt":(n+timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "downloadAuthorized":True, "mirrorAuthorized":False,
        "redistributionAuthorized":False,
        "records":[{
            "sourceGroup":"external", "extension":"vector", "pgMajor":"16",
            "targetEnvironment":row["targetEnvironment"],
            "sourceRepo":SOURCE,"repositoryId":REPO_ID,
            "releaseTag":TAG,"releaseId":RELEASE_ID,"assetName":ASSET_NAME,
            "assetId":ASSET_ID,"originalBytes":ASSET_SIZE,"originalSha256":ASSET_SHA,
            "originalProviderUrl":row["originalProviderUrl"],
            "licenseUrl":row["licenseUrl"],
            "noticeTreatment":row["noticeTreatment"],
            "dependencyTreatment":row["dependencyTreatment"],
            "approvedOperation":old.OPERATION,"downloadAuthorized":True,
            "mirrorAuthorized":False,
        }],
    }

def main():
    stage="OWNER_RUN"
    try:
        env=dict(os.environ)
        event=json.loads(Path(env["GITHUB_EVENT_PATH"]).read_bytes(),
                         object_pairs_hook=old.no_duplicates)
        build,runid=old.validate_original_owner_run(
            env,event,old.gh_get("repos/pgextwin/build/branches/main"),
            old.gh_get("repos/pgextwin/build/actions/runs/"+env["GITHUB_RUN_ID"]),
            expected_extension="portalcorp_pgvector")
        stage="CATALOG_PROVIDER"
        catalog=Path(env["CATALOG_CHECKOUT"])
        sha,row=validate_source(catalog,
            old.gh_get("repos/pgextwin/catalog/branches/main"),
            old.gh_get("repos/"+SOURCE),
            old.gh_get("repos/"+SOURCE+"/git/ref/tags/"+TAG),
            old.gh_get("repos/"+SOURCE+"/releases/tags/"+TAG),
            old.gh_get(f"repos/pgextwin/catalog/actions/runs/{RUNTIME_RUN}"),
            old.gh_get(f"repos/pgextwin/catalog/actions/runs/{RUNTIME_RUN}/jobs?per_page=100"))
        stage="ORIGINAL_ZIP"
        proof=verify_original(env["ORIGINAL_ZIP"],catalog)
        stage="APP_SCOPE"
        api,jwt=old.load_external_app_helpers()
        old.verify_app_readonly(env["EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY"],api=api,jwt=jwt)
        stage="SOURCE_RECHECK"
        require(old.gh_get("repos/pgextwin/build/branches/main")["commit"]["sha"]==build
                and old.gh_get("repos/pgextwin/catalog/branches/main")["commit"]["sha"]==sha,
                "protected source advanced before issuance")
        stage="MANIFEST"
        output=Path(env["OUTPUT_FILE"])
        require(not output.exists() and not output.is_symlink(),
                "issuer may only create original new subject")
        payload=manifest(build,runid,sha,row,proof,datetime.now(timezone.utc))
        with output.open("xb") as file:
            file.write((json.dumps(payload,sort_keys=True,separators=(",",":"),
                        allow_nan=False)+"\n").encode("utf-8"))
        print("PORTALCORP_PG16_SIGNABLE_SUBJECT_CREATED ZIP_UPLOAD=NONE MIRROR=DENY")
    except Exception as e:
        print(old.denial_diagnostic(stage,e),file=sys.stderr)
        raise SystemExit(1)

if __name__=="__main__":
    main()
