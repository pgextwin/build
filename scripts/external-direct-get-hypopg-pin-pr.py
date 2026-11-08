#!/usr/bin/env python3
"""Authentic signed HypoPG three-asset metadata App PR; NO original ZIPs.

Only a dedicated, owner-approved same-Run Build job following independent
Sigstore verification may propose this immutable Catalog PR. Not publication.
"""
import base64
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "existing_exact_public_pin_pr", ROOT / "scripts/external-direct-get-public-pin-pr.py")
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
HYP = "hypopg"
ASSETS = {
    "14": (164673161, 23115, "ac1114d1392494e688b5b6b6f151aebe6ccab2d8ae1a004ec510669c47ef3634"),
    "15": (164673166, 23123, "d23ea9ba7d064ee08e431b12ade50bed4b19a725b5f4df1e088e79e4af8d08ec"),
    "16": (164673171, 22997, "7afd7cda50050829787d4e901fc8292cf1eb2bc5ad59c996a92e414a1bead1f7"),
}

def require(condition, reason):
    old.require(condition, reason)

def verify_hypopg_manifest(doc, build_sha, catalog_sha, runid, now):
    require(type(doc) is dict and set(doc) == old.TOP_KEYS,
            "unknown cohort admission envelope")
    for key, value in (
        ("schemaVersion", "pgextwin-external-direct-get-admission/v1"),
        ("sourceKind", "EXTERNAL_GITHUB_RELEASE_ASSET"),
        ("issuerRepository", old.BUILD), ("issuerCommit", build_sha),
        ("catalogCommit", catalog_sha), ("issuerEvent", "workflow_dispatch"),
        ("issuerRunId", runid), ("issuerRunAttempt", 1),
        ("ownerActor", "ShutenOishi"), ("ownerId", 27071164),
        ("publisherEnvironment", old.ENVIRONMENT), ("publisherAppId", 5609317),
        ("approvedOperation", old.OPERATION), ("downloadAuthorized", True),
        ("mirrorAuthorized", False), ("redistributionAuthorized", False),
    ):
        require(type(doc[key]) is type(value) and doc[key] == value,
                "untrusted source/operation/owner identity: " + key)
    issued = old.parse_utc(doc["issuedAt"])
    expires = old.parse_utc(doc["expiresAt"])
    require(expires - issued == timedelta(hours=6)
            and issued <= now < expires, "invalid/expired original cohort permission")
    rows = doc["records"]
    require(type(rows) is list and len(rows) == 3, "unknown signed cohort size")
    for expected_major, row in zip(("14", "15", "16"), rows):
        require(type(row) is dict and set(row) == old.ROW_KEYS, "unreviewed signed row")
        aid, length, sha = ASSETS[expected_major]
        asset = f"hypopg-1.4.1-pg{expected_major}-x64.zip"
        url = f"https://github.com/HypoPG/hypopg/releases/download/1.4.1/{asset}"
        for key, expected in (
            ("sourceGroup", "external"), ("extension", "hypopg"),
            ("pgMajor", expected_major), ("sourceRepo", "HypoPG/hypopg"),
            ("repositoryId", 37308208), ("releaseTag", "1.4.1"),
            ("releaseId", 153113229), ("assetId", aid),
            ("assetName", asset), ("originalBytes", length),
            ("originalSha256", sha), ("originalProviderUrl", url),
            ("licenseUrl", "https://github.com/HypoPG/hypopg/blob/1.4.1/LICENSE"),
            ("approvedOperation", old.OPERATION),
            ("downloadAuthorized", True), ("mirrorAuthorized", False),
        ):
            require(type(row[key]) is type(expected) and row[key] == expected,
                    "changed signed exact asset or permission: " + key)
        require(all(type(row[k]) is str and len(row[k]) >= 60
                    for k in ("targetEnvironment", "noticeTreatment", "dependencyTreatment"))
                and ("PostgreSQL "+expected_major) in row["targetEnvironment"]
                and "Windows x64" in row["targetEnvironment"],
                "unreviewed ABI or user-visible notice/dependency")
    return expires

def path_for(runid, name):
    require(type(runid) is int and runid > 0 and runid < 10**15
            and name in ("external-get-admission.json", "attestation.json"),
            "nonimmutable signed file path")
    return f"external/signed-direct-get/hypopg/run-{runid}/{name}"

def make_pr(api, token, runid, catalog_sha, contents, expiry):
    base = "/repos/pgextwin/catalog"
    branch_name = f"issue112-hypopg-signed-get-run-{runid}"
    current = api("GET", base + "/branches/main", token)
    require(current.get("protected") is True and
            current.get("commit", {}).get("sha") == catalog_sha,
            "protected Catalog advanced before proposal")
    api("POST", base + "/git/refs", token, {
        "ref": "refs/heads/" + branch_name, "sha": catalog_sha})
    for name in ("external-get-admission.json", "attestation.json"):
        dest = path_for(runid, name)
        route = base + "/contents/" + dest
        raw = contents[name]
        api("PUT", route, token, {
            "message": "chore(#112): create-only genuine three-PG GET permission " + name,
            "branch": branch_name,
            "content": base64.b64encode(raw).decode("ascii"),
        })
        fetched = api("GET", route + "?ref=" + branch_name, token)
        require(fetched.get("type") == "file" and
                fetched.get("path") == dest and
                base64.b64decode(fetched.get("content", "")) == raw,
                "same bytes not read back on protected PR branch")
    current = api("GET", base + "/branches/main", token)
    require(current.get("protected") is True and
            current.get("commit", {}).get("sha") == catalog_sha
            and datetime.now(timezone.utc) < expiry,
            "Catalog moved or signed cohort permission already expired")
    pr = api("POST", base + "/pulls", token, {
        "title": f"feat(#112): genuine signed three-PG HypoPG original GET-only Run {runid}",
        "head": branch_name, "base": "main", "draft": False,
        "body": (
            "True owner workflow_dispatch protected Build/main, reviewed Publisher "
            "Environment, same-Run independent Sigstore and exact original source/Windows "
            "PG14-16 bytes. Metadata only. Six-hour expiry; MIRROR_DENY and "
            "REDISTRIBUTION_DENY. No public permission until protected merge plus "
            "original postmerge and actual public CLI GET E2E. "
            "HypoPG upstream LICENSE link (ZIP has no embedded LICENSE/NOTICE), "
            "no automatic installer or legacy held P3 source. Issue pgextwin/build#112."
        ),
    })
    require(type(pr.get("number")) is int and pr["number"] > 0
            and pr.get("head", {}).get("ref") == branch_name
            and pr.get("base", {}).get("ref") == "main",
            "genuine App Catalog PR proposal did not materialize")
    return pr["number"]

def main():
    try:
        env = dict(os.environ)
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_bytes(),
                           object_pairs_hook=old.no_duplicates)
        base = "repos/pgextwin/build/actions/runs/" + env["GITHUB_RUN_ID"]
        build_sha, catalog_sha, runid = old.check_run_context(
            env, event,
            branch=old.gh_read("repos/pgextwin/build/branches/main"),
            run=old.gh_read(base),
            jobs=old.gh_read(base + "/jobs?per_page=100"),
            approvals=old.gh_read(base + "/approvals"),
            catalog=old.gh_read("repos/pgextwin/catalog/branches/main"),
            expected_extension=HYP)
        files = old.read_exact(env["SIGNED_METADATA_DIR"])
        doc = json.loads(files["external-get-admission.json"],
                         object_pairs_hook=old.no_duplicates)
        expiry = verify_hypopg_manifest(doc, build_sha, catalog_sha, runid,
                                        datetime.now(timezone.utc))
        old.verify_sigstore(env["SIGNED_METADATA_DIR"], build_sha)
        helpers = old.load_module("hypopg_existing_app_proposal_helpers", old.APP_MODULE)
        key = env.pop("EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY")
        with helpers.scoped_catalog_token(
                helpers.shared._existing.api, helpers.shared._existing.jwt, key) as token:
            number = make_pr(helpers.shared._existing.api, token, runid,
                             catalog_sha, files, expiry)
        print(f"HYPOPG_THREE_PG_SIGNED_METADATA_PROTECTED_PR={number} "
              "ZIP=NONE RELEASE=NONE APP_TOKEN_REVOKED=TRUE")
    except Exception:
        print("HYPOPG_SIGNED_PR_DENY; no App credentials, raw source or exception disclosed",
              file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
