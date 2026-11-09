#!/usr/bin/env python3
"""Two previously Windows-tested PG18 originals for the owner-signed GET cohort.

The protected Catalog review is evidence, never permission. Only the genuine
owner issuer, independent Sigstore verification and Catalog protected merge
can enable CLI GET of these exact unmodified provider assets.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

PINS = (
    ("laurenz/oracle_fdw", "oracle_fdw", "18", 14332609, 335861225,
     "ORACLE_FDW_2_9_0", 442625860, "oracle_fdw-2.9.0-pg18-win64.zip",
     365101, "ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678",
     "https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/LICENSE",
     41661506504, "30929a791f7926c078034cc891a99244bffa9e4d",
     ".github/workflows/issue112-oracle-oci-smoke.yml"),
    ("andreiramani/pgvector_pgsql_windows", "pgvector", "18", 838202416,
     419235203, "0.8.7", 661612613, "vector.v0.8.7-pg18.zip",
     174796, "7c4ae0e2b2cb1e547779209a34a7d3f05b82fd7912818bf3d7042266eda87e7d",
     "https://github.com/pgvector/pgvector/blob/v0.8.7/LICENSE",
     41657903202, "72320cbf5113d89f69af86c5eafcc630f2aaa02c",
     ".github/workflows/issue112-external-windows-pilot.yml"),
)


def require(ok, message):
    if not ok:
        raise ValueError("reviewed PG18 original DENY: " + message)


def expected_row(pin, review):
    repo, ext, pg, rid, release, tag, asset, name, size, sha, license_url, *_ = pin
    url = f"https://github.com/{repo}/releases/download/{tag}/{name}"
    require(review["sourceRepo"] == repo and review["extension"] == ext
            and review["pgMajor"] == pg and review["repositoryId"] == rid
            and review["releaseId"] == release and review["releaseTag"] == tag
            and review["assetId"] == asset and review["assetName"] == name
            and review["originalBytes"] == size and review["originalSha256"] == sha
            and review["originalProviderUrl"] == url
            and review["packageLicenseUrl"] == license_url
            and review["referenceLinkReviewed"] is True
            and review["downloadAuthorized"] is False
            and review["mirrorAuthorized"] is False,
            "Catalog immutable review or authorization flag changed")
    dependency = (review["providerStatusNotice"] + " " +
                  review["dependencyInformationUrl"] + " " +
                  (review.get("dependencyLicenseUrl") or "No bundled dependency license") +
                  "; dependency installation and license are the user's responsibility.")
    return {
        "sourceGroup": "external", "extension": ext, "pgMajor": pg,
        "targetEnvironment": review["targetEnvironment"],
        "sourceRepo": repo, "repositoryId": rid, "releaseTag": tag,
        "releaseId": release, "assetName": name, "assetId": asset,
        "originalBytes": size, "originalSha256": sha,
        "originalProviderUrl": url, "licenseUrl": license_url,
        "noticeTreatment": review["noticeTreatment"],
        "dependencyTreatment": dependency,
        "approvedOperation": "ORIGINAL_PROVIDER_GET_ONLY",
        "downloadAuthorized": True, "mirrorAuthorized": False,
    }


def validate_rows(catalog, branch, upstream, releases, runtime):
    root = Path(catalog)
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            check=True, capture_output=True, timeout=30).stdout.decode().strip()
    require(branch.get("protected") is True and branch.get("commit", {}).get("sha") == commit,
            "checked out Catalog is not protected main")
    sys.path.insert(0, str(root / "scripts"))
    from external_direct_link_review import validate_review, strict_read, REVIEW
    result = validate_review(root)
    require(result == {"referenceLinksReviewed": 2, "signedExternalCatalogPins": 0,
                       "downloadAuthorized": False, "mirrorAuthorized": False,
                       "scope": "CANDIDATE_ONLY"}, "review must remain nonauthorizing")
    rows = strict_read(root / REVIEW)["records"]
    require(len(rows) == len(PINS), "not exactly two reviewed originals")
    signed = []
    for pin, review, repo_doc, release_doc, run_doc in zip(
            PINS, rows, upstream, releases, runtime):
        repo, _, _, rid, release, tag, aid, name, size, sha, _, runid, head, workflow = pin
        row = expected_row(pin, review)
        require(repo_doc.get("full_name") == repo and repo_doc.get("id") == rid
                and release_doc.get("id") == release and release_doc.get("tag_name") == tag
                and release_doc.get("draft") is False and
                release_doc.get("published_at") is not None,
                "provider repo or tagged Release identity changed")
        matching = [a for a in release_doc.get("assets", [])
                    if a.get("id") == aid or a.get("name") == name]
        require(len(matching) == 1 and matching[0].get("id") == aid
                and matching[0].get("name") == name
                and matching[0].get("size") == size
                and matching[0].get("browser_download_url") == row["originalProviderUrl"]
                and matching[0].get("state") == "uploaded"
                and matching[0].get("digest") in (None, "sha256:" + sha),
                "provider original asset identity or digest changed")
        require(run_doc.get("id") == runid and run_doc.get("event") == "push"
                and run_doc.get("run_attempt") == 1
                and run_doc.get("head_branch") == "main"
                and run_doc.get("head_sha") == head
                and run_doc.get("path") == workflow
                and run_doc.get("status") == "completed"
                and run_doc.get("conclusion") == "success"
                and run_doc.get("repository", {}).get("full_name") == "pgextwin/catalog",
                "independent original Windows runtime evidence differs")
        original = Path(os.environ["ORIGINAL_PG18_DIR"]) / name
        require(original.is_file() and not original.is_symlink()
                and original.stat().st_size == size,
                "privately downloaded original asset size differs")
        with original.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == sha,
                    "privately downloaded original asset digest differs")
        signed.append(row)
    return commit, signed


def verify_signed_rows(rows):
    """Exact immutable signature payload check; does not trust a Catalog flag."""
    require(type(rows) is list and len(rows) == 2, "unexpected reviewed cohort size")
    for row, pin in zip(rows, PINS):
        repo, ext, pg, rid, release, tag, aid, name, size, sha, license_url, *_ = pin
        fixed = {"sourceGroup": "external", "extension": ext, "pgMajor": pg,
                 "sourceRepo": repo, "repositoryId": rid, "releaseId": release,
                 "releaseTag": tag, "assetId": aid, "assetName": name,
                 "originalBytes": size, "originalSha256": sha,
                 "originalProviderUrl":
                     f"https://github.com/{repo}/releases/download/{tag}/{name}",
                 "licenseUrl": license_url,
                 "approvedOperation": "ORIGINAL_PROVIDER_GET_ONLY",
                 "downloadAuthorized": True, "mirrorAuthorized": False}
        require(type(row) is dict and set(row) == {
            *fixed, "targetEnvironment", "noticeTreatment", "dependencyTreatment"},
            "unknown signed PG18 source field")
        require(all(type(row[k]) is type(v) and row[k] == v for k, v in fixed.items())
                and "PostgreSQL 18" in row["targetEnvironment"]
                and "Windows x64" in row["targetEnvironment"]
                and len(row["noticeTreatment"]) >= 100
                and len(row["dependencyTreatment"]) >= 100,
                "source identity, license, NOTICE or dependency mismatched")
        if ext == "oracle_fdw":
            require("Oracle Instant Client" in row["noticeTreatment"]
                    and "www.oracle.com/downloads/licenses/instant-client-lic.html"
                        in row["dependencyTreatment"], "Oracle dependency license missing")
        else:
            require("no LICENSE/NOTICE" in row["noticeTreatment"]
                    and "Unofficial" in row["dependencyTreatment"],
                    "unofficial pgvector copyright/attribution missing")

