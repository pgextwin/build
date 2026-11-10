#!/usr/bin/env python3
"""Strict PG14-17 original-source verifier for the 11-ZIP latest cohort.

Proof is a protected Catalog/main Windows push (4 genuine matrix jobs), the
unchanged original test script, two fixed provider Releases and independently
rehashed ORIGINAL ZIPs. No fallback, publication, historical substitutions or
repacking. The signed owner subject is assembled in the existing shared issuer.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

PILOT_SHA = "9442cb0f9fb703a9431691514248f93b93f62f7c"
PILOT_RUN = 42836398873
PILOT_PATH = ".github/workflows/issue112-external-pg14-17-private-pilot.yml"
PILOT_SCRIPT = "scripts/issue112-external-pg14-17-private-pilot.ps1"
PILOT_SCRIPT_BLOB = "1a6c99db93ee87d756840713fb67b619c271ee3d"
EXPECTED_JOBS = {
    "newest-external-major-private (14, 14.24.0)",
    "newest-external-major-private (15, 15.19.0)",
    "newest-external-major-private (16, 16.15.5)",
    "newest-external-major-private (17, 17.11.4)",
}
PINS = (
    ('laurenz/oracle_fdw', 'oracle_fdw', '14', 14332609, 335861225, 'ORACLE_FDW_2_9_0', 442625883, 'oracle_fdw-2.9.0-pg14-win64.zip', 375533, '91a9857041c3e78981f4f554fa03cb606ff8cd0347b7cc3e3604b215f9655b2d', 'https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/LICENSE'),
    ('andreiramani/pgvector_pgsql_windows', 'pgvector', '14', 838202416, 419235203, '0.8.7', 661612126, 'vector.v0.8.7-pg14.zip', 174619, '51dd3626905d31509e06552d16ddcc8eda2ac47d1e84eb923d2aff9207716ee7', 'https://github.com/pgvector/pgvector/blob/v0.8.7/LICENSE'),
    ('laurenz/oracle_fdw', 'oracle_fdw', '15', 14332609, 335861225, 'ORACLE_FDW_2_9_0', 442625869, 'oracle_fdw-2.9.0-pg15-win64.zip', 363671, '3894a25a80cf2d3ac672894ba5cbcbc11c9533ad72cd25d31235285b73182f7a', 'https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/LICENSE'),
    ('andreiramani/pgvector_pgsql_windows', 'pgvector', '15', 838202416, 419235203, '0.8.7', 661612214, 'vector.v0.8.7-pg15.zip', 174667, '33562f2d2bab702a7d6f68b7d53c98e52480eb039c6635164d6b4cfcfdf40cc9', 'https://github.com/pgvector/pgvector/blob/v0.8.7/LICENSE'),
    ('laurenz/oracle_fdw', 'oracle_fdw', '16', 14332609, 335861225, 'ORACLE_FDW_2_9_0', 442625866, 'oracle_fdw-2.9.0-pg16-win64.zip', 365436, 'b9e8826d11c794c03bd49874100712f2ee446a01294b4c1d3632053bbaee8290', 'https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/LICENSE'),
    ('andreiramani/pgvector_pgsql_windows', 'pgvector', '16', 838202416, 419235203, '0.8.7', 661612305, 'vector.v0.8.7-pg16.zip', 174594, '69dee8f237966a5b87ec109ec8ed619613432940a8e6150a1d0da627fc0f2f7e', 'https://github.com/pgvector/pgvector/blob/v0.8.7/LICENSE'),
    ('laurenz/oracle_fdw', 'oracle_fdw', '17', 14332609, 335861225, 'ORACLE_FDW_2_9_0', 442625846, 'oracle_fdw-2.9.0-pg17-win64.zip', 371386, 'a67d0582e855ef5a1099039528cfdfd25b7e31938dab29c5bfb0366d0a368fc7', 'https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/LICENSE'),
    ('andreiramani/pgvector_pgsql_windows', 'pgvector', '17', 838202416, 419235203, '0.8.7', 661612406, 'vector.v0.8.7-pg17.zip', 174653, 'acd9d678200e856623f0b7416f6f5d132ef8606a2273ff37f0fdf8a7f2c5d7d2', 'https://github.com/pgvector/pgvector/blob/v0.8.7/LICENSE'),
)
ROW_KEYS = {
    "sourceGroup", "extension", "pgMajor", "targetEnvironment",
    "sourceRepo", "repositoryId", "releaseTag", "releaseId", "assetName",
    "assetId", "originalBytes", "originalSha256", "originalProviderUrl",
    "licenseUrl", "noticeTreatment", "dependencyTreatment",
    "approvedOperation", "downloadAuthorized", "mirrorAuthorized",
}


def require(ok, message):
    if not ok:
        raise ValueError("newest original Windows ZIP DENY: " + message)


def original_url(pin):
    repo, _, _, _, _, tag, _, name, *_ = pin
    return "https://github.com/" + repo + "/releases/download/" + tag + "/" + name


def verify_pilot(catalog_root, branch, run, jobs):
    root = Path(catalog_root)
    proc = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          check=True, capture_output=True, timeout=30)
    commit = proc.stdout.decode().strip()
    require(branch.get("protected") is True and
            branch.get("commit", {}).get("sha") == commit,
            "not checked out at current protected Catalog main")
    test_file = root / PILOT_SCRIPT
    require(test_file.is_file() and not test_file.is_symlink(),
            "original runtime test script missing")
    blob = subprocess.run(
        ["git", "-C", str(root), "hash-object", PILOT_SCRIPT],
        check=True, capture_output=True, timeout=30).stdout.decode().strip()
    require(blob == PILOT_SCRIPT_BLOB, "qualified Windows runtime test changed")
    require(run.get("id") == PILOT_RUN and
            run.get("head_sha") == PILOT_SHA and
            run.get("event") == "push" and
            run.get("run_attempt") == 1 and
            run.get("path") == PILOT_PATH and
            run.get("head_branch") == "main" and
            run.get("status") == "completed" and
            run.get("conclusion") == "success" and
            run.get("repository", {}).get("full_name") == "pgextwin/catalog",
            "genuine protected-main Windows pilot identity changed")
    verified = jobs.get("jobs")
    require(type(verified) is list and len(verified) == 4 and
            {job.get("name") for job in verified} == EXPECTED_JOBS and
            all(job.get("conclusion") == "success" and
                job.get("status") == "completed" for job in verified),
            "not all four PG14-17 Windows runtime jobs succeeded")
    return commit


def verify_signed_rows(rows):
    require(type(rows) is list and len(rows) == len(PINS),
            "not exactly eight current original Windows binaries")
    for row, pin in zip(rows, PINS):
        repo, ext, pg, repo_id, release_id, tag, asset_id, name, size, sha, license_url = pin
        fixed = {
            "sourceGroup": "external", "extension": ext, "pgMajor": pg,
            "sourceRepo": repo, "repositoryId": repo_id,
            "releaseId": release_id, "releaseTag": tag, "assetId": asset_id,
            "assetName": name, "originalBytes": size, "originalSha256": sha,
            "originalProviderUrl": original_url(pin), "licenseUrl": license_url,
            "approvedOperation": "ORIGINAL_PROVIDER_GET_ONLY",
            "downloadAuthorized": True, "mirrorAuthorized": False,
        }
        require(type(row) is dict and set(row) == ROW_KEYS and
                all(type(row[k]) is type(val) and row[k] == val
                    for k, val in fixed.items()) and
                "PostgreSQL " + pg in row["targetEnvironment"] and
                "Windows x64" in row["targetEnvironment"] and
                len(row["noticeTreatment"]) >= 100 and
                len(row["dependencyTreatment"]) >= 100,
                "signed exact identity, rights, dependency or PG/ABI scope changed")
        if ext == "oracle_fdw":
            require("Oracle Instant Client" in row["noticeTreatment"] and
                    "www.oracle.com/downloads/licenses/instant-client-lic.html"
                    in row["dependencyTreatment"], "Oracle client terms absent")
        else:
            require("no LICENSE/NOTICE" in row["noticeTreatment"] and
                    "Unofficial" in row["dependencyTreatment"],
                    "unofficial pgvector rights disclosure absent")


def validate_rows(catalog_root, branch, upstream, releases, run, jobs,
                  pg18_signed_rows, original_dir):
    """Current provider IDs + exact source digest + old independently proven rights.

    Only PG14-17 assets are added. The existing strict PG18 source reviewer
    validates the two rights/NOTICE templates before calling this function.
    """
    commit = verify_pilot(catalog_root, branch, run, jobs)
    require(type(upstream) is list and len(upstream) == 2 and
            type(releases) is list and len(releases) == 2 and
            type(pg18_signed_rows) is list and len(pg18_signed_rows) == 2,
            "source discovery or PG18 rights template count changed")
    providers = ("laurenz/oracle_fdw", "andreiramani/pgvector_pgsql_windows")
    ids = (14332609, 838202416)
    tags = ("ORACLE_FDW_2_9_0", "0.8.7")
    release_ids = (335861225, 419235203)
    for i in range(2):
        require(upstream[i].get("full_name") == providers[i] and
                upstream[i].get("id") == ids[i] and
                releases[i].get("id") == release_ids[i] and
                releases[i].get("tag_name") == tags[i] and
                releases[i].get("draft") is False and
                releases[i].get("prerelease") is False and
                releases[i].get("published_at") is not None,
                "provider official/community Release changed")
    by_source = {row["sourceRepo"]: row for row in pg18_signed_rows}
    require(set(by_source) == set(providers),
            "reviewed PG18 legal/dependency reference sources differ")
    directory = Path(original_dir)
    require(directory.is_dir() and not directory.is_symlink(),
            "private originals directory unavailable")
    signed = []
    for pin in PINS:
        repo, ext, pg, repo_id, release_id, tag, asset_id, name, size, sha, license_url = pin
        i = providers.index(repo)
        assets = releases[i].get("assets", [])
        matches = [a for a in assets if a.get("id") == asset_id or
                   a.get("name") == name]
        require(len(matches) == 1 and matches[0].get("id") == asset_id and
                matches[0].get("name") == name and
                matches[0].get("size") == size and
                matches[0].get("browser_download_url") == original_url(pin) and
                matches[0].get("state") == "uploaded" and
                matches[0].get("digest") == "sha256:" + sha,
                "asset identity or provider digest mismatch")
        file = directory / name
        require(file.is_file() and not file.is_symlink() and
                file.stat().st_size == size and
                file.resolve().parent == directory.resolve(),
                "original file missing, substituted or wrong size")
        with file.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == sha,
                    "original bytes hash mismatch")
        row = dict(by_source[repo])
        row.update(pgMajor=pg, targetEnvironment="EDB PostgreSQL " + pg +
                   " Windows x64; verified original ZIP, Oracle Client separately "
                   "licensed and installed" if ext == "oracle_fdw" else
                   "EDB PostgreSQL " + pg +
                   " Windows x64; independently tested community pgvector binary",
                   assetId=asset_id, assetName=name, originalBytes=size,
                   originalSha256=sha, originalProviderUrl=original_url(pin))
        signed.append(row)
    verify_signed_rows(signed)
    return commit, signed


def download_plan():
    """Only these reviewed HTTPS URLs enter the existing fail-closed GET helper."""
    for pin in PINS:
        _, _, _, _, _, _, asset_id, name, size, sha, _ = pin
        print("\t".join((original_url(pin), name, str(size), sha, str(asset_id))))


if __name__ == "__main__":
    if sys.argv[1:] != ["--download-plan"]:
        raise SystemExit("Only the immutable private download plan is available")
    download_plan()
