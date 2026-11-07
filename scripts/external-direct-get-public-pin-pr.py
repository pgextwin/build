#!/usr/bin/env python3
"""Issue #112: propose ONLY genuine signed GET-only metadata on a protected Catalog PR.

Runs solely as a third job of a genuine owner-dispatched Build issuer, after its
independent Sigstore verifier. An Environment-gated, Catalog-only GitHub App
creates an immutable two-file proposal; it never writes main, a Release, ZIP,
tag, mirror or an existing path. A green proposal is NOT a public Catalog pin:
protected merge and genuine postmerge checks are separately mandatory.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
APP_MODULE = ROOT / "scripts/external-direct-source-pr-admission.py"
ISSUER_MODULE = ROOT / "scripts/external-direct-get-issuer.py"
BUILD = "pgextwin/build"
CATALOG = "pgextwin/catalog"
ENVIRONMENT = "external-direct-provider-publisher"
ENV_ID = 26208765001
OWNER_ID = 27071164
OPERATION = "ORIGINAL_PROVIDER_GET_ONLY"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TOP_KEYS = {
    "schemaVersion", "sourceKind", "issuerRepository", "issuerCommit",
    "catalogCommit", "issuerEvent", "issuerRunId", "issuerRunAttempt",
    "ownerActor", "ownerId", "publisherEnvironment", "publisherAppId",
    "approvedOperation", "issuedAt", "expiresAt", "downloadAuthorized",
    "mirrorAuthorized", "redistributionAuthorized", "records",
}
ROW_KEYS = {
    "sourceGroup", "extension", "pgMajor", "targetEnvironment", "sourceRepo",
    "repositoryId", "releaseTag", "releaseId", "assetName", "assetId",
    "originalBytes", "originalSha256", "originalProviderUrl",
    "licenseUrl", "noticeTreatment", "dependencyTreatment",
    "approvedOperation", "downloadAuthorized", "mirrorAuthorized",
}

class Denied(ValueError):
    pass

def require(ok, why):
    if not ok:
        raise Denied("external public signed GET pin PR DENY: " + why)

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "missing approved helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def gh_read(route):
    require(re.fullmatch(
        r"repos/pgextwin/(?:build|catalog)/(?:branches/main|actions/runs/[0-9]+(?:/jobs\?per_page=100|/approvals)?)",
        route) is not None, "unexpected GitHub GET route")
    p = subprocess.run(["gh", "api", "--method", "GET", route],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=60)
    require(p.returncode == 0 and 0 < len(p.stdout) < 3000000, "authenticated GitHub GET unavailable")
    return json.loads(p.stdout, object_pairs_hook=no_duplicates)

def no_duplicates(items):
    d = {}
    for key, value in items:
        require(key not in d, "duplicate JSON key")
        d[key] = value
    return d

def read_exact(directory):
    root = Path(directory)
    require(root.is_dir() and not root.is_symlink(), "missing flat artifact")
    expected = {"external-get-admission.json", "attestation.json"}
    require({p.name for p in root.iterdir()} == expected, "unexpected signed artifact layout")
    contents = {}
    for name in sorted(expected):
        p = root / name
        require(p.is_file() and not p.is_symlink() and 100 < p.stat().st_size < 200000,
                "missing or unsafe signed file")
        contents[name] = p.read_bytes()
    return contents

def parse_utc(value):
    require(type(value) is str and re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value) is not None, "invalid timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Denied("invalid timestamp") from None

def verify_manifest(data, *, build_sha, catalog_sha, run_id, now):
    require(type(data) is dict and set(data) == TOP_KEYS, "unknown admission envelope")
    for key, expected in (
        ("schemaVersion", "pgextwin-external-direct-get-admission/v1"),
        ("sourceKind", "EXTERNAL_GITHUB_RELEASE_ASSET"),
        ("issuerRepository", BUILD),
        ("issuerCommit", build_sha),
        ("catalogCommit", catalog_sha),
        ("issuerEvent", "workflow_dispatch"),
        ("issuerRunId", run_id),
        ("issuerRunAttempt", 1),
        ("ownerActor", "ShutenOishi"),
        ("ownerId", OWNER_ID),
        ("publisherEnvironment", ENVIRONMENT),
        ("publisherAppId", 5609317),
        ("approvedOperation", OPERATION),
        ("downloadAuthorized", True),
        ("mirrorAuthorized", False),
        ("redistributionAuthorized", False),
    ):
        require(type(data[key]) is type(expected) and data[key] == expected,
                "untrusted admission field " + key)
    issued, expires = parse_utc(data["issuedAt"]), parse_utc(data["expiresAt"])
    require(expires - issued == timedelta(hours=6)
            and issued <= now < expires, "expired or altered six-hour admission")
    records = data["records"]
    require(type(records) is list and len(records) == 1
            and type(records[0]) is dict and set(records[0]) == ROW_KEYS,
            "wrong source/row count")
    row = records[0]
    for key, expected in (
        ("sourceGroup", "external"), ("extension", "pg_trickle"),
        ("pgMajor", "18"), ("sourceRepo", "trickle-labs/pg-trickle"),
        ("repositoryId", 1164857056), ("releaseTag", "v0.108.3"),
        ("releaseId", 404988260), ("assetId", 616203967),
        ("assetName", "pg_trickle-0.108.3-pg18-windows-amd64.zip"),
        ("originalBytes", 7029107),
        ("originalSha256", "c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b"),
        ("approvedOperation", OPERATION),
        ("downloadAuthorized", True), ("mirrorAuthorized", False),
    ):
        require(type(row[key]) is type(expected) and row[key] == expected,
                "source permission/identity changed: " + key)
    require(row["originalProviderUrl"] ==
            "https://github.com/trickle-labs/pg-trickle/releases/download/v0.108.3/"
            "pg_trickle-0.108.3-pg18-windows-amd64.zip", "provider URL substituted")
    require(type(row["licenseUrl"]) is str and
            row["licenseUrl"] == "https://github.com/trickle-labs/pg-trickle/blob/v0.108.3/LICENSE",
            "license reference changed")
    for name in ("targetEnvironment", "noticeTreatment", "dependencyTreatment"):
        require(type(row[name]) is str and len(row[name]) >= 30,
                "required end-user notice absent")
    return expires

def check_run_context(env, event, *, branch, run, jobs, approvals, catalog):
    issuer = load_module("issue112_get_issuer", ISSUER_MODULE)
    build_sha, run_id = issuer.validate_original_owner_run(env, event, branch, run)
    require(catalog.get("protected") is True and
            SHA40.fullmatch((catalog.get("commit") or {}).get("sha", "")) is not None,
            "Catalog main is unprotected")
    job_map = {j.get("name"): j for j in jobs.get("jobs", [])}
    require(all(name in job_map and job_map[name].get("conclusion") == "success"
            and job_map[name].get("run_id") == run_id
            for name in ("issue-and-attest", "independent-verify")),
            "same-Run independent verification did not succeed")
    require(type(approvals) is list and any(
        a.get("state") == "approved" and
        (a.get("user") or {}).get("login") == "ShutenOishi" and
        (a.get("user") or {}).get("id") == OWNER_ID and
        any(e.get("id") == ENV_ID and e.get("name") == ENVIRONMENT
            for e in a.get("environments", []))
        for a in approvals), "owner did not approve this Run's Environment")
    return build_sha, catalog["commit"]["sha"], run_id

def verify_sigstore(directory, build_sha):
    p = subprocess.run([
        "gh", "attestation", "verify",
        str(Path(directory) / "external-get-admission.json"),
        "--repo", BUILD,
        "--bundle", str(Path(directory) / "attestation.json"),
        "--signer-workflow", BUILD + "/.github/workflows/external-direct-get-issuer.yml",
        "--source-ref", "refs/heads/main",
        "--source-digest", build_sha, "--deny-self-hosted-runners", "--format", "json",
    ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=120)
    require(p.returncode == 0 and 2 <= len(p.stdout) <= 5000000,
            "independent cryptographic Sigstore verification failed")
    results = json.loads(p.stdout, object_pairs_hook=no_duplicates)
    require(type(results) is list and len(results) >= 1,
            "no independent verified Sigstore attestations")

def path_for(run_id, filename):
    require(type(run_id) is int and 0 < run_id < 10**15, "invalid Run ID")
    require(filename in ("external-get-admission.json", "attestation.json"),
            "unexpected metadata filename")
    return f"external/signed-direct-get/pg_trickle/run-{run_id}/{filename}"

def allowed_write(method, route, run_id):
    allowed = {
        ("POST", "/repos/pgextwin/catalog/git/refs"),
        ("POST", "/repos/pgextwin/catalog/pulls"),
    } | {
        ("PUT", "/repos/pgextwin/catalog/contents/" + path_for(run_id, f))
        for f in ("external-get-admission.json", "attestation.json")
    }
    require((method, route) in allowed, "Catalog PR-only App write allowlist")

def make_pr(*, api, token, run_id, catalog_sha, contents, expires):
    base = "/repos/pgextwin/catalog"
    branch_name = f"issue112-pg-trickle-signed-get-run-{run_id}"
    branch = api("GET", base + "/branches/main", token)
    require(branch.get("protected") is True
            and branch.get("commit", {}).get("sha") == catalog_sha,
            "Catalog protected main advanced before PR")
    allowed_write("POST", base + "/git/refs", run_id)
    api("POST", base + "/git/refs", token, {
        "ref": "refs/heads/" + branch_name, "sha": catalog_sha})
    # Two original signed files, unchanged, separately create-only.
    for filename in ("external-get-admission.json", "attestation.json"):
        dest = path_for(run_id, filename)
        route = base + "/contents/" + dest
        allowed_write("PUT", route, run_id)
        api("PUT", route, token, {
            "message": "chore(#112): stage immutable GET-only signed metadata " + filename,
            "branch": branch_name,
            "content": base64.b64encode(contents[filename]).decode("ascii"),
        })
        source = api("GET", route + "?ref=" + branch_name, token)
        require(source.get("type") == "file" and
                source.get("path") == dest and
                base64.b64decode(source.get("content", ""), validate=False) ==
                    contents[filename], "PR-branch original metadata readback mismatch")
    again = api("GET", base + "/branches/main", token)
    require(again.get("protected") is True
            and again.get("commit", {}).get("sha") == catalog_sha
            and datetime.now(timezone.utc) < expires,
            "main advanced or admission expired before PR")
    allowed_write("POST", base + "/pulls", run_id)
    pr = api("POST", base + "/pulls", token, {
        "title": f"feat(#112): authentic pg_trickle signed GET-only pin Run {run_id}",
        "head": branch_name, "base": "main", "draft": False,
        "body": (
            "Original Build owner workflow_dispatch, Run %d / attempt 1, "
            "protected main, dedicated Environment owner review, same-Run "
            "independent Sigstore verification and exact signed bytes verified. "
            "Metadata only; zero third-party ZIPs. Six-hour expiry; an expired "
            "pin is DENY and MUST NOT be refreshed without a fresh genuine issuer. "
            "This PR is NOT an authorized public Catalog pin until protected "
            "merge and original postmerge succeed. External ZIP MIRROR_DENY, "
            "REDISTRIBUTION_DENY; older oracle_fdw / community pgvector HOLD. "
            "Independent third-party NOTICE/dependency closure is not claimed. "
            "Issue pgextwin/build#112." % run_id),
    })
    require(type(pr) is dict and type(pr.get("number")) is int
            and pr["number"] > 0
            and pr.get("head", {}).get("ref") == branch_name
            and pr.get("base", {}).get("ref") == "main",
            "Catalog PR creation did not return exact branch")
    return pr["number"]

def main():
    try:
        env = dict(os.environ)
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_bytes(),
                           object_pairs_hook=no_duplicates)
        build_sha, catalog_sha, run_id = check_run_context(
            env, event,
            branch=gh_read("repos/pgextwin/build/branches/main"),
            run=gh_read("repos/pgextwin/build/actions/runs/" + env["GITHUB_RUN_ID"]),
            jobs=gh_read("repos/pgextwin/build/actions/runs/" + env["GITHUB_RUN_ID"] + "/jobs?per_page=100"),
            approvals=gh_read("repos/pgextwin/build/actions/runs/" + env["GITHUB_RUN_ID"] + "/approvals"),
            catalog=gh_read("repos/pgextwin/catalog/branches/main"),
        )
        directory = env["SIGNED_METADATA_DIR"]
        contents = read_exact(directory)
        admission = json.loads(contents["external-get-admission.json"],
                               object_pairs_hook=no_duplicates)
        expires = verify_manifest(admission, build_sha=build_sha,
            catalog_sha=catalog_sha, run_id=run_id, now=datetime.now(timezone.utc))
        verify_sigstore(directory, build_sha)
        old = load_module("issue112_source_pr_helpers", APP_MODULE)
        key = env.pop("EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY")
        with old.scoped_catalog_token(old.shared._existing.api, old.shared._existing.jwt, key) as token:
            number = make_pr(api=old.shared._existing.api, token=token,
                run_id=run_id, catalog_sha=catalog_sha,
                contents=contents, expires=expires)
        print(f"SIGNED_GET_ONLY_METADATA_PR={number} "
              "APP_REVOKED=TRUE PUBLIC_MAIN_PIN=NOT_YET "
              "ZIP_UPLOAD=NONE MIRROR=DENY REDISTRIBUTION=DENY")
    except Exception:
        print("EXTERNAL_SIGNED_GET_ONLY_PUBLIC_PIN_PR_DENY; "
              "no tokens, sensitive API bodies or external bytes emitted", file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
