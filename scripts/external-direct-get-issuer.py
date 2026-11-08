#!/usr/bin/env python3
"""Issue #112: genuine protected-main, Environment-gated GET-only signed issuer.

The workflow, not local invocations of this script, provides the authenticated
GitHub Actions OIDC signing identity. This program signs nothing, publishes
nothing and writes only the short-lived manifest that Actions must attest.
No mirror/redistribution, installer, ref or GitHub Release write is permitted.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

OWNER = "ShutenOishi"
OWNER_ID = 27071164
BUILD = "pgextwin/build"
CATALOG = "pgextwin/catalog"
APP_ID = 5609317
INSTALL_ID = 178510512
WORKFLOW = ".github/workflows/external-direct-get-issuer.yml"
OPERATION = "ORIGINAL_PROVIDER_GET_ONLY"
SOURCE_REPO = "trickle-labs/pg-trickle"
SOURCE_ID = 1164857056
RELEASE_ID = 404988260
ASSET_ID = 616203967
ASSET_SIZE = 7029107
ASSET_SHA = "c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b"
RUNTIME_RUN = 41870312567
RUNTIME_HEAD = "47b8351250c283a923b5e4f6d0ed74f9d7db6d10"
UPSTREAM_RUN = 37489585623
UPSTREAM_HEAD = "ce709f06327b4801f79fc48934bc96107b450907"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
REPO_PATH = re.compile(r"repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:branches/main|actions/runs/[0-9]+(?:/jobs\?per_page=100)?|releases/tags/[A-Za-z0-9_.-]+)\Z")

class Denied(ValueError):
    pass

def require(ok, detail):
    if not ok:
        raise Denied("external original GET-only issuer DENY: " + detail)

def no_duplicates(items):
    obj = {}
    for key, value in items:
        require(key not in obj, "duplicate API or GitHub event JSON key")
        obj[key] = value
    return obj

def gh_get(route):
    require(REPO_PATH.fullmatch(route) is not None or
            route in ("repos/pgextwin/catalog", "repos/trickle-labs/pg-trickle",
                      "repos/HypoPG/hypopg", "repos/portalcorp/pgvector_compiled",
                      "repos/portalcorp/pgvector_compiled/git/ref/tags/v0.16.105"),
            "nonallowlisted GitHub read")
    result = subprocess.run(["gh", "api", "--method", "GET", route],
                            capture_output=True, check=False, timeout=60)
    require(result.returncode == 0 and 0 < len(result.stdout) < 3_000_000,
            "GitHub authenticated GET unavailable")
    return json.loads(result.stdout, object_pairs_hook=no_duplicates)

def validate_original_owner_run(env, event, build_branch, run, expected_extension="pg_trickle"):
    require(expected_extension in ("pg_trickle", "hypopg", "portalcorp_pgvector"), "unreviewed dispatch cohort")
    """A real owner workflow_dispatch is not equivalent to a Chat flag."""
    expected = {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": BUILD,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_ACTOR": OWNER, "GITHUB_TRIGGERING_ACTOR": OWNER,
        "GITHUB_ACTOR_ID": str(OWNER_ID), "GITHUB_RUN_ATTEMPT": "1",
    }
    require(type(env) is dict and all(env.get(k) == v for k, v in expected.items()),
            "wrong GitHub runtime or owner actor")
    sha = env.get("GITHUB_SHA")
    runid = env.get("GITHUB_RUN_ID")
    require(type(sha) is str and SHA40.fullmatch(sha) is not None
            and type(runid) is str and runid.isascii() and runid.isdecimal()
            and int(runid) > 0, "invalid protected build source")
    require(type(event) is dict
            and set(event.get("inputs", {})) == {"extension", "operation"}
            and event["inputs"] == {"extension": expected_extension, "operation": OPERATION}
            and (event.get("repository") or {}).get("full_name") == BUILD,
            "wrong exact source-specific dispatch")
    require(type(build_branch) is dict and build_branch.get("protected") is True
            and (build_branch.get("commit") or {}).get("sha") == sha,
            "Build protected main no longer matches issuer")
    require(type(run) is dict and run.get("id") == int(runid)
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == WORKFLOW
            and run.get("head_branch") == "main"
            and run.get("head_sha") == sha
            and run.get("run_attempt") == 1
            and run.get("status") == "in_progress"
            and run.get("conclusion") is None
            and (run.get("repository") or {}).get("full_name") == BUILD
            and (run.get("actor") or {}).get("login") == OWNER
            and (run.get("actor") or {}).get("id") == OWNER_ID
            and (run.get("triggering_actor") or {}).get("login") == OWNER,
            "wrong original source-specific owner Run")
    return sha, int(runid)

def validate_catalog_and_provider(catalog, catalog_branch, repository, release,
                                  runtime_run, upstream_run):
    """Never use candidate JSON as its own permission or REST authenticator."""
    root = Path(catalog)
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, check=True).stdout.decode().strip()
    require(SHA40.fullmatch(commit) is not None and
            catalog_branch.get("protected") is True and
            (catalog_branch.get("commit") or {}).get("sha") == commit,
            "Catalog protected main or checked out source diverged")
    sys.path.insert(0, str(root / "scripts"))
    from external_direct_get_intake import INTAKE, validate_intake
    from external_direct_link_review import strict_read
    from external_provider_release_identity import compare_exact_source
    doc = strict_read(root / INTAKE)
    rows = validate_intake(doc)
    require(len(rows) == 1, "unexpected added source permission")
    row = rows[0]
    require(row["sourceRepo"] == SOURCE_REPO
            and row["repositoryId"] == SOURCE_ID
            and row["releaseId"] == RELEASE_ID
            and row["assetId"] == ASSET_ID
            and row["originalBytes"] == ASSET_SIZE
            and row["originalSha256"] == ASSET_SHA
            and row["extension"] == "pg_trickle" and row["pgMajor"] == "18"
            and row["licenseSpdx"] == "Apache-2.0"
            and doc["authorizationIssuer"] == "NONE"
            and doc["downloadAuthorized"] is False
            and doc["mirrorAuthorized"] is False,
            "intake attempted authorization or provider substitution")
    match = compare_exact_source(row, repository, release)
    require(match["downloadAuthorized"] is False and
            match["mirrorAuthorized"] is False, "untrusted provider admission")
    for info, expected_id, expected_sha, expected_repo in (
        (runtime_run, RUNTIME_RUN, RUNTIME_HEAD, CATALOG),
        (upstream_run, UPSTREAM_RUN, UPSTREAM_HEAD, SOURCE_REPO),
    ):
        require(info.get("id") == expected_id
                and info.get("event") == "push"
                and info.get("run_attempt") == 1
                and info.get("status") == "completed"
                and info.get("conclusion") == "success"
                and info.get("head_sha") == expected_sha
                and (info.get("repository") or {}).get("full_name") == expected_repo,
                "original Windows/provider source Run not authenticated")
    return commit, row

def verify_original_zip(path):
    """Independently hash exact provider original ZIP, bounded CRC and LICENSE."""
    p = Path(path)
    require(p.is_file() and not p.is_symlink()
            and p.stat().st_size == ASSET_SIZE, "original bytes absent or changed")
    b = p.read_bytes()
    require(hashlib.sha256(b).hexdigest() == ASSET_SHA, "original byte SHA256 drift")
    expanded = 0
    seen = set()
    prefix = "pg_trickle-0.108.3-pg18-windows-amd64/"
    with zipfile.ZipFile(p) as z:
        infos = z.infolist()
        require(4 <= len(infos) <= 1000, "ZIP entries out of bound")
        for i in infos:
            name = i.filename
            require(name.startswith(prefix) and "\\" not in name and
                    ":" not in name and not name.startswith("/") and
                    all(part not in (".", "..") for part in name.split("/"))
                    and name.casefold() not in seen
                    and stat.S_IFMT((i.external_attr >> 16)) != stat.S_IFLNK,
                    "unsafe ZIP member")
            seen.add(name.casefold())
            require(i.file_size <= 64 * 1024 * 1024 and
                    i.file_size <= 1000 * max(1, i.compress_size),
                    "ZIP expansion ratio or single file bound")
            expanded += i.file_size
            require(expanded <= 256 * 1024 * 1024, "ZIP cumulative expansion")
        require(z.testzip() is None, "ZIP CRC failed")
        license_name = prefix + "LICENSE"
        require(license_name.casefold() in seen, "original Apache LICENSE absent")
        license_bytes = z.read(license_name)
        require(b"Apache License" in license_bytes and
                b"Version 2.0, January 2004" in license_bytes,
                "original packaged license not as reviewed")
    return {"bytes": len(b), "sha256": ASSET_SHA, "zipMembers": len(infos)}

def verify_app_readonly(private_key, *, api, jwt):
    """Require the dedicated external App/installation, without mint/write."""
    require(type(private_key) is str and len(private_key) > 40,
            "dedicated Environment App key absent")
    assertion = jwt(private_key, APP_ID)
    app = api("GET", "/app", assertion)
    install = api("GET", f"/app/installations/{INSTALL_ID}", assertion)
    require(app.get("id") == APP_ID and
            app.get("slug") == "pgextwin-external-direct-publisher" and
            install.get("id") == INSTALL_ID and install.get("app_id") == APP_ID and
            install.get("repository_selection") == "selected" and
            install.get("permissions") ==
                {"metadata": "read", "contents": "write", "pull_requests": "write"} and
            install.get("suspended_at") is None and
            (install.get("account") or {}).get("login") == "pgextwin",
            "wrong external App scope or identity")

def make_manifest(*, build_sha, runid, catalog_sha, row, proof, now):
    """Data construction only; NEVER itself an authorization or signature."""
    require(SHA40.fullmatch(build_sha) is not None and
            SHA40.fullmatch(catalog_sha) is not None and
            type(runid) is int and runid > 0 and
            proof == {"bytes": ASSET_SIZE, "sha256": ASSET_SHA, "zipMembers": 158},
            "missing independently verified original proof")
    assert row["assetId"] == ASSET_ID and row["sourceRepo"] == SOURCE_REPO
    n = now.astimezone(timezone.utc).replace(microsecond=0)
    expiry = n + timedelta(hours=6)
    return {
        "schemaVersion": "pgextwin-external-direct-get-admission/v1",
        "sourceKind": "EXTERNAL_GITHUB_RELEASE_ASSET",
        "issuerRepository": BUILD, "issuerCommit": build_sha,
        "catalogCommit": catalog_sha, "issuerEvent": "workflow_dispatch",
        "issuerRunId": runid, "issuerRunAttempt": 1,
        "ownerActor": OWNER, "ownerId": OWNER_ID,
        "publisherEnvironment": "external-direct-provider-publisher",
        "publisherAppId": APP_ID, "approvedOperation": OPERATION,
        "issuedAt": n.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "downloadAuthorized": True, "mirrorAuthorized": False,
        "redistributionAuthorized": False,
        "records": [{
            "sourceGroup": "external", "extension": "pg_trickle",
            "pgMajor": "18", "targetEnvironment": row["targetEnvironment"],
            "sourceRepo": SOURCE_REPO, "repositoryId": SOURCE_ID,
            "releaseTag": row["releaseTag"], "releaseId": RELEASE_ID,
            "assetName": row["assetName"], "assetId": ASSET_ID,
            "originalBytes": ASSET_SIZE, "originalSha256": ASSET_SHA,
            "originalProviderUrl": row["originalProviderUrl"],
            "licenseUrl": row["licenseUrl"],
            "noticeTreatment": row["noticeTreatment"],
            "dependencyTreatment": row["dependencyTreatment"],
            "approvedOperation": OPERATION,
            "downloadAuthorized": True, "mirrorAuthorized": False,
        }]
    }

# Fixed, nonsecret stage labels only; never log exceptions or API response bodies.
DENIAL_STAGES = frozenset({
    "EVENT", "OWNER_RUN", "CATALOG_PROVIDER", "ORIGINAL_ZIP",
    "APP_MODULE", "APP_SCOPE", "SOURCE_RECHECK", "MANIFEST", "OUTPUT_CREATE",
})

def denial_diagnostic(stage, error):
    label = stage if stage in DENIAL_STAGES else "UNKNOWN"
    category = "POLICY" if isinstance(error, Denied) else "RUNTIME"
    return ("EXTERNAL_DIRECT_GET_ISSUER_DENY STAGE=" + label +
            " CLASS=" + category +
            "; no tokens or untrusted API payloads emitted")

def load_external_app_helpers():
    """Import the actual nonpublishing App probe and reuse its original primitives."""
    source = importlib.util.spec_from_file_location(
        "external_app_proof",
        Path(__file__).with_name("probe-external-direct-provider-app.py"))
    require(source is not None and source.loader is not None,
            "external App probe module unavailable")
    mod = importlib.util.module_from_spec(source)
    source.loader.exec_module(mod)
    # probe-external-direct-provider-app.py imports the shared probe as _existing.
    return mod._existing.api, mod._existing.jwt

def main():
    stage = "EVENT"
    try:
        env = dict(os.environ)
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text("utf-8"),
                           object_pairs_hook=no_duplicates)
        stage = "OWNER_RUN"
        build, runid = validate_original_owner_run(env, event,
            gh_get("repos/pgextwin/build/branches/main"),
            gh_get("repos/pgextwin/build/actions/runs/" + env["GITHUB_RUN_ID"]))
        stage = "CATALOG_PROVIDER"
        catalog_root = Path(env["CATALOG_CHECKOUT"])
        sha, row = validate_catalog_and_provider(catalog_root,
            gh_get("repos/pgextwin/catalog/branches/main"),
            gh_get("repos/trickle-labs/pg-trickle"),
            gh_get("repos/trickle-labs/pg-trickle/releases/tags/v0.108.3"),
            gh_get(f"repos/pgextwin/catalog/actions/runs/{RUNTIME_RUN}"),
            gh_get(f"repos/trickle-labs/pg-trickle/actions/runs/{UPSTREAM_RUN}"))
        stage = "ORIGINAL_ZIP"
        zip_proof = verify_original_zip(env["ORIGINAL_ZIP"])
        stage = "APP_MODULE"
        api, jwt = load_external_app_helpers()
        stage = "APP_SCOPE"
        verify_app_readonly(env["EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY"],
                            api=api, jwt=jwt)
        stage = "SOURCE_RECHECK"
        # TOCTOU protection: reauthenticate Build and Catalog main immediately
        # before emitting an unsigned manifest for the real OIDC signer.
        require(gh_get("repos/pgextwin/build/branches/main")["commit"]["sha"] == build
                and gh_get("repos/pgextwin/catalog/branches/main")["commit"]["sha"] == sha,
                "protected source advanced before issuance")
        stage = "MANIFEST"
        payload = make_manifest(build_sha=build, runid=runid, catalog_sha=sha,
                                row=row, proof=zip_proof, now=datetime.now(timezone.utc))
        stage = "OUTPUT_CREATE"
        output = Path(env["OUTPUT_FILE"])
        require(not output.exists() and not output.is_symlink(),
                "non-create-only issuer output")
        with output.open("xb") as f:
            f.write((json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8"))
        print("GET_ONLY_MANIFEST_CREATED_UNSIGNED; NEXT=REAL_OIDC_ATTESTATION "
              "PUBLICATION=DENY MIRROR=DENY REDISTRIBUTION=DENY")
    except Exception as error:
        print(denial_diagnostic(stage, error), file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
