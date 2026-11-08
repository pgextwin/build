#!/usr/bin/env python3
"""Issue #112: exact three-asset HypoPG GET-only manifest for authentic owner Run.

This unsigned manifest is not approval: only the real protected Build/main
owner workflow_dispatch + Environment reviewer + same-Run OIDC Sigstore signer
can produce a transferable permission. No mirror, binary upload or Release.
"""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
old_spec = importlib.util.spec_from_file_location("issue112_original_issuer", ROOT / "scripts/external-direct-get-issuer.py")
old = importlib.util.module_from_spec(old_spec)
old_spec.loader.exec_module(old)
SOURCE = "HypoPG/hypopg"
VERSION = "1.4.1"
REPO_ID = 37308208
RELEASE_ID = 153113229
RUNTIME_RUN_ID = 42457245493
RUNTIME_HEAD = "52e695e4959a07e18971e26d293ff4249c071237"
INTAKE = "config/issue112-hypopg-original-get-intake-v1.json"
PINS = {
    "14": (164673161, 23115, "ac1114d1392494e688b5b6b6f151aebe6ccab2d8ae1a004ec510669c47ef3634"),
    "15": (164673166, 23123, "d23ea9ba7d064ee08e431b12ade50bed4b19a725b5f4df1e088e79e4af8d08ec"),
    "16": (164673171, 22997, "7afd7cda50050829787d4e901fc8292cf1eb2bc5ad59c996a92e414a1bead1f7"),
}

def require(condition, why):
    old.require(condition, why)

def validate_source(catalog_checkout, catalog_branch, repo, release, runtime, jobs):
    root = Path(catalog_checkout)
    commit = __import__("subprocess").run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, check=True,
        timeout=30).stdout.decode().strip()
    require(catalog_branch.get("protected") is True
            and catalog_branch.get("commit", {}).get("sha") == commit
            and old.SHA40.fullmatch(commit), "Catalog protected checkout drift")
    sys.path.insert(0, str(root / "scripts"))
    from external_direct_get_intake import validate_intake
    from external_direct_link_review import strict_read
    from issue112_hypopg_original_private import review
    doc = strict_read(root / INTAKE)
    rows = validate_intake(doc)
    require(len(rows) == 3
            and [r["pgMajor"] for r in rows] == ["14", "15", "16"],
            "unexpected reviewed cohort length/PG selection")
    require(repo.get("id") == REPO_ID and repo.get("full_name") == SOURCE
            and repo.get("html_url") == "https://github.com/" + SOURCE
            and release.get("id") == RELEASE_ID
            and release.get("tag_name") == VERSION
            and release.get("html_url") == "https://github.com/" + SOURCE + "/releases/tag/" + VERSION
            and release.get("draft") is False and release.get("prerelease") is False,
            "untrusted upstream provider Release identity")
    assets = release.get("assets")
    require(type(assets) is list and 1 <= len(assets) <= 100,
            "unexpected provider asset inventory")
    seen = set()
    originals = []
    for row in rows:
        pg = row["pgMajor"]
        aid, size, sha = PINS[pg]
        filename = f"hypopg-1.4.1-pg{pg}-x64.zip"
        url = f"https://github.com/{SOURCE}/releases/download/{VERSION}/{filename}"
        require(row["extension"] == "hypopg" and
                row["providerType"] == "upstream-official"
                and row["sourceRepo"] == SOURCE
                and row["repositoryId"] == REPO_ID and row["releaseId"] == RELEASE_ID
                and row["releaseTag"] == VERSION
                and row["assetId"] == aid and row["assetName"] == filename
                and row["originalBytes"] == size and row["originalSha256"] == sha
                and row["originalProviderUrl"] == url
                and row["licenseSpdx"] == "PostgreSQL"
                and row["licenseUrl"] ==
                    f"https://github.com/{SOURCE}/blob/{VERSION}/LICENSE"
                and row["sourcePublisherAuthorized"] is False
                and row["downloadAuthorized"] is False and row["mirrorAuthorized"] is False
                and row["runtimeEvidence"]["repository"] == "pgextwin/catalog"
                and row["runtimeEvidence"]["runId"] == RUNTIME_RUN_ID
                and row["runtimeEvidence"]["headSha"] == RUNTIME_HEAD,
                "unreviewed source row or privilege mismatch")
        matching = [a for a in assets if a.get("id") == aid or a.get("name") == filename]
        require(len(matching) == 1
                and matching[0].get("id") == aid and matching[0].get("name") == filename
                and matching[0].get("size") == size
                and matching[0].get("browser_download_url") == url
                and matching[0].get("state") == "uploaded"
                and matching[0].get("digest") in (None, "sha256:" + sha),
                "provider metadata identity/digest mismatch")
        require(aid not in seen, "replayed asset across signed cohort")
        seen.add(aid)
        original = Path(os.environ["ORIGINAL_BATCH_DIR"]) / f"hypopg-pg{pg}.zip"
        evidence = review(original, pg)
        require(evidence["originalBytes"] == size
                and evidence["independentlyHashedSha256"] == sha
                and evidence["zipCrc"] == "PASS"
                and evidence["peMachine"] == "AMD64"
                and evidence["publisherAuthorized"] is False
                and evidence["downloadAuthorized"] is False,
                "private immutable original bytes or DLL ZIP structure mismatch")
        originals.append((row, evidence))
    require(runtime.get("id") == RUNTIME_RUN_ID
            and runtime.get("event") == "push"
            and runtime.get("run_attempt") == 1
            and runtime.get("status") == "completed"
            and runtime.get("conclusion") == "success"
            and runtime.get("head_branch") == "main"
            and runtime.get("head_sha") == RUNTIME_HEAD
            and runtime.get("path") == ".github/workflows/issue112-hypopg-original-pg14-16.yml"
            and runtime.get("repository", {}).get("full_name") == "pgextwin/catalog",
            "not authentic original Windows qualification run")
    named = {j.get("name"): j for j in jobs.get("jobs", [])}
    require(all(named.get(f"real-original-windows-runtime ({pg})", {}).get("conclusion") == "success"
                and named[f"real-original-windows-runtime ({pg})"].get("run_id") == RUNTIME_RUN_ID
                for pg in PINS), "one or more original Windows PG majors not successful")
    return commit, originals

def manifest(build_sha, runid, catalog_sha, verified, now):
    n = now.astimezone(timezone.utc).replace(microsecond=0)
    require(old.SHA40.fullmatch(build_sha) and old.SHA40.fullmatch(catalog_sha)
            and len(verified) == 3 and type(runid) is int and runid > 0,
            "invalid signed subject source or cohort")
    return {
        "schemaVersion": "pgextwin-external-direct-get-admission/v1",
        "sourceKind": "EXTERNAL_GITHUB_RELEASE_ASSET",
        "issuerRepository": old.BUILD, "issuerCommit": build_sha,
        "catalogCommit": catalog_sha, "issuerEvent": "workflow_dispatch",
        "issuerRunId": runid, "issuerRunAttempt": 1,
        "ownerActor": old.OWNER, "ownerId": old.OWNER_ID,
        "publisherEnvironment": "external-direct-provider-publisher",
        "publisherAppId": old.APP_ID,
        "approvedOperation": old.OPERATION,
        "issuedAt": n.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (n + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "downloadAuthorized": True, "mirrorAuthorized": False,
        "redistributionAuthorized": False,
        "records": [{
            "sourceGroup": "external", "extension": "hypopg",
            "pgMajor": row["pgMajor"],
            "targetEnvironment": row["targetEnvironment"],
            "sourceRepo": SOURCE, "repositoryId": REPO_ID,
            "releaseTag": VERSION, "releaseId": RELEASE_ID,
            "assetName": row["assetName"], "assetId": row["assetId"],
            "originalBytes": row["originalBytes"],
            "originalSha256": row["originalSha256"],
            "originalProviderUrl": row["originalProviderUrl"],
            "licenseUrl": row["licenseUrl"],
            "noticeTreatment": row["noticeTreatment"],
            "dependencyTreatment": row["dependencyTreatment"],
            "approvedOperation": old.OPERATION,
            "downloadAuthorized": True, "mirrorAuthorized": False
        } for row, _ in verified]
    }

def main():
    stage = "OWNER_RUN"
    try:
        env = dict(os.environ)
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_bytes(),
                           object_pairs_hook=old.no_duplicates)
        build, runid = old.validate_original_owner_run(env, event,
            old.gh_get("repos/pgextwin/build/branches/main"),
            old.gh_get("repos/pgextwin/build/actions/runs/" + env["GITHUB_RUN_ID"]),
            expected_extension="hypopg")
        stage = "CATALOG_PROVIDER_ORIGINAL"
        catalog = Path(env["CATALOG_CHECKOUT"])
        sha, verified = validate_source(catalog,
            old.gh_get("repos/pgextwin/catalog/branches/main"),
            old.gh_get("repos/HypoPG/hypopg"),
            old.gh_get("repos/HypoPG/hypopg/releases/tags/1.4.1"),
            old.gh_get(f"repos/pgextwin/catalog/actions/runs/{RUNTIME_RUN_ID}"),
            old.gh_get(f"repos/pgextwin/catalog/actions/runs/{RUNTIME_RUN_ID}/jobs?per_page=100"))
        stage = "APP_SCOPE"
        api, jwt = old.load_external_app_helpers()
        old.verify_app_readonly(env["EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY"], api=api, jwt=jwt)
        stage = "SOURCE_RECHECK"
        require(old.gh_get("repos/pgextwin/build/branches/main")["commit"]["sha"] == build
                and old.gh_get("repos/pgextwin/catalog/branches/main")["commit"]["sha"] == sha,
                "protected source changed during issuance")
        stage = "MANIFEST"
        result = manifest(build, runid, sha, verified, datetime.now(timezone.utc))
        stage = "OUTPUT_CREATE"
        p = Path(env["OUTPUT_FILE"])
        require(not p.exists() and not p.is_symlink(), "non-create-only signed subject")
        with p.open("xb") as f:
            f.write((json.dumps(result, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8"))
        print("HYPOPG_THREE_ASSET_SIGNABLE_SUBJECT_ONLY; SIGNATURE=NEXT_GENUINE_OIDC_STEP "
              "ZIP_UPLOAD=NONE MIRROR=DENY")
    except Exception as error:
        print(old.denial_diagnostic(stage, error), file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
