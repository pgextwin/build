#!/usr/bin/env python3
"""Issue #112: assemble seven independently qualified provider originals for ONE owner Run.

This creates only an unsigned, six-hour GET-only subject. A real protected-main
owner workflow_dispatch and Environment, then a separate OIDC/Sigstore signer,
independent verifier, and second Environment-approved PR are still required.
No third-party ZIPs are uploaded, mirrored, installed, or published.
"""
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing source-specific immutable verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trickle = load("qualified_trickle", "external-direct-get-issuer.py")
hypopg = load("qualified_hypopg", "external-direct-get-hypopg-issuer.py")
portalcorp = load("qualified_portalcorp", "external-direct-get-portalcorp-issuer.py")
reviewed = load("qualified_reviewed_pg18", "external-direct-get-reviewed-pg18.py")
latest = load("qualified_reviewed_pg14_17", "external-direct-get-reviewed-latest-majors.py")
COHORT = "qualified_cohort"


def combine_manifests(build, runid, catalog_sha, trickle_row, trickle_proof,
                      hypopg_verified, portalcorp_row, portalcorp_proof, now,
                      pg18_rows=None):
    """Pure unsigned data assembly: three source validators own their exact pins."""
    sources = [
        trickle.make_manifest(build_sha=build, runid=runid, catalog_sha=catalog_sha,
                              row=trickle_row, proof=trickle_proof, now=now),
        hypopg.manifest(build, runid, catalog_sha, hypopg_verified, now),
        portalcorp.manifest(build, runid, catalog_sha,
                            portalcorp_row, portalcorp_proof, now),
    ]
    root = {key: val for key, val in sources[0].items() if key != "records"}
    trickle.require(all({key: val for key, val in source.items()
                          if key != "records"} == root for source in sources),
                    "source-specific owner admission envelopes disagree")
    records = [record for source in sources for record in source["records"]]
    trickle.require(len(records) == 5 and
                    [(r["sourceRepo"], r["pgMajor"]) for r in records] == [
                        ("trickle-labs/pg-trickle", "18"),
                        ("HypoPG/hypopg", "14"), ("HypoPG/hypopg", "15"),
                        ("HypoPG/hypopg", "16"),
                        ("portalcorp/pgvector_compiled", "16")],
                    "unreviewed source or original asset cohort")
    if pg18_rows is not None:
        reviewed.verify_signed_rows(pg18_rows)
        records.extend(pg18_rows)
    trickle.require(len(records) in (5, 7), "unreviewed mixed source count")
    return dict(root, records=records)



def combine_latest_manifests(build, runid, catalog_sha, trickle_row,
                             trickle_proof, latest_rows, pg18_rows, now):
    """Newest Windows originals only. Older signed seven-ZIP archives remain untouched."""
    latest.verify_signed_rows(latest_rows)
    reviewed.verify_signed_rows(pg18_rows)
    doc = trickle.make_manifest(build_sha=build, runid=runid, catalog_sha=catalog_sha,
                                row=trickle_row, proof=trickle_proof, now=now)
    records = doc["records"] + latest_rows + pg18_rows
    trickle.require(len(records) == 11 and
                    len({(r["extension"], r["pgMajor"]) for r in records}) == 11 and
                    set(r["extension"] for r in records) ==
                    {"pg_trickle", "oracle_fdw", "pgvector"} and
                    set(r["pgMajor"] for r in records if r["extension"] in
                        ("oracle_fdw", "pgvector")) ==
                    {"14", "15", "16", "17", "18"},
                    "newest reviewed eleven-original cohort mismatch")
    return dict(doc, records=records)


def main():
    stage = "OWNER_RUN"
    try:
        env = dict(os.environ)
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_bytes(),
                           object_pairs_hook=trickle.no_duplicates)
        build, runid = trickle.validate_original_owner_run(
            env, event, trickle.gh_get("repos/pgextwin/build/branches/main"),
            trickle.gh_get("repos/pgextwin/build/actions/runs/" + env["GITHUB_RUN_ID"]),
            expected_extension=COHORT)

        stage = "CATALOG_PROVIDER"
        catalog_root = Path(env["CATALOG_CHECKOUT"])
        branch = trickle.gh_get("repos/pgextwin/catalog/branches/main")
        catalog_sha, trickle_row = trickle.validate_catalog_and_provider(
            catalog_root, branch,
            trickle.gh_get("repos/trickle-labs/pg-trickle"),
            trickle.gh_get("repos/trickle-labs/pg-trickle/releases/tags/v0.108.3"),
            trickle.gh_get(f"repos/pgextwin/catalog/actions/runs/{trickle.RUNTIME_RUN}"),
            trickle.gh_get(f"repos/trickle-labs/pg-trickle/actions/runs/{trickle.UPSTREAM_RUN}"))
        pg18_sha, pg18_rows = reviewed.validate_rows(
            catalog_root, branch,
            [trickle.gh_get("repos/" + p[0]) for p in reviewed.PINS],
            [trickle.gh_get("repos/" + p[0] + "/releases/tags/" + p[5])
             for p in reviewed.PINS],
            [trickle.gh_get("repos/pgextwin/catalog/actions/runs/" + str(p[11]))
             for p in reviewed.PINS])
        latest_sha, latest_rows = latest.validate_rows(
            catalog_root, branch,
            [trickle.gh_get("repos/" + repo) for repo in
             ("laurenz/oracle_fdw", "andreiramani/pgvector_pgsql_windows")],
            [trickle.gh_get("repos/laurenz/oracle_fdw/releases/tags/ORACLE_FDW_2_9_0"),
             trickle.gh_get("repos/andreiramani/pgvector_pgsql_windows/releases/tags/0.8.7")],
            trickle.gh_get("repos/pgextwin/catalog/actions/runs/" + str(latest.PILOT_RUN)),
            trickle.gh_get("repos/pgextwin/catalog/actions/runs/" +
                           str(latest.PILOT_RUN) + "/jobs?per_page=100"),
            pg18_rows, env["ORIGINAL_PG14_17_DIR"])
        trickle.require(catalog_sha == pg18_sha == latest_sha,
                        "protected Catalog source changed across current providers")

        stage = "ORIGINAL_ZIP"
        trickle_proof = trickle.verify_original_zip(env["ORIGINAL_ZIP"])

        stage = "APP_SCOPE"
        api, jwt = trickle.load_external_app_helpers()
        trickle.verify_app_readonly(env["EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY"],
                                    api=api, jwt=jwt)

        stage = "SOURCE_RECHECK"
        trickle.require(
            trickle.gh_get("repos/pgextwin/build/branches/main")["commit"]["sha"] == build
            and trickle.gh_get("repos/pgextwin/catalog/branches/main")["commit"]["sha"] == catalog_sha,
            "protected source moved before combined subject")

        stage = "MANIFEST"
        doc = combine_latest_manifests(build, runid, catalog_sha, trickle_row,
                                       trickle_proof, latest_rows, pg18_rows,
                                       datetime.now(timezone.utc))
        stage = "OUTPUT_CREATE"
        output = Path(env["OUTPUT_FILE"])
        trickle.require(not output.exists() and not output.is_symlink(),
                        "combined subject is create-only")
        with output.open("xb") as stream:
            stream.write((json.dumps(doc, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8"))
        print("QUALIFIED_LATEST_ELEVEN_ASSET_UNSIGNED_SUBJECT_CREATED SIGNATURE=PENDING "
              "RELEASE=NONE ZIP_UPLOAD=NONE MIRROR=DENY")
    except Exception as error:
        print(trickle.denial_diagnostic(stage, error), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
