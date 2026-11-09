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
        hypo_sha, hypo_verified = hypopg.validate_source(
            catalog_root, branch,
            trickle.gh_get("repos/HypoPG/hypopg"),
            trickle.gh_get("repos/HypoPG/hypopg/releases/tags/1.4.1"),
            trickle.gh_get(f"repos/pgextwin/catalog/actions/runs/{hypopg.RUNTIME_RUN_ID}"),
            trickle.gh_get(f"repos/pgextwin/catalog/actions/runs/{hypopg.RUNTIME_RUN_ID}/jobs?per_page=100"))
        portal_sha, portal_row = portalcorp.validate_source(
            catalog_root, branch,
            trickle.gh_get("repos/portalcorp/pgvector_compiled"),
            trickle.gh_get("repos/portalcorp/pgvector_compiled/git/ref/tags/v0.16.105"),
            trickle.gh_get("repos/portalcorp/pgvector_compiled/releases/tags/v0.16.105"),
            trickle.gh_get(f"repos/pgextwin/catalog/actions/runs/{portalcorp.RUNTIME_RUN}"),
            trickle.gh_get(f"repos/pgextwin/catalog/actions/runs/{portalcorp.RUNTIME_RUN}/jobs?per_page=100"))
        pg18_sha, pg18_rows = reviewed.validate_rows(
            catalog_root, branch,
            [trickle.gh_get("repos/" + p[0]) for p in reviewed.PINS],
            [trickle.gh_get("repos/" + p[0] + "/releases/tags/" + p[5])
             for p in reviewed.PINS],
            [trickle.gh_get("repos/pgextwin/catalog/actions/runs/" + str(p[11]))
             for p in reviewed.PINS])
        trickle.require(catalog_sha == hypo_sha == portal_sha == pg18_sha,
                        "reviewed protected Catalog source changed across providers")

        stage = "ORIGINAL_ZIP"
        trickle_proof = trickle.verify_original_zip(env["ORIGINAL_ZIP"])
        portal_proof = portalcorp.verify_original(env["ORIGINAL_PORTALCORP_ZIP"], catalog_root)

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
        doc = combine_manifests(build, runid, catalog_sha, trickle_row,
                                trickle_proof, hypo_verified, portal_row, portal_proof,
                                datetime.now(timezone.utc), pg18_rows)
        stage = "OUTPUT_CREATE"
        output = Path(env["OUTPUT_FILE"])
        trickle.require(not output.exists() and not output.is_symlink(),
                        "combined subject is create-only")
        with output.open("xb") as stream:
            stream.write((json.dumps(doc, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8"))
        print("QUALIFIED_SEVEN_ASSET_UNSIGNED_SUBJECT_CREATED SIGNATURE=PENDING "
              "RELEASE=NONE ZIP_UPLOAD=NONE MIRROR=DENY")
    except Exception as error:
        print(trickle.denial_diagnostic(stage, error), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
