#!/usr/bin/env python3
"""Issue #112: original owner/Environment signed five-asset metadata-only PR.

No issuer authority is inferred from a synthetic subject or past successful Run.
A dedicated Catalog-only App creates a fresh protected PR with the exact original
Sigstore subject and bundle. No provider ZIP, Release, tag or mirror is written.
"""
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
# Reuse the older exact issuer's genuine same-Run/App/Sigstore checks.
import importlib.util


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing exact owner verification helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


old = load("qualified_existing_signed_proposal", "external-direct-get-public-pin-pr.py")
hypopg = load("qualified_hypopg_signed_proposal", "external-direct-get-hypopg-pin-pr.py")
portalcorp = load("qualified_portalcorp_signed_proposal", "external-direct-get-portalcorp-pin-pr.py")
COHORT = "qualified_cohort"


def verify_qualified_manifest(doc, build, catalog, runid, now):
    old.require(type(doc) is dict and set(doc) == old.TOP_KEYS,
                "unknown combined signed envelope")
    rows = doc.get("records")
    old.require(type(rows) is list and len(rows) == 5,
                "wrong number of independently reviewed original assets")
    # Each source's existing strict immutable validator independently checks
    # every exact ID, SHA256, licence, ABI, operation, and issuer envelope.
    checks = (
        old.verify_manifest({**doc, "records": rows[:1]},
                            build_sha=build, catalog_sha=catalog, run_id=runid, now=now),
        hypopg.verify_hypopg_manifest({**doc, "records": rows[1:4]},
                                      build, catalog, runid, now),
        portalcorp.verify_portalcorp_manifest({**doc, "records": rows[4:]},
                                               build, catalog, runid, now),
    )
    old.require(checks[0] == checks[1] == checks[2],
                "inconsistent original source expiry")
    return checks[0]


def path_for(runid, filename):
    old.require(type(runid) is int and 0 < runid < 10**15 and
                filename in ("external-get-admission.json", "attestation.json"),
                "unapproved immutable source metadata path")
    return f"external/signed-direct-get/{COHORT}/run-{runid}/{filename}"


def make_pr(api, token, runid, catalog_sha, files, expires):
    base = "/repos/pgextwin/catalog"
    branch = f"issue112-five-originals-signed-get-run-{runid}"
    old.require(set(files) == {"external-get-admission.json", "attestation.json"},
                "nonflat signed metadata set")
    current = api("GET", base + "/branches/main", token)
    old.require(current.get("protected") is True and
                current.get("commit", {}).get("sha") == catalog_sha and
                datetime.now(timezone.utc) < expires,
                "Catalog moved or owner-signed admission expired")
    # Create-only ref and file endpoints, then a PR. Existing paths are never
    # edited or overwritten. This restricted App has only Catalog write scope.
    api("POST", base + "/git/refs", token,
        {"ref": "refs/heads/" + branch, "sha": catalog_sha})
    for name in ("external-get-admission.json", "attestation.json"):
        route = base + "/contents/" + path_for(runid, name)
        payload = files[name]
        api("PUT", route, token, {
            "message": "chore(#112): create-only signed five-source GET metadata " + name,
            "branch": branch, "content": base64.b64encode(payload).decode("ascii")})
        readback = api("GET", route + "?ref=" + branch, token)
        old.require(readback.get("type") == "file" and
                    readback.get("path") == path_for(runid, name) and
                    base64.b64decode(readback.get("content", "")) == payload,
                    "Catalog PR signed bytes changed during proposal")
    current = api("GET", base + "/branches/main", token)
    old.require(current.get("protected") is True and
                current.get("commit", {}).get("sha") == catalog_sha and
                datetime.now(timezone.utc) < expires,
                "Catalog changed or admission expired before PR")
    pr = api("POST", base + "/pulls", token, {
        "title": f"feat(#112): authentic owner-signed five-original GET-only Run {runid}",
        "head": branch, "base": "main", "draft": False,
        "body": (
            "Authentic owner workflow_dispatch protected Build/main, twice-reviewed "
            "Publisher Environment, same-Run independent Sigstore and exact five "
            "original provider ZIPs across pg_trickle PG18, HypoPG PG14–16 and "
            "portalcorp pgvector PG16. Signed metadata only, no provider ZIPs. "
            "Expiry six hours, MIRROR_DENY/REDISTRIBUTION_DENY, no install. "
            "Public permission requires this PR's protected merge, true postmerge, "
            "and public Windows CLI original-byte GET E2E. Held oracle_fdw and "
            "andreiramani sources remain excluded. Related: pgextwin/build#112.")})
    old.require(type(pr.get("number")) is int and pr["number"] > 0 and
                pr.get("head", {}).get("ref") == branch and
                pr.get("base", {}).get("ref") == "main",
                "source-specific signed PR was not created")
    return pr["number"]


def main():
    try:
        env = dict(os.environ)
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_bytes(),
                           object_pairs_hook=old.no_duplicates)
        base = "repos/pgextwin/build/actions/runs/" + env["GITHUB_RUN_ID"]
        build, catalog, runid = old.check_run_context(
            env, event, branch=old.gh_read("repos/pgextwin/build/branches/main"),
            run=old.gh_read(base),
            jobs=old.gh_read(base + "/jobs?per_page=100"),
            approvals=old.gh_read(base + "/approvals"),
            catalog=old.gh_read("repos/pgextwin/catalog/branches/main"),
            expected_extension=COHORT)
        files = old.read_exact(env["SIGNED_METADATA_DIR"])
        doc = json.loads(files["external-get-admission.json"],
                         object_pairs_hook=old.no_duplicates)
        expires = verify_qualified_manifest(
            doc, build, catalog, runid, datetime.now(timezone.utc))
        old.verify_sigstore(env["SIGNED_METADATA_DIR"], build)
        helpers = old.load_module("qualified_scoped_catalog_app", old.APP_MODULE)
        key = env.pop("EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY")
        with helpers.scoped_catalog_token(
                helpers.shared._existing.api, helpers.shared._existing.jwt, key) as token:
            number = make_pr(helpers.shared._existing.api, token, runid,
                             catalog, files, expires)
        print(f"QUALIFIED_FIVE_ORIGINALS_SIGNED_METADATA_PR={number} "
              "APP_REVOKED=TRUE RELEASE=NONE ZIP_UPLOAD=NONE MIRROR=DENY")
    except Exception:
        print("QUALIFIED_FIVE_SIGNED_METADATA_PR_DENY; no source tokens or ZIPs emitted",
              file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
