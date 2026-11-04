#!/usr/bin/env python3
"""Source-specific external direct-provider admission, Catalog PR ONLY.

This extends the EXISTING central Publisher intake. Do not create Releases,
download/mirror public assets, promote unsigned review JSON, or write main.
Authenticated exact owner event + GitHub Environment reviewer + current
protected Catalog Sigstore source + original ZIP bytes are independently
required before a strictly scoped Catalog-only App creates a nonpublic PR
proposal. This script has no public authorization or Release API routes.
"""
from __future__ import annotations
import base64
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError

SOURCE_KIND = "EXTERNAL_GITHUB_RELEASE_ASSET"
COMMAND = "/pgextwin external-direct propose-pg18"
CATALOG = "pgextwin/catalog"
BUILD = "pgextwin/build"
TARGET_PATH = "external/provider-direct-pg18-proposal.json"
APP = 5609317
INSTALL = 178510512
APP_SLUG = "pgextwin-external-direct-publisher"
PERMISSIONS = {"metadata": "read", "contents": "write", "pull_requests": "write"}
SHA40 = re.compile(r"[0-9a-f]{40}\Z")

_spec = importlib.util.spec_from_file_location(
    "shared_app_proof", Path(__file__).with_name("probe-external-direct-provider-app.py"))
shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shared)


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied("external direct-provider DENY: " + reason)


def check_owner_event(env, event, api):
    """Fresh owner issue_comment ONLY; not dispatch, schedule, or fabricated JSON."""
    for k, expected in (
        ("GITHUB_EVENT_NAME", "issue_comment"),
        ("GITHUB_REPOSITORY", BUILD),
        ("GITHUB_REF", "refs/heads/main"),
        ("GITHUB_ACTOR", "ShutenOishi"),
        ("GITHUB_TRIGGERING_ACTOR", "ShutenOishi"),
        ("GITHUB_RUN_ATTEMPT", "1"),
    ):
        require(env.get(k) == expected, "untrusted trigger " + k)
    head = env.get("GITHUB_SHA")
    require(type(head) is str and SHA40.fullmatch(head), "untrusted build SHA")
    require(type(event) is dict and event.get("action") == "created"
            and type(event.get("repository")) is dict
            and event["repository"].get("full_name") == BUILD
            and type(event.get("sender")) is dict
            and event["sender"].get("login") == "ShutenOishi"
            and type(event.get("issue")) is dict
            and event["issue"].get("number") == 112
            and "pull_request" not in event["issue"]
            and type(event.get("comment")) is dict,
            "untrusted issue comment identity")
    comment = event["comment"]
    require(type(comment.get("id")) is int and comment["id"] > 0
            and comment.get("body") == COMMAND
            and type(comment.get("user")) is dict
            and comment["user"].get("login") == "ShutenOishi",
            "wrong owner command")
    token = env.get("GITHUB_TOKEN")
    require(type(token) is str and bool(token), "missing build read token")
    branch = api("GET", "/repos/pgextwin/build/branches/main", token)
    require(branch.get("protected") is True and
            branch.get("commit", {}).get("sha") == head, "stale build main")
    online = api("GET", f"/repos/pgextwin/build/issues/comments/{comment['id']}", token)
    require(online.get("id") == comment["id"]
            and online.get("body") == COMMAND
            and online.get("user", {}).get("login") == "ShutenOishi"
            and online.get("html_url") ==
            f"https://github.com/pgextwin/build/issues/112#issuecomment-{comment['id']}",
            "online owner comment mismatch")
    return head, comment["id"]


def verify_catalog_source(catalog, catalog_sha, read_token, api, *, exec_cmd=subprocess.run):
    """All reads on exact protected Catalog SHA; verify Sigstore and actual bytes."""
    require(type(catalog_sha) is str and SHA40.fullmatch(catalog_sha), "invalid Catalog SHA")
    source = api("GET", "/repos/pgextwin/catalog/branches/main", read_token)
    require(source.get("protected") is True
            and source.get("commit", {}).get("sha") == catalog_sha,
            "Catalog main moved or unprotected")
    require((catalog / "scripts/external_signed_asset_pin.py").is_file()
            and (catalog / "scripts/issue112-external-zip-pilot.py").is_file(),
            "missing reviewed source helpers")
    checked = exec_cmd(["git", "-C", str(catalog), "rev-parse", "HEAD"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
    require(checked.stdout.decode().strip() == catalog_sha, "checkout not exact main")

    # Read only protected, reviewed module. The candidate itself grants NO publish.
    sys.path.insert(0, str(catalog / "scripts"))
    from external_provider_release_identity import compare_publisher_intake
    from external_signed_asset_pin import build_candidate, canonical_bytes
    from issue112_external_zip_pilot_bridge import verify_original_bytes  # trusted local shim

    candidate = build_candidate(catalog, catalog_sha)
    require(candidate["sourceSpecificPublisherPolicy"]["formalAdmissionReady"] is False
            and candidate["sourceSpecificPublisherPolicy"]["appProofRunId"] == 41817355221
            and candidate["catalogCommit"] == catalog_sha
            and all(candidate[k] is False for k in
                    ("publicationAuthorized", "sourcePublisherAuthorized",
                     "downloadAuthorized", "mirrorAuthorized",
                     "redistributionAuthorized", "installAuthorized")),
            "signed source attempted authorization elevation")
    with tempfile.TemporaryDirectory() as temp:
        subject = Path(temp) / "external-asset-pin.json"
        subject.write_bytes(canonical_bytes(candidate))
        # --bundle intentionally omitted: GitHub's independently authenticated
        # public attestation service must authenticate these actual source bytes.
        args = ["gh", "attestation", "verify", str(subject),
                "--repo", CATALOG,
                "--signer-workflow", "pgextwin/catalog/.github/workflows/issue112-external-signed-pin.yml",
                "--source-ref", "refs/heads/main",
                "--source-digest", catalog_sha,
                "--deny-self-hosted-runners", "--format", "json"]
        gh_env = dict(os.environ)
        gh_env.pop("EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY", None)
        gh_env["GH_TOKEN"] = read_token
        verified = exec_cmd(args, env=gh_env, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, check=True)
        try:
            proof = json.loads(verified.stdout)
        except (ValueError, UnicodeError):
            raise Denied("unreadable independent Sigstore proof") from None
        require(type(proof) is list and len(proof) >= 1,
                "missing genuine signed source proof")

    snaps = {}
    for row in candidate["records"]:
        name = row["sourceRepo"]
        snaps[name] = {
            "repository": api("GET", "/repos/" + name, read_token),
            "release": api("GET", "/repos/" + name + "/releases/" +
                           str(row["releaseId"]), read_token)
        }
    result = compare_publisher_intake(catalog, catalog_sha, snaps)
    require(result["metadataIdentityMatched"] == 2
            and result["downloadDeniedCandidates"] == 203
            and result["publicationAuthorized"] is False,
            "provider source metadata not independently authenticated")
    # Uses the existing strict raw-byte SHA256, member CRC and bounded ZIP
    # verifier. No extraction, mirror, write or authorized user download.
    byte_result = verify_original_bytes(catalog, candidate)
    require(len(byte_result) == 2 and all(x["bytesVerified"] for x in byte_result),
            "original provider byte acceptance failed")
    source_after = api("GET", "/repos/pgextwin/catalog/branches/main", read_token)
    require(source_after.get("protected") is True
            and source_after.get("commit", {}).get("sha") == catalog_sha,
            "Catalog advanced during independent validation")
    return candidate, byte_result


def require_catalog_writer(method, path):
    """Hard code the complete write API allowlist; no release/ref update routes."""
    allowed = {
        ("POST", "/repos/pgextwin/catalog/git/refs"),
        ("PUT", "/repos/pgextwin/catalog/contents/" + TARGET_PATH),
        ("POST", "/repos/pgextwin/catalog/pulls"),
    }
    require((method, path) in allowed, "write operation outside Catalog PR boundary")


@contextmanager
def scoped_catalog_token(api, jwt, private_key, *, sleep=time.sleep):
    """Restrict App installation to one target and prove same-token revocation."""
    require(type(private_key) is str and bool(private_key), "missing App key")
    assertion = jwt(private_key, APP)
    ident = api("GET", "/app", assertion)
    require(ident.get("id") == APP and ident.get("slug") == APP_SLUG,
            "App JWT identity mismatch")
    install = api("GET", f"/app/installations/{INSTALL}", assertion)
    require(install.get("id") == INSTALL and install.get("app_id") == APP
            and install.get("repository_selection") == "selected"
            and install.get("permissions") == PERMISSIONS
            and install.get("account", {}).get("login") == "pgextwin"
            and install.get("suspended_at") is None,
            "App installation identity or permissions mismatch")
    token = None
    try:
        grant = api("POST", f"/app/installations/{INSTALL}/access_tokens", assertion,
                    {"repositories": ["catalog"], "permissions": PERMISSIONS})
        require(type(grant) is dict, "no scoped token")
        token = grant.get("token")
        require(type(token) is str and len(token) > 20
                and grant.get("repository_selection") == "selected"
                and grant.get("permissions") == PERMISSIONS,
                "scoped token grant altered")
        expiry = grant.get("expires_at")
        require(type(expiry) is str and expiry.endswith("Z"),
                "missing token expiry")
        remaining = datetime.fromisoformat(expiry.replace("Z", "+00:00")) - \
            datetime.now(timezone.utc)
        require(timedelta(seconds=60) < remaining <= timedelta(hours=1),
                "token expiry outside boundary")
        repos = api("GET", "/installation/repositories?per_page=100", token)
        require(repos.get("total_count") == 1 and type(repos.get("repositories")) is list
                and len(repos["repositories"]) == 1
                and repos["repositories"][0].get("full_name") == CATALOG
                and repos["repositories"][0].get("id") == 1405939279,
                "token scope not exactly Catalog")
        yield token
    finally:
        if type(token) is str and token:
            api("DELETE", "/installation/token", token)
            revoked = False
            for delay in (0, 0.5, 1, 2):
                if delay:
                    sleep(delay)
                try:
                    api("GET", "/installation/repositories?per_page=100", token)
                except HTTPError as exc:
                    if exc.code == 401:
                        revoked = True
                        break
                    raise Denied("token not verifiably revoked") from None
            require(revoked, "same-token 401 revocation missing")


def proposal_bytes(candidate, byte_result, source_sha, build_sha, comment_id):
    require(candidate["catalogCommit"] == source_sha
            and len(candidate["records"]) == 2
            and all(x["bytesVerified"] for x in byte_result),
            "incomplete independent provider admission")
    source_proofs = {(x["sourceRepo"], x["releaseId"], x["assetId"])
                     for x in byte_result}
    rows = []
    for row in candidate["records"]:
        key = (row["sourceRepo"], row["releaseId"], row["assetId"])
        require(key in source_proofs and row["pgMajor"] == "18"
                and row["referenceLinkReviewed"] is True
                and row["sourcePublisherAuthorized"] is False
                and row["downloadAuthorized"] is False
                and row["mirrorAuthorized"] is False
                and row["originalProviderUrl"].startswith("https://github.com/"),
                "unreviewed provider source")
        rows.append({k: row[k] for k in (
            "extension", "upstreamVersion", "pgMajor", "targetEnvironment",
            "providerType", "sourceRepo", "repositoryId", "releaseId",
            "releaseTag", "assetId", "assetName", "originalProviderUrl",
            "originalBytes", "originalSha256", "licenseUrl",
            "dependencyInformationUrl", "dependencyLicenseUrl",
            "noticeTreatment", "providerStatusNotice", "runtimeEvidence",
            "runtimeScope")})
    obj = {
        "schemaVersion": "pgextwin-external-provider-catalog-proposal/v1",
        "sourceKind": SOURCE_KIND, "mode": "PROTECTED_PR_PROPOSAL_ONLY",
        "sourceCatalogCommit": source_sha, "sourceBuildCommit": build_sha,
        "originalOwnerCommentId": comment_id,
        "externalAppId": APP, "externalInstallationId": INSTALL,
        "requiredEnvironment": "external-direct-provider-publisher",
        "approvedOperation": "PROPOSE_DIRECT_ORIGINAL_REFERENCE_ONLY",
        "actualOriginalBytesVerified": True,
        "sourceSigstoreVerified": True,
        "publicSignedExternalFeedExists": False,
        "formalPublicationAuthorized": False,
        "downloadAuthorized": False, "mirrorAuthorized": False,
        "redistributionAuthorized": False, "installAuthorized": False,
        "records": rows,
    }
    return (json.dumps(obj, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def create_protected_pr(api, token, *, source_sha, payload):
    require(SHA40.fullmatch(source_sha) and type(payload) is bytes,
            "unsafe proposal source")
    target = f"issue112-external-direct-pg18-{source_sha[:12]}"
    before = api("GET", "/repos/pgextwin/catalog/branches/main", token)
    require(before.get("protected") is True and
            before.get("commit", {}).get("sha") == source_sha,
            "Catalog main changed before proposed branch")
    path = "/repos/pgextwin/catalog/git/refs"
    require_catalog_writer("POST", path)
    api("POST", path, token, {"ref": "refs/heads/" + target, "sha": source_sha})
    path = "/repos/pgextwin/catalog/contents/" + TARGET_PATH
    require_catalog_writer("PUT", path)
    api("PUT", path, token, {
        "message": "chore(#112): propose verified provider-direct source pins (nonpublishing)",
        "branch": target, "content": base64.b64encode(payload).decode("ascii")
    })
    # A proposal branch is not published; only GitHub's real PR protections
    # can ever merge its content. No direct main/ref updates or Releases.
    path = "/repos/pgextwin/catalog/pulls"
    require_catalog_writer("POST", path)
    pr = api("POST", path, token, {
        "title": "feat(#112): propose exact verified direct-provider PG18 sources (nonpublishing)",
        "head": target, "base": "main", "draft": False,
        "body": ("## Source-specific proposal from genuine central Publisher\n\n"
                 "Original protected Catalog source, exact main signer Sigstore, "
                 "provider repository/Release/asset API IDs and actual ZIP bytes "
                 "were independently verified. Only two reviewed PG18 origins. "
                 "NOTICE/dependency/license links remain visible.\n\n"
                 "**This PR authorizes no public external download, mirror, "
                 "Catalog feed, installer or Release.** A separate signed "
                 "source-specific publication gate and protected CI/merge are "
                 "mandatory. 203 candidates remain DOWNLOAD_DENY/MIRROR_DENY.\n\n"
                 "Ref pgextwin/build#112.")
    })
    require(type(pr) is dict and type(pr.get("number")) is int and pr["number"] > 0
            and pr.get("head", {}).get("ref") == target
            and pr.get("base", {}).get("ref") == "main",
            "unexpected Catalog PR response")
    return {"catalogPr": pr["number"], "catalogBranch": target,
            "sourceCatalogCommit": source_sha,
            "operation": "PROTECTED_CATALOG_PR_ONLY_NO_PUBLISH",
            "downloadAuthorized": False, "mirrorAuthorized": False}


def main():
    try:
        env = dict(os.environ)
        key = env.pop("EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY", "")
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text("utf-8"))
        build_sha, comment_id = check_owner_event(env, event, shared.api)
        catalog = Path(env["PGEXTWIN_CATALOG_CHECKOUT"]).resolve()
        source_sha = env["EXTERNAL_CATALOG_SOURCE_SHA"]
        candidate, byte_result = verify_catalog_source(
            catalog, source_sha, env["GITHUB_TOKEN"], shared.api)
        payload = proposal_bytes(candidate, byte_result, source_sha,
                                 build_sha, comment_id)
        with scoped_catalog_token(shared.api, shared.jwt, key) as token:
            report = create_protected_pr(shared.api, token,
                                         source_sha=source_sha, payload=payload)
        print(json.dumps(report, sort_keys=True))
    except Exception:
        print("EXTERNAL_DIRECT_SOURCE_PR_DENY; no credential or untrusted API output emitted",
              file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
