#!/usr/bin/env python3
"""Issue #75: nonpublishing scoped Publisher App-token evidence validator.

Inputs MUST come from same-job authenticated GitHub App JWT issuance and a
GET performed using the issued token. Untrusted PR artifacts are not inputs.
No return value authorizes Release WRITE; publication requires separate
live candidate, CI, Sigstore, Grype, branch, policy and tag checks.
"""
from __future__ import annotations
import argparse
import importlib.util
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import re
import sys

REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
FIELDS = {"schemaVersion", "mode", "publisherAppId",
          "publisherInstallationId", "signerAppId"}

_policy_spec=importlib.util.spec_from_file_location("shared_fleet_policy",Path(__file__).with_name("fleet-policy.py"))
fleet_policy=importlib.util.module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(fleet_policy)

class Denied(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Denied(reason)

def positive(v):
    return type(v) is int and v > 0

def parse_utc(value):
    require(type(value) is str and value.endswith("Z"), "invalid token expiry")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Denied("invalid token expiry") from exc
    require(result.tzinfo is not None, "missing timezone")
    return result

def validate_live_scope(issuance, live_repositories, blob, *,
                        repository, observed_at, expected_blob_sha):
    """Use only same-job live API results, including an actual Git blob WRITE.

    GitHub's real issuance permissions also include mandatory metadata:read.
    Token issuance does not enumerate repositories; the token-authenticated
    installation inventory establishes its *effective* repository scope.
    A successful result is NEVER a formal Release authorization.
    """
    require(type(repository) is str and REPO.fullmatch(repository),
            "invalid destination repository")
    require(type(issuance) is dict and type(issuance.get("token")) is str
            and len(issuance["token"]) > 20
            and issuance.get("repository_selection") == "selected"
            and issuance.get("permissions") == {"contents": "write", "metadata": "read"},
            "token issuance is not exclusively scoped Contents WRITE")
    require(type(live_repositories) is dict
            and type(live_repositories.get("total_count")) is int
            and live_repositories["total_count"] == 1
            and type(live_repositories.get("repositories")) is list
            and len(live_repositories["repositories"]) == 1,
            "token-authenticated repository inventory missing or expanded")
    actual = live_repositories["repositories"][0]
    require(type(actual) is dict and actual.get("full_name") == repository,
            "token-authenticated repository differs from target")
    # Installation token issuance reports permission strings, not a
    # permissions.push Boolean. Establish WRITE through an authenticated POST
    # and exact Git blob SHA instead of fabricating a repository permission.
    require(type(blob) is dict and type(expected_blob_sha) is str
            and re.fullmatch(r"[0-9a-f]{40}", expected_blob_sha)
            and blob.get("sha") == expected_blob_sha,
            "same-token Git blob WRITE was not independently confirmed")
    require(type(observed_at) is datetime and observed_at.tzinfo is not None,
            "missing trusted observation time")
    expires = parse_utc(issuance.get("expires_at"))
    remaining = expires - observed_at.astimezone(timezone.utc)
    require(timedelta(seconds=60) < remaining <= timedelta(hours=1),
            "token expired or implausible lifetime")
    return {"schemaVersion": 1,
            "status": "SCOPED_CONTENTS_WRITE_PROVEN_NONPUBLISHING",
            "repository": repository, "scopedRepositoryCount": 1,
            "blobSha": expected_blob_sha,
            "expiresAt": expires.isoformat(), "observedAt": observed_at.isoformat(),
            "publicationAuthorized": False, "publishableReceipt": False,
            "publisherWriteAuthorized": False}


def inspect_policy(policy,fleet,*,repository):
    """Read-only declaration inspection: no token, live WRITE or authority."""
    require(type(policy) is dict and set(policy) == FIELDS
            and type(policy["schemaVersion"]) is int
            and policy["schemaVersion"] == 1
            and policy["mode"] in ("DENY", "ENFORCE"),
            "unknown Publisher policy")
    try:
        rows=fleet_policy.members(fleet)
        require(repository in rows,"unknown Publisher target")
    except fleet_policy.Denied as exc:
        raise Denied("unexpected fleet policy") from exc
    require(positive(policy["signerAppId"]) and policy["signerAppId"] == 15368,
            "unexpected Signer/Actions principal")
    if policy["mode"] == "DENY":
        require(policy["publisherAppId"] is None
                and policy["publisherInstallationId"] is None,
                "DENY mode cannot silently select Publisher App")
        return {"schemaVersion": 1, "status": "PUBLISH_DENY",
                "repository": repository,
                "blockers": ["PUBLISHER_POLICY_DISABLED",
                             "EFFECTIVE_APP_WRITE_UNVERIFIED"],
                "publisherWriteAuthorized": False,
                "publicationAuthorized": False}
    require(positive(policy["publisherAppId"])
            and positive(policy["publisherInstallationId"])
            and policy["publisherAppId"] != policy["signerAppId"],
            "Publisher App identity missing or shared with Signer")
    return {"schemaVersion":1,"status":"POLICY_CONFIGURED_LIVE_EVIDENCE_REQUIRED",
            "repository":repository,"publisherAppId":policy["publisherAppId"],
            "publisherInstallationId":policy["publisherInstallationId"],
            "publisherWriteAuthorized":False,"publicationAuthorized":False}


def evaluate(policy, fleet, issuance, live_repositories, *, repository,
             observed_at, trusted_issuer_app_id, trusted_issuer_installation_id,
             blob=None, expected_blob_sha=None):
    """Only authenticated same-job issuer/token/real WRITE can add evidence."""
    configured=inspect_policy(policy,fleet,repository=repository)
    if configured["status"]=="PUBLISH_DENY":
        return configured
    require(positive(trusted_issuer_app_id)
            and trusted_issuer_app_id == policy["publisherAppId"]
            and positive(trusted_issuer_installation_id)
            and trusted_issuer_installation_id == policy["publisherInstallationId"],
            "authenticated issuer differs from protected policy")
    proof = validate_live_scope(
        issuance, live_repositories, blob, repository=repository,
        observed_at=observed_at, expected_blob_sha=expected_blob_sha)
    return {"schemaVersion": 1, "status": "SCOPED_APP_WRITE_EVIDENCE_ONLY",
            "repository": repository, "publisherAppId": policy["publisherAppId"],
            "publisherInstallationId": policy["publisherInstallationId"],
            "scopedRepositoryCount": proof["scopedRepositoryCount"],
            "blobSha": proof["blobSha"],
            "observedAt": proof["observedAt"], "expiresAt": proof["expiresAt"],
            "needsSameJobCryptographicAndGitHubAuthorization": True,
            "publisherWriteAuthorized": False, "publicationAuthorized": False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--fleet", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    try:
        policy = fleet_policy.read(args.policy)
        fleet = fleet_policy.read(args.fleet)
        outcome=inspect_policy(policy,fleet,repository=args.repository)
        print(json.dumps(outcome, sort_keys=True))
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError) as err:
        print("PUBLISHER WRITE SCOPE DENY: " + str(err), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
