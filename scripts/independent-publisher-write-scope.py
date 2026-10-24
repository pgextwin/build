#!/usr/bin/env python3
"""Issue #75: nonpublishing scoped Publisher App-token evidence validator.

Inputs MUST come from same-job authenticated GitHub App JWT issuance and a
GET performed using the issued token. Untrusted PR artifacts are not inputs.
No return value authorizes Release WRITE; publication requires separate
live candidate, CI, Sigstore, Grype, branch, policy and tag checks.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import re
import sys

REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
FIELDS = {"schemaVersion", "mode", "publisherAppId",
          "publisherInstallationId", "signerAppId"}

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

def evaluate(policy, fleet, issuance, live_repositories, *, repository,
             observed_at, trusted_issuer_app_id, trusted_issuer_installation_id):
    """Compare independently obtained GitHub data, never issue an auth receipt.

    Caller MUST prove trusted_issuer_* with a GitHub-JWT-authenticated GET
    and mint a token via the same trusted Publisher job. No caller-supplied
    artifact, PR comment, CI fixture or READ-ONLY report proves that identity.
    """
    require(type(policy) is dict and set(policy) == FIELDS
            and type(policy["schemaVersion"]) is int
            and policy["schemaVersion"] == 1
            and policy["mode"] in ("DENY", "ENFORCE"),
            "unknown Publisher policy")
    require(type(fleet) is dict and fleet.get("schemaVersion") == 1
            and fleet.get("releasePolicy") == "manual-only"
            and type(fleet.get("entries")) is list
            and len(fleet["entries"]) == 17,
            "unexpected fleet policy")
    rows = fleet["entries"]
    names = [x.get("repository") for x in rows if type(x) is dict]
    require(len(names) == 17 and len(set(names)) == 17
            and type(repository) is str and REPO.fullmatch(repository)
            and repository in names
            and all(type(n) is str and REPO.fullmatch(n) for n in names)
            and all(x.get("mode") == "BUILD"
                    and x.get("candidateEnabled") is True
                    and x.get("releasePolicy") == "manual-only" for x in rows),
            "unknown Publisher repository")
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
    require(positive(trusted_issuer_app_id)
            and trusted_issuer_app_id == policy["publisherAppId"]
            and positive(trusted_issuer_installation_id)
            and trusted_issuer_installation_id == policy["publisherInstallationId"],
            "authenticated issuer differs from protected policy")
    require(type(issuance) is dict
            and type(issuance.get("token")) is str
            and len(issuance["token"]) > 20
            and issuance.get("repository_selection") == "selected"
            and issuance.get("permissions") == {"contents": "write"},
            "token issuance is not exactly scoped Contents WRITE")
    minted = issuance.get("repositories")
    require(type(minted) is list and len(minted) == 1
            and type(minted[0]) is dict
            and minted[0].get("full_name") == repository
            and positive(minted[0].get("id")),
            "minted token accesses wrong/multiple repositories")
    require(type(live_repositories) is dict
            and type(live_repositories.get("total_count")) is int
            and live_repositories["total_count"] == 1
            and type(live_repositories.get("repositories")) is list
            and len(live_repositories["repositories"]) == 1,
            "token-authenticated repository GET missing or expanded")
    actual = live_repositories["repositories"][0]
    require(type(actual) is dict and actual.get("id") == minted[0]["id"]
            and actual.get("full_name") == repository
            and type(actual.get("permissions")) is dict
            and actual["permissions"].get("push") is True,
            "live token lacks scoped repository WRITE proof")
    require(type(observed_at) is datetime and observed_at.tzinfo is not None,
            "missing trusted observation time")
    expires = parse_utc(issuance.get("expires_at"))
    remaining = expires - observed_at.astimezone(timezone.utc)
    require(timedelta(seconds=60) < remaining <= timedelta(hours=1),
            "token expired or implausible lifetime")
    return {"schemaVersion": 1, "status": "SCOPED_APP_WRITE_EVIDENCE_ONLY",
            "repository": repository, "publisherAppId": policy["publisherAppId"],
            "publisherInstallationId": policy["publisherInstallationId"],
            "scopedRepositoryCount": 1,
            "observedAt": observed_at.isoformat(), "expiresAt": expires.isoformat(),
            "needsSameJobCryptographicAndGitHubAuthorization": True,
            "publisherWriteAuthorized": False, "publicationAuthorized": False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--fleet", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    try:
        policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        fleet = json.loads(Path(args.fleet).read_text(encoding="utf-8"))
        require(policy.get("mode") == "DENY",
                "CLI deliberately cannot mint tokens or authorize WRITE")
        outcome = evaluate(policy, fleet, None, None, repository=args.repository,
                           observed_at=None, trusted_issuer_app_id=None,
                           trusted_issuer_installation_id=None)
        print(json.dumps(outcome, sort_keys=True))
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError) as err:
        print("PUBLISHER WRITE SCOPE DENY: " + str(err), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
