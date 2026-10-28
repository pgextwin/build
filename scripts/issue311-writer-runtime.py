#!/usr/bin/env python3
"""Issue #311: fixed-scope, nonpublishing GitHub App state Writer proof.

One protected global ledger provides atomic CAS for both request leases and
cross-request candidate claims. Only the dedicated build-only App can write it.
No Publisher, Catalog, tag, Release or workflow-dispatch API is implemented.
"""
from __future__ import annotations
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

APP_ID = 5517840
INSTALLATION_ID = 176347451
REPOSITORY = "pgextwin/build"
REPOSITORY_ID = 1405931353
STATE_BRANCH = "issue311-state"
STATE_PATH = "checkpoints/issue311-ledger-v1.json"
PROOF_REQUEST = "r-20261029-r04writerproof001"
PROOF_PATH = ".github/execution-requests/" + PROOF_REQUEST + ".json"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
SHA1 = re.compile(r"^[a-f0-9]{40}$")
API_URL = "https://api.github.com/"
LEASE_SECONDS = 120


class Denied(ValueError):
    pass


class HTTPStatus(Denied):
    def __init__(self, code, detail=""):
        self.code = code
        super().__init__("GitHub API HTTP " + str(code) + " " + detail[:180])


class UncertainWrite(Denied):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def app_jwt(private_key, now=None):
    require(private_key.startswith("-----BEGIN RSA PRIVATE KEY-----") or
            private_key.startswith("-----BEGIN PRIVATE KEY-----"), "invalid App PEM format")
    moment = int(time.time()) if now is None else int(now)
    header = b64url(canonical({"alg": "RS256", "typ": "JWT"}).strip())
    payload = b64url(canonical({"iat": moment - 45, "exp": moment + 480, "iss": str(APP_ID)}).strip())
    unsigned = (header + "." + payload).encode("ascii")
    fd, path = tempfile.mkstemp(prefix="issue311-app-key-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(private_key)
        signed = subprocess.run(["openssl", "dgst", "-sha256", "-sign", path],
                                input=unsigned, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=20, check=True).stdout
    finally:
        os.unlink(path)
    return unsigned.decode("ascii") + "." + b64url(signed)


def api(method, endpoint, token, payload=None):
    require(endpoint.startswith("repos/pgextwin/build/") or
            endpoint.startswith("app/installations/") or endpoint == "installation/repositories" or
            endpoint == "installation/token", "API endpoint outside Writer allowlist")
    require(".." not in endpoint and not endpoint.startswith("/"), "unsafe API endpoint")
    request = urllib.request.Request(
        API_URL + endpoint, method=method,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "pgextwin-issue311-state-writer-proof"},
        data=None if payload is None else canonical(payload))
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            content = response.read()
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as error:
        raise HTTPStatus(error.code) from error


def mint_token(private_key):
    jwt = app_jwt(private_key)
    installation = api("GET", "app/installations/" + str(INSTALLATION_ID), jwt)
    require(installation.get("id") == INSTALLATION_ID, "installation mismatch")
    require(installation.get("app_id") == APP_ID, "App mismatch")
    require(installation.get("account", {}).get("login") == "pgextwin", "owner mismatch")
    require(installation.get("repository_selection") == "selected", "broad installation")
    result = api("POST", "app/installations/" + str(INSTALLATION_ID) + "/access_tokens",
                 jwt, {"repositories": ["build"], "permissions": {"contents": "write"}})
    token = result.get("token")
    require(type(token) is str and len(token) > 30, "missing runtime token")
    print("::add-mask::" + token, flush=True)
    permissions = result.get("permissions", {})
    require(permissions.get("contents") == "write", "missing contents write scope")
    require(set(permissions) <= {"contents", "metadata"}, "unapproved token permission")
    repos = api("GET", "installation/repositories?per_page=100", token)
    require(repos.get("total_count") == 1 and len(repos.get("repositories", [])) == 1,
            "App token not restricted to exactly one repository")
    repo = repos["repositories"][0]
    require(repo.get("full_name") == REPOSITORY and repo.get("id") == REPOSITORY_ID,
            "token selected repository mismatch")
    return token


def revoke_and_prove_401(token):
    api("DELETE", "installation/token", token)
    try:
        api("GET", "repos/pgextwin/build/contents/README.md?ref=main", token)
    except HTTPStatus as error:
        require(error.code == 401, "revoked token did not produce HTTP 401")
        return
    raise Denied("revoked token was still accepted")


def ledger_endpoint():
    return "repos/pgextwin/build/contents/" + STATE_PATH


def unique_pairs(pairs):
    output = {}
    for key, value in pairs:
        require(key not in output, "duplicate JSON field")
        output[key] = value
    return output


def read_ledger(token):
    response = api("GET", ledger_endpoint() + "?ref=" + STATE_BRANCH, token)
    require(response.get("encoding") == "base64" and SHA1.fullmatch(response.get("sha", "")),
            "invalid GitHub original Contents proof")
    raw = base64.b64decode(response["content"], validate=False)
    state = json.loads(raw, object_pairs_hook=unique_pairs)
    validate_ledger(state)
    # Git blob identity must actually match original bytes, not mutable metadata.
    git_blob = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    require(hashlib.sha1(git_blob).hexdigest() == response["sha"], "Git blob SHA mismatch")
    return response["sha"], state


def validate_ledger(s):
    require(type(s) is dict and set(s) == {
        "schemaVersion", "scope", "requestId", "requestSha256",
        "revision", "phase", "lease", "candidateClaims", "publisherAuthorized",
        "writeOutcomeUnknown"}, "ledger schema mismatch")
    require(s["schemaVersion"] == 1 and s["scope"] == "AUDIT_ONLY_READONLY", "unsafe ledger scope")
    require(s["requestId"] == PROOF_REQUEST and type(s["requestSha256"]) is str and
            SHA256.fullmatch(s["requestSha256"]), "bad proof identifier")
    require(type(s["revision"]) is int and s["revision"] >= 0, "bad revision")
    require(s["phase"] in {"PREPARED", "LEASED", "RECOVERED"}, "unknown phase")
    require(s["publisherAuthorized"] is False and s["writeOutcomeUnknown"] is False,
            "privileged or ambiguous ledger")
    require(type(s["candidateClaims"]) is dict, "unsafe claim index")
    lease = s["lease"]
    if lease is not None:
        require(type(lease) is dict and set(lease) == {
            "owner", "expiresAt", "generation", "scope"}, "invalid lease")
        require(lease["scope"] == "READONLY" and type(lease["owner"]) is str and
                re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", lease["owner"]) and
                type(lease["generation"]) is int and 1 <= lease["generation"] <= 10000,
                "invalid lease owner or generation")
        expires = datetime.fromisoformat(lease["expiresAt"].replace("Z", "+00:00"))
        require(expires.tzinfo is not None and expires.utcoffset() == timedelta(0),
                "lease time untrusted")
    return s


def new_ledger(request_hash):
    require(SHA256.fullmatch(request_hash), "missing original request hash")
    return {"schemaVersion": 1, "scope": "AUDIT_ONLY_READONLY",
            "requestId": PROOF_REQUEST, "requestSha256": request_hash,
            "revision": 0, "phase": "PREPARED", "lease": None,
            "candidateClaims": {}, "publisherAuthorized": False,
            "writeOutcomeUnknown": False}


def lease_next(old, owner, now, phase):
    validate_ledger(old)
    require(phase in {"LEASED", "RECOVERED"}, "unsupported lease transition")
    require(type(now) is datetime and now.tzinfo is not None and
            now.utcoffset() == timedelta(0), "not a trusted UTC time")
    lease = old["lease"]
    if phase == "LEASED":
        require(old["phase"] == "PREPARED" and lease is None, "not an initial lease")
    else:
        require(old["phase"] == "LEASED" and lease is not None,
                "recovery requires earlier durable lease")
        expires = datetime.fromisoformat(lease["expiresAt"])
        require(now >= expires, "previous lease not expired")
        require(owner != lease["owner"], "new runner owner required")
    require(re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", owner or ""), "bad owner")
    result = copy.deepcopy(old)
    result["revision"] += 1
    result["phase"] = phase
    result["lease"] = {"owner": owner, "expiresAt": (now + timedelta(seconds=LEASE_SECONDS)).isoformat(),
                       "generation": 1 if lease is None else lease["generation"] + 1,
                       "scope": "READONLY"}
    return result


def claim_candidate(old, request_id, repo, sha):
    """Pure atomic-ledger transition. Never called by proof workflow."""
    validate_ledger(old)
    require(re.fullmatch(r"r-[0-9]{8}-[a-z0-9-]{8,56}", request_id or ""),
            "invalid claiming request")
    require(re.fullmatch(r"pgextwin/[a-z0-9_\-]+", repo or "") and
            SHA1.fullmatch(sha or ""), "invalid candidate identity")
    key = repo + "@" + sha
    owner = old["candidateClaims"].get(key)
    require(owner is None or owner == request_id, "candidate claimed by another request")
    if owner == request_id:
        return copy.deepcopy(old)
    result = copy.deepcopy(old)
    result["candidateClaims"][key] = request_id
    result["revision"] += 1
    return result


def commit(token, intended, previous_blob=None):
    validate_ledger(intended)
    data = {"message": "state(issue311): nonpublishing CAS " + intended["phase"],
            "branch": STATE_BRANCH, "content": base64.b64encode(canonical(intended)).decode("ascii")}
    if previous_blob is not None:
        require(SHA1.fullmatch(previous_blob), "invalid expected Git blob")
        data["sha"] = previous_blob
    try:
        result = api("PUT", ledger_endpoint(), token, data)
    except HTTPStatus:
        raise
    except Exception as error:
        # Never replay an ambiguous write. Resolve only by a fresh GET.
        try:
            _, observed = read_ledger(token)
        except Exception as read_error:
            raise UncertainWrite("QUARANTINED: ambiguous write and failed GET") from read_error
        if observed == intended:
            return "RECONCILED_ORIGINAL_GET"
        raise UncertainWrite("QUARANTINED: unknown write outcome") from error
    require(SHA1.fullmatch(result.get("content", {}).get("sha", "")),
            "unverifiable GitHub Contents response")
    _, observed = read_ledger(token)
    require(observed == intended, "authoritative postwrite content mismatch")
    return "ORIGINAL_GET_VERIFIED"


def request_bytes_hash():
    raw = Path(PROOF_PATH).read_bytes()
    data = json.loads(raw, object_pairs_hook=unique_pairs)
    require(set(data) == {"schemaVersion", "requestId", "mode", "kind",
                          "publicReleaseAuthorized", "baseMainSha"},
            "unexpected nonpublishing proof request fields")
    require(data["schemaVersion"] == 1 and data["requestId"] == PROOF_REQUEST and
            data["mode"] == "AUDIT_ONLY" and data["kind"] == "issue311-r04-writer-proof" and
            data["publicReleaseAuthorized"] is False and
            data["baseMainSha"] == "a0cf784edf3cea11df9d925a605a78177c46f9c8",
            "unrecognized proof request")
    return hashlib.sha256(raw).hexdigest()


def perform(token, phase, owner, request_hash):
    if phase == "lease":
        try:
            blob, current = read_ledger(token)
        except HTTPStatus as error:
            require(error.code == 404, "unexpected ledger read error")
            current = new_ledger(request_hash)
            commit(token, current)
            blob, current = read_ledger(token)
        require(current["requestSha256"] == request_hash, "request changed")
        if current["phase"] == "RECOVERED":
            return {"phase": "ALREADY_RECOVERED", "revision": current["revision"]}
        next_state = lease_next(current, owner, datetime.now(timezone.utc), "LEASED")
        proof = commit(token, next_state, blob)
        # A stale contents SHA must fail closed, never overwrite the current lease.
        try:
            commit(token, next_state, blob)
        except HTTPStatus as error:
            require(error.code in (409, 422), "unexpected stale CAS response")
        else:
            raise Denied("stale CAS improperly accepted")
        return {"phase": "LEASED", "revision": next_state["revision"],
                "fencingGeneration": 1, "writeProof": proof, "staleCas": "DENY"}
    if phase == "recover":
        blob, current = read_ledger(token)
        require(current["requestSha256"] == request_hash, "request changed")
        require(current["phase"] == "LEASED", "cross-job recovery requires leased prior state")
        expires = datetime.fromisoformat(current["lease"]["expiresAt"])
        delay = max(0.0, (expires - datetime.now(timezone.utc)).total_seconds() + 1.0)
        require(delay <= LEASE_SECONDS + 2, "invalid recovery wait")
        if delay:
            time.sleep(delay)
        next_state = lease_next(current, owner, datetime.now(timezone.utc), "RECOVERED")
        proof = commit(token, next_state, blob)
        return {"phase": "RECOVERED", "revision": next_state["revision"],
                "fencingGeneration": next_state["lease"]["generation"],
                "previousOwner": current["lease"]["owner"],
                "writeProof": proof, "recoveredFromDurableState": True}
    raise Denied("unsupported Writer phase")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=["lease", "recover"])
    arguments = parser.parse_args()
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY and
            os.environ.get("GITHUB_EVENT_NAME") == "push" and
            os.environ.get("GITHUB_REF") == "refs/heads/main", "wrong event or repo")
    key = os.environ.get("STATE_WRITER_PRIVATE_KEY", "")
    require(bool(key), "missing dedicated Environment key")
    raw_hash = request_bytes_hash()
    owner = ("run-" + os.environ["GITHUB_RUN_ID"] + "." +
             os.environ["GITHUB_RUN_ATTEMPT"] + "." + arguments.phase)
    token = mint_token(key)
    caught = None
    try:
        receipt = perform(token, arguments.phase, owner, raw_hash)
        receipt.update({"requestId": PROOF_REQUEST, "requestSha256": raw_hash,
                        "appId": APP_ID, "installationId": INSTALLATION_ID,
                        "runId": int(os.environ["GITHUB_RUN_ID"]),
                        "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                        "publicationAuthorized": False, "permission": "contents:write",
                        "ledgerRef": "refs/heads/" + STATE_BRANCH})
    except Exception as error:
        caught = error
        receipt = None
    finally:
        # Every minted scoped token must be revoked, including failed write cases.
        revoke_and_prove_401(token)
    if caught:
        raise caught
    receipt["revoked401"] = True
    dest = Path("issue311-r04-" + arguments.phase + "-receipt.json")
    dest.write_bytes(canonical(receipt))
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
