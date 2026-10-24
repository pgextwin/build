#!/usr/bin/env python3
"""Nonpublishing, protected-main Publisher credential proof; never print secrets."""
import base64
import hashlib
import importlib.util
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

_scope_spec = importlib.util.spec_from_file_location(
    "independent_scope", Path(__file__).with_name("independent-publisher-write-scope.py"))
scope = importlib.util.module_from_spec(_scope_spec)
_scope_spec.loader.exec_module(scope)

_scope_token_spec = importlib.util.spec_from_file_location(
    "publisher_token_lifecycle", Path(__file__).with_name("publisher-scoped-token.py"))
scope_token = importlib.util.module_from_spec(_scope_token_spec)
_scope_token_spec.loader.exec_module(scope_token)

def require(ok):
    if not ok:
        raise ValueError("Publisher probe rejected")

def api(method, path, token, body=None):
    require(path.startswith("/") and not path.startswith("//"))
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request("https://api.github.com" + path, data=data,
        method=method, headers={"Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pgextwin-publisher-proof"})
    with urllib.request.urlopen(request, timeout=40) as response:
        raw = response.read()
        return json.loads(raw) if raw else {}

def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=")

def jwt(key, app):
    now = int(time.time())
    message = b64(b'{"alg":"RS256","typ":"JWT"}') + b"." + b64(
        json.dumps({"iat": now-60, "exp": now+300, "iss": str(app)}).encode())
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "key.pem"
        path.write_text(key)
        path.chmod(0o600)
        result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(path)],
            input=message, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
    return (message + b"." + b64(result.stdout)).decode()

def repositories(fleet):
    rows = fleet.get("entries")
    require(fleet.get("schemaVersion") == 1 and fleet.get("releasePolicy") == "manual-only"
            and type(rows) is list and bool(rows))
    names = []
    for row in rows:
        require(type(row) is dict)
        name = row.get("repository")
        require(type(name) is str and re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*", name)
            and row.get("mode") == "BUILD" and row.get("candidateEnabled") is True
            and row.get("releasePolicy") == "manual-only")
        names.append(name)
    require(len(set(names)) == len(names))
    return names

def run():
    require(os.environ.get("GITHUB_REPOSITORY") == "pgextwin/build"
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch")
    app = int(os.environ["PUBLISHER_APP_ID"])
    installation = int(os.environ["PUBLISHER_INSTALLATION_ID"])
    require(app == 5451798 and installation == 174720074 and app != 15368)
    names = repositories(json.loads(Path("metadata/automation-fleet.json").read_text()))
    key = os.environ.pop("PUBLISHER_PRIVATE_KEY")
    # One central code path validates the authenticated issuer + installation
    # and scopes every fresh token. No App key is sent to Signer jobs.
    scope_token.issuer(api, jwt, key, app, installation)
    report = {"appId": app, "installationId": installation,
        "installationRepositorySelection": "all", "signerAppId": 15368,
        "independentApp": True, "publicationAuthorized": False, "repositories": []}
    payload = b"pgextwin Publisher authorization probe; no refs, tags or Releases.\n"
    expected = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
    fleet = json.loads(Path("metadata/automation-fleet.json").read_text())
    for name in names:
        row = {"repository": name, "status": "DENY", "tokenRevoked": False}
        report["repositories"].append(row)
        try:
            with scope_token.single_repository_token(
                    api=api, jwt=jwt, key=key, app=app, installation=installation,
                    repository=name, fleet=fleet) as (token, minted, scoped):
                blob = api("POST", "/repos/" + name + "/git/blobs", token,
                    {"content": base64.b64encode(payload).decode(), "encoding": "base64"})
                proof = scope.validate_live_scope(
                    minted, scoped, blob, repository=name,
                    observed_at=datetime.now(timezone.utc), expected_blob_sha=expected)
                require(proof["publicationAuthorized"] is False
                    and proof["publisherWriteAuthorized"] is False)
                row.update(status="SCOPED_CONTENTS_WRITE_PROVEN",
                    expiresAt=minted["expires_at"],
                    scopedRepositoryCount=proof["scopedRepositoryCount"],
                    permissions=minted["permissions"], blobSha=proof["blobSha"])
            row["tokenRevoked"] = True
        except Exception:
            row["status"] = "DENY"
    Path("publisher-app-proof.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    require(all(row["status"] == "SCOPED_CONTENTS_WRITE_PROVEN" and row["tokenRevoked"]
                for row in report["repositories"]))

if __name__ == "__main__":
    try:
        run()
    except Exception:
        print("PUBLISHER_PROOF_DENY; credential values and API error bodies suppressed")
        raise SystemExit(1)
