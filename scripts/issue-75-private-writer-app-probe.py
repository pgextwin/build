#!/usr/bin/env python3
"""Private-only, nonpublishing scoped GitHub App Writer issuer probe.

Not wired to GitHub Actions. Credential mint is a privileged side effect:
only a separately authorized, protected private executor may call probe().
This file neither publishes Releases nor grants any GO gate.

The app JWT is authenticated by GitHub's GET /app and installation GET.
A single short-lived token is minted by POST with repository_ids and a
contents:write ONLY request, GET-checked and immediately revoked by DELETE.
A successful test/mock is not an authentic issuance or cross-job isolation.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPO = "pgextwin/plpgsql_check"  # historical pilot, retained as default
WAVE3_REPOS = frozenset((
    "pgextwin/pgtap",
    "pgextwin/pg_variables",
    "pgextwin/pg_store_plans",
))
ALLOWED_TARGETS = WAVE3_REPOS | {REPO}
OWNER = "pgextwin"
# GitHub Actions App resolver / job token cannot be the independent Writer.
NON_WRITER_APP_IDS = frozenset((15368,))
MINIMAL_WRITER_PERMISSIONS = (
    {"contents": "write"}, {"contents": "write", "metadata": "read"})
REPO_NAME = "plpgsql_check"
MAX_RESPONSE = 100_000
API = "https://api.github.com"
TOKEN_ENDPOINT = "/installation/token"
REPOS_ENDPOINT = "/installation/repositories?per_page=100&page=1"

class Deny(ValueError):
    pass

def need(value):
    if not value:
        raise Deny("independent Writer issuance/identity/isolation not proven")

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Deny("redirect denied")

def unique(pairs):
    value = {}
    for k,v in pairs:
        need(k not in value)
        value[k]=v
    return value

def permitted(method, path):
    need(type(method) is str and type(path) is str)
    if method == "GET":
        need(path == "/app" or
             bool(re.fullmatch(r"/app/installations/[1-9][0-9]*",path)) or
             path == REPOS_ENDPOINT)
    elif method == "POST":
        need(bool(re.fullmatch(r"/app/installations/[1-9][0-9]*/access_tokens",path)))
    elif method == "DELETE":
        need(path == TOKEN_ENDPOINT)
    else:
        raise Deny("HTTP method denied")

def authenticated_call(method, path, credential, payload=None, *,
                       opener=None):
    """One bounded GitHub REST request, no redirects/response logging."""
    permitted(method,path)
    need(type(credential) is str and len(credential) >= 20)
    if method == "POST":
        need(type(payload) is dict and set(payload)=={"repository_ids","permissions"})
        data = json.dumps(payload,separators=(",",":")).encode("utf-8")
    else:
        need(payload is None)
        data = None
    req=Request(API+path,data=data,method=method,headers={
        "Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2026-03-10",
        "Authorization":"Bearer "+credential,
        "User-Agent":"pgextwin-issue75-private-writer-proof"})
    call=opener or build_opener(NoRedirect()).open
    try:
        with call(req,timeout=20) as r:
            expected=201 if method=="POST" else 204 if method=="DELETE" else 200
            need(r.status==expected)
            need(not r.headers.get("Link"))  # paginated/partial == unproven
            raw=r.read(MAX_RESPONSE+1)
            need(len(raw)<=MAX_RESPONSE)
            if method=="DELETE":
                need(raw==b"")
                return {"revoked":True}
            obj=json.loads(raw.decode("utf-8"),object_pairs_hook=unique)
            need(type(obj) is dict)
            return obj
    except Exception:
        raise Deny("GitHub App authenticated REST probe failed") from None

def read_expiry(value, now):
    need(type(value) is str and value.endswith("Z"))
    try:
        d=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError:
        raise Deny("invalid Writer expiry") from None
    need(d.tzinfo is not None)
    until=d.astimezone(timezone.utc)-now
    need(timedelta(seconds=30)<until<=timedelta(hours=1))
    return int(until.total_seconds())

def probe(app_jwt, *, app_id, installation_id, repository_id, now,
          repository=REPO, api=authenticated_call):
    """Not used in public CI. Never pass in a Reader token.

    Token is ephemeral; only this function sees it. Revocation is attempted
    in finally. Revocation failure DENIES (no false success), and must be
    quarantined by the future private operator. This does NOT prove job
    isolation or authorise release publication.
    """
    need(type(app_jwt) is str and len(app_jwt)>=20)
    # Exact allowlist: never probe arbitrary orgs or the Catalog-only App target.
    need(type(repository) is str and repository in ALLOWED_TARGETS)
    need(all(type(v) is int and v>0 for v in
             (app_id,installation_id,repository_id)) and
         app_id not in NON_WRITER_APP_IDS)
    need(type(now) is datetime and now.tzinfo is not None)
    now=now.astimezone(timezone.utc)
    try:
        identity=api("GET","/app",app_jwt)
    except Exception:
        raise Deny("app JWT issuer lookup failed") from None
    need(type(identity) is dict and type(identity.get("id")) is int
         and identity["id"]==app_id)
    try:
        install=api("GET","/app/installations/"+str(installation_id),app_jwt)
    except Exception:
        raise Deny("installation JWT identity lookup failed") from None
    need(type(install) is dict
         and type(install.get("id")) is int
         and install["id"]==installation_id
         and type(install.get("app_id")) is int
         and install["app_id"]==app_id
         and install.get("target_type")=="Organization"
         and type(install.get("account")) is dict
         and install["account"].get("login")==OWNER
         and install.get("suspended_at") is None
         and install.get("repository_selection")=="selected"
         and type(install.get("permissions")) is dict
         and install["permissions"] in MINIMAL_WRITER_PERMISSIONS)
    request={"repository_ids":[repository_id],"permissions":{"contents":"write"}}
    minted=None
    try:
        minted=api("POST",
                   "/app/installations/"+str(installation_id)+"/access_tokens",
                   app_jwt,request)
        need(type(minted) is dict)
        token=minted.get("token")
        need(type(token) is str and len(token)>=20 and token!=app_jwt)
        need(minted.get("repository_selection")=="selected")
        perms=minted.get("permissions")
        need(type(perms) is dict
             and perms in MINIMAL_WRITER_PERMISSIONS)
        repos=minted.get("repositories")
        need(type(repos) is list and len(repos)==1
             and type(repos[0]) is dict
             and type(repos[0].get("id")) is int
             and repos[0]["id"]==repository_id
             and repos[0].get("full_name")==repository)
        ttl=read_expiry(minted.get("expires_at"),now)
        view=api("GET",REPOS_ENDPOINT,token)
        need(type(view) is dict
             and type(view.get("total_count")) is int
             and view["total_count"]==1
             and type(view.get("repositories")) is list
             and len(view["repositories"])==1
             and type(view["repositories"][0]) is dict
             and view["repositories"][0].get("id")==repository_id
             and view["repositories"][0].get("full_name")==repository)
        # A GET to public repository alone does not establish actual scope.
        # Source is the authenticated JWT-scoped token mint response.
        result={"classification":"PRIVATE_APP_SCOPED_MINT_AND_REVOKE_CONTRACT",
                "installationId":installation_id,"appId":app_id,
                "targetRepository":repository,"expiresWithinSeconds":ttl,
                "independentReaderSignerCustodyProven":False,
                "publisherPrewriteProven":False,
                "publicationAuthorized":False,
                "goB":"NO_GO","g4":"NO_GO","g5":"NO_GO"}
    except Exception:
        raise Deny("Writer installation scope/identity unproven") from None
    finally:
        if type(minted) is dict and type(minted.get("token")) is str:
            # Never print raw token, even in failure; a failed revoke
            # causes DENY and needs out-of-band private quarantine.
            try:
                revoked=api("DELETE",TOKEN_ENDPOINT,minted["token"])
                need(type(revoked) is dict and revoked.get("revoked") is True)
            except Exception:
                raise Deny("Writer scoped token revocation unconfirmed") from None
    result["scopedTokenRevocation204Observed"] = True
    result["positivePublisherPrewriteAuthorized"] = False
    return result
