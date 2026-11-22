#!/usr/bin/env python3
"""Dedicated isolated owner issue_comment signed-main formal Publisher.

The read-only step authenticates the request and verifies the original signed
bytes. The publish step uses the same job's digest-bound preparation, rechecks
live authorization and upload bytes, and scopes the App token to one repository.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote

ROOT=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

owner=load("owner_formal_original","publisher-owner-source-admission.py")
selector=load("owner_formal_selector","publisher-owner-source-publish-request.py")
policy=load("owner_formal_policy","owner-source-publish-policy.py")
issuer=load("owner_formal_issuer","automatic-publisher-receipt-issuer.py")
formal=load("owner_formal_writer","fleet-publish-release.py")
scope=load("owner_formal_scoped_token","publisher-scoped-token.py")
probe=load("owner_formal_app_identity","probe-publisher-app.py")
tagplan=load("owner_formal_tag_inventory","automatic-release-tag-plan.py")
provenance=load("owner_formal_public_locator","automatic-release-provenance.py")
ident=issuer.ident
REPO=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
class Denied(ValueError):pass

def need(ok,why):
    if not ok:raise Denied(why)

def instant(value):
    need(type(value) is str and value.endswith("Z"),"missing UTC original time")
    return datetime.fromisoformat(value.replace("Z","+00:00"))

def authenticate(repo,run_id,sha,env):
    need(env.get("GITHUB_REPOSITORY")=="pgextwin/build"
         and env.get("GITHUB_EVENT_NAME")=="issue_comment"
         and env.get("GITHUB_REF")=="refs/heads/main"
         and env.get("GITHUB_RUN_ATTEMPT")=="1"
         and type(env.get("GH_TOKEN")) is str and len(env["GH_TOKEN"])>10
         and REPO.fullmatch(repo) is not None
         and type(run_id) is int and run_id>0
         and type(sha) is str and owner.SHA.fullmatch(sha) is not None,
         "untrusted owner Publisher runtime")
    event=json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text("utf-8"),
                     object_pairs_hook=owner.unique)
    cid=(event.get("comment") or {}).get("id")
    need(type(cid) is int and cid>0,"invalid owner request ID")
    central_branch=owner.get("pgextwin/build","branches/main")
    current=owner.get("pgextwin/build",f"actions/runs/{env['GITHUB_RUN_ID']}")
    target,source=owner.authenticate_request(
        event,owner.get("pgextwin/build",f"issues/comments/{cid}"),
        current,central_branch,env,request_pattern=owner.PUBLISH_REQUEST)
    need(repo==target and run_id==source
         and type(env.get("GITHUB_SHA")) is str
         and central_branch["commit"]["sha"]==env["GITHUB_SHA"],
         "original exact Run selector differs from immutable owner request")
    original=owner.get(repo,f"actions/runs/{run_id}")
    owner.source_run(repo, sha, run_id, original)
    # A freshly created Publisher command may reference a successful original
    # signed Run, but not a stale or future original / edited request.
    signed_at=instant(original.get("updated_at"))
    requested_at=instant(event["comment"]["created_at"])
    central_at=instant(current.get("created_at"))
    need(signed_at<=requested_at<=central_at+timedelta(minutes=5)
         and central_at-requested_at<=timedelta(minutes=30)
         and requested_at-signed_at<=timedelta(days=7),
         "owner source/request freshness or replay window not satisfied")
    return event,central_branch,current,original,cid

def original_job(publisher_id,central_sha):
    jobs=owner.get("pgextwin/build",
        f"actions/runs/{publisher_id}/attempts/1/jobs?per_page=100")
    items=jobs.get("jobs")
    need(type(jobs.get("total_count")) is int and type(items) is list
         and jobs["total_count"]==len(items) and 0<len(items)<100,
         "Publisher job inventory truncated or changed")
    matches=[j for j in items if j.get("name")==
             "Select protected owner formal-source request (DENY)"]
    need(len(matches)==1 and type(matches[0].get("id")) is int
         and matches[0].get("run_attempt")==1
         and matches[0].get("run_id")==publisher_id
         and matches[0].get("head_sha")==central_sha
         and matches[0].get("status")=="completed"
         and matches[0].get("conclusion")=="success",
         "same-Publisher-Run owner request selection not successful")
    return matches[0]["id"]

def verify_upload_bytes(folder, manifest, lifecycle, proof):
    majors = ident.maintained_majors(manifest, lifecycle)
    expected_files = ident.expected_assets(manifest, majors) - {"SHA256SUMS.txt"}
    need(folder.is_dir() and not folder.is_symlink()
         and {p.name for p in folder.iterdir()} == expected_files
         and all(p.is_file() and not p.is_symlink() for p in folder.iterdir()),
         "missing/extra original signed ZIP/SPDX/Grype")
    expected = proof["SHA256"]
    need(proof.get("maintainedMajors") == majors
         and {p.name: formal.digest(p) for p in folder.iterdir()} == expected,
         "verified per-major SHA256 differs from upload bytes")
    return expected.copy()


def tag_from_live(repo,manifest,source_run):
    stem=ident.tag_stem(manifest)
    prefix=stem+"-windows."
    releases=tagplan.get_listing(repo,"releases?per_page=100")
    refs=tagplan.get_listing(repo,
        "git/matching-refs/tags/"+quote(prefix,safe=""),allow_missing=True)
    need(type(releases) is list and type(refs) is list,
         "unverifiable exact Release/tag inventory")
    existing=set()
    for item in releases:
        need(type(item) is dict and type(item.get("id")) is int
             and item["id"]>0 and type(item.get("tag_name")) is str
             and type(item.get("draft")) is bool,
             "unverifiable Release identity")
        text=item.get("body") or ""
        if provenance.PREFIX in text:
            record=provenance.decode(text)
            need(not (record.get("repository")==repo
                      and record.get("sourceRunId")==source_run),
                 "original source Run already published, replay forbidden")
        if item["tag_name"].startswith(prefix):
            existing.add(item["tag_name"])
    for item in refs:
        need(type(item) is dict and type(item.get("ref")) is str
             and item["ref"].startswith("refs/tags/"+prefix),
             "unverifiable exact matching tag ref")
        existing.add(item["ref"].removeprefix("refs/tags/"))
    seq=[]
    for val in existing:
        suffix=val[len(prefix):]
        need(re.fullmatch(r"[1-9][0-9]*",suffix) is not None,
             "malformed previous same-version Release tag")
        seq.append(int(suffix))
    tag=prefix+str(max(seq,default=0)+1)
    ident.validate_release_tag(manifest,tag)
    need(tag not in existing,"tag already exists")
    return tag

def recheck(state, env):
    proof = state["proof"]
    repo, run_id, sha = proof["repository"], proof["sourceRunId"], proof["mainSha"]
    _, central_branch, current, _, cid = authenticate(repo, run_id, sha, env)
    intent = state["intent"]
    owner.signing_request(
        repo, sha, run_id, intent, owner.get(repo, f"issues/comments/{intent['commentId']}"))
    source_branch = owner.get(repo, "branches/main")
    need(cid == state["requestCommentId"]
         and source_branch.get("name") == "main"
         and source_branch.get("protected") is True
         and (source_branch.get("commit") or {}).get("sha") == sha
         and owner.get("pgextwin/build", "branches/main") == central_branch,
         "protected main or immutable owner request changed")
    need(original_job(int(env["GITHUB_RUN_ID"]), env["GITHUB_SHA"]) == state["selectorJobId"],
         "owner request selection changed before Release")
    return central_branch, current, source_branch


POLICY_ARGS = ("fleet", "central_policy", "owner_central_policy", "owner_policy",
               "unattended", "publisher_boundary", "lifecycle")
STATE_FILE = "owner-source-prepared.json"


def prepare(a, scratch, env):
    repo, run_id, sha = a.repository, int(a.source_run), a.source_sha
    _, _, _, _, cid = authenticate(repo, run_id, sha, env)
    policies = {name: issuer.fleet_policy.read(getattr(a, name)) for name in POLICY_ARGS}
    local = selector.protected_local(repo, sha, "release-promotion")
    owner_local = selector.protected_local(repo, sha, "owner-source-publication")
    policy.gate(fleet=policies["fleet"], central=policies["central_policy"],
                local=local, unattended=policies["unattended"],
                boundary=policies["publisher_boundary"],
                owner_central=policies["owner_central_policy"],
                owner_local=owner_local, repository=repo)
    issuer.owner_policy_gate(policies["owner_policy"])
    proof, manifest, intent = owner.admit(
        repo, run_id, scratch=scratch, fleet=policies["fleet"],
        lifecycle=policies["lifecycle"], expected_sha=sha)
    blocking = proof["blockingGrypeFindings"]
    print(f"Grype blocking findings across verified majors: {blocking}")
    need(blocking == 0, "blocking Critical/High/Unknown Grype vulnerability")
    state = {"proof": proof, "manifest": manifest, "intent": intent,
             "requestCommentId": cid, "local": local, "ownerLocal": owner_local,
             "selectorJobId": original_job(int(env["GITHUB_RUN_ID"]), env["GITHUB_SHA"]),
             "policies": policies}
    raw = json.dumps(state, sort_keys=True).encode("utf-8")
    with (scratch / STATE_FILE).open("xb") as out:
        out.write(raw)
    with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
        out.write("prepared_sha256=" + hashlib.sha256(raw).hexdigest() + "\n")
    return 0


def publish(a, scratch, env):
    raw = (scratch / STATE_FILE).read_bytes()
    need(hashlib.sha256(raw).hexdigest() == env.get("OWNER_SOURCE_PREPARED_SHA256"),
         "same-job verified preparation changed")
    state = json.loads(raw, object_pairs_hook=owner.unique)
    proof, manifest = state["proof"], state["manifest"]
    repo, run_id, sha = proof["repository"], proof["sourceRunId"], proof["mainSha"]
    policies = state["policies"]
    lifecycle = policies["lifecycle"]
    folder = scratch / "original-owner-signed" / "signed"

    key = env.pop("PUBLISHER_PRIVATE_KEY")
    need(bool(key), "Publisher App key unavailable")
    recheck(state, env)
    tag = tag_from_live(repo, manifest, run_id)
    formal.REPO = repo
    formal.absent(tag)
    need(env.get("PUBLISHER_APP_ID") == str(issuer.APP)
         and env.get("PUBLISHER_INSTALLATION_ID") == str(issuer.INSTALLATION),
         "independent Publisher App identity variables missing")
    app_id = int(env["PUBLISHER_APP_ID"])
    installation = int(env["PUBLISHER_INSTALLATION_ID"])
    jwt = probe.jwt(key, app_id)
    app_identity = probe.api("GET", "/app", jwt)
    installation_identity = probe.api("GET", "/app/installations/" + str(installation), jwt)
    with scope.single_repository_token(
            api=probe.api, jwt=probe.jwt, key=key, app=app_id, installation=installation,
            repository=repo, fleet=policies["fleet"],
            release_policy=issuer.MODE) as (token, minted, scoped):
        central_branch, central_run, source_branch = recheck(state, env)
        receipt = issuer.issue(
            proof=proof, lifecycle=lifecycle, manifest=manifest, fleet=policies["fleet"],
            central=policies["central_policy"], local=state["local"],
            unattended=policies["unattended"], boundary=policies["publisher_boundary"],
            schedule_run=central_run, central_branch=central_branch,
            signed_branch=source_branch, app_identity=app_identity,
            installation_identity=installation_identity, minted=minted, scoped=scoped,
            repository=repo, sha=sha, source_run=run_id,
            central_sha=env["GITHUB_SHA"], publisher_run=int(env["GITHUB_RUN_ID"]),
            event="issue_comment", ref=env["GITHUB_REF"], attempt=int(env["GITHUB_RUN_ATTEMPT"]),
            tag=tag, tag_absent=True, release_absent=True, actor=env["GITHUB_ACTOR"],
            owner_policy=policies["owner_policy"], request_comment_id=state["requestCommentId"],
            source_kind=issuer.OWNER_KIND, source_signing_comment_id=proof["sourceCommentId"],
            owner_central=policies["owner_central_policy"], owner_local=state["ownerLocal"])
        # The protected writer also compares the staged GitHub asset digests
        # to this same map before the draft can become public.
        expected = verify_upload_bytes(folder, manifest, lifecycle, proof)
        formal.absent(tag)
        read_credential = env["GH_TOKEN"]
        try:
            env["GH_TOKEN"] = token
            formal.publish_preverified(
                folder, manifest, receipt, sha, expected, Path(a.recovery),
                publish_run_id=int(env["GITHUB_RUN_ID"]))
        finally:
            env["GH_TOKEN"] = read_credential
    Path(a.output).write_text(json.dumps({
        "schemaVersion": 1, "status": "PUBLISHED_VERIFIED", "sourceKind": issuer.OWNER_KIND,
        "repository": repo, "sourceRunId": run_id, "publisherRunId": int(env["GITHUB_RUN_ID"]),
        "releaseTag": tag, "publisherTokenRevoked": True}, sort_keys=True, indent=2) + "\n", "utf-8")
    print("OWNER_SIGNED_SOURCE_FORMAL_RELEASE_VERIFIED_AND_TOKEN_REVOKED")
    return 0


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    for key in ("repository", "source_run", "source_sha", *POLICY_ARGS):
        prepare_parser.add_argument("--" + key.replace("_", "-"), required=True)
    publish_parser = commands.add_parser("publish")
    for key in ("recovery", "output"):
        publish_parser.add_argument("--" + key, required=True)
    a = parser.parse_args()
    try:
        scratch = Path(os.environ["RUNNER_TEMP"])
        need(scratch.is_dir() and not scratch.is_symlink(), "untrusted Publisher temporary directory")
        if a.command == "prepare":
            return prepare(a, scratch, os.environ)
        return publish(a, scratch, os.environ)
    except Exception as exc:
        print("OWNER_SIGNED_SOURCE_FORMAL_PUBLISHER_DENY ("+
              type(exc).__name__+"); API/token details suppressed",
              file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
