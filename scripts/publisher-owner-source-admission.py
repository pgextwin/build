#!/usr/bin/env python3
"""Independently admit a REAL owner issue_comment signed source (READ ONLY).

A different source kind from main/push. This is a Publisher-side cryptographic
admission observation, NEVER a Release receipt. Fail closed and PUBLISH_DENY.
The existing credentialed Publisher is deliberately NOT connected to this job.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
SOURCE_KIND = "OWNER_ISSUE_COMMENT_MAIN_SIGNING"
SOURCE_WORKFLOW = ".github/workflows/chat-signed-main.yml"
CENTRAL_WORKFLOW = ".github/workflows/publisher-candidate-intake.yml"
OWNER = {"login": "ShutenOishi", "id": 27071164, "type": "User"}
REQUEST = re.compile(r"^/pgextwin admit-owner-source (pgextwin/[a-z][a-z0-9_]*) ([1-9][0-9]*)$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
SHA = re.compile(r"^[0-9a-f]{40}$")

def module(label, filename):
    spec = importlib.util.spec_from_file_location(label, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

audit = module("publisher_owner_signer_audit", "chat-signed-main-audit.py")
ident = module("publisher_owner_ident", "fleet-release-identity.py")

class Denied(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Denied(reason)

def unique(items):
    result = {}
    for key, val in items:
        need(key not in result, "duplicate JSON keys")
        result[key] = val
    return result

def owner(value):
    return type(value) is dict and all(value.get(k) == v for k, v in OWNER.items())

def command(args, *, timeout=120):
    need(type(args) is list and all(type(a) is str for a in args)
         and (args[:4] == ["gh", "api", "--method", "GET"]
              or args[:3] == ["gh", "run", "download"]),
         "non-read-only command")
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                       check=False)
    need(p.returncode == 0, "original GitHub read/download failed")
    return p.stdout

def get(repo, route):
    need(REPO.fullmatch(repo) is not None, "invalid repository")
    allowed = (route == "branches/main"
               or re.fullmatch(r"actions/runs/[1-9][0-9]*", route)
               or re.fullmatch(r"actions/runs/[1-9][0-9]*/attempts/1/jobs\?per_page=100", route)
               or re.fullmatch(r"actions/runs/[1-9][0-9]*/artifacts\?per_page=100", route)
               or re.fullmatch(r"issues/comments/[1-9][0-9]*", route)
               or re.fullmatch(r"contents/config/extension\.json\?ref=[0-9a-f]{40}", route))
    need(bool(allowed), "non-allowlisted source GET")
    raw = command(["gh", "api", "--method", "GET",
                   "repos/" + repo + "/" + route])
    need(0 < len(raw) < 4_000_000, "empty or oversized GitHub response")
    result = json.loads(raw, object_pairs_hook=unique)
    need(type(result) is dict, "malformed GitHub API document")
    return result

def authenticate_request(event, live, central, central_branch, env):
    """Validate independent central Publisher original comment, not a fake push."""
    m = REQUEST.fullmatch((event.get("comment") or {}).get("body", ""))
    need(m is not None and env.get("GITHUB_REPOSITORY") == "pgextwin/build"
         and env.get("GITHUB_EVENT_NAME") == "issue_comment"
         and env.get("GITHUB_RUN_ATTEMPT") == "1"
         and env.get("GITHUB_REF") == "refs/heads/main"
         and env.get("GITHUB_ACTOR") == OWNER["login"]
         and env.get("GITHUB_TRIGGERING_ACTOR") == OWNER["login"]
         and env.get("GITHUB_ACTOR_ID") == str(OWNER["id"])
         and type(env.get("GITHUB_SHA")) is str
         and SHA.fullmatch(env["GITHUB_SHA"])
         and re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ID", "")),
         "not genuine original owner Publisher admission request")
    comment = event["comment"]
    cid = comment.get("id")
    need(type(cid) is int and cid > 0
         and event.get("action") == "created"
         and (event.get("repository") or {}).get("full_name") == "pgextwin/build"
         and (event.get("issue") or {}).get("number") == 311
         and "pull_request" not in event["issue"]
         and owner(event.get("sender")) and owner(comment.get("user"))
         and comment.get("issue_url") == "https://api.github.com/repos/pgextwin/build/issues/311"
         and comment.get("created_at") == comment.get("updated_at"),
         "wrong Issue #311 event, comment or author")
    need(type(live) is dict and live.get("id") == cid
         and live.get("body") == comment["body"]
         and owner(live.get("user"))
         and live.get("issue_url") == comment["issue_url"]
         and live.get("created_at") == comment["created_at"]
         and live.get("updated_at") == comment["updated_at"],
         "owner Publisher command altered or replayed")
    need(type(central_branch) is dict and central_branch.get("name") == "main"
         and central_branch.get("protected") is True
         and (central_branch.get("commit") or {}).get("sha") == env["GITHUB_SHA"],
         "central protected main changed")
    need(type(central) is dict and central.get("id") == int(env["GITHUB_RUN_ID"])
         and central.get("run_attempt") == 1
         and central.get("event") == "issue_comment"
         and central.get("path") == CENTRAL_WORKFLOW
         and central.get("head_branch") == "main"
         and central.get("head_sha") == env["GITHUB_SHA"]
         and central.get("status") == "in_progress"
         and (central.get("repository") or {}).get("full_name") == "pgextwin/build"
         and owner(central.get("actor")) and owner(central.get("triggering_actor")),
         "central Publisher original event or run differs")
    return m.group(1), int(m.group(2))

def source_metadata(repo, sha, run_id, run, jobs, artifacts, intent, live, majors):
    """Strict original owner source chain, including two *successful* audits."""
    need(REPO.fullmatch(repo) is not None and SHA.fullmatch(sha) is not None
         and type(run_id) is int and run_id > 0
         and type(run) is dict and run.get("id") == run_id
         and run.get("run_attempt") == 1
         and run.get("event") == "issue_comment"
         and run.get("path") == SOURCE_WORKFLOW
         and run.get("head_sha") == sha
         and run.get("head_branch") == "main"
         and run.get("status") == "completed"
         and run.get("conclusion") == "success"
         and (run.get("repository") or {}).get("full_name") == repo
         and owner(run.get("actor")) and owner(run.get("triggering_actor")),
         "not genuine completed attempt-1 signed main owner Run")
    need(type(intent) is dict
         and intent.get("sourceKind") == SOURCE_KIND
         and intent.get("sourceEvent") == "issue_comment"
         and intent.get("repository") == repo
         and intent.get("mainSha") == sha
         and intent.get("runId") == run_id
         and intent.get("runAttempt") == 1
         and type(intent.get("issueNumber")) is int
         and intent["issueNumber"] > 0
         and type(intent.get("commentId")) is int
         and intent["commentId"] > 0
         and intent.get("signingEligible") is True
         and intent.get("publisherEligible") is False
         and intent.get("publicationAuthorized") is False
         and intent.get("PUBLISH") == "DENY",
         "owner intent not authentic signed-only source")
    need(type(live) is dict and live.get("id") == intent["commentId"]
         and live.get("body") == "/pgextwin sign-main"
         and live.get("issue_url") ==
         f"https://api.github.com/repos/{repo}/issues/{intent['issueNumber']}"
         and live.get("created_at") == live.get("updated_at")
         and owner(live.get("user")),
         "original signing request is edited, deleted or forged")
    need(type(jobs) is dict and type(jobs.get("jobs")) is list
         and type(jobs.get("total_count")) is int
         and jobs["total_count"] == len(jobs["jobs"])
         and len(jobs["jobs"]) == len(majors) + 5,
         "incomplete/paginated or unexpected original signed jobs")
    names = [j.get("name") for j in jobs["jobs"]]
    need(len(set(names)) == len(names)
         and all(type(j) is dict and type(j.get("id")) is int and j["id"] > 0
                 and j.get("run_id") == run_id
                 and j.get("run_attempt") == 1
                 and j.get("head_sha") == sha
                 and j.get("status") == "completed"
                 and j.get("conclusion") == "success"
                 for j in jobs["jobs"]),
         "failed/replayed/foreign original Windows/signing/audit jobs")
    for part in (["Original authenticated owner/main/comment source (DENY Publisher)",
                  "Resolve extension and PostgreSQL matrix",
                  "Independent original Sigstore/ZIP/SPDX/Grype audit (first)",
                  "Independent original Sigstore/ZIP/SPDX/Grype audit (second)",
                  "Require exact independent real-signature byte agreement (NO PUBLISH)"]
                 + [f"PostgreSQL {major} / Windows x64" for major in majors]):
        need(sum(part in name for name in names) == 1,
             "missing/duplicate original source, signed PG or audit job")
    need(type(artifacts) is dict and type(artifacts.get("artifacts")) is list
         and type(artifacts.get("total_count")) is int
         and artifacts["total_count"] == len(artifacts["artifacts"])
         and artifacts["total_count"] < 100,
         "missing or incomplete original signed artifacts")
    names = [a.get("name") for a in artifacts["artifacts"]]
    required = {"chat-main-source-intent-nonpublishing",
                "chat-owner-sigstore-first-nonpublishing",
                "chat-owner-sigstore-second-nonpublishing",
                "chat-owner-dual-sigstore-nonpublishing"}
    need(all(names.count(name) == 1 for name in required)
         and all(type(a) is dict and type(a.get("id")) is int and a["id"] > 0
                 and type(a.get("size_in_bytes")) is int and a["size_in_bytes"] > 0
                 and a.get("expired") is False
                 for a in artifacts["artifacts"] if a.get("name") in required),
         "missing/expired/duplicate independent original Sigstore artifacts")

def fetch_artifact(repo, run_id, name, folder, *, pattern=False):
    need(not folder.exists() and not folder.is_symlink(), "stale proof artifact path")
    flag = "--pattern" if pattern else "--name"
    command(["gh", "run", "download", str(run_id), "--repo", repo,
             flag, name, "--dir", str(folder)], timeout=240)
    need(folder.is_dir() and not folder.is_symlink()
         and all(not f.is_symlink() for f in folder.rglob("*")),
         "downloaded source archive unsafe")

def read_file(folder, name):
    path = folder / name
    need(path.is_file() and not path.is_symlink()
         and 0 < path.stat().st_size < 5_000_000,
         "missing or invalid source JSON")
    return json.loads(path.read_text("utf-8"), object_pairs_hook=unique)

def admit(repo, run_id, *, scratch, fleet, lifecycle):
    need(type(fleet) is dict and type(fleet.get("entries")) is list
         and repo in [e.get("repository") for e in fleet["entries"] if type(e) is dict],
         "non-fleet signed source")
    branch = get(repo, "branches/main")
    sha = (branch.get("commit") or {}).get("sha")
    need(branch.get("name") == "main" and branch.get("protected") is True
         and type(sha) is str and SHA.fullmatch(sha), "source unprotected or advanced")
    contents = get(repo, f"contents/config/extension.json?ref={sha}")
    need(contents.get("encoding") == "base64" and type(contents.get("content")) is str,
         "protected manifest unavailable")
    manifest = json.loads(base64.b64decode(
        contents["content"].replace("\n", ""), validate=True), object_pairs_hook=unique)
    need(manifest.get("name") == repo.split("/")[1], "wrong source manifest")
    majors = ident.maintained_majors(manifest, lifecycle)
    run = get(repo, f"actions/runs/{run_id}")
    jobs = get(repo, f"actions/runs/{run_id}/attempts/1/jobs?per_page=100")
    artifacts = get(repo, f"actions/runs/{run_id}/artifacts?per_page=100")
    root = scratch / "original-owner-signed"
    need(not root.exists(), "duplicate scratch source")
    root.mkdir()
    groups = {
        "intent": "chat-main-source-intent-nonpublishing",
        "first": "chat-owner-sigstore-first-nonpublishing",
        "second": "chat-owner-sigstore-second-nonpublishing",
        "dual": "chat-owner-dual-sigstore-nonpublishing",
        "signed": repo.split("/")[1] + "-pg*-windows-x64",
    }
    for label, name in groups.items():
        fetch_artifact(repo, run_id, name, root / label, pattern=(label == "signed"))
    # gh run download --pattern creates per-artifact subdirectories. Flatten
    # only disjoint, regular, expected signed ZIP/SPDX/Grype names.
    signed_folder = root / "signed"
    source_files = [p for p in signed_folder.rglob("*") if p.is_file()]
    need(bool(source_files) and len({p.name for p in source_files}) == len(source_files)
         and all(p.name.startswith(repo.split("/")[1] + "-")
                 and p.name.endswith((".zip", ".spdx.json", ".vulnerabilities.json"))
                 and not p.is_symlink() for p in source_files),
         "incomplete/duplicate/unexpected signed artifact bytes")
    for file in source_files:
        if file.parent != signed_folder:
            shutil.copyfile(file, signed_folder / file.name)
    for folder in list(signed_folder.iterdir()):
        if folder.is_dir():
            shutil.rmtree(folder)
    intent = read_file(root / "intent", "owner-main-intent.json")
    live = get(repo, f"issues/comments/{intent['commentId']}")
    source_metadata(repo, sha, run_id, run, jobs, artifacts, intent, live, majors)
    def receipt(label):
        return read_file(root / label, "chat-owner-audit-" + label + ".json")
    first, second = receipt("first"), receipt("second")
    original_dual = read_file(root / "dual", "chat-owner-dual-sigstore.json")
    fresh_first = audit.audit(root / "signed", intent, manifest, lifecycle,
                              repo=repo, sha=sha, run_id=run_id, auditor="first")
    fresh_second = audit.audit(root / "signed", intent, manifest, lifecycle,
                               repo=repo, sha=sha, run_id=run_id, auditor="second")
    need(first == fresh_first and second == fresh_second,
         "Publisher's independent real Sigstore/byte recheck differs")
    dual = audit.join(fresh_first, fresh_second)
    need(dual == original_dual, "original dual attestation and independent Publisher disagree")
    current = get(repo, "branches/main")
    need(current.get("protected") is True
         and (current.get("commit") or {}).get("sha") == sha,
         "signed main advanced during independent admission")
    return {"schemaVersion": 1,
            "status": "OWNER_MAIN_SIGNED_SOURCE_INDEPENDENTLY_VERIFIED_NONPUBLISHING",
            "sourceKind": SOURCE_KIND, "sourceEvent": "issue_comment",
            "repository": repo, "mainSha": sha, "sourceRunId": run_id,
            "sourceRunAttempt": 1, "sourceCommentId": intent["commentId"],
            "maintainedMajors": majors, "originalAndFreshDualSigstoreAgree": True,
            "SHA256": dual["SHA256"],
            "publisherEligible": False, "publicationAuthorized": False,
            "publishableReceipt": False, "publisherWriteAuthorized": False,
            "PUBLISH": "DENY"}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--fleet", required=True)
    p.add_argument("--lifecycle", required=True)
    p.add_argument("--output", required=True)
    a = p.parse_args()
    try:
        env = os.environ
        need(bool(env.get("GH_TOKEN")) and bool(env.get("RUNNER_TEMP")),
             "read-only GitHub credentials/runner directory missing")
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text("utf-8"),
                           object_pairs_hook=unique)
        cid = (event.get("comment") or {}).get("id")
        need(type(cid) is int and cid > 0, "missing original comment ID")
        repo, run_id = authenticate_request(
            event, get("pgextwin/build", f"issues/comments/{cid}"),
            get("pgextwin/build", f"actions/runs/{env['GITHUB_RUN_ID']}"),
            get("pgextwin/build", "branches/main"), env)
        scratch = Path(env["RUNNER_TEMP"]).resolve()
        need(scratch.is_dir() and not scratch.is_symlink(), "untrusted scratch")
        result = admit(repo, run_id, scratch=scratch,
                       fleet=json.loads(Path(a.fleet).read_text("utf-8"),
                                        object_pairs_hook=unique),
                       lifecycle=json.loads(Path(a.lifecycle).read_text("utf-8"),
                                            object_pairs_hook=unique))
        dest = Path(a.output).resolve()
        need(dest.parent == scratch and not dest.is_symlink(),
             "proof output outside dedicated scratch")
        dest.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", "utf-8")
        print(result["status"] + "; real Sigstore verified; PUBLISH_DENY")
        return 0
    except (Denied, audit.Denied, ident.Denied, OSError, KeyError, ValueError,
            TypeError, UnicodeDecodeError, subprocess.TimeoutExpired) as exc:
        print("OWNER_PUBLISHER_ADMISSION_DENY (" + type(exc).__name__ +
              "); no token, Release or authorization", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
