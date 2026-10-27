#!/usr/bin/env python3
"""Issue #75: authenticate merged bot candidate for a NEW scheduled signing lane.

This is deliberately READ ONLY and NONPUBLISHING. It reuses the original
candidate PR/Windows check without pretending intervening main repairs produced
a new signed main/push. Separate genuine OIDC signing and two real-byte audits
must be designed and accepted before Publisher can consume any new source kind.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
BRANCH = re.compile(r"^auto-candidate/[0-9a-f]{20}$")
CENTRAL = "pgextwin/build"
WATCH = ".github/workflows/fleet-upstream-watch.yml"
SOURCE_KIND = "MERGED_BOT_PR_REQUALIFICATION_NONPUBLISHING"
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

check_gate = module("merged_requalification_native_check", "native-required-check.py")
contents = module("merged_requalification_contents", "github_contents.py")

class Denied(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Denied(reason)

def positive(value):
    return type(value) is int and value > 0

def github(repo, endpoint):
    require(type(repo) is str and REPO.fullmatch(repo), "nonfleet repo")
    allow = (
        endpoint == "branches/main"
        or re.fullmatch(r"pulls/[1-9][0-9]*", endpoint)
        or re.fullmatch(r"pulls/[1-9][0-9]*/files\?per_page=100", endpoint)
        or re.fullmatch(r"commits/[0-9a-f]{40}/pulls\?per_page=100", endpoint)
        or re.fullmatch(r"compare/[0-9a-f]{40}\.\.\.main", endpoint)
        or re.fullmatch(r"contents/config/extension\.json\?ref=[0-9a-f]{40}", endpoint)
        or re.fullmatch(r"actions/runs/[1-9][0-9]*", endpoint)
        or re.fullmatch(r"commits/[0-9a-f]{40}/check-runs\?per_page=100", endpoint))
    require(allow, "GET endpoint not allowlisted")
    require(bool(os.environ.get("GH_TOKEN")), "read-only GH_TOKEN missing")
    process = subprocess.run(["gh", "api", "--method", "GET",
        "repos/" + repo + "/" + endpoint], capture_output=True,
        text=True, check=False, timeout=50)
    require(process.returncode == 0 and 0 < len(process.stdout) < 3_000_000,
            "authenticated GET unavailable")
    def unique(pairs):
        out = {}
        for k, v in pairs:
            require(k not in out, "duplicate JSON key")
            out[k] = v
        return out
    return json.loads(process.stdout, object_pairs_hook=unique)

def validate_schedule(run, central, snapshot, fleet, run_id, now):
    """Require the ORIGINAL current-main schedule and same-run complete scan."""
    require(type(run) is dict and run.get("id") == run_id
        and positive(run_id) and run.get("event") == "schedule"
        and run.get("path") == WATCH and run.get("head_branch") == "main"
        and run.get("run_attempt") == 1
        and (run.get("repository") or {}).get("full_name") == CENTRAL
        and run.get("head_sha") == (central.get("commit") or {}).get("sha")
        and run.get("status") in ("in_progress", "completed")
        and run.get("conclusion") in (None, "success"),
        "no completed genuine central fleet scan at exact protected main")
    # Whole-run completion is impossible inside its own dependency job.
    # We validate its ORIGINAL in-progress schedule without altering run bytes;
    # the same-run full snapshot comes from succeeded readonly-fleet.
    require(central.get("protected") is True
        and type(snapshot) is dict
        and snapshot.get("schemaVersion") == 1
        and snapshot.get("scope") == "STABLE_UPSTREAM_GET_ONLY"
        and snapshot.get("publication") == "DENY"
        and snapshot.get("candidatePrCreated") is False
        and snapshot.get("indeterminate") == 0
        and type(fleet) is dict and type(fleet.get("entries")) is list
        and snapshot.get("fleetSize") == len(fleet["entries"]),
        "invalid same-run complete protected fleet scan")
    names = [x.get("repository") for x in fleet["entries"] if type(x) is dict]
    entries = snapshot.get("extensions")
    require(len(names) == len(fleet["entries"]) and len(names) == len(set(names))
        and type(entries) is list and len(entries) == len(names)
        and {e.get("repository") for e in entries if type(e) is dict} == set(names)
        and all(e.get("status") in ("up-to-date", "update-available")
                for e in entries if type(e) is dict),
        "fleet scan identity or status incomplete")
    for name in names:
        require(type(name) is str and REPO.fullmatch(name), "bad fleet member")
    def when(v):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            raise Denied("invalid scheduled timestamp") from None
    start = when(run.get("created_at"))
    generated = when(snapshot.get("generatedAt"))
    require(start <= generated + timedelta(minutes=5)
        and generated <= now + timedelta(minutes=5)
        and now - generated < timedelta(hours=3),
        "stale or pre-schedule scan")
    return {e["repository"]:e for e in entries}

def validate_merged(entry, *, current, pr, changed, associated, compare,
                    candidate_contents, main_contents, native_run, checks):
    """No CI, source, or merge-state shortcut converts a historical PR to signing."""
    repo = entry.get("repository")
    head = entry.get("candidateHead")
    merge = entry.get("mergeSha")
    n = entry.get("pr")
    run_id = entry.get("nativeRun")
    blob = entry.get("manifestBlob")
    require(type(repo) is str and REPO.fullmatch(repo)
        and type(head) is str and SHA.fullmatch(head)
        and type(merge) is str and SHA.fullmatch(merge)
        and type(blob) is str and SHA.fullmatch(blob)
        and positive(n) and positive(run_id),
        "malformed pinned original PR descriptor")
    main_sha = (current.get("commit") or {}).get("sha")
    required = (((current.get("protection") or {}).get("required_status_checks") or {})
                .get("checks") or [])
    require(current.get("name") == "main" and current.get("protected") is True
        and type(main_sha) is str and SHA.fullmatch(main_sha)
        and any(x.get("context") == "Windows required summary" and x.get("app_id") == 15368
                for x in required if type(x) is dict),
        "current branch or App15368 required check unprotected")
    branch = (pr.get("head") or {}).get("ref")
    require(pr.get("number") == n and pr.get("state") == "closed"
        and pr.get("merged") is True and pr.get("draft") is False
        and pr.get("merge_commit_sha") == merge and pr.get("merged_at")
        and (pr.get("user") or {}).get("login") == "github-actions[bot]"
        and (pr.get("base") or {}).get("ref") == "main"
        and (pr.get("base") or {}).get("repo",{}).get("full_name") == repo
        and (pr.get("head") or {}).get("repo",{}).get("full_name") == repo
        and (pr.get("head") or {}).get("sha") == head
        and type(branch) is str and BRANCH.fullmatch(branch)
        and "<!-- pgextwin-candidate:v1:" + branch.split("/")[1] + " -->" in (pr.get("body") or ""),
        "original merged bot PR identity not authenticated")
    require(type(changed) is list and len(changed) == 1
        and changed[0].get("filename") == "config/extension.json"
        and changed[0].get("status") == "modified"
        and changed[0].get("sha") == blob,
        "original bot PR changed another path or manifest hash")
    require(type(associated) is list and len(associated) == 1
        and associated[0].get("number") == n
        and (associated[0].get("head") or {}).get("sha") == head,
        "HEAD is not independently bound to unique merged PR")
    require(type(compare) is dict and compare.get("status") in ("ahead", "identical")
        and (compare.get("merge_base_commit") or {}).get("sha") == merge
        and type(compare.get("ahead_by")) is int
        and compare["ahead_by"] >= 0,
        "original candidate merge no longer an ancestor of protected main")
    require(type(candidate_contents) is dict and type(main_contents) is dict
        and candidate_contents.get("sha") == blob
        and main_contents.get("sha") == blob,
        "candidate manifest not byte-identical to current protected main")
    manifest = contents.decode_json_file(main_contents, "config/extension.json")
    original = contents.decode_json_file(candidate_contents, "config/extension.json")
    require(manifest == original and manifest.get("name") == repo.split("/")[1]
        and manifest.get("schemaVersion") == 1
        and (manifest.get("windows") or {}).get("architecture") == "x64",
        "source manifest identity and Windows target diverged")
    upstream = manifest.get("upstream") or {}
    require(type(upstream) is dict and bool(upstream)
        and (("commit" in upstream and type(upstream.get("commit")) is str
              and SHA.fullmatch(upstream["commit"])
              and bool(upstream.get("version")))
             or ("perPostgresql" in upstream and
                 type(upstream["perPostgresql"]) is dict and bool(upstream["perPostgresql"]) and
                 all(type(x) is dict and SHA.fullmatch(str(x.get("commit","")))
                     and bool(x.get("version"))
                     for x in upstream["perPostgresql"].values()))),
        "stable upstream SHA/version incomplete")
    require(type(native_run) is dict and native_run.get("id") == run_id
        and native_run.get("run_attempt") == 1
        and native_run.get("head_branch") == branch,
        "original native CI identity or first attempt invalid")
    try:
        proof = check_gate.verify(native_run, checks, repository=repo, head=head)
    except check_gate.Denied as exc:
        raise Denied("original App15368 native Windows CI denied: " + str(exc)) from exc
    return {"repository":repo, "originalPr":n, "originalHead":head,
        "mergedAncestor":merge, "currentProtectedMain":main_sha,
        "manifestBlob":blob, "originalNativeWindowsRun":run_id,
        "requiredCheckRun":proof["checkRunId"], "upstream":upstream,
        "status":SOURCE_KIND, "verifiedOriginalNativeCi":True,
        "originalNativeZipBytesRehashed":False,
        "newOIDCSigningRun":None, "independentSigstoreAudits":0,
        "publicationAuthorized":False, "publisherSourceKindAuthorized":False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True)
    parser.add_argument("--fleet", required=True)
    parser.add_argument("--scan", required=True)
    parser.add_argument("--output", required=True)
    opts = parser.parse_args()
    try:
        require(os.environ.get("GITHUB_REPOSITORY") == CENTRAL
            and os.environ.get("GITHUB_EVENT_NAME") == "schedule"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
            "genuine protected main schedule required")
        central = github(CENTRAL, "branches/main")
        require((central.get("commit") or {}).get("sha") == os.environ.get("GITHUB_SHA"),
                "central protected main drift")
        # This job starts AFTER readonly-fleet, not after whole-run completion;
        # require same-run snapshot and running status, never dispatch/push.
        run_id = int(os.environ["GITHUB_RUN_ID"])
        run = github(CENTRAL, "actions/runs/"+str(run_id))
        require(run.get("id") == run_id and run.get("event") == "schedule"
            and run.get("path") == WATCH and run.get("head_branch") == "main"
            and run.get("head_sha") == os.environ["GITHUB_SHA"]
            and run.get("run_attempt") == 1
            and run.get("status") in ("in_progress", "completed")
            and run.get("conclusion") in (None, "success"),
            "not original current genuine scheduled central run")
        fleet = json.loads(Path(opts.fleet).read_text("utf-8"))
        scan = json.loads(Path(opts.scan).read_text("utf-8"))
        # Preserve the actual in-progress/completed original Run identity.
        by_repo = validate_schedule(run, central, scan, fleet, run_id,
                                    datetime.now(timezone.utc))
        registry = json.loads(Path(opts.registry).read_text("utf-8"))
        require(registry.get("schemaVersion") == 1
            and type(registry.get("entries")) is list
            and 0 < len(registry["entries"]) <= len(fleet["entries"]),
            "invalid bounded explicit requalification registry")
        enabled = {x["repository"] for x in fleet["entries"]
                   if x.get("mode") == "BUILD" and x.get("candidateEnabled") is True}
        seen = set()
        outputs = []
        for row in registry["entries"]:
            repo = row.get("repository")
            require(repo in enabled and repo in by_repo and repo not in seen,
                    "duplicate or unregistered requalification target")
            seen.add(repo)
            before = github(repo,"branches/main")
            require((before.get("commit") or {}).get("sha") == by_repo[repo].get("mainSha"),
                    "central scan target main drift")
            n, head, merge, run_native = (row["pr"], row["candidateHead"],
                                          row["mergeSha"], row["nativeRun"])
            result = validate_merged(row,
                current=before,
                pr=github(repo,"pulls/"+str(n)),
                changed=github(repo,"pulls/"+str(n)+"/files?per_page=100"),
                associated=github(repo,"commits/"+head+"/pulls?per_page=100"),
                compare=github(repo,"compare/"+merge+"...main"),
                candidate_contents=github(repo,"contents/config/extension.json?ref="+head),
                main_contents=github(repo,"contents/config/extension.json?ref="+by_repo[repo]["mainSha"]),
                native_run=github(repo,"actions/runs/"+str(run_native)),
                checks=github(repo,"commits/"+head+"/check-runs?per_page=100"))
            after = github(repo,"branches/main")
            require(after == before,"target branch drift during requalification")
            outputs.append(result)
        require(github(CENTRAL,"branches/main") == central,
                "central main drift during audit")
        payload = {"schemaVersion":1, "sourceKind":SOURCE_KIND,
            "centralScheduleRun":run_id, "centralScheduleSha":os.environ["GITHUB_SHA"],
            "status":"NONPUBLISHING_REQUALIFICATION_ONLY",
            "entries":outputs, "signedArtifactsVerified":False,
            "publisherWriteAuthorized":False, "publicationAuthorized":False}
        Path(opts.output).write_text(json.dumps(payload,ensure_ascii=False,indent=2)+"\n",
                                    encoding="utf-8")
        print("MERGED_REQUALIFICATION_PROVENANCE_ONLY="+str(len(outputs))+
              "; NEW_OIDC_SIGNING_REQUIRED; REAL_BYTES_REQUIRED; PUBLISH_DENY")
        return 0
    except (Denied,ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired) as exc:
        print("MERGED_REQUALIFICATION_DENY: "+str(exc),file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
