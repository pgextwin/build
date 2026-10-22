#!/usr/bin/env python3
"""Read-only real-GitHub join of native candidate CI + exact audit artifact.

Issue #75: native ZIP/SPDX audits are already proven in Windows runners.
This tool independently fetches the immutable GitHub Run/PR/artifact identities,
the exact-head source manifest, and the audit's two actual JSON files.
No event handler, publisher, Release authorization, write, or auto-merge.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
s = importlib.util.spec_from_file_location("native_audit_binder", HERE / "bind-native-candidate-audit.py")
binder = importlib.util.module_from_spec(s)
s.loader.exec_module(binder)

REPO = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
SHA = re.compile(r"^[a-f0-9]{40}$")
NAME = "candidate-audit-native-pr"
JSON_FILES = frozenset({"native-pr-ci-context.json", "candidate-audit-native-pr.json"})


class Denied(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Denied(reason)


def identity(repo, pr, run, audit_run, artifact_id, fleet, *, current_repo, ref, event):
    require(type(repo) is str and REPO.fullmatch(repo)
            and repo == current_repo
            and ref == "refs/heads/main"
            and event in ("schedule", "workflow_dispatch", "workflow_run"),
            "main-only repository/event origin required")
    for n in (pr, run, audit_run, artifact_id):
        require(type(n) is int and n > 0, "invalid positive GitHub evidence identifier")
    require(type(fleet) is dict and fleet.get("schemaVersion") == 1
            and fleet.get("releasePolicy") == "manual-only"
            and type(fleet.get("entries")) is list and len(fleet["entries"]) == 17,
            "missing existing exact 17-member fleet policy")
    roster = [x.get("repository") for x in fleet["entries"] if type(x) is dict]
    require(len(roster) == 17 and len(set(roster)) == 17
            and all(type(n) is str and REPO.fullmatch(n) for n in roster)
            and repo in roster, "not a known 17-fleet repository")
    return True


def validate_live(*, repo, pr_number, ci_id, audit_id, artifact_id,
                  pr, files, ci_run, audit_run, artifact_list, main, manifest):
    """Safely join separately fetched authentic GitHub REST snapshots.

    A passing result is exclusively a candidate audit observation and never
    becomes an automatic Release/PUBLISH receipt.
    """
    require(type(pr) is dict and pr.get("number") == pr_number
            and pr.get("state") == "open" and pr.get("merged") is False
            and (pr.get("head") or {}).get("repo", {}).get("full_name") == repo
            and (pr.get("base") or {}).get("repo", {}).get("full_name") == repo
            and (pr.get("base") or {}).get("ref") == "main"
            and (pr.get("user") or {}).get("login") == "github-actions[bot]"
            and type(files) is list and len(files) == 1
            and files[0].get("filename") == "config/extension.json"
            and files[0].get("status") == "modified",
            "current bot-owned PR is missing, merged, or no longer manifest-only")
    head = (pr.get("head") or {}).get("sha")
    require(type(head) is str and SHA.fullmatch(head)
            and type(manifest) is dict and manifest.get("encoding") == "base64"
            and manifest.get("path") == "config/extension.json"
            and manifest.get("sha") == files[0].get("sha")
            and type(manifest.get("content")) is str,
            "exact immutable candidate HEAD manifest blob not authenticated")
    require(type(main) is dict and main.get("name") == "main"
            and main.get("protected") is True
            and type((main.get("commit") or {}).get("sha")) is str
            and SHA.fullmatch(main["commit"]["sha"]),
            "no authoritative protected current main")
    main_sha = main["commit"]["sha"]
    require(type(ci_run) is dict and ci_run.get("id") == ci_id
            and ci_run.get("head_sha") == head
            and ci_run.get("event") == "pull_request"
            and ci_run.get("status") == "completed"
            and ci_run.get("conclusion") == "success",
            "original native candidate CI not exactly successful")
    require(type(audit_run) is dict and audit_run.get("id") == audit_id
            and audit_run.get("head_sha") == main_sha
            and audit_run.get("event") == "workflow_run"
            and audit_run.get("status") == "completed"
            and audit_run.get("conclusion") == "success",
            "current protected main and independent audit run differ")
    require(type(artifact_list) is dict
            and type(artifact_list.get("total_count")) is int
            and 0 <= artifact_list["total_count"] < 100
            and type(artifact_list.get("artifacts")) is list
            and len(artifact_list["artifacts"]) == artifact_list["total_count"],
            "incomplete/ambiguous audit artifact inventory")
    eligible = [a for a in artifact_list["artifacts"]
                if type(a) is dict and a.get("name") == NAME]
    require(len(eligible) == 1 and eligible[0].get("id") == artifact_id,
            "native candidate audit artifact ID or uniqueness mismatch")
    try:
        candidate_manifest = json.loads(base64.b64decode(manifest["content"], validate=False))
    except (ValueError, TypeError) as e:
        raise Denied("invalid actual candidate source manifest") from e
    require(type(candidate_manifest) is dict and candidate_manifest.get("name") == repo.split("/")[1],
            "wrong candidate extension manifest")
    return main_sha, candidate_manifest, eligible[0]


def strictly_read_audit(path):
    require(type(path) is Path and path.is_dir(), "missing downloaded artifact directory")
    entries = list(path.iterdir())
    require(len(entries) == 2 and {p.name for p in entries} == JSON_FILES
            and all(p.is_file() and not p.is_symlink()
                    and p.resolve().parent == path.resolve()
                    and p.stat().st_size <= 128 * 1024 for p in entries),
            "unexpected candidate audit artifact content")
    try:
        return (json.loads((path / "native-pr-ci-context.json").read_text("utf-8")),
                json.loads((path / "candidate-audit-native-pr.json").read_text("utf-8")))
    except (ValueError, UnicodeError) as e:
        raise Denied("malformed authenticated candidate audit bytes") from e


def gh_json(endpoint):
    require(type(endpoint) is str and endpoint.startswith("repos/pgextwin/")
            and "\n" not in endpoint and "\r" not in endpoint,
            "non-allowlisted GitHub GET path")
    result = subprocess.run(["gh", "api", "--method", "GET", endpoint],
                            capture_output=True, text=True, check=False, timeout=45)
    require(result.returncode == 0 and len(result.stdout) <= 3 * 1024 * 1024,
            "authenticated GitHub GET refused/oversized")
    return json.loads(result.stdout)


def run(repo, pr_number, ci_id, audit_id, artifact_id, *, root):
    require(os.environ.get("GITHUB_REPOSITORY") == repo
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") in
            ("schedule", "workflow_dispatch", "workflow_run")
            and bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")),
            "nonprivileged trusted main-only GitHub Actions runtime required")
    fleet = json.loads((root / "metadata/automation-fleet.json").read_text("utf-8"))
    identity(repo, pr_number, ci_id, audit_id, artifact_id, fleet,
             current_repo=os.environ["GITHUB_REPOSITORY"],
             ref=os.environ["GITHUB_REF"], event=os.environ["GITHUB_EVENT_NAME"])
    p = "repos/" + repo + "/"
    pr = gh_json(p + "pulls/" + str(pr_number))
    head = (pr.get("head") or {}).get("sha")
    require(type(head) is str and SHA.fullmatch(head), "invalid candidate HEAD")
    snapshots = {
        "pr": pr,
        "files": gh_json(p + "pulls/" + str(pr_number) + "/files?per_page=100"),
        "ci_run": gh_json(p + "actions/runs/" + str(ci_id)),
        "audit_run": gh_json(p + "actions/runs/" + str(audit_id)),
        "artifact_list": gh_json(p + "actions/runs/" + str(audit_id) + "/artifacts?per_page=100"),
        "main": gh_json(p + "branches/main"),
        "manifest": gh_json(p + "contents/config/extension.json?ref=" + head),
    }
    main_sha, ext, artifact = validate_live(
        repo=repo, pr_number=pr_number, ci_id=ci_id, audit_id=audit_id,
        artifact_id=artifact_id, **snapshots)
    # Exact one artifact with this name and ID was independently fetched.
    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp)
        command = ["gh", "run", "download", str(audit_id),
                   "--repo", repo, "--name", NAME, "--dir", str(target)]
        process = subprocess.run(command, capture_output=True, text=True,
                                 check=False, timeout=90)
        require(process.returncode == 0, "exact GitHub audit artifact download failed")
        context, audit = strictly_read_audit(target)
    lifecycle = json.loads((root / "metadata/postgresql.json").read_text("utf-8"))
    try:
        outcome = binder.join(context=context, audit=audit, ext=ext,
                              lifecycle=lifecycle,
                              ci_run=snapshots["ci_run"],
                              audit_run=snapshots["audit_run"],
                              artifact=artifact, repository=repo,
                              current_main_sha=main_sha)
    except (binder.Denied, ValueError, TypeError, KeyError) as e:
        raise Denied("candidate binding rejected: " + str(e)) from e
    require(outcome["publicationAuthorized"] is False
            and outcome["publishableReceipt"] is False
            and outcome["signedArtifactsVerified"] is False,
            "bound candidate observations cannot authorize publishing")
    return outcome


def main():
    p = argparse.ArgumentParser()
    for k in ("candidate-pr", "ci-run-id", "audit-run-id", "artifact-id"):
        p.add_argument("--" + k, required=True, type=int)
    p.add_argument("--out", required=True)
    p.add_argument("--build-root", default=".")
    args = p.parse_args()
    try:
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        record = run(repo, args.candidate_pr, args.ci_run_id,
                     args.audit_run_id, args.artifact_id,
                     root=Path(args.build_root))
        Path(args.out).write_text(json.dumps(record, indent=2) + "\n", "utf-8")
        print("REAL_NATIVE_AUDIT_BOUND_NONPUBLISHING: " + record["status"])
        return 0
    except (Denied, OSError, TypeError, ValueError, KeyError,
            subprocess.TimeoutExpired) as e:
        print("REAL_NATIVE_AUDIT_DENY: " + str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
