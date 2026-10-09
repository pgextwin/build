#!/usr/bin/env python3
"""Step 21: refuse publication unless real immutable candidate evidence and human approval agree.

Runs only from a reviewed extension main workflow_dispatch. Never mutates GitHub.
The approval file is committed via a separate reviewed PR, NOT on a candidate branch.
"""
import argparse
import base64
from datetime import date
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SHA = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+)-windows\.([1-9][0-9]*)$")
BRANCH = re.compile(r"^auto-candidate/([0-9a-f]{20})$")
REPO = "pgextwin/plpgsql_check"
CENTRAL = "repos/pgextwin/build/contents/metadata/release-promotion.json?ref=main"

class Denied(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise Denied(message)

def command(*args):
    p = subprocess.run(args, text=True, capture_output=True, check=False)
    if p.returncode != 0:
        raise Denied("Command failed (closed): " + " ".join(args[:3]) + " " + p.stderr[:250])
    return p.stdout

def api(path):
    return json.loads(command("gh", "api", path))

def download(run, artifact, destination):
    command("gh", "run", "download", str(run), "--repo", REPO,
            "--name", artifact, "--dir", str(destination))
    path = destination / (artifact + ".json")
    require(path.is_file(), "missing " + artifact + " JSON")
    return json.loads(path.read_text(encoding="utf-8-sig"))

def verified_review(pr):
    reviews = api("repos/" + REPO + "/pulls/" + str(pr["number"]) + "/reviews?per_page=100")
    require(isinstance(reviews, list) and len(reviews) < 100, "review list inaccessible or truncated")
    latest = {}
    for review in reviews:
        name = (review.get("user") or {}).get("login", "")
        if name:
            latest[name] = review
    humans = [name for name, review in latest.items()
              if review.get("state") == "APPROVED" and review.get("commit_id") == pr["head"]["sha"]
              and name.lower() not in {"github-actions[bot]", "dependabot[bot]"}
              and (review.get("user") or {}).get("type") != "Bot"
              and name != pr["user"]["login"]]
    require(bool(humans), "no current human approval on merged PR head")
    return sorted(humans)

def merged_pr(number, main_sha, expected_path, only_file):
    require(type(number) is int and number > 0, "invalid PR number")
    pr = api("repos/" + REPO + "/pulls/" + str(number))
    require(pr.get("merged") is True and pr.get("state") == "closed"
            and pr.get("base", {}).get("ref") == "main"
            and pr.get("merged_at") and pr.get("merge_commit_sha"), "PR is not merged into main")
    require(pr.get("head", {}).get("sha") and SHA.fullmatch(pr["head"]["sha"]),
            "invalid PR head SHA")
    require(pr.get("merge_commit_sha") and SHA.fullmatch(pr["merge_commit_sha"]),
            "invalid PR merged SHA")
    # A squash/rebase merge is allowed, but its merge result must be in trusted main.
    command("git", "merge-base", "--is-ancestor", pr["merge_commit_sha"], main_sha)
    reviewers = verified_review(pr)
    files = api("repos/" + REPO + "/pulls/" + str(number) + "/files?per_page=100")
    require(isinstance(files, list) and 0 < len(files) < 100, "PR file listing truncated")
    names = {f.get("filename") for f in files}
    require(expected_path in names, "expected reviewed file missing")
    if only_file:
        require(names == {expected_path}, "automation PR changed files outside manifest")
    return pr, reviewers

def maintained(ext, lifecycle):
    require(lifecycle.get("schemaVersion") == 1, "invalid lifecycle")
    configured = {int(x) for x in ext["postgresql"]["majors"]}
    return sorted(int(x["major"]) for x in lifecycle["postgresql"]
                  if int(x["major"]) in configured and date.fromisoformat(x["eol"]) >= date.today())

def verify(policy, local, ext, lifecycle, approval, decision, audit, candidate_pr,
           approval_pr, candidate_run, decision_run, main_sha, release_tag):
    """Pure security policy evaluator. Inject immutable API and artifact snapshots in tests."""
    require(policy == {"schemaVersion": 1, "allowedRepositories": [REPO],
                       "releasePolicy": "manual-approval"}, "central promotion disabled")
    require(local == {"schemaVersion": 1, "enabled": True,
                      "releasePolicy": "manual-approval"}, "local promotion disabled")
    require(ext["name"] == "plpgsql_check" and ext["upstream"]["repository"] == "okbob/plpgsql_check",
            "unsupported extension")
    require(SHA.fullmatch(main_sha) is not None, "invalid trusted main SHA")
    m = TAG.fullmatch(release_tag)
    require(m and m.group(1) == ext["upstream"]["version"], "tag and manifest version mismatch")
    require(SHA.fullmatch(ext["upstream"].get("commit", "")) is not None, "upstream SHA not pinned")
    majors = maintained(ext, lifecycle)
    require(majors == [15, 16, 17, 18], "PG-major completeness/lifecycle gate failed")
    branch = candidate_pr["head"]["ref"]
    bm = BRANCH.fullmatch(branch)
    require(bm is not None, "candidate branch not automation-owned")
    marker = "<!-- pgextwin-candidate:v1:" + bm.group(1) + " -->"
    require(marker in (candidate_pr.get("body") or ""), "candidate PR ownership marker absent")
    require((candidate_pr.get("user") or {}).get("login") == "github-actions[bot]",
            "candidate PR not authored by automation")
    require(candidate_run["status"] == "completed" and candidate_run["conclusion"] == "success"
            and candidate_run["event"] == "workflow_dispatch"
            and candidate_run["head_branch"] == branch
            and candidate_run["head_sha"] == candidate_pr["head"]["sha"],
            "candidate Windows CI identity/status mismatch")
    require(decision_run["status"] == "completed" and decision_run["conclusion"] == "success"
            and decision_run["head_branch"] == "main", "decision watch run is not trusted")
    require(decision.get("schemaVersion") == 1 and decision.get("status") == "candidate"
            and decision.get("branch") == branch and decision.get("candidateId") == bm.group(1)
            and decision.get("extension") == ext["name"]
            and decision.get("repository") == ext["upstream"]["repository"]
            and decision.get("releasePolicy") == "manual-only", "candidate-decision identity mismatch")
    updates = decision.get("updates", [])
    require(len(updates) == 1 and updates[0]["major"] is None
            and updates[0]["commit"] == ext["upstream"]["commit"]
            and updates[0]["ref"] == ext["upstream"]["ref"]
            and updates[0]["version"] == ext["upstream"]["version"], "candidate update not identical to manifest")
    require(audit.get("schemaVersion") == 1 and audit.get("status") == "VERIFIED"
            and audit.get("matrixResult") == "success"
            and audit.get("extension") == ext["name"]
            and audit.get("runId") == candidate_run["id"]
            and audit.get("branch") == branch
            and audit.get("branchSha") == candidate_pr["head"]["sha"],
            "candidate-audit is not verified for this PR/run")
    items = audit.get("majors")
    require(isinstance(items, list) and len(items) == len(majors)
            and sorted(x.get("major") for x in items) == majors, "PG major artifact missing/duplicate")
    for item in items:
        require(item.get("status") == "SUCCESS" and
                item.get("sourceSha") == ext["upstream"]["commit"] and
                re.fullmatch(r"[a-f0-9]{64}", item.get("zipSha256", "")) is not None
                and item.get("zip") and item.get("sbom") and item.get("grype"),
                "unverified major or source SHA mismatch")
    require(approval == {
        "schemaVersion": 1, "status": "APPROVED",
        "candidatePr": candidate_pr["number"], "candidateRunId": candidate_run["id"],
        "decisionRunId": decision_run["id"], "candidateId": bm.group(1),
        "upstreamCommit": ext["upstream"]["commit"], "releaseTag": release_tag,
        "licenseReviewed": True, "windowsCompatibilityReviewed": True,
        "sourceChangesReviewed": True, "testContractReviewed": True,
        "requiredMajors": majors
    }, "reviewed machine-readable approval missing or inconsistent")
    require(approval_pr["number"] != candidate_pr["number"], "approval must be a separate reviewed PR")
    return {"schemaVersion": 1, "status": "VERIFIED_APPROVED", "extension": ext["name"],
            "repository": REPO, "trustedCommit": main_sha, "releaseTag": release_tag,
            "upstreamCommit": ext["upstream"]["commit"], "upstreamRef": ext["upstream"]["ref"],
            "version": ext["upstream"]["version"], "majors": majors,
            "candidatePr": candidate_pr["number"], "approvalPr": approval_pr["number"],
            "candidateRunId": candidate_run["id"], "decisionRunId": decision_run["id"],
            "candidateId": bm.group(1)}

def main():
    p = argparse.ArgumentParser()
    for key in ("candidate-pr", "candidate-run-id", "decision-run-id", "approval-pr"):
        p.add_argument("--" + key, type=int, required=True)
    for key in ("release-tag", "extension", "local-policy", "lifecycle", "output"):
        p.add_argument("--" + key, required=True)
    a = p.parse_args()
    try:
        require(os.environ.get("GITHUB_REPOSITORY") == REPO
                and os.environ.get("GITHUB_REF") == "refs/heads/main"
                and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
                "promotion must be manually dispatched from trusted main")
        main_sha = os.environ["GITHUB_SHA"]
        require(SHA.fullmatch(main_sha) is not None, "invalid main SHA")
        # Constrain to currently trusted main: no old or PR workflow revisions.
        current = api("repos/" + REPO + "/branches/main")
        require(current["commit"]["sha"] == main_sha, "main advanced; re-review promotion")
        raw = api(CENTRAL)
        require(raw.get("encoding") == "base64", "central policy is unavailable")
        policy = json.loads(base64.b64decode(raw["content"]).decode("utf-8"))
        local = json.loads(Path(a.local_policy).read_text(encoding="utf-8"))
        ext = json.loads(Path(a.extension).read_text(encoding="utf-8"))
        lifecycle = json.loads(Path(a.lifecycle).read_text(encoding="utf-8"))
        candidate, candidate_reviewers = merged_pr(a.candidate_pr, main_sha, "config/extension.json", True)
        run = api("repos/" + REPO + "/actions/runs/" + str(a.candidate_run_id))
        watch = api("repos/" + REPO + "/actions/runs/" + str(a.decision_run_id))
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            decision = download(a.decision_run_id, "candidate-decision", folder / "decision")
            audit = download(a.candidate_run_id, "candidate-audit", folder / "audit")
        branch = candidate["head"]["ref"]
        m = BRANCH.fullmatch(branch)
        require(m is not None, "candidate ID malformed")
        approval_path = "approvals/" + m.group(1) + ".json"
        approved_pr, approval_reviewers = merged_pr(a.approval_pr, main_sha, approval_path, True)
        approval = json.loads(Path(approval_path).read_text(encoding="utf-8"))
        receipt = verify(policy, local, ext, lifecycle, approval, decision, audit, candidate,
                         approved_pr, run, watch, main_sha, a.release_tag)
        receipt["candidateReviewers"] = candidate_reviewers
        receipt["approvalReviewers"] = approval_reviewers
        Path(a.output).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print("Promotion authorization VERIFIED_APPROVED; no publication performed by this gate.")
        return 0
    except (Denied, OSError, ValueError, KeyError, TypeError, IndexError) as e:
        print("PROMOTION DENIED (fail-closed): " + str(e), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
