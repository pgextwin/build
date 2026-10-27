#!/usr/bin/env python3
"""Issue #75: genuine local schedule -> bounded merged-bot SIGNING INTENT only.

This gate is deliberately NOT a signature, Publisher source, authorization,
or formal Release. It repeats PR #304's complete authenticated live origin
verification before any separate OIDC Windows build can be scheduled.
"""
from __future__ import annotations
from datetime import datetime, timezone
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "merged_original_provenance", ROOT / "scripts/verify-merged-candidate-requalification.py")
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)
WATCH = ".github/workflows/update-watch.yml"
CENTRAL_WORKFLOW = "fleet-upstream-watch.yml"
STATUS = "AUTHENTIC_LOCAL_SCHEDULE_MERGED_BOT_SIGNING_INTENT_ONLY"

class Denied(ValueError):
    pass

def need(ok, explanation):
    if not ok:
        raise Denied(explanation)

def verify_local_runtime(run, branch, *, repo, sha, run_id, attempt, event, ref):
    """Fail closed before acquiring a signing-capable job; no synthetic schedule."""
    need(repo in {r["repository"] for r in json.loads(
        (ROOT / "metadata/merged-candidate-requalification.json").read_text("utf-8"))["entries"]},
        "repository not in explicitly pinned four-candidate registry")
    need(event == "schedule" and ref == "refs/heads/main" and attempt == 1,
        "local event must be original first-attempt schedule on main")
    need(type(sha) is str and origin.SHA.fullmatch(sha) and type(run_id) is int
         and run_id > 0, "invalid current local source identity")
    need(type(run) is dict and run.get("id") == run_id
         and run.get("run_attempt") == 1 and run.get("event") == "schedule"
         and run.get("path") == WATCH and run.get("head_branch") == "main"
         and run.get("head_sha") == sha
         and (run.get("repository") or {}).get("full_name") == repo
         and run.get("status") in ("in_progress", "completed")
         and run.get("conclusion") in (None, "success"),
         "live GitHub does not authenticate this exact local schedule")
    need(branch.get("name") == "main" and branch.get("protected") is True
         and (branch.get("commit") or {}).get("sha") == sha
         and any(x.get("context") == "Windows required summary" and
                 x.get("app_id") == 15368 for x in
                 (((branch.get("protection") or {}).get("required_status_checks") or {})
                  .get("checks") or [])),
         "local main or App15368 required check not protected")

def get_latest_central_schedule():
    """Latest original schedule only; no fallback to a conveniently green run."""
    need(bool(os.environ.get("GH_TOKEN")), "authenticated read-only GET required")
    endpoint = ("repos/pgextwin/build/actions/workflows/" + CENTRAL_WORKFLOW +
                "/runs?event=schedule&branch=main&per_page=5")
    p = subprocess.run(["gh", "api", "--method", "GET", endpoint],
                       capture_output=True, text=True, check=False, timeout=60)
    need(p.returncode == 0 and 0 < len(p.stdout) < 3_000_000,
         "central schedule inventory GET failure")
    response = json.loads(p.stdout)
    runs = response.get("workflow_runs")
    need(type(runs) is list and len(runs) > 0, "central schedule inventory empty")
    run = runs[0]
    need(run.get("event") == "schedule" and run.get("run_attempt") == 1
         and run.get("status") == "completed" and run.get("conclusion") == "success",
         "newest original central schedule is not successful")
    return origin.github("pgextwin/build", "actions/runs/" + str(run["id"]))

def download_original_scan(run_id, path):
    need(type(run_id) is int and run_id > 0, "invalid central Run")
    p = subprocess.run(["gh", "run", "download", str(run_id),
                        "--repo", "pgextwin/build", "--name", "fleet-upstream-watch",
                        "--dir", str(path)], capture_output=True, text=True,
                       check=False, timeout=180)
    need(p.returncode == 0, "original fleet scan download failed")
    receipt = path / "fleet-upstream-watch.json"
    need(receipt.is_file() and not receipt.is_symlink()
         and 0 < receipt.stat().st_size < 1_000_000,
         "missing, linked or oversized original central scan")
    return json.loads(receipt.read_text("utf-8"))

def bound_intent(*, repo, current, central, scan_run, scan, fleet, registry, local_run,
                 now):
    """Return strictly nonpublishing metadata after independent live GET joins."""
    by_repo = origin.validate_schedule(scan_run, central, scan, fleet,
                                       scan_run["id"], now)
    entries = [r for r in registry["entries"] if r.get("repository") == repo]
    need(len(entries) == 1 and repo in by_repo and
         by_repo[repo].get("status") == "up-to-date" and
         by_repo[repo].get("mainSha") == current["commit"]["sha"],
         "missing exactly one current untouched merged candidate")
    row = entries[0]
    n, head, merge, native_run = (row["pr"], row["candidateHead"],
                                   row["mergeSha"], row["nativeRun"])
    proof = origin.validate_merged(row, current=current,
        pr=origin.github(repo, "pulls/" + str(n)),
        changed=origin.github(repo, "pulls/" + str(n) + "/files?per_page=100"),
        associated=origin.github(repo, "commits/" + head + "/pulls?per_page=100"),
        compare=origin.github(repo, "compare/" + merge + "...main"),
        candidate_contents=origin.github(repo, "contents/config/extension.json?ref=" + head),
        main_contents=origin.github(repo, "contents/config/extension.json?ref=" + current["commit"]["sha"]),
        native_run=origin.github(repo, "actions/runs/" + str(native_run)),
        checks=origin.github(repo, "commits/" + head + "/check-runs?per_page=100"))
    need(proof["status"] == origin.SOURCE_KIND
         and proof["verifiedOriginalNativeCi"] is True
         and proof["publicationAuthorized"] is False
         and proof["publisherSourceKindAuthorized"] is False,
         "historical provenance must remain read-only")
    return {"schemaVersion": 1, "status": STATUS, "sourceKind":
        "MERGED_BOT_SCHEDULED_REQUALIFICATION_BUILD_ONLY",
        "repository": repo, "currentProtectedMain": current["commit"]["sha"],
        "localScheduleRun": local_run["id"], "localScheduleAttempt": 1,
        "originalFleetScheduleRun": scan_run["id"],
        "originalFleetScheduleSha": central["commit"]["sha"],
        "originalCandidatePr": n, "originalCandidateHead": head,
        "originalCandidateMerge": merge, "originalNativeWindowsRun": native_run,
        "originalRequiredCheck": proof["requiredCheckRun"],
        "manifestBlob": proof["manifestBlob"], "upstream": proof["upstream"],
        "newOIDCSigningRun": None, "independentSigstoreAudits": 0,
        "signedArtifactsVerified": False, "publisherSourceKindAuthorized": False,
        "publicationAuthorized": False}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    p.add_argument("--github-output")
    args = p.parse_args()
    try:
        repo, sha = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"]
        run_id, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
        current = origin.github(repo, "branches/main")
        local_run = origin.github(repo, "actions/runs/" + str(run_id))
        verify_local_runtime(local_run, current, repo=repo, sha=sha,
                             run_id=run_id, attempt=attempt,
                             event=os.environ.get("GITHUB_EVENT_NAME"),
                             ref=os.environ.get("GITHUB_REF"))
        central = origin.github("pgextwin/build", "branches/main")
        scan_run = get_latest_central_schedule()
        with TemporaryDirectory(prefix="pgextwin-scheduled-intent-") as temp:
            scan = download_original_scan(scan_run["id"], Path(temp))
        fleet = json.loads((ROOT / "metadata/automation-fleet.json").read_text("utf-8"))
        registry = json.loads((ROOT / "metadata/merged-candidate-requalification.json").read_text("utf-8"))
        need(registry.get("schemaVersion") == 1 and
             registry.get("publication") == "DENY", "registry policy drift")
        result = bound_intent(repo=repo, current=current, central=central,
                              scan_run=scan_run, scan=scan, fleet=fleet,
                              registry=registry, local_run=local_run,
                              now=datetime.now(timezone.utc))
        need(origin.github(repo, "branches/main") == current and
             origin.github("pgextwin/build", "branches/main") == central,
             "main source moved while proving signing intent")
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n", "utf-8")
        if args.github_output:
            with open(args.github_output, "a", encoding="utf-8") as f:
                f.write("verified=true\n")
        print("MERGED_SCHEDULE_SIGNING_INTENT_ONLY; NEW_OIDC_REQUIRED; PUBLISH_DENY")
        return 0
    except (Denied, origin.Denied, ValueError, TypeError, KeyError, OSError,
            subprocess.TimeoutExpired) as exc:
        print("MERGED_SCHEDULE_SIGNING_INTENT_DENY: " + str(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
