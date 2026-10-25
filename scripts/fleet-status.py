#!/usr/bin/env python3
"""Read-only operational snapshot for the configured protected extension fleet."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import quote
from update_watch_lib import WatchError, github_get_json
from importlib.util import spec_from_file_location,module_from_spec

BASE="https://api.github.com/repos/"
MARKER="<!-- pgextwin-update-watch:v1:upstream:"
def request(url):
    return github_get_json(url,os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))

def most_recent(payload, key):
    if not isinstance(payload,dict) or not isinstance(payload.get(key),list):
        raise WatchError("unexpected GitHub API response for "+key)
    return payload[key]

def scheduled_watch_state(runs):
    """Observe only the true scheduled update scan, never an unrelated event.

    The update-watch workflow also receives workflow_run from Windows CI.
    GitHub legitimately marks those unrelated invocations skipped. Treating
    the latest skipped workflow_run as a failed daily scan created false
    INVESTIGATE_EVIDENCE work across otherwise healthy extensions.

    This is observational ONLY: even a successful schedule is historical
    and never proves current protected-main / source SHA authorization.
    """
    if type(runs) is not list or not all(type(r) is dict for r in runs):
        raise WatchError("malformed scheduled watch run list")
    if any(r.get("event") != "schedule" for r in runs):
        raise WatchError("non-scheduled run in filtered watch response")
    if not runs:
        return None, "UNKNOWN"
    run = runs[0]  # GitHub runs API newest-first, filtered event=schedule
    if run.get("status") == "completed":
        return run, ("SUCCESS" if run.get("conclusion") == "success" else "FAILED")
    if run.get("status") in ("queued", "in_progress", "pending", "waiting", "requested"):
        return run, "RUNNING"
    raise WatchError("unexpected original scheduled watch run status")


def current_main_schedule_state(run, watch_status, branch):
    """Observe an original successful schedule on *today's protected main*.

    A historic SUCCESS after subsequent source changes is not evidence of a
    post-repair schedule. This pure GET-only check neither verifies candidate
    creation nor grants Release authorization.
    """
    sha = (branch.get("commit") or {}).get("sha") if type(branch) is dict else None
    if (type(branch) is not dict or branch.get("protected") is not True
            or type(sha) is not str or re.fullmatch(r"[0-9a-f]{40}", sha) is None):
        raise WatchError("protected current main SHA unavailable")
    if run is None:
        return "NOT_YET_OBSERVED", sha
    if (type(run) is not dict or run.get("event") != "schedule"
            or run.get("head_branch") != "main"):
        raise WatchError("latest watch is not a genuine main/schedule event")
    if run.get("head_sha") != sha:
        return "PREVIOUS_MAIN_ONLY", sha
    if run.get("run_attempt") != 1:
        return "UNVERIFIED_ATTEMPT", sha
    if watch_status == "SUCCESS" and run.get("status") == "completed":
        return "CURRENT_MAIN_SCHEDULE_SUCCESS", sha
    if watch_status == "RUNNING":
        return "CURRENT_MAIN_SCHEDULE_RUNNING", sha
    if watch_status == "FAILED":
        return "CURRENT_MAIN_SCHEDULE_FAILED", sha
    return "INDETERMINATE", sha


def compact_run(run):
    if not run:
        return None
    return {"runId":run.get("id"),"url":run.get("html_url"),"startedAt":run.get("run_started_at") or run.get("created_at"),
            "updatedAt":run.get("updated_at"),"status":run.get("status"),"conclusion":run.get("conclusion"),
            "event":run.get("event"),"branch":run.get("head_branch"),"headSha":run.get("head_sha"),"runAttempt":run.get("run_attempt")}

def fetch_audit(repo,run):
    artifacts=most_recent(request(BASE+repo+"/actions/runs/"+str(run["id"])+"/artifacts?per_page=100"),"artifacts")
    matches=[a for a in artifacts if a.get("name")=="candidate-audit" and not a.get("expired")]
    if len(matches)!=1:
        return None
    with tempfile.TemporaryDirectory() as temp:
        process=subprocess.run(["gh","run","download",str(run["id"]),"--repo",repo,"--name","candidate-audit",
                                "--dir",temp],text=True,capture_output=True)
        if process.returncode:
            raise WatchError("cannot fetch candidate-audit: "+process.stderr[:160])
        target=Path(temp)/"candidate-audit.json"
        if not target.is_file():
            raise WatchError("downloaded candidate audit JSON missing")
        data=json.loads(target.read_text(encoding="utf-8"))
    if (data.get("schemaVersion")!=1 or data.get("runId")!=run.get("id") or
        data.get("extension")!=repo.split("/")[-1] or data.get("status") not in {"VERIFIED","FAILED"}):
        raise WatchError("candidate audit has inconsistent identity")
    return data

def candidate_run_url(repo, branch, event):
    """Fetch only the active immutable candidate branch; never scan fleet-wide CI."""
    if (type(repo) is not str
            or re.fullmatch(r"pgextwin/[a-z][a-z0-9_]*", repo) is None
            or type(branch) is not str
            or re.fullmatch(r"auto-candidate/[0-9a-f]{20}", branch) is None
            or event not in ("pull_request", "workflow_dispatch")):
        raise WatchError("invalid scoped candidate Windows run query")
    return (BASE + repo + "/actions/workflows/windows.yml/runs?event=" + event
            + "&branch=" + quote(branch, safe="") + "&per_page=100")


def native_candidate_ci(page, pr, repo, event="pull_request"):
    """Observe exact active bot PR Windows CI; NEVER authorize merge or Release.

    Native pull_request CI does not necessarily include a legacy candidate-audit
    artifact. A green root run remains UNVERIFIED until separate exact-HEAD
    App15368 and signed-byte audits independently succeed.
    """
    if event not in ("pull_request", "workflow_dispatch"):
        raise WatchError("unknown original Windows candidate CI event")
    if type(page) is not dict or type(page.get("workflow_runs")) is not list:
        raise WatchError("native PR Windows CI page missing")
    runs = page["workflow_runs"]
    if (type(page.get("total_count")) is not int
            or page["total_count"] != len(runs) or len(runs) > 100):
        raise WatchError("native PR CI response paginated or incomplete")
    head = (pr.get("head") or {}) if type(pr) is dict else {}
    branch, sha = head.get("ref"), head.get("sha")
    if (type(pr) is not dict or (pr.get("user") or {}).get("login") != "github-actions[bot]"
            or (head.get("repo") or {}).get("full_name") != repo
            or type(branch) is not str
            or re.fullmatch(r"auto-candidate/[0-9a-f]{20}", branch) is None
            or type(sha) is not str or re.fullmatch(r"[0-9a-f]{40}", sha) is None):
        raise WatchError("active PR is not an authentic same-repository bot candidate")
    if not all(type(r) is dict and r.get("event") == event for r in runs):
        raise WatchError("unfiltered native PR run list")
    if any(r.get("head_branch") != branch for r in runs):
        raise WatchError("GitHub returned CI outside the requested candidate branch")
    if not runs:
        return None, "NOT_RUN"
    run = runs[0]
    if (run.get("path") != ".github/workflows/windows.yml"
            or run.get("name") != "Windows CI/CD"
            or (run.get("head_repository") or {}).get("full_name") != repo):
        raise WatchError("active native Windows CI identity mismatch")
    if run.get("head_sha") != sha:
        return run, "STALE_HEAD_CI"
    if type(run.get("run_attempt")) is not int or run["run_attempt"] != 1:
        raise WatchError("candidate PR CI attempt is not original")
    if run.get("status") in ("queued", "waiting", "pending", "in_progress", "requested"):
        return run, "RUNNING"
    if run.get("status") != "completed":
        raise WatchError("unknown native PR Windows status")
    if run.get("conclusion") == "success":
        return run, ("NATIVE_CI_SUCCESS_UNVERIFIED" if event == "pull_request"
                     else "DISPATCH_CI_SUCCESS_UNVERIFIED")
    return run, "FAILED_OR_UNVERIFIED"


def one(entry,lifecycle):
    repo=entry["repository"]
    row={"extension":repo.split("/")[-1],"repository":repo,"mode":entry["mode"],
         "scheduleUtc":entry["scheduleUtc"],"lastWatch":None,"watchResult":"UNKNOWN",
         "currentMainScheduleStatus":"INDETERMINATE","currentProtectedMainSha":None,
         "detectedCandidate":None,"candidatePrUrl":None,"lastWindowsCi":None,"candidateCiMode":"NONE",
         "lastCandidateStatus":"NOT_RUN","perMajor":[],"lastSuccessfulCandidate":None,
         "lastSuccessfulUpstreamShas":{},"errors":[]}
    original_schedule=None
    try:
        runs=most_recent(request(BASE+repo+
            "/actions/workflows/update-watch.yml/runs?event=schedule&per_page=10"),"workflow_runs")
        original_schedule, row["watchResult"]=scheduled_watch_state(runs)
        row["lastWatch"]=compact_run(original_schedule)
    except (WatchError,ValueError,KeyError,OSError) as e:
        row["errors"].append("watch: "+str(e))
    try:
        branch=request(BASE+repo+"/branches/main")
        row["currentMainScheduleStatus"],row["currentProtectedMainSha"] = (
            current_main_schedule_state(original_schedule, row["watchResult"], branch))
    except (WatchError,ValueError,KeyError,OSError,TypeError) as e:
        row["errors"].append("protected-main schedule: "+str(e))
    try:
        issues=request(BASE+repo+"/issues?state=open&per_page=100")
        if not isinstance(issues,list):
            raise WatchError("unexpected Issues payload")
        owned=[i for i in issues if isinstance(i,dict) and MARKER+row["extension"]+" -->" in (i.get("body") or "")]
        if len(owned)>1:
            raise WatchError("duplicate owned update Issues")
        if owned:
            i=owned[0]
            row["detectedCandidate"]={"url":i.get("html_url"),"title":i.get("title"),
                                      "updatedAt":i.get("updated_at"),
                                      "mayBeStale":True}  # Watch success alone does not prove an older Issue is a new update.
    except (WatchError,ValueError,KeyError,OSError) as e:
        row["errors"].append("upstream issue: "+str(e))
    owned_pr=None
    try:
        prs=request(BASE+repo+"/pulls?state=open&per_page=100")
        if not isinstance(prs,list):
            raise WatchError("unexpected PR payload")
        owned=[]
        for pr in prs:
            branch=(pr.get("head") or {}).get("ref") or ""
            m=re.fullmatch(r"auto-candidate/([0-9a-f]{20})",branch)
            if m and "<!-- pgextwin-candidate:v1:"+m.group(1)+" -->" in (pr.get("body") or ""):
                owned.append(pr)
        row["candidatePrUrl"]=owned[0].get("html_url") if len(owned)==1 else None
        owned_pr=owned[0] if len(owned)==1 else None
        if len(owned)>1:
            row["errors"].append("multiple active owned candidate PRs; inspect separately")
    except (WatchError,ValueError,KeyError,OSError) as e:
        row["errors"].append("candidate PR: "+str(e))
    try:
        if owned_pr is not None:
            # Active native pull_request CI ALWAYS takes precedence over stale
            # legacy workflow_dispatch runs. Do not assume green means audited.
            page=request(candidate_run_url(repo,owned_pr["head"]["ref"],"pull_request"))
            active_run,native_status=native_candidate_ci(page,owned_pr,repo)
            if active_run is not None:
                row["candidateCiMode"]="NATIVE_PULL_REQUEST"
                row["lastWindowsCi"]=compact_run(active_run)
                row["lastCandidateStatus"]=native_status
                return row
            # The existing GITHUB_TOKEN candidate proposer creates a Draft PR
            # and explicitly dispatches windows.yml: PR event suppression may
            # prevent ANY native pull_request Windows run. The exact branch
            # and HEAD of the active PR still MUST match; no old green dispatch.
            dispatched=request(candidate_run_url(repo,owned_pr["head"]["ref"],"workflow_dispatch"))
            run,status=native_candidate_ci(dispatched,owned_pr,repo,
                                           event="workflow_dispatch")
            row["candidateCiMode"]="ACTIVE_DISPATCH" if run is not None else "NONE"
            row["lastWindowsCi"]=compact_run(run)
            row["lastCandidateStatus"]=status
            return row

        # Legacy read-only telemetry retained if there is no active candidate.
        runs=most_recent(request(BASE+repo+"/actions/workflows/windows.yml/runs?event=workflow_dispatch&per_page=100"),"workflow_runs")
        row["candidateCiMode"]="LEGACY_DISPATCH"
        candidates=[r for r in runs if (r.get("head_branch") or "").startswith("auto-candidate/")]
        row["lastWindowsCi"]=compact_run(candidates[0]) if candidates else None
        if candidates:
            latest=candidates[0]
            row["lastCandidateStatus"]="RUNNING" if latest.get("status")!="completed" else "FAILED_OR_UNVERIFIED"
            audit=fetch_audit(repo,latest) if latest.get("status")=="completed" else None
            if audit:
                row["lastCandidateStatus"]=audit["status"] if latest.get("conclusion")=="success" else "FAILED"
                row["perMajor"]=audit.get("majors",[])
            for run in candidates:
                if run.get("conclusion")!="success":
                    continue
                older=fetch_audit(repo,run)
                if older and older.get("status")=="VERIFIED":
                    row["lastSuccessfulCandidate"]={"runId":run["id"],"url":run.get("html_url"),
                        "packagingCommit":older.get("branchSha")}
                    row["lastSuccessfulUpstreamShas"]={str(m["major"]):m["sourceSha"] for m in older["majors"]
                                                       if m.get("status")=="SUCCESS" and m.get("sourceSha")}
                    break
    except (WatchError,ValueError,KeyError,OSError) as e:
        row["errors"].append("candidate CI: "+str(e))
        row["lastCandidateStatus"]="INDETERMINATE"
    return row

def render(state):
    lines=["# pgextwin Fleet Automation Status","",
        "Generated "+state["generatedAt"]+"; centralized mode is live policy, GitHub runs are observed state.",
        "Status is **not** a claim of strict 09:00 execution. Unknown/stale data is not success.","",
        "## Manual candidate queue (not release approval)","",
        "A draft PR link means **manual inspection is required**, even if its latest CI is green.",
        "Never infer that a candidate is release-ready without checking the matching SHA, run, artifacts, audit and source diff.","",
        "Current-main schedule SUCCESS proves only an authentic completed first-attempt schedule on the current protected main, not an update, signature, or Release.","",
        "| Extension | Mode | Last watch | Current-main schedule | Update Issue | Candidate PR (manual queue) | Candidate CI | Last verified SHA |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for s in state["extensions"]:
        w=s["lastWatch"]
        watch=(w.get("conclusion") or w.get("status")) if w else "NOT_RUN"
        candidate=(s["detectedCandidate"] or {}).get("title") or "—"
        candidate_pr=s.get("candidatePrUrl")
        expected="https://github.com/"+s["repository"]+"/pull/"
        if candidate_pr and candidate_pr.startswith(expected) and candidate_pr[len(expected):].isdigit():
            queue="[Review candidate PR]("+candidate_pr+")"
        elif candidate_pr:
            queue="INDETERMINATE (unexpected PR URL)"
        else:
            queue="—"
        success=(s["lastSuccessfulCandidate"] or {}).get("packagingCommit") or "—"
        lines.append("| "+s["extension"]+" | "+s["mode"]+" | "+watch+" | "+s.get("currentMainScheduleStatus","INDETERMINATE")+" | "+candidate.replace("|","/")[:70]+
                     " | "+queue+" | "+s["lastCandidateStatus"]+" | "+success+" |")
    queue=state.get("hourlyChatQueue")
    if queue is not None:
        lines.extend(["", "## Hourly Chat task queue (nonpublishing)", "",
                      "This queue is observational; every PR or CI action needs fresh GitHub GET."])
        for task in queue["actions"]:
            lines.append("- "+task["repository"]+": "+task["action"]+
                         " — "+task["reason"])
        if not queue["actions"]:
            lines.append("- No pending nonpublishing action detected.")
        lines.append("Formal Release authorization: **DENY**. A schedule is never PUBLISH.")
    lines.extend(["","Latest run failures and missing artifacts remain visible even if an older candidate passed.",
                  "No item in this report authorizes merging a PR or publishing binaries.",
                  "Machine-readable state is attached to this Actions run. This status job never publishes binaries."])
    return "\n".join(lines)+"\n"

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--policy",required=True)
    p.add_argument("--lifecycle",required=True)
    p.add_argument("--json",required=True)
    p.add_argument("--markdown",required=True)
    args=p.parse_args()
    policy=json.loads(Path(args.policy).read_text())
    f=Path(__file__).with_name("fleet-control.py")
    spec=spec_from_file_location("fleet_control",f)
    module=module_from_spec(spec);spec.loader.exec_module(module)
    module.validate(policy)
    lifecycle=json.loads(Path(args.lifecycle).read_text())
    results=[one(entry,lifecycle) for entry in policy["entries"]]
    status={"schemaVersion":1,"generatedAt":datetime.now(timezone.utc).isoformat(),
            "policyRelease":policy["releasePolicy"],"extensions":results}
    task_spec=spec_from_file_location("hourly_chat_task", Path(__file__).with_name("chat-task-queue.py"))
    task_module=module_from_spec(task_spec)
    task_spec.loader.exec_module(task_module)
    status["hourlyChatQueue"]=task_module.plan(policy,status)
    Path(args.json).write_text(json.dumps(status,indent=2)+"\n")
    Path(args.markdown).write_text(render(status))
    errors=[s["extension"] for s in results if s["errors"]]
    if errors:
        print("WARN: indeterminate fleet rows: "+", ".join(errors))
    print(render(status))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
