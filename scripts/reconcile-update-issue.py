#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, subprocess, sys
from pathlib import Path
from update_watch_lib import WatchError, candidate_signature, decide_issue_action, safe_text

UPSTREAM_PREFIX = "<!-- pgextwin-update-watch:v1:upstream:"
POSTGRES_MARKER = "<!-- pgextwin-update-watch:v1:postgresql -->"


def run_gh(args: list[str], repo: str) -> str:
    env=dict(os.environ)
    env["GH_REPO"] = repo
    cp=subprocess.run(["gh", *args], text=True, capture_output=True, env=env, check=False)
    if cp.returncode != 0:
        raise WatchError(f"GitHub issue operation failed: {cp.stderr.strip()}")
    return cp.stdout


def marker_for(result: dict) -> str:
    if result.get("kind") == "postgresql": return POSTGRES_MARKER
    name=safe_text(result.get("extension"), 80)
    return f"{UPSTREAM_PREFIX}{name} -->"


def render_extension(result: dict, marker: str) -> tuple[str,str]:
    updates=result.get("updates", [])
    if len(updates)==1 and "postgresqlMajor" not in updates[0]:
        cand=updates[0]["candidate"]
        title=f"Upstream update available: {safe_text(result['extension'],80)} {safe_text(cand['version'],80)}"
    else:
        title=f"Upstream update available: {safe_text(result['extension'],80)}"
    lines=[marker, f"<!-- pgextwin-update-watch-candidate:{candidate_signature(result)} -->", "", "## Detected upstream update", "", f"- Extension: `{safe_text(result['extension'])}`", f"- Upstream repository: `{safe_text(result['repository'])}`", f"- Detection timestamp: `{safe_text(result['detectedAt'])}`", f"- Watcher revision: `{safe_text(result['watcher']['repository'])}@{safe_text(result['watcher']['sha'])}`", ""]
    for u in updates:
        majors = str(u.get("postgresqlMajor")) if "postgresqlMajor" in u else ", ".join(str(x) for x in u.get("postgresqlMajors", []))
        c=u["current"]; n=u["candidate"]
        lines += [f"### PostgreSQL {safe_text(majors)}", f"- Current configured ref/version: `{safe_text(c['ref'])}` / `{safe_text(c['version'])}`", f"- Candidate ref/version: `{safe_text(n['ref'])}` / `{safe_text(n['version'])}`", f"- Upstream Release/tag: {safe_text(n['url'],500)}", ""]
    lines += ["## Manual validation gate", "", "This issue is notification-only. Do **not** publish directly from this detection.", "", "- Review upstream release notes and compatibility changes.", "- Verify upstream license files/terms against the packaging repository contract.", "- Review Windows/MSVC compatibility and any extension-specific source adaptation.", "- Update the pinned source ref only after review, then run the maintained PostgreSQL matrix build.", "- Run the Test Contract functional validation for every affected PostgreSQL major.", "- Require the normal PACKAGE-INFO, SPDX SBOM, vulnerability-report, checksum, and attestation pipeline for an eventual release.", "- After a real pgextwin Release exists, update Catalog release metadata through the existing release/catalog process.", "- Website data is derived from Catalog; do not hand-edit Website availability for this detection.", "", "No branch, PR, source-ref update, build, Release, Catalog change, or Website change was created by this watcher."]
    return title, "\n".join(lines)+"\n"


def render_postgresql(result: dict, marker: str) -> tuple[str,str]:
    pg19 = any(int(x.get("major",0))==19 for x in result.get("newMajors", []))
    title = "PostgreSQL 19 GA detected — review production onboarding gate" if pg19 else "PostgreSQL release/lifecycle metadata update detected"
    lines=[marker, f"<!-- pgextwin-update-watch-candidate:{candidate_signature(result)} -->", "", "## PostgreSQL official metadata drift", "", f"- Detection timestamp: `{safe_text(result['detectedAt'])}`", f"- Official source: {safe_text(result['sources']['versioning'],500)}", "- Windows package availability: **requires manual verification**", ""]
    for d in result.get("drift", []):
        lines += [f"### PostgreSQL {d['major']}", f"- Current metadata: minor `{safe_text(d.get('currentMinor'))}`, EOL `{safe_text(d.get('currentEol'))}`", f"- Official current release: `{safe_text(d.get('officialMinor'))}`", f"- Official EOL: `{safe_text(d.get('officialEol'))}`", ""]
    for n in result.get("newMajors", []):
        lines += [f"### New supported major: PostgreSQL {n['major']}", f"- Official current release: `{safe_text(n.get('officialMinor'))}`", f"- Official EOL: `{safe_text(n.get('officialEol'))}`", ""]
    lines += ["## Manual validation gate", "", "- Confirm the official PostgreSQL announcement/versioning data.", "- Verify the standard Windows x64 distribution and the corresponding Chocolatey package/version; do not guess package availability.", "- Assess whether `metadata/postgresql.json` should change only after the Windows install path is reproducible.", "- Rebuild/revalidate the initial eight extensions for any PostgreSQL version whose package identity changes."]
    if pg19:
        lines += ["- Follow [`docs/postgresql-19-readiness.md`](https://github.com/pgextwin/build/blob/main/docs/postgresql-19-readiness.md) before production onboarding.", "- Reconfirm GA status, standard Windows x64 distribution, CI installation, official lifecycle metadata, acceptable upstream PG19 refs, and functional tests.", "- GA detection alone does **not** add PostgreSQL 19 to the production matrix."]
    lines += ["", "This watcher does not modify PostgreSQL metadata, create a source-update PR, build candidates, publish Releases, or change Catalog/Website data."]
    return title, "\n".join(lines)+"\n"


def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--result", required=True); p.add_argument("--repository", required=True); p.add_argument("--output", required=True); p.add_argument("--dry-run", action="store_true"); args=p.parse_args()
    try:
        result=json.loads(Path(args.result).read_text(encoding="utf-8")); marker=marker_for(result)
        raw=run_gh(["issue","list","--state","open","--limit","100","--json","number,title,body,state"], args.repository)
        issues=json.loads(raw or "[]")
        decision=decide_issue_action(result, issues, marker)
        action=decision["action"]; number=(decision.get("issue") or {}).get("number")
        if result.get("status")=="update-available":
            title,body=(render_postgresql(result,marker) if result.get("kind")=="postgresql" else render_extension(result,marker))
        else: title=body=None
        if not args.dry_run:
            if action=="create":
                out=run_gh(["issue","create","--title",title,"--body",body], args.repository); number=out.strip().rstrip("/").split("/")[-1]
            elif action=="update":
                run_gh(["issue","edit",str(number),"--title",title,"--body",body], args.repository)
            elif action=="close":
                run_gh(["issue","close",str(number),"--reason","completed","--comment","The configured metadata now matches the detected stable upstream state. Closing this automation-owned update watch issue."], args.repository)
        payload={"action": action if not args.dry_run else f"dry-run:{action}", "issueNumber": number, "marker": marker}
        Path(args.output).write_text(json.dumps(payload,indent=2)+"\n",encoding="utf-8"); print(json.dumps(payload)); return 0
    except (WatchError,OSError,json.JSONDecodeError,KeyError,TypeError) as exc:
        print(f"Issue reconciliation failed: {exc}", file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
