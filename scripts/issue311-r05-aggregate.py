#!/usr/bin/env python3
"""R05 pure fail-closed aggregation of real same-run 17 matrix child jobs."""
REPOS=frozenset("pgextwin/"+x for x in (
"pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user","pg_repack","pg_ivm",
"pg_qualstats","plpgsql_check","orafce","hypopg","wal2json","pg_partman",
"pg_stat_monitor","pgtap","pg_variables","pg_store_plans"))

def evaluate_jobs(jobs):
    found={}
    for job in jobs:
        name=job.get("name","")
        if not name.startswith("GET pgextwin/"):
            continue
        repo=name.removeprefix("GET ")
        if repo not in REPOS or repo in found:
            raise ValueError("unexpected or duplicate target job")
        found[repo]=(job.get("conclusion") if job.get("status")=="completed" else "incomplete")
    return {repo:found.get(repo,"missing") for repo in sorted(REPOS)}
