#!/usr/bin/env python3
"""Offline adversarial R10-02 final-report tests; never network or credentials."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "r10", Path("scripts/issue311-r10-final-readonly-report.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

repos = ["pgextwin/" + name for name in (
    "hypopg", "orafce", "pg_bigm", "pg_cron", "pg_hint_plan", "pg_ivm",
    "pg_partman", "pg_qualstats", "pg_repack", "pg_stat_monitor",
    "pg_store_plans", "pg_variables", "pgaudit", "pgtap",
    "plpgsql_check", "set_user", "wal2json")]
sha = "a" * 40
digest = "b" * 64
state = {
    "schemaVersion": 1, "revision": 2, "scope": "AUDIT_ONLY_READONLY",
    "publisherAuthorized": False, "writeOutcomeUnknown": False,
    "terminal": "NO_UPDATE", "targetScope": repos,
    "targets": {repo: "SUCCESS" for repo in repos},
    "sourceRun": {"id": 101, "attempt": 1}, "completionRun": {"id": 102, "attempt": 1},
    "sourceHeadSha": sha, "requestId": "r-20261030-r06appauto101",
    "requestSha256": digest, "eventTransport": "workflow_run.completed",
    "expiresAt": "2026-10-30T16:54:04Z",
}
run = {"id": 101, "run_attempt": 1, "head_sha": sha,
       "status": "completed", "conclusion": "success",
       "name": m.SOURCE_WORKFLOW, "path": m.SOURCE_PATH,
       "event": "workflow_run", "head_branch": "main"}
children = {repo: {"repository": repo, "attempt": 1, "runId": 300 + i,
                   "artifactId": 900 + i, "headSha": sha, "zipSha256": digest,
                   "verifiedOriginal": True, "result": "NO_UPDATE"}
            for i, repo in enumerate(repos)}
art = {"artifactId": 88, "zipSha256": digest}

def deny(name, work):
    try:
        work()
    except (ValueError, KeyError, TypeError, AssertionError):
        print("R10_02_DENY", name)
        return
    raise AssertionError("R10_02_FALSE_ACCEPT " + name)


good = m.build(state, sha, run, source_artifact=art, children=children)
assert len(good["targets"]) == 17 and good["evidenceCompleteness"] == "COMPLETE_17_ORIGINAL_ZIP"
assert all(t["originalZipSha256"] == digest and t["originalArtifactId"] for t in good["targets"])
assert good["r10_02Accepted"] is False and good["publicationAuthorized"] is False
assert good["targets"][0]["safeRestartPoint"] == "STOP_NO_UPDATE"
deny("missing original child", lambda: m.build(state, sha, run,
     source_artifact=art, children={k: v for k, v in children.items() if k != repos[0]}))
deny("missing source outer ZIP", lambda: m.build(state, sha, run,
     source_artifact=None, children=children))
deny("cross-request HEAD", lambda: m.build(state, sha, {**run, "head_sha": "f"*40},
     source_artifact=art, children=children))
deny("wrong attempt", lambda: m.build(state, sha, {**run, "run_attempt": 2},
     source_artifact=art, children=children))
deny("forged child checksum", lambda: m.build(state, sha, run,
     source_artifact=art, children={**children, repos[0]: {**children[repos[0]], "zipSha256": "X"}}))
deny("unverified child", lambda: m.build(state, sha, run,
     source_artifact=art, children={**children, repos[0]: {**children[repos[0]], "verifiedOriginal": False}}))
deny("publisher privilege", lambda: m.build({**state, "publisherAuthorized": True},
     sha, run, source_artifact=art, children=children))
deny("ambiguous write", lambda: m.build({**state, "writeOutcomeUnknown": True},
     sha, run, source_artifact=art, children=children))
deny("lost target", lambda: m.build({**state, "targetScope": repos[:-1]},
     sha, run, source_artifact=art, children=children))
deny("unknown terminal", lambda: m.build({**state, "terminal": "COMPLETED"},
     sha, run, source_artifact=art, children=children))
deny("unknown transport", lambda: m.build({**state, "eventTransport": "FAKE_SCHEDULE"},
     sha, run, source_artifact=art, children=children))
for terminal, status in (("QUARANTINED", "QUARANTINED"),
                         ("FAILED", "FAILED"), ("BLOCKED_APPROVAL", "BLOCKED_APPROVAL")):
    scoped = {**state, "terminal": terminal,
              "eventTransport": "BOUNDED_WATCHDOG",
              "targets": {k: status for k in repos}}
    result = m.build(scoped, sha, run)
    assert result["evidenceCompleteness"] == "INCOMPLETE_TARGET_REASON_AND_ZIP_FAIL_CLOSED"
    assert all(t["originalZipSha256"] is None and
               t["missingEvidenceReason"] == "NO_AUTHENTICATED_PER_TARGET_RECEIPT_JOIN"
               for t in result["targets"])
    assert all(t["safeRestartPoint"] != "STOP_NO_UPDATE" for t in result["targets"])
    deny("quarantine borrowing success " + terminal,
         lambda: m.build(scoped, sha, run, source_artifact=art, children=children))
print("R10_02_OFFLINE_REPORT_POLICY_PASS no release no App key no network")
