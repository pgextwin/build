#!/usr/bin/env python3
"""Bind version 2 central results to the real merged PR and original native audit."""
from copy import deepcopy
import hashlib
import importlib.util
from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("local_live_fixture",
    ROOT / "tests/test-automatic-postmerge-audit-live.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
mod = fixtures.mod
CENTRAL = "pgextwin/build"
SHA = "f" * 40
RUN, JOB, ART = 601, 602, 603
PATH = ".github/workflows/recover-native-pr-fleet.yml"
NAME = "Hourly central recovery of approved original native PR artifacts (NONPUBLISHING)"
JOBNAME = "Independent approved attempt and original ZIP/SPDX/Grype audit (no Release)"
ARTIFACT = "registered-original-native-pr-audits"
CI_PATH = "actions/runs/" + str(fixtures.CI)
PR_PATH = "pulls/" + str(fixtures.PR)
MERGED = "2026-01-22T12:00:00Z"
RUNS = mod.central.runs_endpoint(mod.central.utc(MERGED))


def central_fixture():
    event, local, context, audit = fixtures.fixture()
    local["actions/runs?event=workflow_run&head_sha=" + fixtures.OLD +
          "&per_page=100"] = {"total_count": 0, "workflow_runs": []}
    local[PR_PATH].update(created_at="2026-01-22T09:00:00Z", merged_at=MERGED)
    local[CI_PATH].update(workflow_id=81)
    context.update(candidateRunAttempt=1, candidateCheckSuiteId=700, candidateRequiredCheckRunId=701)
    audit["runAttempt"] = 1
    row = {"status": "verified", "observedAt": "2026-01-22T10:02:00Z",
           "targetMainSha": fixtures.OLD, "candidatePr": fixtures.PR,
           "candidateHeadSha": fixtures.HEAD, "workflowId": 81,
           "manifestBlob": local["contents/config/extension.json?ref=" + fixtures.NEW]["sha"],
           "native": context, "candidateAudit": audit}
    calls = {
        "branches/main": {"name": "main", "protected": True, "commit": {"sha": SHA}},
        RUNS: {"total_count": 0, "workflow_runs": []},
    }
    reports = {}
    add_run(calls, reports, RUN, row=row)
    return event, local, calls, reports


def add_run(calls, reports, run_id, *, row, created="2026-01-22T10:00:00Z",
            start="2026-01-22T10:01:00Z", uploaded="2026-01-22T10:03:00Z",
            finish="2026-01-22T10:04:00Z"):
    run = {"id": run_id, "name": NAME, "path": PATH,
           "event": "schedule", "run_attempt": 1, "created_at": created, "updated_at": finish,
           "repository": {"full_name": CENTRAL}, "head_sha": SHA, "head_branch": "main",
           "status": "completed", "conclusion": "success"}
    job = {"id": run_id + 1, "run_id": run_id, "run_attempt": 1, "name": JOBNAME,
           "status": "completed", "conclusion": "success", "started_at": start, "completed_at": finish}
    artifact = {"id": run_id + 2, "name": ARTIFACT, "size_in_bytes": 9876,
                "created_at": uploaded, "expired": False, "workflow_run": {"id": run_id}}
    report = {"schemaVersion": 2, "auditor": {"repository": CENTRAL, "event": "schedule",
              "sourceSha": SHA, "runId": run_id, "runAttempt": 1},
              "results": {fixtures.REPO: row,
                          "pgextwin/orafce": {"status": "rejected", "observedAt": start,
                                              "reason": "candidate manifest blob differs"}},
              "signedArtifactsVerified": False, "publicationAuthorized": False,
              "publishableReceipt": False}
    calls[RUNS]["workflow_runs"].append(deepcopy(run))
    calls[RUNS]["total_count"] += 1
    path = "actions/runs/" + str(run_id)
    calls[path] = run
    calls[path + "/jobs?per_page=100"] = {"total_count": 1, "jobs": [job]}
    calls[path + "/artifacts?per_page=100"] = {"total_count": 1, "artifacts": [artifact]}
    reports[run_id] = report


class CentralNativeSchedulePostmergeTests(unittest.TestCase):
    def verify(self, change=None):
        event, local, central, reports = central_fixture()
        if change:
            change(event, local, central, reports)
        ci_calls = []

        def api(repo, endpoint):
            if repo == fixtures.REPO:
                if endpoint == CI_PATH:
                    ci_calls.append(endpoint)
                if endpoint not in local:
                    raise mod.Denied("untrusted changed original native GET")
                return deepcopy(local[endpoint])
            if repo == CENTRAL:
                if endpoint not in central:
                    raise mod.Denied("untrusted changed central schedule GET")
                return deepcopy(central[endpoint])
            raise AssertionError(repo)

        def download(run, asset, target):
            self.assertEqual(target, fixtures.REPO)
            self.assertEqual(asset["id"], run["id"] + 2)
            return deepcopy(reports[run["id"]])

        result = mod.live(fixtures.REPO, event, deepcopy(fixtures.FLEET),
                          deepcopy(fixtures.LIFE), auth_api=api,
                          central_api=api, central_retrieve=download)
        self.assertEqual(ci_calls, [CI_PATH])
        return result

    def test_genuine_schedule_uses_only_its_target_row_with_one_native_get(self):
        result = self.verify()
        self.assertEqual(result["nativeAuditEvent"], "schedule")
        self.assertEqual(result["nativeAuditRepository"], CENTRAL)
        self.assertEqual(result["nativeAuditRunId"], RUN)
        self.assertEqual(result["nativeAuditArtifactId"], ART)
        self.assertEqual(result["candidateCiRunId"], fixtures.CI)
        self.assertEqual(result["mainParentAtAudit"], fixtures.OLD)
        self.assertEqual(result["status"], "MERGED_NATIVE_CANDIDATE_NONPUBLISHING")
        for key in ("signedArtifactsVerified", "publishableReceipt",
                    "publicationAuthorized", "automaticReleaseEnabled"):
            self.assertIs(result[key], False)

    def test_tampering_cannot_convert_other_evidence_to_authority(self):
        run_path = "actions/runs/" + str(RUN)
        job_path = run_path + "/jobs?per_page=100"
        artifact_path = run_path + "/artifacts?per_page=100"

        def target(reports):
            return reports[RUN]["results"][fixtures.REPO]

        changes = (
            lambda e, l, c, r: c[run_path].update(event="workflow_dispatch"),
            lambda e, l, c, r: c[run_path].update(run_attempt=2),
            lambda e, l, c, r: c[run_path].update(conclusion="failure"),
            lambda e, l, c, r: c[run_path].update(path=".github/workflows/fleet-upstream-watch.yml"),
            lambda e, l, c, r: c[run_path]["repository"].update(full_name=fixtures.REPO),
            lambda e, l, c, r: c["branches/main"].update(protected=False),
            lambda e, l, c, r: c["branches/main"]["commit"].update(sha="e" * 40),
            lambda e, l, c, r: c[job_path]["jobs"][0].update(conclusion="skipped"),
            lambda e, l, c, r: c[job_path]["jobs"][0].update(run_id=123),
            lambda e, l, c, r: c[job_path]["jobs"][0].update(run_attempt=2),
            lambda e, l, c, r: c[job_path]["jobs"][0].update(completed_at="2099-01-22T10:04:00Z"),
            lambda e, l, c, r: c[artifact_path]["artifacts"][0].update(expired=True),
            lambda e, l, c, r: c[artifact_path]["artifacts"][0].update(name="fake-audit"),
            lambda e, l, c, r: c[artifact_path]["artifacts"][0]["workflow_run"].update(id=999),
            lambda e, l, c, r: c[artifact_path]["artifacts"][0].update(created_at="2026-01-22T10:05:00Z"),
            lambda e, l, c, r: r[RUN].update(schemaVersion=1),
            lambda e, l, c, r: r[RUN]["results"].pop(fixtures.REPO),
            lambda e, l, c, r: r[RUN]["auditor"].update(event="workflow_run"),
            lambda e, l, c, r: r[RUN]["auditor"].update(sourceSha="e" * 40),
            lambda e, l, c, r: r[RUN]["auditor"].update(runId=999),
            lambda e, l, c, r: r[RUN].update(publicationAuthorized=True),
            lambda e, l, c, r: target(r).update(targetMainSha="e" * 40),
            lambda e, l, c, r: target(r).update(manifestBlob="e" * 40),
            lambda e, l, c, r: target(r).update(workflowId=82),
            lambda e, l, c, r: target(r)["native"].update(candidateHeadSha="e" * 40),
            lambda e, l, c, r: target(r)["native"].update(candidateRequiredCheckRunId=702),
            lambda e, l, c, r: target(r)["candidateAudit"].update(runAttempt=2),
            lambda e, l, c, r: target(r)["candidateAudit"]["majors"][0].update(zipSha256="bad"),
            lambda e, l, c, r: l[CI_PATH].update(run_attempt=2),
            lambda e, l, c, r: l[CI_PATH].update(check_suite_id=777),
            lambda e, l, c, r: e["sender"].update(login="github-actions[bot]"),
            lambda e, l, c, r: e.update(before="e" * 40),
        )
        for index, change in enumerate(changes):
            with self.subTest(case=index), self.assertRaises(mod.Denied):
                self.verify(change)

    def test_newer_in_window_result_blocks_older_success(self):
        for status in ("rejected", "waiting", "unavailable", "no_candidate", "missing"):
            with self.subTest(status=status):
                def change(event, local, calls, reports):
                    row = {"status": status, "reason": status, "observedAt": "2026-01-22T11:02:00Z"}
                    add_run(calls, reports, 701, row=None if status == "missing" else row,
                            created="2026-01-22T11:00:00Z", start="2026-01-22T11:01:00Z",
                            uploaded="2026-01-22T11:03:00Z", finish="2026-01-22T11:04:00Z")
                reason = "target original native audit row missing" if status == "missing" else "latest target native audit " + status
                with self.assertRaisesRegex(mod.Denied, reason):
                    self.verify(change)

    def test_post_merge_no_candidate_is_outside_the_candidate_observation_window(self):
        def change(event, local, calls, reports):
            add_run(calls, reports, 701,
                    row={"status": "no_candidate", "observedAt": "2026-01-22T12:02:00Z"},
                    created="2026-01-22T11:59:00Z", start="2026-01-22T12:01:00Z",
                    uploaded="2026-01-22T12:03:00Z", finish="2026-01-22T12:04:00Z")
        self.assertEqual(self.verify(change)["nativeAuditRunId"], RUN)

    def test_observation_order_handles_a_run_that_finishes_later(self):
        def change(event, local, calls, reports):
            add_run(calls, reports, 701,
                    row={"status": "waiting", "reason": "earlier observation",
                         "observedAt": "2026-01-22T10:01:30Z"},
                    created="2026-01-22T09:59:00Z", start="2026-01-22T10:01:00Z",
                    uploaded="2026-01-22T10:05:00Z", finish="2026-01-22T10:06:00Z")
        self.assertEqual(self.verify(change)["nativeAuditRunId"], RUN)

    def test_unfinished_or_missing_schedule_never_falls_back(self):
        def unfinished(event, local, calls, reports):
            add_run(calls, reports, 701, row=None, created="2026-01-22T11:00:00Z")
            calls[RUNS]["workflow_runs"][-1].update(status="in_progress")
            calls["actions/runs/701"].update(status="in_progress")
        for change in (unfinished, lambda e, l, c, r: c[RUNS].update(total_count=0, workflow_runs=[])):
            with self.subTest(change=change), self.assertRaises(mod.Denied):
                self.verify(change)

    def test_download_by_real_artifact_id_and_hashes_original_archive(self):
        raw = BytesIO()
        with ZipFile(raw, "w") as archive:
            archive.writestr(ARTIFACT + ".json", '{"schemaVersion": 2}')
        data = raw.getvalue()
        artifact = {"id": ART, "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
        response = SimpleNamespace(returncode=0, stdout=data)
        with patch.object(mod.central.subprocess, "run", return_value=response) as gh:
            self.assertEqual(mod.central.download_original({"id": RUN}, artifact, fixtures.REPO),
                             {"schemaVersion": 2})
            self.assertEqual(gh.call_args.args[0],
                             ["gh", "api", "--method", "GET", f"repos/{CENTRAL}/actions/artifacts/{ART}/zip"])
        with patch.object(mod.central.subprocess, "run", return_value=response), \
             self.assertRaisesRegex(mod.central.Denied, "digest mismatch"):
            mod.central.download_original({"id": RUN}, {**artifact, "digest": "sha256:" + "0" * 64},
                                          fixtures.REPO)

    def test_runs_endpoint_passes_allowlist_and_malformed_endpoints_are_denied(self):
        response = SimpleNamespace(returncode=0,
                                   stdout=json.dumps({"total_count": 0, "workflow_runs": []}))
        with patch.object(mod.central.subprocess, "run", return_value=response) as gh:
            self.assertEqual(mod.central.gh(CENTRAL, RUNS),
                             {"total_count": 0, "workflow_runs": []})
            self.assertEqual(len(gh.call_args_list), 1)
            self.assertEqual(gh.call_args.args[0],
                             ["gh", "api", "--method", "GET", "repos/" + CENTRAL + "/" + RUNS])
        malformed = (
            RUNS.replace("%3A", ":"),  # unencoded colons
            RUNS.replace("%3A", "%3a"),  # lowercase percent-encoding
            RUNS.replace("&per_page=100", "&per_page=99"),
            RUNS.replace("&per_page=100", "&per_page=100&extra=1"),
            RUNS.replace("2026-01-22T12", "2026-1-22T12"),  # single-digit month
            RUNS.replace("T12%3A00%3A00Z", "T12%3A00%3A00"),  # missing Z
        )
        for endpoint in malformed:
            with self.subTest(endpoint=endpoint), \
                 patch.object(mod.central.subprocess, "run", return_value=response) as gh, \
                 self.assertRaisesRegex(mod.central.Denied, "unallowlisted central schedule GET"):
                mod.central.gh(CENTRAL, endpoint)
            self.assertEqual(len(gh.call_args_list), 0)


if __name__ == "__main__":
    unittest.main()
