#!/usr/bin/env python3
"""Offline fixtures for per-repository results on the central native PR schedule."""
import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit_fleet", ROOT / "scripts/recover-native-pr-fleet.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fixtures = mod.load("fleet_native_fixtures", "tests/test-native-pr-candidate-audit.py")
artifacts = mod.load("fleet_artifact_fixtures", "tests/test-pr-candidate-artifacts.py")

SHA = "f" * 40
SCHEDULE = {"GITHUB_EVENT_NAME": "schedule", "GITHUB_REPOSITORY": "pgextwin/build",
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": SHA, "GH_TOKEN": "fixture",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "450"}
PULLS = "pulls?state=open&per_page=100"
RUNS = "actions/runs?event=pull_request&head_sha=" + fixtures.SHA + "&per_page=100"
RUN = "actions/runs/" + str(fixtures.RUN)
FILES = f"pulls/{fixtures.PR}/files?per_page=100"
MANIFEST = "contents/config/extension.json?ref=" + fixtures.SHA


def responses(repo=fixtures.REPO):
    x = fixtures.fixture()
    run = {**x["run"], "workflow_id": 70}
    ext = {**artifacts.EXT, "name": repo.split("/")[1]}
    raw = json.dumps(ext).encode()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    x["pr_files"][0]["sha"] = blob
    entries = {
        PULLS: [x["pr"]],
        RUNS: {"total_count": 1, "workflow_runs": [deepcopy(run)]},
        RUN: run,
        "commits/" + fixtures.SHA + "/pulls?per_page=100": fixtures.association(),
        f"pulls/{fixtures.PR}": x["pr"],
        FILES: x["pr_files"],
        f"git/ref/pull/{fixtures.PR}/merge": x["merge_ref"],
        "branches/main": x["main"],
        "commits/" + fixtures.SHA + "/check-runs?per_page=100": x["checks"],
        MANIFEST: {"path": "config/extension.json", "encoding": "base64", "sha": blob,
                   "content": base64.encodebytes(raw).decode()},
    }
    return json.loads(json.dumps(entries).replace(fixtures.REPO, repo)
                      .replace('"name": "pg_ivm"', '"name": "' + ext["name"] + '"'))


def download(args, **kwargs):
    assert args[1:6] == ["run", "download", str(fixtures.RUN), "--repo", fixtures.REPO]
    for major in (14, 15):
        artifacts.emit(Path(args[-1]) / f"pg_ivm-pg{major}-windows-x64", major)
    return SimpleNamespace(returncode=0, stderr="")


class FleetRecoveryTests(TestCase):
    def collect(self, sources, retrieve=None):
        calls = []

        def api(repo, path):
            calls.append((repo, path))
            doc = sources[repo][path]
            if isinstance(doc, Exception):
                raise doc
            return deepcopy(doc)

        with patch.object(mod.recovery, "get_json", side_effect=api), \
             patch.object(mod.native, "gh_get", side_effect=api), \
             patch.object(mod, "gh_json", side_effect=api), \
             patch.object(mod.subprocess, "run", side_effect=retrieve) as downloaded:
            result = mod.collect(sources, artifacts.LIFECYCLE)
        return result, calls, downloaded

    def test_roster_dynamic_no_fixed_repositories(self):
        live = mod.membership(ROOT / "metadata/automation-fleet.json")
        self.assertIn("pgextwin/hypopg", live)
        self.assertGreater(len(live), 1)
        self.assertEqual(len(set(live)), len(live))

    def test_membership_rejects_duplicates_and_untrusted_repositories(self):
        entry = {"mode": "BUILD", "candidateEnabled": True, "repository": "pgextwin/hypopg"}
        with TemporaryDirectory() as temp:
            path = Path(temp) / "fleet.json"
            for rows in ([entry], [entry, entry], [{**entry, "repository": "rogue/hypopg"}]):
                path.write_text(json.dumps({"schemaVersion": 1, "entries": rows}))
                if rows == [entry]:
                    self.assertEqual(mod.membership(path), ["pgextwin/hypopg"])
                else:
                    with self.assertRaises(mod.Denied):
                        mod.membership(path)

    def test_only_real_central_first_attempt_main_schedule_trusted(self):
        with patch.object(mod, "gh_json", return_value={
                "name": "main", "protected": True, "commit": {"sha": SHA}}):
            with patch.dict(os.environ, SCHEDULE, clear=True):
                self.assertEqual(mod.central_schedule_gate()["runId"], 450)
            for key, invalid in (("GITHUB_EVENT_NAME", "workflow_dispatch"),
                                 ("GITHUB_EVENT_NAME", "push"),
                                 ("GITHUB_REPOSITORY", fixtures.REPO),
                                 ("GITHUB_REF", "refs/heads/evil"), ("GITHUB_SHA", "b" * 40),
                                 ("GH_TOKEN", ""), ("GITHUB_RUN_ATTEMPT", "2")):
                with self.subTest(key=key, invalid=invalid), \
                     patch.dict(os.environ, {**SCHEDULE, key: invalid}, clear=True), \
                     self.assertRaises(mod.Denied):
                    mod.central_schedule_gate()

    def test_empty_and_unavailable_are_distinct_and_have_no_evidence(self):
        empty, broken = "pgextwin/hypopg", "pgextwin/orafce"
        rows, _, retrieved = self.collect({
            empty: {PULLS: []}, broken: {PULLS: mod.Unavailable("GitHub GET unavailable")}})
        self.assertEqual(rows[empty]["status"], "no_candidate")
        self.assertIsNotNone(rows[empty]["observedAt"])
        self.assertEqual(rows[broken], {"status": "unavailable", "observedAt": None,
                                        "reason": "GitHub GET unavailable"})
        retrieved.assert_not_called()

    def test_jobless_hold_and_running_wait_without_discovery_of_dispatch_or_jobs(self):
        for status, conclusion in (("completed", "action_required"), ("in_progress", None),
                                   ("queued", None), ("waiting", None)):
            with self.subTest(status=status):
                source = responses()
                source[RUNS]["workflow_runs"][0].update(status=status, conclusion=conclusion)
                rows, calls, retrieved = self.collect({fixtures.REPO: source})
                row = rows[fixtures.REPO]
                self.assertEqual(row["status"], "waiting")
                self.assertEqual(row["candidatePr"], fixtures.PR)
                self.assertIn(f"{status}/{conclusion}", row["reason"])
                self.assertEqual(calls, [(fixtures.REPO, PULLS), (fixtures.REPO, RUNS)])
                retrieved.assert_not_called()

    def test_failed_ci_refuses_original_conclusion(self):
        source = responses()
        source[RUNS]["workflow_runs"][0]["conclusion"] = "failure"
        rows, _, retrieved = self.collect({fixtures.REPO: source})
        row = rows[fixtures.REPO]
        self.assertEqual(row["status"], "rejected")
        self.assertIn("completed/failure", row["reason"])
        retrieved.assert_not_called()

    def test_original_attempt_must_match_inventory_and_package_bytes(self):
        for changed in ("live", "package"):
            with self.subTest(changed=changed):
                source = responses()
                source[RUN]["run_attempt"] = 2
                if changed == "package":
                    source[RUNS]["workflow_runs"][0]["run_attempt"] = 2
                rows, _, retrieved = self.collect({fixtures.REPO: source}, download)
                row = rows[fixtures.REPO]
                self.assertEqual(row["status"], "rejected")
                self.assertNotIn("candidateAudit", row)
                if changed == "live":
                    self.assertIn("re-fetched native run changed identity or attempt", row["reason"])
                    retrieved.assert_not_called()
                else:
                    self.assertIn("package workflow run attempt does not match", row["reason"])
                    retrieved.assert_called_once()

    def test_multi_file_and_blob_rejections_do_not_stop_native_success(self):
        partman, orafce = "pgextwin/pg_partman", "pgextwin/orafce"
        multi, changed = responses(partman), responses(orafce)
        multi[FILES].extend({"filename": name, "status": "modified", "sha": "c" * 40}
                            for name in (".github/workflows/bgw.yml", "scripts/build.ps1",
                                         "scripts/test.ps1", "scripts/package.ps1", "README.md"))
        changed[FILES][0]["sha"] = "2c6cea58646b7224c1369e6863a22e90a043ae11"
        rows, calls, retrieved = self.collect({
            partman: multi, fixtures.REPO: responses(), orafce: changed}, download)
        for repo, reason in ((partman, "candidate modifies files other than pinned manifest"),
                             (orafce, "PR manifest bytes differ from exact PR patch")):
            self.assertEqual(rows[repo]["status"], "rejected")
            self.assertEqual(rows[repo]["reason"], reason)
            self.assertNotIn("candidateAudit", rows[repo])
            self.assertNotIn("native", rows[repo])
        passed = rows[fixtures.REPO]
        self.assertEqual(passed["status"], "verified")
        self.assertEqual(passed["native"]["packagingMergeSha"], fixtures.MERGE)
        self.assertEqual(passed["targetMainSha"], fixtures.BASE)
        self.assertEqual(passed["manifestBlob"], responses()[FILES][0]["sha"])
        self.assertEqual(passed["workflowId"], 70)
        audit = passed["candidateAudit"]
        self.assertEqual(audit["originEvent"], "pull_request")
        self.assertEqual(audit["runAttempt"], 1)
        self.assertTrue(all(len(row["zipSha256"]) == 64 for row in audit["majors"]))
        retrieved.assert_called_once()
        for repo in rows:
            self.assertEqual(calls.count((repo, FILES)), 1)

    def test_failure_to_finish_all_targets_still_records_remaining_rows(self):
        exhausted = "pgextwin/orafce"
        with patch.object(mod.time, "monotonic", side_effect=[1, 2, mod.FLEET_SECONDS + 2]):
            rows, _, _ = self.collect({fixtures.REPO: {PULLS: []}, exhausted: {}})
        self.assertEqual(rows[exhausted]["status"], "unavailable")
        self.assertIsNone(rows[exhausted]["observedAt"])
        self.assertEqual(rows[fixtures.REPO]["status"], "no_candidate")

    def test_candidate_timeout_during_byte_audit_still_records_next_repository(self):
        empty = "pgextwin/hypopg"
        with patch.object(mod.candidate, "one", side_effect=mod.CandidateTimeout("time budget")):
            rows, _, _ = self.collect({fixtures.REPO: responses(), empty: {PULLS: []}}, download)
        self.assertEqual(rows[fixtures.REPO]["status"], "unavailable")
        self.assertEqual(rows[fixtures.REPO]["reason"], "time budget")
        self.assertNotIn("candidateAudit", rows[fixtures.REPO])
        self.assertEqual(rows[empty]["status"], "no_candidate")

    def test_complete_results_and_summary_written_even_with_rejections(self):
        with TemporaryDirectory() as temp:
            path, summary = Path(temp) / "result.json", Path(temp) / "summary.md"
            rows = {fixtures.REPO: {"status": "rejected", "reason": "original reason",
                                    "observedAt": "2026-11-21T01:00:00Z",
                                    "candidatePr": fixtures.PR, "candidateHeadSha": fixtures.SHA}}
            with patch.dict(os.environ, {**SCHEDULE, "GITHUB_STEP_SUMMARY": str(summary)}), \
                 patch.object(mod, "gh_json", return_value={"protected": True, "commit": {"sha": SHA}}), \
                 patch.object(mod, "collect", return_value=rows), \
                 patch.object(mod.sys, "argv", ["recover", "--output", str(path)]), \
                 patch("builtins.print"):
                self.assertEqual(mod.main(), 0)
            report = json.loads(path.read_text())
            self.assertEqual(report["schemaVersion"], 2)
            self.assertEqual(report["results"], rows)
            self.assertIs(report["publicationAuthorized"], False)
            self.assertIn("original reason", summary.read_text())

    def test_workflows_keep_scan_and_original_audit_in_separate_readonly_runs(self):
        workflow = (ROOT / ".github/workflows/recover-native-pr-fleet.yml").read_text()
        self.assertIn('cron: "47 * * * *"', workflow)
        self.assertIn("github.event_name == 'schedule'", workflow)
        self.assertIn("registered-original-native-pr-audits", workflow)
        self.assertIn("if-no-files-found: error", workflow)
        for field in ("workflow_dispatch:", "contents: write", "id-token: write", "attestations: write"):
            self.assertNotIn(field, workflow)
        scan = (ROOT / ".github/workflows/fleet-upstream-watch.yml").read_text()
        self.assertIn("name: fleet-upstream-watch", scan)
        for field in ("original-native-audit-fallback:", "merged-bot-requalification-readonly:",
                      "registered-original-native-pr-audits", "contents: write"):
            self.assertNotIn(field, scan)


if __name__ == "__main__":
    main()
