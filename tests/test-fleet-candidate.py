#!/usr/bin/env python3
"""Exercise the same-run candidate handoff without GitHub writes."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("fleet_candidate", ROOT / "scripts/fleet-candidate.py")
direct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(direct)

REPO = "pgextwin/pg_ivm"
BUILD_SHA = "a" * 40
TARGET_SHA = "b" * 40
UPDATE_SHA = "c" * 40
UPSTREAM = "sraoss/pg_ivm"
WRITER = (direct.APP_SLUG + "[bot]", 123)
REGISTRY = json.loads((ROOT / "metadata/automation-fleet.json").read_text(encoding="utf-8"))
MANIFEST = {"name": "pg_ivm", "postgresql": {"majors": [17, 18]},
            "upstream": {"repository": UPSTREAM, "ref": "v1.17", "version": "1.17", "commit": "e" * 40},
            "watch": {"source": "github", "strategy": "github-releases", "prereleases": False,
                      "stableTagPattern": r"^v(?P<version>\d+\.\d+)$"}}
UPDATE = {"current": {"ref": "v1.17", "version": "1.17"},
          "candidate": {"ref": "v1.18", "version": "1.18"}}


def branch(sha):
    return {"protected": True, "commit": {"sha": sha}}


def fixture(updated=True):
    now = datetime.now(timezone.utc)
    run = {"id": 100, "status": "in_progress", "conclusion": None, "head_sha": BUILD_SHA,
           "event": "schedule", "path": direct.receipt.WATCH_PATH, "head_branch": "main",
           "repository": {"full_name": direct.receipt.BUILD}, "run_attempt": 1,
           "created_at": (now - timedelta(minutes=4)).isoformat()}
    scan = {"name": "readonly-fleet", "conclusion": "success", "status": "completed",
            "run_id": 100, "run_attempt": 1, "head_sha": BUILD_SHA,
            "completed_at": (now - timedelta(minutes=1)).isoformat()}
    rows = [{"repository": row["repository"], "mainSha": TARGET_SHA,
             "status": "up-to-date", "updates": []} for row in REGISTRY["entries"]]
    if updated:
        row = next(row for row in rows if row["repository"] == REPO)
        row.update(status="update-available", updates=[deepcopy(UPDATE)])
    report = {"schemaVersion": 1, "scope": "STABLE_UPSTREAM_GET_ONLY",
              "publication": "DENY", "candidatePrCreated": False, "fleetSize": len(rows),
              "indeterminate": 0, "updatesDetected": int(updated), "extensions": rows,
              "generatedAt": (now - timedelta(minutes=2)).isoformat()}
    return report, (run, branch(BUILD_SHA), scan, REGISTRY)


def fetch(url):
    if url.endswith("/releases?per_page=100"):
        return [{"tag_name": "v1.18", "draft": False, "prerelease": False}]
    if url.endswith("/git/ref/tags/v1.18"):
        return {"object": {"type": "commit", "sha": UPDATE_SHA}}
    if url.endswith("/contents/metadata/automation-fleet.json?ref=main"):
        return {"encoding": "base64",
                "content": base64.b64encode(json.dumps(REGISTRY).encode()).decode()}
    raise AssertionError(url)


class FleetCandidate(TestCase):
    def setUp(self):
        def branches(url, token):
            if url.endswith("/pgextwin/build/branches/main"):
                return branch(BUILD_SHA)
            self.assertEqual(url, direct.receipt.HOST + REPO + "/branches/main")
            return branch(TARGET_SHA)

        self.enterContext(patch.dict(os.environ, {"PGEXTWIN_SCAN_READ_TOKEN": "reader"}))
        self.enterContext(patch.object(direct.receipt, "api", branches))

    def test_no_update_runs_selection_only(self):
        report, context = fixture(updated=False)
        with patch.object(direct.candidate, "plan") as compute:
            matrix, summary = direct.select(report, context)
            self.assertEqual(matrix, [])
            self.assertIn("no update", summary[0])
            with self.assertRaises(direct.receipt.Denied):
                direct.checked_plan(report, context, REPO, fetch=fetch)
            compute.assert_not_called()

    def test_require_own_successful_scan_even_if_other_jobs_fail(self):
        report, context = fixture()
        context[0]["unrelated_audit"] = "failure"
        self.assertEqual(direct.select(report, context)[0][0]["repository"], REPO)
        for field, value in (("run_id", 101), ("head_sha", "0" * 40),
                             ("conclusion", "failure"), ("run_attempt", 2),
                             ("completed_at", "2020-01-01T00:00:00Z")):
            with self.subTest(field=field), patch.dict(context[2], {field: value}):
                with self.assertRaises(direct.receipt.Denied):
                    direct.select(report, context)
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event), patch.dict(context[0], {"event": event}):
                with self.assertRaises(direct.receipt.Denied):
                    direct.select(report, context)
        with patch.object(direct.receipt, "api", return_value=branch("0" * 40)):
            with self.assertRaises(direct.receipt.Denied):
                direct.select(report, context)

    def test_update_plan_to_proposal_uses_real_engine_with_stubbed_git_and_gh(self):
        report, context = fixture()
        commands = []

        def execute(*args):
            commands.append(args)
            if args[:2] == ("git", "rev-parse"):
                return TARGET_SHA
            if args[:3] == ("git", "remote", "get-url"):
                return "https://github.com/" + REPO
            if args[:3] in (("gh", "pr", "list"), ("gh", "run", "list")):
                return "[]"
            if args[:3] == ("gh", "pr", "create"):
                return "https://github.com/" + REPO + "/pull/123"
            return ""

        matrix, _ = direct.select(report, context)
        self.assertEqual(matrix, [{"repository": REPO, "sha": TARGET_SHA, "extension": "pg_ivm"}])
        previous = Path.cwd()
        with TemporaryDirectory() as tmp, patch.dict(os.environ, {"RUNNER_TEMP": tmp}), \
                patch.object(direct.candidate, "execute", execute):
            try:
                os.chdir(tmp)
                manifest = Path(direct.MANIFEST)
                manifest.parent.mkdir()
                manifest.write_text(json.dumps(MANIFEST), encoding="utf-8")
                plan = direct.checked_plan(report, context, REPO, fetch=fetch)
                self.assertEqual(plan["updates"][0]["commit"], UPDATE_SHA)
                self.assertEqual(plan["releasePolicy"], "manual-only")
                altered = deepcopy(plan)
                altered["updates"][0]["commit"] = "0" * 40
                with self.assertRaises(direct.receipt.Denied):
                    direct.propose(report, context, REPO, altered, WRITER, fetch=fetch)
                self.assertFalse(any(call[:2] == ("git", "push") for call in commands))
                direct.propose(report, context, REPO, plan, WRITER, fetch=fetch)
                self.assertEqual(json.loads(manifest.read_text())["upstream"]["commit"], UPDATE_SHA)
            finally:
                os.chdir(previous)
        self.assertIn(("git", "push", "--set-upstream", "origin", plan["branch"]), commands)
        self.assertTrue(any(call[:3] == ("gh", "pr", "create") and "--draft" in call for call in commands))
        self.assertIn(("gh", "workflow", "run", "windows.yml", "--repo", REPO, "--ref", plan["branch"]), commands)

    def test_workflow_restricts_selection_and_proposal(self):
        workflow = (ROOT / ".github/workflows/fleet-upstream-watch.yml").read_text()
        candidate = (ROOT / ".github/workflows/fleet-candidate.yml").read_text()
        for text in (workflow, candidate):
            self.assertEqual(text.count("github.event_name == 'schedule'"), 2)
        self.assertIn("needs: readonly-fleet", workflow)
        self.assertIn("needs.candidate-selection.outputs.has_updates == 'true'", workflow)
        self.assertIn("needs.plan.outputs.decision != ''", candidate)
        self.assertIn("vars.PGEXTWIN_FLEET_CANDIDATE_WRITES == 'enabled'", candidate)
        self.assertIn("secrets.fleet_candidate_app_private_key", candidate)
        self.assertNotIn("PUBLISHER_APP", candidate)


if __name__ == "__main__":
    main()
