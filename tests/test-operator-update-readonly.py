#!/usr/bin/env python3
"""Execute the ACTUAL new shared on-demand Bash gate against all 17 identities.

Offline only: no workflows are dispatched, no GitHub access, no mutation.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/operator-update-readonly.yml").read_text()
ROSTER = tuple(x["repository"] for x in json.loads(
    (ROOT / "metadata/automation-fleet.json").read_text())["entries"])
OLD = "16b886b9d06d6f389b369b87ce0c155767697ca0"
NEW = "acd6eb28be6d750e89b626fa4ccd4403e1265cd6"
WAVE3 = {"pgextwin/pgtap", "pgextwin/pg_variables",
         "pgextwin/pg_store_plans"}
HEAD = "a" * 40


def gate():
    start = WORKFLOW.index("          set -euo pipefail\n")
    end = WORKFLOW.index("\n  watch_readonly:\n", start)
    return "\n".join(s[10:] for s in WORKFLOW[start:end].splitlines()) + "\n"


def run(repo, pin, *, dry="true", confirm="", expected="", actor="ShutenOishi",
        triggering=None, ref="refs/heads/main", event="workflow_dispatch",
        attempt="1"):
    with tempfile.TemporaryDirectory() as d:
        out, summ = Path(d) / "output", Path(d) / "summary"
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "EVENT_NAME": event, "REPO": repo, "DETECTOR_SHA": pin,
               "REF_NAME": ref, "HEAD_SHA": HEAD, "RUN_ATTEMPT": attempt,
               "ACTOR": actor,
               "TRIGGERING_ACTOR": actor if triggering is None else triggering,
               "DRY_RUN": dry, "CONFIRM_UPDATE": confirm,
               "EXPECTED_MAIN_SHA": expected,
               "GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summ)}
        result = subprocess.run(["bash", "-c", gate()], env=env, text=True,
                                capture_output=True, timeout=10)
        return result.returncode, out.read_text() if out.exists() else ""


class SharedUpdateTests(unittest.TestCase):
    def test_all_seventeen_exact_live_roster_positive(self):
        self.assertEqual(len(ROSTER), len(set(ROSTER)))
        self.assertEqual(len(ROSTER), 17)
        self.assertTrue(WAVE3.issubset(ROSTER))
        for repo in ROSTER:
            pin = NEW if repo in WAVE3 else OLD
            with self.subTest(repo=repo):
                self.assertEqual(run(repo, pin), (0, "mode=read-only\n"))
                self.assertEqual(run(repo, pin, dry="false", confirm="UPDATE",
                                     expected=HEAD), (0, "mode=candidate\n"))

    def test_foreign_or_wrong_sha_cannot_be_called(self):
        for repo in ROSTER:
            wrong = OLD if repo in WAVE3 else NEW
            self.assertNotEqual(run(repo, wrong)[0], 0, repo)
        for repo in ("pgextwin/build", "pgextwin/catalog", "other/pgtap",
                     "pgextwin/rogue", "pgextwin/pgtap/../catalog"):
            self.assertNotEqual(run(repo, NEW)[0], 0, repo)

    def test_adversarial_human_request_denied(self):
        for repo in ("pgextwin/hypopg", "pgextwin/pgtap"):
            pin = NEW if repo in WAVE3 else OLD
            defaults = {"dry": "false", "confirm": "UPDATE", "expected": HEAD}
            for changed in (
                {"actor": "github-actions[bot]"},
                {"triggering": "attacker"},
                {"confirm": ""},
                {"confirm": "PUBLISH"},
                {"expected": "b" * 40},
                {"expected": "not-sha"},
                {"ref": "refs/heads/auto-candidate/0123456789abcdef0123"},
                {"event": "push"},
                {"event": "pull_request"},
                {"attempt": "2"},
                {"dry": "garbage"},
            ):
                case = {**defaults, **changed}
                with self.subTest(repo=repo, case=changed):
                    self.assertNotEqual(run(repo, pin, **case)[0], 0)
            self.assertNotEqual(run(repo, pin, confirm="UPDATE")[0], 0)
            self.assertNotEqual(run(repo, pin, expected=HEAD)[0], 0)

    def test_shared_is_read_only_and_has_workflow_outputs(self):
        for value in ("on:\n  workflow_call:",
                      "permissions:\n  contents: read",
                      "value: ${{ jobs.authorize.outputs.mode }}",
                      "needs: authorize", "persist-credentials: false",
                      "ref: ${{ inputs.detector_sha }}",
                      '--watcher-sha "${{ inputs.detector_sha }}"',
                      "mode=candidate", "mode=read-only"):
            self.assertIn(value, WORKFLOW)
        for forbidden in ("contents: write", "issues: write", "actions: write",
                          "pull-requests: write", "secrets.", "gh pr create",
                          "gh release ", "git push", "gh workflow run ",
                          "\n  candidate:\n", "\n  watch_candidate:\n"):
            self.assertNotIn(forbidden, WORKFLOW)


if __name__ == "__main__":
    unittest.main()
