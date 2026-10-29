#!/usr/bin/env python3
"""Regression: unified 17-target request fails closed on forgery and partial proof."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


source = load("unified_source", "scripts/issue311-r05-unified17.py")
complete = load("unified_complete", "scripts/issue311-r05-unified17-completion.py")


class Unified17Tests(unittest.TestCase):
    def test_all_three_python_stages_install_json_schema(self):
        workflow = (ROOT / ".github/workflows/issue311-r05-unified17.yml").read_text()
        self.assertEqual(workflow.count("jsonschema>=4,<5"), 3)

    def test_full_allowlist_is_frozen_nonpublishing(self):
        self.assertEqual(len(source.win.TARGETS), 17)
        self.assertEqual(len(set(source.win.TARGETS)), 17)
        self.assertEqual(source.win.REQUEST, source.REQUEST)
        self.assertEqual(source.win.REQUEST_PATH, source.REQUEST_PATH)
        self.assertNotEqual(source.win.ARTIFACT_PREFIX, "issue311-r05-win17-")

    def test_unsigned_foreign_source_denied_before_network(self):
        for override in ({"actor": {"login": "random-user"}},
                         {"name": "forged-workflow"}, {"conclusion": "failure"},
                         {"run_attempt": 2}, {"path": ".github/workflows/other.yml"}):
            run = {"id": 23, "name": source.SOURCE_NAME, "path": source.SOURCE_PATH,
                   "event": "push", "head_branch": "main", "run_attempt": 1,
                   "status": "completed", "conclusion": "success",
                   "actor": {"login": "ShutenOishi"}, "head_sha": "a" * 40}
            run.update(override)
            with self.subTest(override=override):
                with self.assertRaisesRegex(ValueError, "DENY"):
                    complete.validated_source({"action": "completed",
                        "repository": {"full_name": "pgextwin/build"}, "workflow_run": run})

    def test_missing_or_forged_17_original_artifacts_denied(self):
        verifier = source.bridge
        verifier.ZIP_PREFIX = source.PREFIX
        verifier.ZIP_TERMINAL = "issue311-r05-win17-terminal"
        for artifacts in ([], [{"name": source.PREFIX + "orafce",
                                 "workflow_run": {"id": 8}, "expired": False,
                                 "digest": "sha256:" + "a" * 64, "id": 4}]):
            with self.assertRaisesRegex(ValueError, "DENY"):
                verifier.parse_artifacts({"total_count": len(artifacts),
                                          "artifacts": artifacts}, 8)

    def test_app_lifecycle_rejects_partial_or_replayed_receipts(self):
        targets = sorted(source.win.TARGETS)
        initial = source.life.new(source.REQUEST, "a" * 64, "b" * 40, targets,
                                  "2026-10-29T23:00:00Z")
        bound = source.life.bind_source(initial, 0, "source-run",
                                        run_id=71, attempt=1, head_sha="b" * 40)
        for partial in ({t: "SUCCESS" for t in targets[:-1]},
                        {t: ("FAILED" if t == targets[0] else "SUCCESS") for t in targets}):
            with self.subTest(partial=partial):
                with self.assertRaises(source.life.Denied):
                    source.life.record_completion(
                        bound, 1, "complete", run_id=72, attempt=1, source_id=71,
                        outcome="NO_UPDATE", target_outcomes=partial, original_zip_sha="c" * 64)
        passed = source.life.record_completion(
            bound, 1, "complete", run_id=72, attempt=1, source_id=71,
            outcome="NO_UPDATE", target_outcomes={t: "SUCCESS" for t in targets},
            original_zip_sha="c" * 64)
        self.assertEqual((passed["revision"], passed["terminal"]), (2, "NO_UPDATE"))
        with self.assertRaises(source.life.Denied):
            source.life.record_completion(passed, 2, "again", run_id=73, attempt=1,
                 source_id=71, outcome="NO_UPDATE",
                 target_outcomes={t: "SUCCESS" for t in targets},
                 original_zip_sha="c" * 64)


if __name__ == "__main__":
    unittest.main()
