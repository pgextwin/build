#!/usr/bin/env python3
"""F21-02: selective CI router and processing-type concurrency contract.

Covers the CB-73 comparison rows: the four input types (single extension,
multiple extensions, shared build foundation, no target), the deletion /
rename variants that must evaluate both the old and the new path, the
safety-side fallback for unclassified paths, extraction-failure
rejections, and the concurrency contract (one group per processing
type, cancel-in-progress false everywhere, series groups carrying the
matrix keys).  The representative inputs used here are the ones recorded
in CB-73 (X-09).
"""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci-router.py"
WORKFLOWS = ROOT / ".github" / "workflows"


def load_module():
    spec = importlib.util.spec_from_file_location("ci_router", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


router = load_module()
REGISTERED = router.registered_extensions()
SMOKE = sorted(router.PILOT_SMOKE_EXTENSIONS)


def route(changes, smoke=router.PILOT_SMOKE_EXTENSIONS):
    return router.route_changes(changes, registered=REGISTERED, smoke=smoke)


class RegistryTests(unittest.TestCase):
    def test_fleet_registry_has_26_extensions(self):
        self.assertEqual(len(REGISTERED), 26)
        for name in ("pg_permissions", "pg_bigm", "pgaudit", "plpgsql_check"):
            self.assertIn(name, REGISTERED)

    def test_smoke_set_is_the_three_pilots(self):
        # Sorted order is by code point: '_' (0x5F) precedes 'a', so the
        # pg_* names come before pgaudit.
        self.assertEqual(SMOKE, ["pg_bigm", "pg_permissions", "pgaudit"])
        for name in SMOKE:
            self.assertIn(name, REGISTERED)


class RoutingTypeTests(unittest.TestCase):
    """CB-73 rows 1-4: the four representative input types."""

    def test_type1_single_extension(self):
        result = route([{"filename": "extensions/pg_bigm/extension.json",
                         "status": "modified"}])
        self.assertEqual(result["targets"], ["pg_bigm"])
        self.assertEqual(result["matrix"], {"include": [{"extension": "pg_bigm"}]})
        self.assertTrue(result["has_targets"])
        # The other two pilots and the other 23 extensions do not start.
        self.assertNotIn("pg_permissions", result["targets"])
        self.assertNotIn("pgaudit", result["targets"])
        self.assertEqual(result["resolver_conclusion"], "success")
        self.assertEqual(result["pending"], 0)

    def test_type2_multiple_extensions_union(self):
        result = route([
            {"filename": "extensions/pg_bigm/extension.json", "status": "modified"},
            {"filename": "extensions/pgaudit/tests/test-contract.json", "status": "added"},
        ])
        self.assertEqual(result["targets"], ["pg_bigm", "pgaudit"])
        self.assertEqual(
            result["matrix"],
            {"include": [{"extension": "pg_bigm"}, {"extension": "pgaudit"}]},
        )
        self.assertEqual(result["resolver_conclusion"], "success")
        self.assertEqual(result["pending"], 0)

    def test_type3_shared_foundation_selects_smoke_set(self):
        result = route([{"filename": "scripts/central-package.py", "status": "modified"}])
        self.assertEqual(result["targets"], SMOKE)
        self.assertEqual(result["resolver_conclusion"], "success")
        self.assertEqual(result["pending"], 0)

    def test_type3_shared_workflow_and_schema_paths(self):
        for path in (".github/workflows/build-extension.yml",
                     "schema/central-extension.schema.json",
                     "windows/ci/package.json",
                     "metadata/automation-fleet.json",
                     "tests/test-ci-router.py"):
            with self.subTest(path=path):
                self.assertEqual(route([{"filename": path, "status": "modified"}])["targets"],
                                 SMOKE)

    def test_type3_shared_policy_all_selects_every_registered_extension(self):
        result = router.route_changes(
            [{"filename": "scripts/central-package.py", "status": "modified"}],
            registered=REGISTERED, smoke=REGISTERED)
        self.assertEqual(result["targets"], REGISTERED)

    def test_type4_documentation_only_has_no_targets_but_succeeds(self):
        result = route([
            {"filename": "docs/selective-ci.md", "status": "added"},
            {"filename": "README.md", "status": "modified"},
        ])
        self.assertEqual(result["targets"], [])
        self.assertEqual(result["matrix"], {"include": []})
        self.assertFalse(result["has_targets"])
        self.assertEqual(result["resolver_conclusion"], "success")
        self.assertEqual(result["pending"], 0)

    def test_empty_change_list_succeeds_with_no_targets(self):
        result = route([])
        self.assertEqual(result["targets"], [])
        self.assertEqual(result["resolver_conclusion"], "success")
        self.assertEqual(result["pending"], 0)


class DeleteRenameTests(unittest.TestCase):
    """CB-73 row 5: deletions and renames evaluate old and new paths."""

    def test_deleted_extension_file_still_selects_the_extension(self):
        result = route([{"filename": "extensions/pg_cron/extension.json",
                         "status": "removed"}])
        self.assertEqual(result["targets"], ["pg_cron"])

    def test_rename_unions_old_and_new_extension(self):
        result = route([{
            "filename": "extensions/pg_repack/patches/0001-fix.patch",
            "status": "renamed",
            "previous_filename": "extensions/wal2json/patches/0001-fix.patch",
        }])
        self.assertEqual(result["targets"], ["pg_repack", "wal2json"])
        kinds = {(entry["path"], entry["kind"]) for entry in result["classified"]}
        self.assertIn(("extensions/wal2json/patches/0001-fix.patch", "extension"), kinds)
        self.assertIn(("extensions/pg_repack/patches/0001-fix.patch", "extension"), kinds)

    def test_rename_out_of_an_extension_keeps_the_old_side(self):
        result = route([{
            "filename": "docs/hypopg-notes.md",
            "status": "renamed",
            "previous_filename": "extensions/hypopg/extension.json",
        }])
        self.assertEqual(result["targets"], ["hypopg"])

    def test_rename_without_previous_filename_is_rejected(self):
        with self.assertRaises(router.RouterError):
            route([{"filename": "extensions/pg_bigm/extension.json",
                    "status": "renamed"}])


class FallbackAndFailureTests(unittest.TestCase):
    def test_unclassified_path_selects_all_registered_extensions(self):
        result = route([{"filename": "LICENSE", "status": "modified"}])
        self.assertEqual(result["targets"], REGISTERED)
        self.assertEqual(result["classified"][0]["kind"], "unclassified")

    def test_mixed_change_unions_each_class(self):
        result = route([
            {"filename": "extensions/pg_cron/extension.json", "status": "modified"},
            {"filename": "scripts/ci-router.py", "status": "modified"},
            {"filename": "docs/selective-ci.md", "status": "modified"},
        ])
        self.assertEqual(result["targets"], sorted({"pg_cron"} | set(SMOKE)))

    def test_windows_reserved_extension_name_is_an_extraction_failure(self):
        with self.assertRaises(router.RouterError):
            route([{"filename": "extensions/aux/extension.json", "status": "added"}])

    def test_trailing_dot_extension_name_is_an_extraction_failure(self):
        with self.assertRaises(router.RouterError):
            route([{"filename": "extensions/pg_bigm./extension.json", "status": "added"}])

    def test_malformed_inputs_are_extraction_failures(self):
        for bad in ({"filename": "x"},                      # not a list
                    [{"status": "modified"}],               # no filename
                    [{"filename": 3}],                      # non-string filename
                    [{"filename": "/abs/path"}],            # absolute path
                    [{"filename": "extensions/../secret"}],  # traversal
                    [{"filename": "extensions//extension.json"}]):  # empty component
            with self.subTest(bad=bad):
                with self.assertRaises(router.RouterError):
                    route(bad)

    def test_routing_is_deterministic(self):
        changes = [
            {"filename": "extensions/pg_bigm/extension.json", "status": "modified"},
            {"filename": "scripts/central-package.py", "status": "modified"},
        ]
        self.assertEqual(json.dumps(route(changes), sort_keys=True),
                         json.dumps(route(changes), sort_keys=True))


class ConcurrencyContractTests(unittest.TestCase):
    """CB-73 row 6 and the DESIGN 2.2 / PLAN-F 5.4 contract."""

    def test_every_processing_type_fixes_cancel_in_progress_false(self):
        for kind, entry in router.CONCURRENCY_CONTRACT.items():
            with self.subTest(kind=kind):
                self.assertIs(entry["cancel_in_progress"], False)

    def test_templated_groups_are_distinct_per_processing_type(self):
        templates = [entry["group"] for entry in router.CONCURRENCY_CONTRACT.values()
                     if entry["group"] is not None]
        self.assertEqual(len(templates), len(set(templates)))

    def test_pr_validation_group_rendering(self):
        self.assertEqual(
            router.concurrency_group("pr-validation", extension="pg_bigm", pr_number=712),
            "ci-pg_bigm-pr-712")

    def test_series_groups_carry_the_pg_major_matrix_key(self):
        pg15 = router.concurrency_group("pr-validation", extension="pg_bigm",
                                        pr_number=712, pg_major=15)
        pg16 = router.concurrency_group("pr-validation", extension="pg_bigm",
                                        pr_number=712, pg_major=16)
        other = router.concurrency_group("pr-validation", extension="pgaudit",
                                         pr_number=712, pg_major=15)
        self.assertNotEqual(pg15, pg16)
        self.assertNotEqual(pg15, other)

    def test_candidate_groups_separate_candidates_and_writers(self):
        self.assertEqual(
            router.concurrency_group("candidate-ci", extension="pg_bigm",
                                     candidate_id="abc123"),
            "candidate-ci-pg_bigm-abc123")
        self.assertNotEqual(
            router.concurrency_group("candidate-ci", extension="pg_bigm",
                                     candidate_id="abc123"),
            router.concurrency_group("candidate-ci", extension="pg_bigm",
                                     candidate_id="def456"))
        self.assertEqual(
            router.concurrency_group("candidate-writer", extension="pg_bigm"),
            "candidate-writer-pg_bigm")
        self.assertEqual(router.concurrency_group("fleet-watch"), "fleet-watch")
        self.assertEqual(
            router.concurrency_group("postmerge", extension="pg_bigm"),
            "postmerge-pg_bigm")

    def test_existing_units_are_not_renamed_by_the_router(self):
        for kind in ("signing", "publishing", "catalog-update"):
            with self.subTest(kind=kind):
                with self.assertRaises(router.RouterError):
                    router.concurrency_group(kind, extension="pg_bigm")

    def test_missing_template_value_is_rejected(self):
        with self.assertRaises(router.RouterError):
            router.concurrency_group("pr-validation", extension="pg_bigm")
        with self.assertRaises(router.RouterError):
            router.concurrency_group("no-such-type", extension="pg_bigm")

    def test_validate_workflow_declares_the_router_group(self):
        text = (WORKFLOWS / "validate.yml").read_text(encoding="utf-8")
        self.assertIn(f"group: {router.ROUTER_WORKFLOW_GROUP}", text)
        self.assertIn("cancel-in-progress: false", text)

    def test_no_workflow_cancels_in_progress(self):
        # CB-73 fixed value: every processing-type group in the live
        # workflows fixes cancel-in-progress to false.
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            for line in workflow.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("cancel-in-progress:"):
                    self.assertEqual(
                        stripped, "cancel-in-progress: false",
                        f"{workflow.name}: {stripped}")


class CliTests(unittest.TestCase):
    def run_cli(self, payload, *extra):
        with TemporaryDirectory() as tmp:
            files = Path(tmp) / "files.json"
            files.write_text(payload, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--files", str(files), *extra],
                capture_output=True, text=True, cwd=ROOT)

    def test_cli_json_output(self):
        proc = self.run_cli(json.dumps(
            [{"filename": "extensions/pg_bigm/extension.json", "status": "modified"}]))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["targets"], ["pg_bigm"])
        self.assertEqual(result["pending"], 0)

    def test_cli_github_output(self):
        proc = self.run_cli(json.dumps(
            [{"filename": "docs/selective-ci.md", "status": "added"}]),
            "--format", "github")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = dict(line.split("=", 1) for line in proc.stdout.strip().splitlines())
        self.assertEqual(lines["has_targets"], "false")
        self.assertEqual(lines["resolver_conclusion"], "success")
        self.assertEqual(lines["pending"], "0")
        self.assertEqual(json.loads(lines["matrix"]), {"include": []})

    def test_cli_rejects_malformed_json(self):
        proc = self.run_cli("{not json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("ci-router:", proc.stderr)


if __name__ == "__main__":
    unittest.main()
