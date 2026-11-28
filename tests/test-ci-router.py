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

Fix round 1 (Neon audit B2-M1..M4, B2-N1..N2) adds: the tree-union
registry path (extensions_root) with the PR-B1 layout rules (no files
directly under extensions/, no symbolic links, no case-insensitive
collisions, the schema name pattern), the classification order (shared
roots before the documentation rule, documentation limited to docs/ and
repository-root Markdown), the concurrency_group() value validation and
router rendering, the status value set and control-character rejection,
and structural (PyYAML) workflow concurrency checks.  PyYAML is
installed by validate.yml in the resolver job before this suite runs.

Fix round 2 (Sol audit B2-SOL-M1 / B2-SOL-M2) adds: the unregistered
extension name rule (a legal but unregistered extensions/ name falls
back to every registered extension instead of becoming a lone target),
the launch matrix (routed targets intersected with the packaging
subtrees present in the tree) in both CLI output formats, and the
structural checks for the validate.yml launch wiring (resolver job
outputs, the route step's $GITHUB_OUTPUT publication, and the
dependent extension-ci matrix job consuming the launch matrix through
fromJSON).

Fix round 3 (Neon re-audit B2R3-M1 / B2R3-N1) adds: the extension-ci
launch inputs pinned to the PR-B1 single-layout paths
(extensions/<name>/extension.json and
extensions/<name>/tests/test-contract.json, never the legacy config/
hierarchy), the per-event concurrency group rendering in validate.yml
(pr-validation for pull requests, postmerge otherwise), and the
launchable_targets() guard against a symbolic-link extensions/ root
on direct calls.
"""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

import yaml

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

    def make_tree(self, tmp, names):
        layout = Path(tmp) / "extensions"
        layout.mkdir()
        for name in names:
            (layout / name).mkdir()
        return Path(tmp)

    def test_tree_union_adds_tree_extensions_to_the_fleet_set(self):
        # B2-M1: the extensions_root union path (previously untested).
        with TemporaryDirectory() as tmp:
            root = self.make_tree(tmp, ["future_ext", "pg_bigm"])
            names = router.registered_extensions(extensions_root=root)
        self.assertEqual(len(names), 27)
        self.assertIn("future_ext", names)
        self.assertIn("pg_bigm", names)

    def test_tree_union_rejects_a_casefold_collision_with_the_fleet(self):
        with TemporaryDirectory() as tmp:
            root = self.make_tree(tmp, ["PG_BIGM"])
            with self.assertRaises(router.RouterError):
                router.registered_extensions(extensions_root=root)

    def test_tree_union_rejects_a_casefold_collision_inside_the_tree(self):
        with TemporaryDirectory() as tmp:
            root = self.make_tree(tmp, ["Zeta_One", "zeta_one"])
            with self.assertRaises(router.RouterError):
                router.registered_extensions(extensions_root=root)

    def test_tree_union_rejects_an_invalid_tree_extension_name(self):
        with TemporaryDirectory() as tmp:
            root = self.make_tree(tmp, ["a..b"])
            with self.assertRaises(router.RouterError):
                router.registered_extensions(extensions_root=root)

    def make_symlink(self, target, link, *, is_dir):
        try:
            os.symlink(target, link, target_is_directory=is_dir)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symbolic links unavailable here: {exc}")

    def test_tree_union_rejects_a_symlink_extension_root(self):
        with TemporaryDirectory() as tmp:
            root = self.make_tree(tmp, ["real_ext"])
            self.make_symlink(root / "extensions" / "real_ext",
                              root / "extensions" / "sym_ext", is_dir=True)
            with self.assertRaises(router.RouterError):
                router.registered_extensions(extensions_root=root)

    def test_tree_union_rejects_a_symlink_extensions_root(self):
        with TemporaryDirectory() as tmp:
            real = Path(tmp) / "real-extensions"
            real.mkdir()
            (real / "some_ext").mkdir()
            self.make_symlink(real, Path(tmp) / "extensions", is_dir=True)
            with self.assertRaises(router.RouterError):
                router.registered_extensions(extensions_root=Path(tmp))

    def test_fleet_registry_shape_errors_are_router_errors(self):
        # B2-N1: a missing file, a non-object document and non-UTF-8
        # bytes are clean RouterErrors, not uncaught exceptions.
        with TemporaryDirectory() as tmp:
            array = Path(tmp) / "array.json"
            array.write_text("[]", encoding="utf-8")
            with self.assertRaises(router.RouterError):
                router.registered_extensions(fleet_path=array)
            binary = Path(tmp) / "binary.json"
            binary.write_bytes(b"\xff\xfe{}")
            with self.assertRaises(router.RouterError):
                router.registered_extensions(fleet_path=binary)
            with self.assertRaises(router.RouterError):
                router.registered_extensions(fleet_path=Path(tmp) / "missing.json")


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

    def test_shared_root_markdown_is_a_shared_change(self):
        # B2-M2: the documentation rule must not override the shared
        # roots -- a Markdown file under scripts/, tests/ or .github/
        # is a shared-foundation change and selects the smoke set.
        for path in ("tests/fixtures/README.md",
                     "scripts/README.md",
                     ".github/workflows/README.md",
                     "windows/README.md"):
            with self.subTest(path=path):
                result = route([{"filename": path, "status": "modified"}])
                self.assertEqual(result["targets"], SMOKE)
                self.assertEqual(result["classified"][0]["kind"], "shared")

    def test_markdown_outside_docs_and_root_is_unclassified(self):
        # B2-M2: documentation is limited to docs/** and Markdown at
        # the repository root; a Markdown file anywhere else falls
        # back to the safety side instead of selecting nothing.
        result = route([{"filename": "tools/notes.md", "status": "added"}])
        self.assertEqual(result["targets"], REGISTERED)
        self.assertEqual(result["classified"][0]["kind"], "unclassified")


class LayoutAndCollisionTests(unittest.TestCase):
    """B2-M1: the PR-B1 layout and name rules on extension paths."""

    def test_file_directly_under_extensions_is_an_extraction_failure(self):
        # A file directly under extensions/ is not extension content;
        # its file name must never enter the matrix as a fake
        # extension name.
        for path in ("extensions/README.md", "extensions/.gitkeep",
                     "extensions/stray.txt"):
            with self.subTest(path=path):
                with self.assertRaises(router.RouterError):
                    route([{"filename": path, "status": "added"}])

    def test_leading_dot_and_repeated_dot_names_are_extraction_failures(self):
        # The PR-B1 schema name pattern (no leading or repeated dots),
        # which central.load_validator() enforces for declarations.
        for path in ("extensions/.hidden/extension.json",
                     "extensions/a..b/extension.json"):
            with self.subTest(path=path):
                with self.assertRaises(router.RouterError):
                    route([{"filename": path, "status": "added"}])

    def test_case_variant_of_a_registered_extension_is_an_extraction_failure(self):
        with self.assertRaises(router.RouterError):
            route([{"filename": "extensions/PG_BIGM/extension.json",
                    "status": "modified"}])

    def test_case_variants_within_one_change_are_an_extraction_failure(self):
        with self.assertRaises(router.RouterError):
            route([
                {"filename": "extensions/Zeta_One/extension.json", "status": "added"},
                {"filename": "extensions/zeta_one/extension.json", "status": "added"},
            ])

    def test_extensions_root_case_variant_is_an_extraction_failure(self):
        # B2-M2: on a Windows checkout Extensions/ is the extensions/
        # root; it must not fall through to the documentation rule.
        with self.assertRaises(router.RouterError):
            route([{"filename": "Extensions/pg_bigm/README.md",
                    "status": "modified"}])


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

    def test_deleted_unregistered_extension_falls_back_to_all_registered(self):
        # B2-SOL-M2 (the audit's independent reproduction): the old
        # directory and its registry entry are already gone, so the
        # name is legal but unregistered.  It must not become a lone
        # fictional target; the impact is unknown, so the safety side
        # (every registered extension) is selected and the resolver
        # still concludes successfully.
        result = route([{"filename": "extensions/not_registered_yet/old.txt",
                         "status": "removed"}])
        self.assertEqual(result["targets"], REGISTERED)
        self.assertEqual(result["classified"][0]["kind"], "unclassified")
        self.assertTrue(result["has_targets"])
        self.assertEqual(result["resolver_conclusion"], "success")
        self.assertEqual(result["pending"], 0)

    def test_modified_unregistered_extension_falls_back_to_all_registered(self):
        result = route([{"filename": "extensions/not_registered_yet/extension.json",
                         "status": "modified"}])
        self.assertEqual(result["targets"], REGISTERED)
        self.assertEqual(result["classified"][0]["kind"], "unclassified")

    def test_rename_with_unregistered_old_side_falls_back(self):
        # B2-SOL-M2: the old side of a rename is no longer registered
        # (renamed away together with its registry entry).
        result = route([{
            "filename": "extensions/pg_bigm/extension.json",
            "status": "renamed",
            "previous_filename": "extensions/retired_ext/extension.json",
        }])
        self.assertEqual(result["targets"], REGISTERED)

    def test_rename_to_unregistered_new_side_falls_back(self):
        # B2-SOL-M2: the new side is not (yet) registered; the old
        # side's extension is still selected, and the unknown impact
        # of the new side widens the selection to the safety side.
        result = route([{
            "filename": "extensions/renamed_ext/extension.json",
            "status": "renamed",
            "previous_filename": "extensions/pg_cron/extension.json",
        }])
        self.assertEqual(result["targets"], REGISTERED)
        self.assertIn("pg_cron", result["targets"])


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

    def test_status_is_required_and_must_be_a_github_value(self):
        # B2-N1: a missing status, an unknown value, a case variant or
        # a non-string status is malformed input, not a silent accept.
        for bad in ({"filename": "docs/notes.md"},
                    {"filename": "docs/notes.md", "status": "bogus"},
                    {"filename": "docs/notes.md", "status": "RENAMED"},
                    {"filename": "docs/notes.md", "status": 3},
                    {"filename": "docs/notes.md", "status": None}):
            with self.subTest(bad=bad):
                with self.assertRaises(router.RouterError):
                    route([bad])

    def test_control_characters_in_a_path_are_extraction_failures(self):
        # B2-N1.
        for path in ("extensions/pg_bigm/foo\nbar", "extensions/pg_bigm/foo\x00bar",
                     "extensions/pg_bigm/foo\x7fbar"):
            with self.subTest(path=path):
                with self.assertRaises(router.RouterError):
                    route([{"filename": path, "status": "added"}])

    def test_routing_is_deterministic(self):
        changes = [
            {"filename": "extensions/pg_bigm/extension.json", "status": "modified"},
            {"filename": "scripts/central-package.py", "status": "modified"},
        ]
        self.assertEqual(json.dumps(route(changes), sort_keys=True),
                         json.dumps(route(changes), sort_keys=True))


class LaunchableTargetsTests(unittest.TestCase):
    """B2-SOL-M1: the launch matrix is the routed targets intersected
    with the packaging subtrees present in the tree."""

    def make_tree(self, tmp, names):
        layout = Path(tmp) / "extensions"
        layout.mkdir()
        for name in names:
            (layout / name).mkdir()
        return Path(tmp)

    def test_launchable_targets_intersect_with_present_subtrees(self):
        with TemporaryDirectory() as tmp:
            root = self.make_tree(tmp, ["pg_bigm"])
            self.assertEqual(
                router.launchable_targets(["pg_bigm", "pgaudit"], root),
                ["pg_bigm"])

    def test_launchable_targets_empty_without_subtrees(self):
        with TemporaryDirectory() as tmp:
            self.assertEqual(
                router.launchable_targets(["pg_bigm", "pgaudit"], Path(tmp)), [])
            # The live tree has no extensions/ subtrees yet either:
            # routing still reports the targets, the launch matrix is
            # empty until the F2-2 / F3a subtrees land.
            self.assertEqual(router.launchable_targets(REGISTERED, ROOT), [])

    def test_launchable_targets_ignore_files_in_place_of_subtrees(self):
        with TemporaryDirectory() as tmp:
            layout = Path(tmp) / "extensions"
            layout.mkdir()
            (layout / "pg_bigm").write_text("not a directory", encoding="utf-8")
            self.assertEqual(
                router.launchable_targets(["pg_bigm"], Path(tmp)), [])

    def test_launchable_targets_reject_symlinked_extensions_root(self):
        # B2R3-N1: the guard is self-contained for direct callers --
        # an extensions/ root that is itself a symbolic link launches
        # nothing, even though the link target holds a real subtree.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_layout = root / "real" / "extensions"
            (real_layout / "pg_bigm").mkdir(parents=True)
            (root / "extensions").symlink_to(
                real_layout, target_is_directory=True)
            self.assertEqual(
                router.launchable_targets(["pg_bigm"], root), [])


class WorkflowWiringTests(unittest.TestCase):
    """B2-SOL-M1: validate.yml consumes the router result as a launch
    contract -- resolver job outputs in, fromJSON launch matrix out."""

    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.safe_load(
            (WORKFLOWS / "validate.yml").read_text(encoding="utf-8"))

    def test_resolver_job_publishes_the_router_outputs(self):
        outputs = self.workflow["jobs"]["resolver"]["outputs"]
        for key in ("matrix", "has_targets", "targets", "launch_matrix",
                    "has_launch_targets", "resolver_conclusion", "pending"):
            with self.subTest(key=key):
                self.assertEqual(
                    outputs[key], "${{ steps.route.outputs." + key + " }}")

    def test_route_step_publishes_github_output(self):
        steps = self.workflow["jobs"]["resolver"]["steps"]
        route_steps = [step for step in steps
                       if isinstance(step, dict) and step.get("id") == "route"]
        self.assertEqual(len(route_steps), 1)
        run = route_steps[0]["run"]
        self.assertIn("--format github", run)
        self.assertIn('>> "$GITHUB_OUTPUT"', run)

    def test_extension_ci_job_consumes_the_launch_matrix(self):
        job = self.workflow["jobs"]["extension-ci"]
        needs = job["needs"]
        self.assertEqual([needs] if isinstance(needs, str) else needs,
                         ["resolver"])
        self.assertIn("needs.resolver.outputs.has_launch_targets", job["if"])
        self.assertEqual(job["strategy"]["matrix"],
                         "${{ fromJSON(needs.resolver.outputs.launch_matrix) }}")
        self.assertIs(job["strategy"]["fail-fast"], False)
        self.assertEqual(job["uses"], "./.github/workflows/build-extension.yml")
        # B2R3-M1: the launch inputs follow the PR-B1 single-layout
        # contract (extension.json at the subtree root, the Test
        # Contract under tests/), which the reusable workflow resolves
        # relative to the caller root.  The legacy per-repo config/
        # hierarchy is not part of that layout -- central-extension.py
        # rejects a config/ directory outright -- so the inputs must
        # never point back into it.
        self.assertEqual(
            job["with"]["extension_config_path"],
            "extensions/${{ matrix.extension }}/extension.json")
        self.assertEqual(
            job["with"]["test_contract_path"],
            "extensions/${{ matrix.extension }}/tests/test-contract.json")
        for value in job["with"].values():
            self.assertNotIn("/config/", value)
        self.assertIn("extension.json", router.central.ALLOWED_FILES)
        self.assertNotIn("config", router.central.ALLOWED_DIRS)
        # B2R3-N1: the group renders the router contract templates
        # per event -- pr-validation on pull requests, postmerge on
        # pushes / dispatches -- instead of a pr- group glued to the
        # ref outside pull requests.
        group = job["concurrency"]["group"]
        self.assertIn("github.event_name == 'pull_request'", group)
        self.assertIn(
            "format('ci-{0}-pr-{1}', matrix.extension, "
            "github.event.pull_request.number)", group)
        self.assertIn("format('postmerge-{0}', matrix.extension)", group)
        self.assertEqual(
            router.concurrency_group(
                "pr-validation", extension="pg_bigm", pr_number=712),
            "ci-pg_bigm-pr-712")
        self.assertEqual(
            router.concurrency_group("postmerge", extension="pg_bigm"),
            "postmerge-pg_bigm")
        self.assertIs(job["concurrency"]["cancel-in-progress"], False)


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

    def test_router_group_renders_the_workflow_group(self):
        # B2-M4: the router type renders the ROUTER_WORKFLOW_GROUP
        # shape from its workflow and scope values.
        self.assertEqual(
            router.concurrency_group(
                "router", workflow="Validate build infrastructure", scope="713"),
            "ci-router-Validate build infrastructure-713")
        self.assertEqual(
            router.concurrency_group(
                "router", workflow="Validate build infrastructure",
                scope="refs/heads/main"),
            "ci-router-Validate build infrastructure-refs/heads/main")

    def test_router_group_requires_workflow_and_scope(self):
        with self.assertRaises(router.RouterError):
            router.concurrency_group("router", scope="713")
        with self.assertRaises(router.RouterError):
            router.concurrency_group(
                "router", workflow="Validate build infrastructure")

    def test_group_values_are_validated(self):
        # B2-M4: empty values, Windows-reserved names, bool / negative
        # / empty numbers and empty candidate ids would collapse or
        # split groups, so all of them are rejected.
        bad_calls = [
            (("pr-validation",), {"extension": "", "pr_number": 712}),
            (("pr-validation",), {"extension": "aux", "pr_number": 712}),
            (("pr-validation",), {"extension": "pg_bigm", "pr_number": -1}),
            (("pr-validation",), {"extension": "pg_bigm", "pr_number": True}),
            (("pr-validation",), {"extension": "pg_bigm", "pr_number": "712"}),
            (("pr-validation",), {"extension": "pg_bigm", "pr_number": 712,
                                  "pg_major": True}),
            (("pr-validation",), {"extension": "pg_bigm", "pr_number": 712,
                                  "pg_major": ""}),
            (("pr-validation",), {"extension": "pg_bigm", "pr_number": 712,
                                  "pg_major": 0}),
            (("candidate-ci",), {"extension": "pg_bigm", "candidate_id": ""}),
            (("candidate-ci",), {"extension": "pg_bigm",
                                 "candidate_id": "white space"}),
            (("router",), {"workflow": "", "scope": "713"}),
        ]
        for args, kwargs in bad_calls:
            with self.subTest(args=args, kwargs=kwargs):
                with self.assertRaises(router.RouterError):
                    router.concurrency_group(*args, **kwargs)

    def test_placeholder_injection_through_a_value_is_rejected(self):
        # B2-M4: substitution is a single pass over validated values,
        # so a value carrying a placeholder can never be re-expanded.
        with self.assertRaises(router.RouterError):
            router.concurrency_group(
                "pr-validation", extension="{pr_number}", pr_number=712)
        with self.assertRaises(router.RouterError):
            router.concurrency_group(
                "router", workflow="{scope}", scope="713")

    def test_validate_workflow_declares_the_router_group(self):
        # B2-N2: structural (PyYAML) check of the workflow, not a
        # substring match.
        data = yaml.safe_load((WORKFLOWS / "validate.yml").read_text(encoding="utf-8"))
        concurrency = data["concurrency"]
        self.assertEqual(concurrency["group"], router.ROUTER_WORKFLOW_GROUP)
        self.assertIs(concurrency["cancel-in-progress"], False)

    def test_no_workflow_cancels_in_progress(self):
        # B2-N2 / CB-73 fixed value: every concurrency declaration in
        # the live workflows -- top level and job level, *.yml and
        # *.yaml, mapping or flow form -- fixes cancel-in-progress to
        # false (an absent flag keeps the GitHub default, false).
        workflows = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
        self.assertTrue(workflows)
        declarations = 0
        for workflow in workflows:
            data = yaml.safe_load(workflow.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            blocks = [data.get("concurrency")]
            jobs = data.get("jobs")
            if isinstance(jobs, dict):
                blocks += [job.get("concurrency") for job in jobs.values()
                           if isinstance(job, dict)]
            for block in blocks:
                if block is None:
                    continue
                declarations += 1
                if isinstance(block, dict):
                    self.assertIs(
                        block.get("cancel-in-progress", False), False,
                        f"{workflow.name}: {block}")
        self.assertGreater(declarations, 0)


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

    def test_cli_json_output_includes_the_launch_fields(self):
        proc = self.run_cli(json.dumps(
            [{"filename": "extensions/pg_bigm/extension.json", "status": "modified"}]))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        # The live tree has no extensions/ subtrees yet, so the routed
        # target is reported but nothing is launchable (B2-SOL-M1).
        self.assertEqual(result["launch_targets"], [])
        self.assertEqual(result["launch_matrix"], {"include": []})
        self.assertIs(result["has_launch_targets"], False)

    def test_cli_github_output_carries_the_launch_contract(self):
        # B2-SOL-M1: the $GITHUB_OUTPUT form the resolver job publishes
        # carries the launch matrix in a fromJSON-ready single line.
        proc = self.run_cli(json.dumps(
            [{"filename": "extensions/pg_bigm/extension.json", "status": "modified"}]),
            "--format", "github")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = dict(line.split("=", 1) for line in proc.stdout.strip().splitlines())
        self.assertEqual(lines["has_targets"], "true")
        self.assertEqual(lines["has_launch_targets"], "false")
        self.assertEqual(json.loads(lines["launch_matrix"]), {"include": []})
        self.assertEqual(json.loads(lines["matrix"]),
                         {"include": [{"extension": "pg_bigm"}]})

    def test_cli_launch_matrix_with_a_present_subtree(self):
        # B2-SOL-M1: with a packaging subtree present in the tree, the
        # shared-foundation smoke set routes three targets and the one
        # landed extension becomes the launch matrix.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "extensions" / "pg_bigm").mkdir(parents=True)
            fleet = root / "fleet.json"
            fleet.write_text(json.dumps({"entries": [
                {"repository": "pgextwin/pg_bigm"},
                {"repository": "pgextwin/pgaudit"},
            ]}), encoding="utf-8")
            files = root / "files.json"
            files.write_text(json.dumps(
                [{"filename": "scripts/ci-router.py", "status": "modified"}]),
                encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--files", str(files),
                 "--fleet", str(fleet), "--extensions-root", str(root),
                 "--format", "github"],
                capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = dict(line.split("=", 1) for line in proc.stdout.strip().splitlines())
        self.assertEqual(lines["has_targets"], "true")
        self.assertEqual(lines["has_launch_targets"], "true")
        self.assertEqual(json.loads(lines["launch_matrix"]),
                         {"include": [{"extension": "pg_bigm"}]})

    def test_cli_rejects_malformed_json(self):
        proc = self.run_cli("{not json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("ci-router:", proc.stderr)

    def test_cli_missing_files_input_is_a_clean_error(self):
        # B2-N1: an unreadable --files input is a RouterError (exit 2
        # with the ci-router: prefix), not an uncaught traceback.
        with TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--files",
                 str(Path(tmp) / "missing.json")],
                capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("ci-router:", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()
