#!/usr/bin/env python3
"""F21-01: central declaration conversion, schema and layout validation.

Covers conversion of the real legacy two-layer declarations of the three
pilots (pg_permissions, pg_bigm, pgaudit), the normalized central schema,
the N-01..N-18 non-carry-in rejections, empty asset rejections, and the
adapter privilege boundary (DESIGN chapter 1, F2-1-PACKAGE F21-01).
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "central-extension"
SCRIPT = ROOT / "scripts" / "central-extension.py"


def load_module():
    spec = importlib.util.spec_from_file_location("central_extension", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


central = load_module()


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def convert(name, **kwargs):
    return central.convert_declaration(
        load_fixture(f"{name}-extension.json"),
        load_fixture(f"{name}-package.json"),
        **kwargs,
    )


class ConversionTests(unittest.TestCase):
    def test_pg_permissions_sql_only(self):
        decl = convert("pg_permissions")
        self.assertEqual(central.validate_declaration(decl, "pg_permissions"), [])
        self.assertEqual(decl["build"]["distribution"], "sql-only")
        self.assertEqual(decl["postgresql"]["majors"], [15, 16, 17, 18, 19])
        self.assertEqual(len(decl["packaging"]["files"]), 4)
        self.assertNotIn("adapter", decl)
        self.assertNotIn("options", decl["build"])
        self.assertEqual(decl["upstream"]["commit"], "bb0746ffc841e99396e912553be9e016b80ae264")
        self.assertEqual(decl["tests"]["contract"], "tests/test-contract.json")

    def test_pg_bigm_min_max_normalized(self):
        decl = convert("pg_bigm")
        self.assertEqual(central.validate_declaration(decl, "pg_bigm"), [])
        # Form-only normalization: the declared PG14 stays declared; the
        # target series decision itself belongs to F2-2 (F2-1-PACKAGE 5.2).
        self.assertEqual(decl["postgresql"]["majors"], [14, 15, 16, 17, 18, 19])
        self.assertEqual(decl["build"]["distribution"], "dll-sql")

    def test_pgaudit_per_postgresql_preserved(self):
        decl = convert("pgaudit")
        self.assertEqual(central.validate_declaration(decl, "pgaudit"), [])
        self.assertEqual(sorted(decl["upstream"]["perPostgresql"]), ["15", "16", "17", "18", "19"])
        self.assertEqual(sorted(decl["packaging"]["perPostgresql"]), ["15", "16", "17", "18", "19"])
        self.assertEqual(decl["watch"]["strategy"], "github-releases-per-postgresql")

    def test_adapter_designation(self):
        decl = convert("pg_bigm", adapter=True)
        self.assertEqual(decl["adapter"], {"path": "adapter.ps1"})
        self.assertEqual(central.validate_declaration(decl, "pg_bigm"), [])

    def test_build_options_declaration(self):
        decl = convert("pg_bigm", build_options={"exports": ["bigm_*"], "defines": ["USE_BIGM"]})
        self.assertEqual(decl["build"]["options"]["exports"], ["bigm_*"])
        self.assertEqual(central.validate_declaration(decl, "pg_bigm"), [])
        with self.assertRaises(ValueError):
            convert("pg_bigm", build_options={"signingKey": ["x"]})

    def test_no_source_lock_created(self):
        decl = convert("pg_permissions")
        self.assertNotIn("source-lock", json.dumps(decl))
        self.assertNotIn("sourceLock", decl)

    def test_mixed_postgresql_block_rejected(self):
        legacy = load_fixture("pg_permissions-extension.json")
        legacy["postgresql"] = {"majors": [15, 16], "minMajor": 15, "maxMajor": 19}
        with self.assertRaises(ValueError):
            central.convert_declaration(legacy, load_fixture("pg_permissions-package.json"))

    def test_bool_and_non_list_majors_rejected(self):
        for bad in ({"majors": [True, 15]}, {"majors": "15-19"}, {"majors": []}):
            with self.subTest(postgresql=bad):
                legacy = load_fixture("pg_permissions-extension.json")
                legacy["postgresql"] = bad
                with self.assertRaises(ValueError):
                    central.convert_declaration(
                        legacy, load_fixture("pg_permissions-package.json")
                    )


class DeclarationSchemaTests(unittest.TestCase):
    def setUp(self):
        self.base = convert("pg_permissions")

    def assert_rejected(self, decl, case):
        errors = central.validate_declaration(decl, "pg_permissions")
        self.assertTrue(errors, f"expected rejection: {case}")

    def test_missing_build_block(self):
        decl = copy.deepcopy(self.base)
        del decl["build"]
        self.assert_rejected(decl, "missing build")

    def test_bad_distribution(self):
        decl = copy.deepcopy(self.base)
        decl["build"]["distribution"] = "zip-only"
        self.assert_rejected(decl, "bad distribution")

    def test_legacy_min_max_form_rejected_in_central(self):
        decl = copy.deepcopy(self.base)
        decl["postgresql"] = {"minMajor": 15, "maxMajor": 19}
        self.assert_rejected(decl, "min/max form must be normalized before landing centrally")

    def test_unsorted_majors_rejected(self):
        decl = copy.deepcopy(self.base)
        decl["postgresql"]["majors"] = [19, 15, 16, 17, 18]
        self.assert_rejected(decl, "unsorted majors")

    def test_adapter_path_fixed(self):
        decl = copy.deepcopy(self.base)
        decl["adapter"] = {"path": "scripts/adapter.ps1"}
        self.assert_rejected(decl, "adapter path must be adapter.ps1")

    def test_unknown_top_level_key(self):
        decl = copy.deepcopy(self.base)
        decl["signing"] = {"workflow": "x"}
        self.assert_rejected(decl, "unknown top-level key")

    def test_upstream_without_commit_rejected(self):
        decl = copy.deepcopy(self.base)
        del decl["upstream"]["commit"]
        self.assert_rejected(decl, "central form requires the pinned commit")

    def test_per_postgresql_outside_majors(self):
        decl = convert("pgaudit")
        decl["postgresql"]["majors"] = [15, 16, 17, 18]
        errors = central.validate_declaration(decl, "pgaudit")
        self.assertTrue(any("outside postgresql.majors" in e for e in errors))

    def test_packaging_file_bad_source(self):
        decl = copy.deepcopy(self.base)
        decl["packaging"]["files"][0]["source"] = "internet"
        self.assert_rejected(decl, "bad packaging file source")

    def test_pg_hint_plan_like_declaration(self):
        # pg_hint_plan form: per-major sqlInstallPath arrays plus a
        # license.perPostgresql block covering every declared major.
        decl = convert("pgaudit")
        decl["packaging"]["sqlInstallPath"] = ["1.7", "1.8"]
        decl["packaging"]["perPostgresql"]["17"]["sqlInstallPath"] = ["17.0", "18.0"]
        decl["license"] = {
            "verifyAgainstUpstream": True,
            "perPostgresql": {
                str(m): [{"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"}]
                for m in (15, 16, 17, 18, 19)
            },
        }
        self.assertEqual(central.validate_declaration(decl, "pgaudit"), [])

    def test_packaging_and_license_document_sources(self):
        # pgtap / pg_store_plans form: files[] may draw on the packaging
        # tree itself and on staged license documents.
        decl = copy.deepcopy(self.base)
        decl["packaging"]["files"][0]["source"] = "packaging"
        decl["packaging"]["files"][1]["source"] = "licenseDocument"
        self.assertEqual(central.validate_declaration(decl, "pg_permissions"), [])

    def test_sql_install_path_scalar_rejected(self):
        decl = copy.deepcopy(self.base)
        decl["packaging"]["sqlInstallPath"] = "share/extension"
        self.assert_rejected(decl, "sqlInstallPath must be an array of SQL versions")
        decl = copy.deepcopy(self.base)
        decl["packaging"]["sqlInstallPath"] = ["only-one"]
        self.assert_rejected(decl, "sqlInstallPath needs at least two entries")

    def test_per_postgresql_commit_missing_rejected(self):
        decl = convert("pgaudit")
        del decl["upstream"]["perPostgresql"]["17"]["commit"]
        errors = central.validate_declaration(decl, "pgaudit")
        self.assertTrue(errors, "perPostgresql commit must be required by the schema")

    def test_per_postgresql_major_missing_rejected(self):
        decl = convert("pgaudit")
        del decl["upstream"]["perPostgresql"]["19"]
        errors = central.validate_declaration(decl, "pgaudit")
        self.assertTrue(any("no pinned upstream" in e for e in errors), errors)

    def test_license_per_postgresql_major_missing_rejected(self):
        decl = convert("pgaudit")
        decl["license"] = {
            "verifyAgainstUpstream": True,
            "perPostgresql": {
                str(m): [{"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"}]
                for m in (15, 16, 17, 18)
            },
        }
        errors = central.validate_declaration(decl, "pgaudit")
        self.assertTrue(any("no license entries" in e for e in errors), errors)

    def test_watch_prereleases_must_be_false(self):
        decl = copy.deepcopy(self.base)
        decl["watch"]["prereleases"] = True
        self.assert_rejected(decl, "watch prereleases must stay false")

    def test_decimal_major_notation_rejected(self):
        # JSON Schema's "integer" accepts 17.0; the conversion path
        # rejects decimal notation, so direct validation must reject it
        # too (SOL-B1-01: both entry points share the major type rule).
        decl = copy.deepcopy(self.base)
        decl["postgresql"]["majors"] = [15.0, 16.0, 17.0, 18.0, 19.0]
        errors = central.validate_declaration(decl, "pg_permissions")
        self.assertTrue(any("decimal notation" in e for e in errors), errors)

    def test_schema_version_decimal_rejected(self):
        # The strict integer rule for schemaVersion matches the
        # handoff records in central-package.py: JSON Schema's "const"
        # accepts 1.0 as equal to 1, direct validation must not
        # (B1R3-N3).
        decl = copy.deepcopy(self.base)
        decl["schemaVersion"] = 1.0
        errors = central.validate_declaration(decl, "pg_permissions")
        self.assertTrue(any("schemaVersion" in e for e in errors), errors)

    def test_per_postgresql_decimal_key_rejected(self):
        # A per-major dictionary keyed by a decimal notation ("17.0")
        # names no declared major and leaves the real major unpinned.
        decl = convert("pgaudit")
        per_major = decl["upstream"]["perPostgresql"]
        per_major["17.0"] = per_major.pop("17")
        errors = central.validate_declaration(decl, "pgaudit")
        self.assertTrue(
            any("perPostgresql" in e for e in errors), errors
        )

    def test_watch_strategy_exclusivity(self):
        decl = copy.deepcopy(self.base)
        decl["watch"]["perPostgresql"] = {"17": {"tagPattern": "^v17"}}
        self.assert_rejected(decl, "github-releases watch must not carry perPostgresql")
        decl = convert("pgaudit")
        decl["watch"]["strategy"] = "github-releases"
        errors = central.validate_declaration(decl, "pgaudit")
        self.assertTrue(errors, "github-releases watch requires stableTagPattern only")


def write_file(root, rel, content):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def valid_tree(root, name="pg_permissions", adapter_content=None):
    decl = convert(name, adapter=adapter_content is not None)
    ext = root / "extensions" / name
    ext.mkdir(parents=True)
    write_file(ext, "extension.json", json.dumps(decl, indent=2) + "\n")
    write_file(ext, "tests/test-contract.json", '{"version": 1, "checks": ["smoke"]}\n')
    write_file(ext, "tests/smoke-test.ps1", "Write-Host 'smoke'\n")
    if adapter_content is not None:
        write_file(ext, "adapter.ps1", adapter_content)
    return ext


class TreeValidationTests(unittest.TestCase):
    def errors_for(self, build_tree):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_tree(root)
            return central.validate_tree(root)

    def test_valid_tree_passes(self):
        self.assertEqual(self.errors_for(lambda r: valid_tree(r)), [])

    def test_valid_tree_with_clean_adapter_passes(self):
        content = "# pg_bigm specific compile step\n& cl /LD pg_bigm.c\n"
        self.assertEqual(
            self.errors_for(lambda r: valid_tree(r, "pg_bigm", adapter_content=content)), []
        )

    def test_non_carry_in_assets_rejected(self):
        cases = {
            "N-01": "windows.yml",
            "N-02": "build.ps1",
            "N-03": "install-postgresql.ps1",
            "N-04": "update-watch.yml",
            "N-05": "create-candidate.ps1",
            "N-06": "package.ps1",
            "N-07": "generate-sbom.ps1",
            "N-08": "run-tests.ps1",
            "N-09": "publish-release.ps1",
            "N-10": "versions.json",
            "N-11": "issue311-one-shot.yml",
            "N-12": "issue-123-proof.py",
            "N-13": "migration-helper.py",
            "N-14": "compat-wrapper.ps1",
            "N-16": "source/pg_permissions.c",
            "N-17": "__pycache__/module.pyc",
            "N-18": "OPERATIONS.md",
        }
        for n_id, rel in cases.items():
            with self.subTest(case=n_id, path=rel):
                def build(root, rel=rel):
                    ext = valid_tree(root)
                    write_file(ext, rel, b"payload\n")
                errors = self.errors_for(build)
                self.assertTrue(
                    any(n_id in e for e in errors),
                    f"{n_id} carry-in '{rel}' not rejected with its class id: {errors}",
                )

    def test_empty_adapter_rejected_n15(self):
        def build(root):
            ext = valid_tree(root, "pg_bigm", adapter_content="x")
            (ext / "adapter.ps1").write_bytes(b"")
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_empty_directory_rejected(self):
        def build(root):
            ext = valid_tree(root)
            (ext / "patches").mkdir()
        errors = self.errors_for(build)
        self.assertTrue(any("empty directory" in e for e in errors), errors)

    def test_empty_file_rejected(self):
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "patches/fix.patch", b"")
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_source_lock_rejected(self):
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "source-lock.json", "{}\n")
        errors = self.errors_for(build)
        self.assertTrue(any("source-lock" in e for e in errors), errors)

    def test_non_carry_in_assets_in_allowed_dirs_rejected(self):
        # The N-01..N-18 classification applies at any depth: hiding a
        # carry-in asset inside an allowed directory must not help.
        cases = {
            "N-01": "packaging/windows.yml",
            "N-02": "tests/build.ps1",
            "N-03": "tests/install-postgresql.ps1",
            "N-04": "packaging/update-watch.json",
            "N-05": "tests/create-candidate.ps1",
            "N-06": "tests/package.ps1",
            "N-07": "tests/generate-sbom.ps1",
            "N-08": "tests/run-tests.ps1",
            "N-09": "tests/publish-release.ps1",
            "N-10": "packaging/versions.json",
            "N-11": "packaging/issue311-one-shot.yml",
            "N-12": "packaging/issue-123-proof.py",
            "N-13": "packaging/migration-helper.py",
            "N-14": "tests/compat-wrapper.ps1",
            "N-16": "packaging/source/pg_permissions.c",
            "N-17": "packaging/__pycache__/module.pyc",
            "N-18": "packaging/OPERATIONS.md",
        }
        for n_id, rel in cases.items():
            with self.subTest(case=n_id, path=rel):
                def build(root, rel=rel):
                    ext = valid_tree(root)
                    write_file(ext, rel, b"payload\n")
                errors = self.errors_for(build)
                self.assertTrue(
                    any(n_id in e for e in errors),
                    f"{n_id} carry-in '{rel}' inside an allowed directory not rejected: {errors}",
                )

    def test_source_lock_in_subdirectory_rejected(self):
        for rel in (
            "packaging/source-lock.json",
            "licenses/source-lock.json",
            "tests/nested/source-lock.json",
        ):
            with self.subTest(path=rel):
                def build(root, rel=rel):
                    ext = valid_tree(root)
                    write_file(ext, rel, "{}\n")
                errors = self.errors_for(build)
                self.assertTrue(any("source-lock" in e for e in errors), errors)

    def test_uppercase_powershell_extension_rejected(self):
        for rel in ("packaging/helper.PS1", "licenses/helper.Ps1"):
            with self.subTest(path=rel):
                def build(root, rel=rel):
                    ext = valid_tree(root)
                    write_file(ext, rel, "Write-Host 'x'\n")
                errors = self.errors_for(build)
                self.assertTrue(
                    any("executable scripts" in e for e in errors),
                    f"uppercase PowerShell '{rel}' not rejected: {errors}",
                )

    def test_symlink_rejected(self):
        def build(root):
            ext = valid_tree(root)
            target = write_file(root, "outside.txt", "outside\n")
            (ext / "packaging").mkdir(exist_ok=True)
            write_file(ext, "packaging/placeholder.txt", "placeholder\n")
            try:
                os.symlink(target, ext / "packaging" / "linked.txt")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
        errors = self.errors_for(build)
        self.assertTrue(any("symbolic link" in e for e in errors), errors)

    def test_tests_script_privilege_mixing_rejected(self):
        samples = {
            "oidc-token": "$t = $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN\n",
            "oidc-url": "$u = $env:ACTIONS_ID_TOKEN_REQUEST_URL\n",
            "runtime-token": "$t = $env:ACTIONS_RUNTIME_TOKEN\n",
            "attest": "uses: actions/attest-build-provenance@v1\n",
            "gh-api": "gh api repos/pgextwin/build\n",
            "gh-workflow": "gh workflow run sign.yml\n",
            "private-key": "$k = $env:APP_PRIVATE_KEY\n",
        }
        for category, content in samples.items():
            with self.subTest(category=category):
                def build(root, content=content):
                    ext = valid_tree(root)
                    write_file(ext, "tests/smoke-test.ps1", content)
                errors = self.errors_for(build)
                self.assertTrue(
                    any("adapter area contains" in e for e in errors),
                    f"{category} material in tests/smoke-test.ps1 not rejected: {errors}",
                )

    def test_whitespace_only_patch_rejected_n15(self):
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "patches/fix.patch", "\n   \n")
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_comment_only_adapter_rejected_n15(self):
        def build(root):
            valid_tree(
                root, "pg_bigm",
                adapter_content="# placeholder only\n\n# nothing substantive\n",
            )
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_adapter_privilege_mixing_rejected(self):
        samples = {
            "signing": "# helper\ngh attestation verify pkg.zip\n",
            "publisher": "$env:PUBLISHER = 'x'\n",
            "authorization": "Read-Auth 'local-auth ticket'\n",
            "credentials": "$t = $env:GITHUB_TOKEN\n",
        }
        for category, content in samples.items():
            with self.subTest(category=category):
                def build(root, content=content):
                    valid_tree(root, "pg_bigm", adapter_content=content)
                errors = self.errors_for(build)
                self.assertTrue(
                    any("adapter area contains" in e for e in errors),
                    f"{category} material not rejected: {errors}",
                )

    def test_undeclared_adapter_rejected(self):
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "adapter.ps1", "& cl /LD x.c\n")
        errors = self.errors_for(build)
        self.assertTrue(any("does not specify it" in e for e in errors), errors)

    def test_declared_adapter_missing_rejected(self):
        def build(root):
            ext = valid_tree(root, "pg_bigm", adapter_content="& cl /LD x.c\n")
            (ext / "adapter.ps1").unlink()
        errors = self.errors_for(build)
        self.assertTrue(any("adapter.ps1 is missing" in e for e in errors), errors)

    def test_name_directory_mismatch_rejected(self):
        def build(root):
            ext = valid_tree(root)
            target = root / "extensions" / "other_name"
            ext.rename(target)
        errors = self.errors_for(build)
        self.assertTrue(any("does not match directory" in e for e in errors), errors)

    def test_declared_test_file_missing_rejected(self):
        def build(root):
            ext = valid_tree(root)
            (ext / "tests" / "smoke-test.ps1").unlink()
        errors = self.errors_for(build)
        self.assertTrue(any("tests.smokeTest" in e for e in errors), errors)

    def test_stray_file_at_extensions_root_rejected(self):
        def build(root):
            valid_tree(root)
            write_file(root / "extensions", "README.md", "stray\n")
        errors = self.errors_for(build)
        self.assertTrue(any("only extension directories" in e for e in errors), errors)

    def test_non_object_extension_json_rejected(self):
        # A parsed JSON null / array / scalar is a declaration failure,
        # never a pass (SOL-B1-01: the pre-parse sentinel and the parsed
        # null were previously conflated, so a null extension.json
        # validated successfully).
        for content in ("null\n", "[1, 2]\n", "42\n", '"text"\n'):
            with self.subTest(content=content.strip()):
                def build(root, content=content):
                    ext = valid_tree(root)
                    (ext / "extension.json").write_text(content, encoding="utf-8")
                errors = self.errors_for(build)
                self.assertTrue(
                    any("not a JSON object" in e for e in errors),
                    f"extension.json {content.strip()!r} not rejected: {errors}",
                )

    def test_extensions_root_symlink_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            valid_tree(real)
            link_root = root / "linked"
            link_root.mkdir()
            try:
                os.symlink(real / "extensions", link_root / "extensions")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            errors = central.validate_tree(link_root)
            self.assertTrue(any("symbolic" in e for e in errors), errors)

    def test_extension_root_symlink_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            ext = valid_tree(real)
            (root / "extensions").mkdir()
            try:
                os.symlink(ext, root / "extensions" / "pg_permissions")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            errors = central.validate_tree(root)
            self.assertTrue(any("symbolic" in e for e in errors), errors)

    def test_case_variant_source_directory_rejected_n16(self):
        # Windows treats Source/ and source/ as the same directory, so
        # the N-16 classification applies to case variants too.
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "Source/pg_permissions.c", "int main(void);\n")
        errors = self.errors_for(build)
        self.assertTrue(any("N-16" in e for e in errors), errors)

    def test_deep_readme_rejected_n18(self):
        # The README exception is limited to the extension root; a
        # Markdown document inside an allowed directory is N-18.
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "packaging/README.md", "# Packaging notes\n\nBody text.\n")
        errors = self.errors_for(build)
        self.assertTrue(any("N-18" in e for e in errors), errors)

    def test_block_comment_only_adapter_rejected_n15(self):
        def build(root):
            valid_tree(
                root, "pg_bigm",
                adapter_content="<# placeholder\nstill only a comment #>\n",
            )
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_block_comment_only_test_script_rejected_n15(self):
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "tests/smoke-test.ps1", "<# nothing substantive #>\n")
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_empty_json_test_asset_rejected_n15(self):
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "tests/test-contract.json", "{}\n")
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_heading_only_readme_rejected_n15(self):
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "README.md", "# pg_permissions\n\n<!-- todo: write me -->\n")
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_substantive_readme_passes(self):
        def build(root):
            ext = valid_tree(root)
            write_file(
                ext, "README.md",
                "# pg_permissions\n\nCentral packaging notes for this extension.\n",
            )
        self.assertEqual(self.errors_for(build), [])

    def test_non_powershell_script_in_tests_scanned(self):
        # Execution rights and static inspection coverage stay aligned:
        # a non-PowerShell helper under tests/ is scanned with the same
        # privilege-boundary patterns as PowerShell.
        def build(root):
            ext = valid_tree(root)
            write_file(
                ext, "tests/helper.py",
                "import os\nTOKEN = os.environ['GITHUB_TOKEN']\n",
            )
        errors = self.errors_for(build)
        self.assertTrue(any("adapter area contains" in e for e in errors), errors)


    def test_uppercase_top_level_directories_rejected(self):
        # The layout is canonical lowercase: Tests/ and Packaging/
        # are not the standard tests/ and packaging/ directories,
        # even though Windows would treat them as the same directory
        # (B1R3-M3 regression: the allowlist check must not be
        # case-folded; the rejection-side classification stays
        # case-insensitive).
        for rel in ("Tests/extra.ps1", "Packaging/note.txt"):
            with self.subTest(path=rel):
                def build(root, rel=rel):
                    ext = valid_tree(root)
                    write_file(ext, rel, "payload\n")
                errors = self.errors_for(build)
                self.assertTrue(
                    any("standard layout" in e for e in errors),
                    f"uppercase directory '{rel}' not rejected: {errors}",
                )

    def test_case_colliding_paths_rejected(self):
        # Two paths that differ only in case collide on a Windows
        # checkout; the tree must reject the pair (B1R3-M3).
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "packaging/a.txt", "one\n")
            write_file(ext, "packaging/A.txt", "two\n")
        errors = self.errors_for(build)
        self.assertTrue(any("collides" in e for e in errors), errors)

    def test_sibling_extension_case_collision_rejected(self):
        # Extension roots are siblings on a Windows checkout too:
        # pg_permissions and PG_PERMISSIONS cannot coexist there, so
        # the tree-level uniqueness check must reject the pair even
        # though each directory is internally consistent
        # (SOL-B1-R2-01; the per-extension collision record alone
        # cannot see across roots).
        def build(root):
            valid_tree(root, "pg_permissions")
            decl = convert("pg_permissions")
            decl["name"] = "PG_PERMISSIONS"
            ext = root / "extensions" / "PG_PERMISSIONS"
            ext.mkdir(parents=True)
            write_file(ext, "extension.json", json.dumps(decl, indent=2) + "\n")
            write_file(
                ext, "tests/test-contract.json",
                '{"version": 1, "checks": ["smoke"]}\n',
            )
            write_file(ext, "tests/smoke-test.ps1", "Write-Host 'smoke'\n")
        errors = self.errors_for(build)
        self.assertTrue(any("collides" in e for e in errors), errors)

    def test_utf16_bom_adapter_privilege_mixing_rejected(self):
        # SOL-B1-R2-02: the static scan must decode a script the way
        # the PowerShell host does. A UTF-16 (BOM) adapter carrying
        # Publisher material must not slip past the scan as
        # replacement-decoded garbage while the host executes it.
        def build(root):
            ext = valid_tree(root, "pg_bigm", adapter_content="placeholder\n")
            (ext / "adapter.ps1").write_bytes(
                "# build step\ngh api repos/pgextwin/build\n".encode("utf-16")
            )
        errors = self.errors_for(build)
        self.assertTrue(any("adapter area contains" in e for e in errors), errors)

    def test_utf16_bom_tests_script_privilege_mixing_rejected(self):
        # The same decoding contract applies under tests/ (CB70-12).
        def build(root):
            ext = valid_tree(root)
            (ext / "tests" / "smoke-test.ps1").write_bytes(
                "Write-Host 'x'\n$env:GITHUB_TOKEN\n".encode("utf-16")
            )
        errors = self.errors_for(build)
        self.assertTrue(any("adapter area contains" in e for e in errors), errors)

    def test_utf8_bom_comment_only_adapter_rejected_n15(self):
        # A byte-order mark is not substance: a UTF-8 BOM followed by
        # comments only is still a comment-only adapter (N-15).
        def build(root):
            ext = valid_tree(root, "pg_bigm", adapter_content="placeholder\n")
            (ext / "adapter.ps1").write_bytes(
                b"\xef\xbb\xbf# only a comment\n"
            )
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_utf16_bom_comment_only_adapter_rejected_n15(self):
        def build(root):
            ext = valid_tree(root, "pg_bigm", adapter_content="placeholder\n")
            (ext / "adapter.ps1").write_bytes(
                "# only a comment\n".encode("utf-16")
            )
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_utf16_bom_comment_only_test_script_rejected_n15(self):
        def build(root):
            ext = valid_tree(root)
            (ext / "tests" / "smoke-test.ps1").write_bytes(
                "# only a comment\n".encode("utf-16")
            )
        errors = self.errors_for(build)
        self.assertTrue(any("N-15" in e for e in errors), errors)

    def test_utf16_bom_substantive_adapter_passes(self):
        # A substantive, clean UTF-16 (BOM) adapter decodes to real
        # content under the shared contract and passes.
        def build(root):
            ext = valid_tree(root, "pg_bigm", adapter_content="placeholder\n")
            (ext / "adapter.ps1").write_bytes(
                "# pg_bigm specific compile step\n& cl /LD pg_bigm.c\n".encode("utf-16")
            )
        self.assertEqual(self.errors_for(build), [])

    def test_unsupported_encoding_adapter_rejected(self):
        # BOM-less bytes that are not valid UTF-8 are outside the
        # encoding contract: Windows PowerShell 5.1 would read them
        # as the legacy ANSI code page while PowerShell 7 reads
        # UTF-8, so no single inspected text is the executed text.
        def build(root):
            ext = valid_tree(root, "pg_bigm", adapter_content="placeholder\n")
            (ext / "adapter.ps1").write_bytes(
                b"# \x93\x94 legacy quotes\n& cl /LD pg_bigm.c\n"
            )
        errors = self.errors_for(build)
        self.assertTrue(any("encoding" in e for e in errors), errors)

    def test_null_tests_block_rejected_without_crash(self):
        # SOL-B1-R2-N2: a declaration whose tests block is null is a
        # validation failure with a controlled diagnostic, never a
        # crash in the declared-test-file check that follows the
        # schema errors.
        def build(root):
            ext = valid_tree(root)
            decl = json.loads(
                (ext / "extension.json").read_text(encoding="utf-8")
            )
            decl["tests"] = None
            (ext / "extension.json").write_text(
                json.dumps(decl, indent=2) + "\n", encoding="utf-8"
            )
        errors = self.errors_for(build)
        self.assertTrue(errors)

    def test_uppercase_bin_directory_rejected_n17(self):
        # The rejection-side path-component classification stays
        # case-insensitive: BIN/ is bin/ for N-17 purposes (B1R3-M3).
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "packaging/BIN/a.dll", b"payload\n")
        errors = self.errors_for(build)
        self.assertTrue(any("N-17" in e for e in errors), errors)

    def test_windows_unusable_extension_names_rejected(self):
        # SOL-B1-R3-01: a name Windows strips or reserves cannot be
        # an extension root -- the audit's real-CLI reproductions
        # (pg_permissions. and aux) both exited 0 before this check.
        for bad_name in ("pg_permissions.", "aux"):
            with self.subTest(name=bad_name):
                def build(root, bad_name=bad_name):
                    decl = convert("pg_permissions")
                    decl["name"] = bad_name
                    ext = root / "extensions" / bad_name
                    ext.mkdir(parents=True)
                    write_file(ext, "extension.json", json.dumps(decl, indent=2) + "\n")
                    write_file(
                        ext, "tests/test-contract.json",
                        '{"version": 1, "checks": ["smoke"]}\n',
                    )
                    write_file(ext, "tests/smoke-test.ps1", "Write-Host 'smoke'\n")
                errors = self.errors_for(build)
                self.assertTrue(
                    any("cannot be used" in e and "Windows" in e for e in errors),
                    (bad_name, errors),
                )

    def test_windows_unusable_path_components_rejected(self):
        # SOL-B1-R3-01: the same Windows name rules bind every path
        # component under the root -- reserved device names with any
        # extension, trailing dots / spaces, invalid characters.
        for rel in (
            "tests/aux.txt",
            "tests/COM1.txt",
            "packaging/notes.",
            "packaging/name /a.txt",
            "tests/a<b.txt",
        ):
            with self.subTest(rel=rel):
                def build(root, rel=rel):
                    ext = valid_tree(root)
                    write_file(ext, rel, "x\n")
                errors = self.errors_for(build)
                self.assertTrue(
                    any("cannot be used on Windows" in e for e in errors),
                    (rel, errors),
                )

    def test_bom_coded_empty_json_assets_rejected(self):
        # SOL-B1-R3-03 / Neon B1R5-O1: a byte-order mark is a
        # signature, not content -- a BOM-coded empty {} / [] is
        # still an empty asset under N-15, in UTF-8 and UTF-16 form.
        cases = {
            "declared contract": (
                "tests/test-contract.json", b"\xef\xbb\xbf{}\n"
            ),
            "unreferenced sample": (
                "tests/samples/example.json", b"\xef\xbb\xbf[]\n"
            ),
            "utf-16 sample": (
                "tests/samples/example.json", "[]\n".encode("utf-16")
            ),
        }
        for label, (rel, data) in cases.items():
            with self.subTest(label=label):
                def build(root, rel=rel, data=data):
                    ext = valid_tree(root)
                    write_file(ext, rel, data)
                errors = self.errors_for(build)
                self.assertTrue(
                    any("empty" in e for e in errors), (label, errors)
                )

    def test_bom_substantive_unreferenced_json_accepted(self):
        # The BOM-aware N-15 judgement rejects emptiness, not the
        # byte-order mark itself: a substantive BOM-coded sample
        # asset keeps passing.
        def build(root):
            ext = valid_tree(root)
            write_file(ext, "tests/samples/example.json", b'\xef\xbb\xbf{"a": 1}\n')
        self.assertEqual(self.errors_for(build), [])

    def test_declared_contract_format_rejected(self):
        # SOL-B1-R3-03: the declared contract must be readable by
        # the existing Test Contract loader (plain UTF-8, one JSON
        # object) -- a merely existing file is not a test contract.
        for content in ("not json {\n", '["x"]\n'):
            with self.subTest(content=content.strip()):
                def build(root, content=content):
                    ext = valid_tree(root)
                    write_file(ext, "tests/test-contract.json", content)
                errors = self.errors_for(build)
                self.assertTrue(
                    any("not a valid test contract" in e for e in errors),
                    (content, errors),
                )

        def build_bom(root):
            ext = valid_tree(root)
            write_file(
                ext,
                "tests/test-contract.json",
                b'\xef\xbb\xbf{"version": 1, "checks": ["smoke"]}\n',
            )
        errors = self.errors_for(build_bom)
        self.assertTrue(
            any("not a valid test contract" in e for e in errors), errors
        )

    def test_double_bom_and_nul_scripts_rejected(self):
        # SOL-B1-R3-03 / Neon B1R5-O3: a doubled byte-order mark or
        # an embedded NUL makes the host report an error yet exit 0,
        # so both byte forms are outside the script contract for
        # the adapter and the smoke test alike.
        def build_double_bom(root):
            valid_tree(
                root,
                "pg_bigm",
                adapter_content=b"\xef\xbb\xbf\xef\xbb\xbf# c\nWrite-Host 'x'\n",
            )
        errors = self.errors_for(build_double_bom)
        self.assertTrue(
            any("U+FEFF" in e for e in errors), errors
        )

        def build_nul(root):
            ext = valid_tree(root)
            write_file(ext, "tests/smoke-test.ps1", b"# comment\x00\nWrite-Host 'smoke'\n")
        errors = self.errors_for(build_nul)
        self.assertTrue(any("embedded NUL" in e for e in errors), errors)

    def test_nonleading_feff_scripts_rejected(self):
        # Neon B1R6-M1 (SOL-B1-R3-03 residual): the shared decoding
        # used to inspect only a leading U+FEFF, so a stray one
        # after blanks or newlines -- or a second mark on the next
        # line -- passed both the N-15 judgement and the common
        # entry, and the real host reported an error yet exited 0.
        # Any U+FEFF beyond the leading signature is now outside
        # the script contract, for the adapter and the smoke test
        # alike (the audit's four reproductions).
        cases = {
            "adapter second BOM": (
                "adapter",
                b"\xef\xbb\xbf\n\xef\xbb\xbf# comment\n",
            ),
            "adapter stray FEFF": (
                "adapter",
                b" \xef\xbb\xbf# comment\n",
            ),
            "smoke stray FEFF after newline": (
                "smoke",
                b"\n\xef\xbb\xbf# comment\n",
            ),
            "smoke utf-16 stray FEFF": (
                "smoke",
                " \ufeff# comment\n".encode("utf-16"),
            ),
        }
        for label, (kind, data) in cases.items():
            with self.subTest(label=label):
                if kind == "adapter":
                    def build(root, data=data):
                        valid_tree(root, "pg_bigm", adapter_content=data)
                else:
                    def build(root, data=data):
                        ext = valid_tree(root)
                        write_file(ext, "tests/smoke-test.ps1", data)
                errors = self.errors_for(build)
                self.assertTrue(
                    any("U+FEFF" in e for e in errors), (label, errors)
                )

    def test_single_bom_substantive_adapter_accepted(self):
        # The U+FEFF ban targets stray marks beyond the signature:
        # one leading byte-order mark on a substantive script stays
        # inside the contract.
        def build(root):
            valid_tree(
                root, "pg_bigm",
                adapter_content=b"\xef\xbb\xbfWrite-Host 'adapter'\n",
            )
        self.assertEqual(self.errors_for(build), [])

    def test_bom_only_and_bom_blank_assets_rejected(self):
        # Neon B1R6-M2 (SOL-B1-R3-03 residual): emptiness used to
        # be judged on the raw bytes, so a file holding only a
        # byte-order mark (or a mark plus blanks) in any encoding
        # was "non-empty" and slipped past N-15; a heading-only
        # README in double-BOM / UTF-16 form slipped past the
        # heading judgement the same way. Emptiness is now judged
        # on the BOM-decoded text for every asset kind (the audit's
        # eight reproductions plus the UTF-16 README form).
        cases = {
            "patch BOM only": ("patches/empty.patch", b"\xef\xbb\xbf"),
            "patch BOM plus blanks": ("patches/ws.patch", b"\xef\xbb\xbf   \n"),
            "packaging BOM only": ("packaging/empty.txt", b"\xef\xbb\xbf"),
            "licenses BOM plus newline": ("licenses/empty.txt", b"\xef\xbb\xbf\n"),
            "json BOM only": ("tests/samples/empty.json", b"\xef\xbb\xbf"),
            "json BOM plus blanks": ("tests/samples/ws.json", b"\xef\xbb\xbf \t\r\n"),
            "json utf-16 blanks": (
                "tests/samples/utf16-ws.json", " \n".encode("utf-16")
            ),
            "readme double BOM heading": (
                "README.md", b"\xef\xbb\xbf\xef\xbb\xbf# Heading only\n"
            ),
            "readme utf-16 heading": (
                "README.md", "# Heading only\n".encode("utf-16")
            ),
        }
        for label, (rel, data) in cases.items():
            with self.subTest(label=label):
                def build(root, rel=rel, data=data):
                    ext = valid_tree(root)
                    write_file(ext, rel, data)
                errors = self.errors_for(build)
                self.assertTrue(
                    any("N-15" in e for e in errors), (label, errors)
                )

    def test_bom_coded_substantive_assets_accepted(self):
        # The BOM-aware judgement rejects emptiness, not the mark:
        # substantive BOM-coded assets keep passing in every form.
        def build(root):
            ext = valid_tree(root)
            write_file(
                ext, "patches/real.patch",
                b"\xef\xbb\xbf--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n",
            )
            write_file(ext, "packaging/notes.txt", "notes\n".encode("utf-16"))
            write_file(
                ext, "README.md",
                "# Title\n\nReal documentation body.\n".encode("utf-16"),
            )
        self.assertEqual(self.errors_for(build), [])

    def test_reserved_names_with_pre_dot_spaces_and_zero_rejected(self):
        # Neon B1R6-M3 (SOL-B1-R3-01 residual): Win32 trims
        # trailing spaces from the base name before the
        # reserved-device check (RtlIsDosDeviceName_U), so
        # "aux .txt" is the AUX device; COM0 / LPT0 are reserved
        # in the Microsoft naming specification. Both forms are
        # rejected like any other reserved name.
        for rel in (
            "tests/aux .txt",
            "tests/NUL   .json",
            "tests/COM0.txt",
            "tests/LPT0.txt",
        ):
            with self.subTest(rel=rel):
                def build(root, rel=rel):
                    ext = valid_tree(root)
                    write_file(
                        ext, rel,
                        '{"a": 1}\n' if rel.endswith(".json") else "x\n",
                    )
                errors = self.errors_for(build)
                self.assertTrue(
                    any("cannot be used on Windows" in e for e in errors),
                    (rel, errors),
                )

    def test_reserved_extension_root_com0_rejected(self):
        # Neon B1R6-M3: the root name itself is judged by the same
        # reserved set -- COM0 cannot be an extension root.
        def build(root):
            decl = convert("pg_permissions")
            decl["name"] = "COM0"
            ext = root / "extensions" / "COM0"
            ext.mkdir(parents=True)
            write_file(ext, "extension.json", json.dumps(decl, indent=2) + "\n")
            write_file(
                ext, "tests/test-contract.json",
                '{"version": 1, "checks": ["smoke"]}\n',
            )
            write_file(ext, "tests/smoke-test.ps1", "Write-Host 'smoke'\n")
        errors = self.errors_for(build)
        self.assertTrue(
            any("cannot be used" in e and "Windows" in e for e in errors),
            errors,
        )


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True, text=True,
        )

    def test_convert_cli_on_real_fixtures(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "extension.json"
            result = self.run_cli(
                "convert",
                "--extension-json", str(FIXTURES / "pg_bigm-extension.json"),
                "--package-json", str(FIXTURES / "pg_bigm-package.json"),
                "--out", str(out),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            decl = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(decl["postgresql"]["majors"], [14, 15, 16, 17, 18, 19])

    def test_validate_cli(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid_tree(root)
            ok = self.run_cli("validate", "--root", str(root))
            self.assertEqual(ok.returncode, 0, ok.stderr)
            write_file(root / "extensions" / "pg_permissions", "build.ps1", "x\n")
            bad = self.run_cli("validate", "--root", str(root))
            self.assertEqual(bad.returncode, 1)
            self.assertIn("N-02", bad.stderr)

    def test_validate_cli_null_extension_json_rejected(self):
        # A JSON null extension.json is a declaration failure through
        # the CLI as well, never a pass (SOL-B1-01 completeness).
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ext = valid_tree(root)
            (ext / "extension.json").write_text("null\n", encoding="utf-8")
            result = self.run_cli("validate", "--root", str(root))
            self.assertEqual(result.returncode, 1)
            self.assertIn("not a JSON object", result.stderr)

    def test_validate_cli_null_tests_block_no_traceback(self):
        # SOL-B1-R2-N2: the CLI diagnostic for a malformed
        # declaration (tests: null) is a controlled error line with
        # exit 1, not a traceback.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ext = valid_tree(root)
            decl = json.loads(
                (ext / "extension.json").read_text(encoding="utf-8")
            )
            decl["tests"] = None
            (ext / "extension.json").write_text(
                json.dumps(decl, indent=2) + "\n", encoding="utf-8"
            )
            result = self.run_cli("validate", "--root", str(root))
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
