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


if __name__ == "__main__":
    unittest.main()
