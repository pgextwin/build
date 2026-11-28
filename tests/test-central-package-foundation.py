#!/usr/bin/env python3
"""F21-04: common build / packaging / K2 / K4 verification foundation.

Covers the pinned upstream SHA comparison, deterministic ZIP packaging
with SHA-256 generation, the K2 T0 -> T1 -> T2 -> T3 handoff chain
(including byte tampering at every stage), and the K4 per-version
license original comparison (fixed-SHA mismatch, tampered bytes, and
per-major original mismatch are all rejected). Pilot execution against
real extension ZIPs is F2-2.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "central-package.py"

spec = importlib.util.spec_from_file_location("central_package", SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)

DECLARED = "bb0746ffc841e99396e912553be9e016b80ae264"
LICENSE_TEXT = b"PostgreSQL-style license text\n"
OTHER_LICENSE = b"Different license bytes\n"


def build_sample_zip(directory, content=b"payload"):
    return package.write_deterministic_zip(
        {"share/extension/sample.control": b"comment = 'sample'\n",
         "lib/sample.dll": content},
        Path(directory) / "sample-pg17-windows-x64.zip",
    )


class PinTests(unittest.TestCase):
    def test_matching_commit_passes(self):
        package.verify_pinned_commit(DECLARED, DECLARED)

    def test_case_insensitive_match_passes(self):
        package.verify_pinned_commit(DECLARED, DECLARED.upper())

    def test_mismatched_commit_rejected(self):
        with self.assertRaises(ValueError):
            package.verify_pinned_commit(DECLARED, "a" * 40)

    def test_short_ref_rejected(self):
        with self.assertRaises(ValueError):
            package.verify_pinned_commit("REL_1_6", DECLARED)


class ZipTests(unittest.TestCase):
    def test_deterministic_bytes(self):
        with TemporaryDirectory() as tmp:
            first = build_sample_zip(tmp)
            second_path = Path(tmp) / "again.zip"
            entries = package.read_zip_entries(Path(tmp) / "sample-pg17-windows-x64.zip")
            second = package.write_deterministic_zip(entries, second_path)
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertEqual(first["size"], second["size"])

    def test_sha256_matches_hashlib(self):
        with TemporaryDirectory() as tmp:
            info = build_sample_zip(tmp)
            raw = (Path(tmp) / "sample-pg17-windows-x64.zip").read_bytes()
            self.assertEqual(info["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(info["size"], len(raw))

    def test_empty_package_rejected(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                package.write_deterministic_zip({}, Path(tmp) / "empty.zip")

    def test_backslash_entry_rejected(self):
        with TemporaryDirectory() as tmp:
            for arcname in ("..\\evil.dll", "dir\\evil.dll", "C:\\evil.dll"):
                with self.subTest(arcname=arcname):
                    with self.assertRaises(ValueError):
                        package.write_deterministic_zip(
                            {arcname: b"x"}, Path(tmp) / "evil.zip"
                        )

    def test_windows_path_contract_rejected(self):
        # The ZIP entry contract matches Assert-PackagePath in
        # scripts/windows-package.ps1 (B1R2-N3): drive-letter forms,
        # reserved device names, trailing space / dot segments, and
        # Windows-invalid characters are all rejected at the packaging
        # entrance, with positive and negative coverage.
        bad = (
            "C:/evil.dll", "C:evil.dll", "dir/CON.dll", "dir/nul.txt",
            "dir/COM1", "dir/lpt9.dat", "dir /file.dll", "dir./file.dll",
            "dir/file*.dll", "dir/file?.dll",
        )
        with TemporaryDirectory() as tmp:
            for arcname in bad:
                with self.subTest(arcname=arcname):
                    with self.assertRaises(ValueError):
                        package.write_deterministic_zip(
                            {arcname: b"x"}, Path(tmp) / "evil.zip"
                        )
            good = package.write_deterministic_zip(
                {"share/extension/sample.control": b"x", "lib/sample.dll": b"y"},
                Path(tmp) / "good.zip",
            )
            self.assertEqual(good["fileName"], "good.zip")

    def test_case_colliding_entries_rejected(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                package.write_deterministic_zip(
                    {"lib/Sample.dll": b"x", "lib/sample.DLL": b"y"},
                    Path(tmp) / "evil.zip",
                )


class HandoffChainTests(unittest.TestCase):
    def make_chain(self, tmp, tamper_stage=None):
        info = build_sample_zip(tmp)
        zip_path = Path(tmp) / "sample-pg17-windows-x64.zip"
        records = []
        previous = None
        for stage in package.STAGES:
            if tamper_stage == stage:
                entries = package.read_zip_entries(zip_path)
                entries["lib/sample.dll"] = entries["lib/sample.dll"] + b"X"
                package.write_deterministic_zip(entries, zip_path)
            record = package.handoff_record(stage, "sample", 17, zip_path, previous)
            records.append(record)
            previous = record
        return records, info

    def verify(self, records, info, **overrides):
        # The expectations are the trusted packaging step's own output
        # (write_deterministic_zip's returned digest / size / file name)
        # plus the intended target: independent values, never values
        # read back out of the chain under verification (SOL-B1-04).
        expectations = {
            "expected_sha256": info["sha256"],
            "expected_size": info["size"],
            "expected_extension": "sample",
            "expected_pg_major": 17,
            "expected_file_name": info["fileName"],
        }
        expectations.update(overrides)
        return package.verify_handoff_chain(records, **expectations)

    def test_complete_chain_passes(self):
        with TemporaryDirectory() as tmp:
            records, info = self.make_chain(tmp)
            self.verify(records, info)

    def test_expectations_are_mandatory(self):
        with TemporaryDirectory() as tmp:
            records, _info = self.make_chain(tmp)
            with self.assertRaises(TypeError):
                package.verify_handoff_chain(records)

    def test_tampering_rejected_at_every_stage(self):
        for stage in package.STAGES:
            with self.subTest(stage=stage), TemporaryDirectory() as tmp:
                records, info = self.make_chain(tmp, tamper_stage=stage)
                with self.assertRaises(ValueError):
                    self.verify(records, info)

    def test_t0_byte_replacement_rejected(self):
        # Replace the ZIP bytes before T0 and rebuild the whole chain
        # from the replaced bytes: the chain is internally consistent,
        # so only the independent packaging expectation can reject it.
        with TemporaryDirectory() as tmp:
            _records, info = self.make_chain(tmp)
            zip_path = Path(tmp) / "sample-pg17-windows-x64.zip"
            entries = package.read_zip_entries(zip_path)
            entries["lib/sample.dll"] = entries["lib/sample.dll"] + b"X"
            package.write_deterministic_zip(entries, zip_path)
            rebuilt = []
            previous = None
            for stage in package.STAGES:
                record = package.handoff_record(stage, "sample", 17, zip_path, previous)
                rebuilt.append(record)
                previous = record
            with self.assertRaises(ValueError):
                self.verify(rebuilt, info)

    def test_wrong_target_chain_rejected(self):
        # A complete, internally consistent chain recorded for another
        # extension / major does not satisfy this target's expectations.
        with TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "sample-pg17-windows-x64.zip"
            info = build_sample_zip(tmp)
            records = []
            previous = None
            for stage in package.STAGES:
                record = package.handoff_record(stage, "other", 18, zip_path, previous)
                records.append(record)
                previous = record
            with self.assertRaises(ValueError):
                self.verify(records, info)

    def test_record_digest_edit_rejected(self):
        with TemporaryDirectory() as tmp:
            records, info = self.make_chain(tmp)
            records[2]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                self.verify(records, info)

    def test_missing_stage_rejected(self):
        with TemporaryDirectory() as tmp:
            records, info = self.make_chain(tmp)
            with self.assertRaises(ValueError):
                self.verify(records[:3], info)

    def test_extension_mismatch_rejected(self):
        with TemporaryDirectory() as tmp:
            records, info = self.make_chain(tmp)
            records[1]["extension"] = "other"
            with self.assertRaises(ValueError):
                self.verify(records, info)

    def test_major_mismatch_rejected(self):
        with TemporaryDirectory() as tmp:
            records, info = self.make_chain(tmp)
            records[3]["pgMajor"] = 18
            with self.assertRaises(ValueError):
                self.verify(records, info)

    def test_empty_or_invalid_digest_chain_rejected(self):
        # A chain of well-linked but empty / malformed records must not
        # verify: the shape checks are fail-closed (B1-M5).
        variants = {
            "empty sha256": ("sha256", ""),
            "null sha256": ("sha256", None),
            "uppercase sha256": ("sha256", "A" * 64),
            "zero size": ("size", 0),
            "bool size": ("size", True),
            "wrong schemaVersion": ("schemaVersion", 2),
            "float schemaVersion": ("schemaVersion", 1.0),
            "empty extension": ("extension", ""),
        }
        for case, (key, value) in variants.items():
            with self.subTest(case=case), TemporaryDirectory() as tmp:
                records, info = self.make_chain(tmp)
                for record in records:
                    record[key] = value
                with self.assertRaises(ValueError):
                    self.verify(records, info)

    def test_missing_previous_key_rejected(self):
        # An absent previous* key is not interchangeable with an
        # explicit null (SOL-B1-04: key requirements are fixed).
        with TemporaryDirectory() as tmp:
            records, info = self.make_chain(tmp)
            del records[0]["previousStage"]
            with self.assertRaises(ValueError):
                self.verify(records, info)
            records, info = self.make_chain(tmp)
            del records[2]["previousSha256"]
            with self.assertRaises(ValueError):
                self.verify(records, info)

    def test_same_size_tamper_rejected(self):
        with TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "sample-pg17-windows-x64.zip"
            info = build_sample_zip(tmp)
            records = [package.handoff_record("T0", "sample", 17, zip_path)]
            entries = package.read_zip_entries(zip_path)
            entries["lib/sample.dll"] = b"payloaX"  # same length as b"payload"
            package.write_deterministic_zip(entries, zip_path)
            previous = records[0]
            for stage in package.STAGES[1:]:
                record = package.handoff_record(stage, "sample", 17, zip_path, previous)
                records.append(record)
                previous = record
            with self.assertRaises(ValueError):
                self.verify(records, info)

    def test_t0_baseline_mismatch_rejected(self):
        with TemporaryDirectory() as tmp:
            records, info = self.make_chain(tmp)
            self.verify(records, info)
            with self.assertRaises(ValueError):
                self.verify(records, info, expected_sha256="0" * 64)
            with self.assertRaises(ValueError):
                self.verify(records, info, expected_size=info["size"] + 1)


class AdapterEnvironmentTests(unittest.TestCase):
    """CB70-12: the adapter execution context carries no credentials."""

    SECRET_ENV = {
        "GITHUB_TOKEN": "dummy-github-token",
        "GH_TOKEN": "dummy-gh-token",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "dummy-oidc-token",
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.invalid/oidc",
        "ACTIONS_RUNTIME_TOKEN": "dummy-runtime-token",
        "PUBLISHER_APP_PRIVATE_KEY": "dummy-private-key",
        "LOCAL_AUTH_TICKET": "dummy-local-auth",
        "MY_API_SECRET": "dummy-secret",
    }

    def base_env(self):
        env = dict(os.environ)
        env.update(self.SECRET_ENV)
        env["PG_BUILD_FLAG"] = "1"
        return env

    def test_credentials_never_passed(self):
        env = package.build_adapter_environment(
            self.base_env(), extra_values={"PG_BUILD_FLAG": "1"}
        )
        for key in self.SECRET_ENV:
            self.assertNotIn(key, env)
        self.assertEqual(env["PG_BUILD_FLAG"], "1")
        self.assertIn("PATH", env)

    def test_extra_values_are_never_pulled_from_parent_by_name(self):
        # PG_BUILD_FLAG exists in the parent environment but is not on
        # the base allowlist: without an explicit extra value it does
        # not cross the boundary. A by-name pull would not be a strict
        # allowlist (SOL-B1-03).
        env = package.build_adapter_environment(self.base_env())
        self.assertNotIn("PG_BUILD_FLAG", env)

    def test_child_process_cannot_reach_credentials(self):
        env = package.build_adapter_environment(self.base_env())
        probe = (
            "import os, sys; "
            f"keys = {sorted(self.SECRET_ENV)!r}; "
            "leaked = [k for k in keys if os.environ.get(k)]; "
            "sys.exit(1 if leaked else 0)"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe], env=env, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_forbidden_extra_values_rejected(self):
        for key in (
            "GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN",
            "GITHUB_ENV", "GITHUB_OUTPUT", "PUBLISHER_TOKEN", "LOCAL_AUTH_SECRET",
            "APP_PRIVATE_KEY", "SOME_API_KEY", "PG_AUTH_TICKET", "SIGNING_KEY_PEM",
        ):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    package.build_adapter_environment(
                        self.base_env(), extra_values={key: "x"}
                    )

    def test_malformed_extra_values_rejected(self):
        for extra in (
            {"pg_build_flag": "1"},       # names are uppercase identifiers
            {"PATH": "C:\\evil"},         # base allowlist cannot be overridden
            {"PG_BUILD_FLAG": 1},         # values are strings
        ):
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    package.build_adapter_environment(self.base_env(), extra_values=extra)


class AdapterExecutionTests(unittest.TestCase):
    """CB70-12: the common execution entry enforces the boundary.

    Adapter / test code runs only through run_adapter_script: the
    script must belong to the statically scanned set, the environment
    comes from build_adapter_environment, and the working directory is
    the extension root. Filesystem-level isolation of the real Windows
    job is F2-2 evidence; here the same common entry is exercised
    offline with a Python probe standing in for the PowerShell host.
    """

    SECRET_ENV = AdapterEnvironmentTests.SECRET_ENV

    def make_tree(self, root):
        ext = root / "extensions" / "sample"
        (ext / "tests").mkdir(parents=True)
        (ext / "packaging").mkdir()
        return ext

    def test_scripts_outside_the_scanned_set_rejected(self):
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            for rel in ("packaging/helper.ps1", "tests/helper.py", "build.ps1"):
                script = ext / rel
                script.write_text("payload\n", encoding="utf-8")
                with self.subTest(rel=rel):
                    with self.assertRaises(ValueError):
                        package.run_adapter_script(
                            script, extension_root=ext, executable=sys.executable
                        )

    def test_symlink_script_rejected(self):
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            target = ext / "tests" / "real.ps1"
            target.write_text("payload\n", encoding="utf-8")
            try:
                os.symlink(target, ext / "tests" / "linked.ps1")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaises(ValueError):
                package.run_adapter_script(
                    ext / "tests" / "linked.ps1",
                    extension_root=ext, executable=sys.executable,
                )

    def test_common_entry_isolates_the_child_context(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ext = self.make_tree(root)
            # A dummy credential file sits in the caller's workspace;
            # the child's working directory is the extension root, so
            # the file is not part of its execution context.
            (root / "dummy-credentials.json").write_text(
                '{"token": "dummy"}\n', encoding="utf-8"
            )
            probe = ext / "tests" / "probe.ps1"
            probe.write_text(
                "import json, os\n"
                "from pathlib import Path\n"
                f"keys = {sorted(self.SECRET_ENV)!r}\n"
                "print(json.dumps({\n"
                "    'leaked': [k for k in keys if os.environ.get(k)],\n"
                "    'cwd_is_extension_root': Path.cwd() == Path(__file__).resolve().parents[1],\n"
                "    'flag': os.environ.get('PG_BUILD_FLAG'),\n"
                "    'caller_credentials_in_cwd': Path('dummy-credentials.json').exists(),\n"
                "}))\n",
                encoding="utf-8",
            )
            base_env = dict(os.environ)
            base_env.update(self.SECRET_ENV)
            result = package.run_adapter_script(
                probe, extension_root=ext, base_env=base_env,
                extra_values={"PG_BUILD_FLAG": "1"}, executable=sys.executable,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(result.stdout)
            self.assertEqual(observed["leaked"], [])
            self.assertTrue(observed["cwd_is_extension_root"])
            self.assertEqual(observed["flag"], "1")
            self.assertFalse(observed["caller_credentials_in_cwd"])


class LicenseTests(unittest.TestCase):
    def test_upstream_form_match_passes(self):
        verified = package.verify_license_entries(
            [{"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"}],
            {"LICENSE": LICENSE_TEXT},
            {"LICENSE": LICENSE_TEXT},
        )
        self.assertEqual(verified[0]["sha256"], hashlib.sha256(LICENSE_TEXT).hexdigest())

    def test_upstream_bytes_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            package.verify_license_entries(
                [{"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"}],
                {"LICENSE": LICENSE_TEXT},
                {"LICENSE": OTHER_LICENSE},
            )

    def test_upstream_file_missing_at_pinned_commit_rejected(self):
        with self.assertRaises(ValueError):
            package.verify_license_entries(
                [{"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"}],
                {},
                {"LICENSE": LICENSE_TEXT},
            )

    def test_start_marker_range(self):
        blob = b"header\n" + LICENSE_TEXT
        verified = package.verify_license_entries(
            [{"repositoryPath": "LICENSE", "upstreamPath": "LICENSE",
              "upstreamStartMarker": "PostgreSQL-style"}],
            {"LICENSE": blob},
            {"LICENSE": LICENSE_TEXT},
        )
        self.assertEqual(verified[0]["size"], len(LICENSE_TEXT))

    def test_packaging_origin_pin(self):
        pin = hashlib.sha256(LICENSE_TEXT).hexdigest()
        entries = [
            {"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"},
            {"origin": "packaging", "repositoryPath": "NOTICE", "sha256": pin},
        ]
        sources = ({"LICENSE": LICENSE_TEXT}, {"LICENSE": LICENSE_TEXT, "NOTICE": LICENSE_TEXT})
        self.assertEqual(len(package.verify_license_entries(entries, *sources)), 2)
        with self.assertRaises(ValueError):
            package.verify_license_entries(
                entries, {"LICENSE": LICENSE_TEXT},
                {"LICENSE": LICENSE_TEXT, "NOTICE": OTHER_LICENSE},
            )

    def test_build_origin_pin_and_source_validation(self):
        pin = hashlib.sha256(LICENSE_TEXT).hexdigest()
        entries = [
            {"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"},
            {"origin": "build", "repositoryPath": "GEN-LICENSE",
             "generatedSource": "upstream", "generatedPath": "LICENSE", "sha256": pin},
        ]
        package.verify_license_entries(
            entries, {"LICENSE": LICENSE_TEXT},
            {"LICENSE": LICENSE_TEXT, "GEN-LICENSE": LICENSE_TEXT},
        )
        bad = copy_entry = json.loads(json.dumps(entries))
        bad[1]["generatedSource"] = "internet"
        with self.assertRaises(ValueError):
            package.verify_license_entries(
                bad, {"LICENSE": LICENSE_TEXT},
                {"LICENSE": LICENSE_TEXT, "GEN-LICENSE": LICENSE_TEXT},
            )

    def test_no_upstream_verified_entry_rejected(self):
        pin = hashlib.sha256(LICENSE_TEXT).hexdigest()
        with self.assertRaises(ValueError):
            package.verify_license_entries(
                [{"origin": "packaging", "repositoryPath": "NOTICE", "sha256": pin}],
                {},
                {"NOTICE": LICENSE_TEXT},
            )

    def test_declaration_simple_form(self):
        block = {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"}
        verified = package.verify_declaration_licenses(
            block, 17, {"LICENSE": LICENSE_TEXT}, {"LICENSE": LICENSE_TEXT}
        )
        self.assertEqual(len(verified), 1)
        with self.assertRaises(ValueError):
            package.verify_declaration_licenses(
                block, 17, {"LICENSE": LICENSE_TEXT}, {"LICENSE": OTHER_LICENSE}
            )

    def test_duplicate_repository_path_across_origins_rejected(self):
        pin = hashlib.sha256(LICENSE_TEXT).hexdigest()
        upstream_entry = {"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"}
        packaging_entry = {"origin": "packaging", "repositoryPath": "LICENSE", "sha256": pin}
        sources = ({"LICENSE": LICENSE_TEXT}, {"LICENSE": LICENSE_TEXT})
        with self.assertRaises(ValueError):
            package.verify_license_entries([upstream_entry, packaging_entry], *sources)
        with self.assertRaises(ValueError):
            package.verify_license_entries([packaging_entry, upstream_entry], *sources)

    def test_duplicate_repository_path_case_insensitive_rejected(self):
        pin = hashlib.sha256(LICENSE_TEXT).hexdigest()
        entries = [
            {"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"},
            {"origin": "packaging", "repositoryPath": "license", "sha256": pin},
        ]
        with self.assertRaises(ValueError):
            package.verify_license_entries(
                entries, {"LICENSE": LICENSE_TEXT},
                {"LICENSE": LICENSE_TEXT, "license": LICENSE_TEXT},
            )

    def test_conflicting_upstream_bytes_rejected(self):
        entries = [
            {"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"},
            {"repositoryPath": "LICENSE", "upstreamPath": "OTHER"},
        ]
        with self.assertRaises(ValueError):
            package.verify_license_entries(
                entries,
                {"LICENSE": LICENSE_TEXT, "OTHER": OTHER_LICENSE},
                {"LICENSE": LICENSE_TEXT},
            )

    def test_identical_upstream_duplicate_passes(self):
        entries = [
            {"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"},
            {"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"},
        ]
        verified = package.verify_license_entries(
            entries, {"LICENSE": LICENSE_TEXT}, {"LICENSE": LICENSE_TEXT}
        )
        self.assertEqual(len(verified), 2)

    def test_duplicate_build_target_rejected(self):
        pin = hashlib.sha256(LICENSE_TEXT).hexdigest()
        entries = [
            {"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"},
            {"origin": "build", "repositoryPath": "GEN-A", "generatedSource": "upstream",
             "generatedPath": "LICENSE", "sha256": pin},
            {"origin": "build", "repositoryPath": "GEN-B", "generatedSource": "upstream",
             "generatedPath": "license", "sha256": pin},
        ]
        with self.assertRaises(ValueError):
            package.verify_license_entries(
                entries, {"LICENSE": LICENSE_TEXT},
                {"LICENSE": LICENSE_TEXT, "GEN-A": LICENSE_TEXT, "GEN-B": LICENSE_TEXT},
            )

    def test_build_metadata_in_verified_output(self):
        pin = hashlib.sha256(LICENSE_TEXT).hexdigest()
        entries = [
            {"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"},
            {"origin": "build", "repositoryPath": "GEN-LICENSE",
             "generatedSource": "buildOutput", "generatedPath": "out/LICENSE",
             "sha256": pin},
        ]
        verified = package.verify_license_entries(
            entries, {"LICENSE": LICENSE_TEXT},
            {"LICENSE": LICENSE_TEXT, "GEN-LICENSE": LICENSE_TEXT},
        )
        self.assertEqual(verified[1]["generatedSource"], "buildOutput")
        self.assertEqual(verified[1]["generatedPath"], "out/LICENSE")

    def test_start_marker_provenance_output(self):
        blob = b"header\n" + LICENSE_TEXT
        verified = package.verify_license_entries(
            [{"repositoryPath": "LICENSE", "upstreamPath": "LICENSE",
              "upstreamStartMarker": "PostgreSQL-style"}],
            {"LICENSE": blob},
            {"LICENSE": LICENSE_TEXT},
        )
        self.assertEqual(verified[0]["upstreamOffset"], len(b"header\n"))
        self.assertEqual(verified[0]["upstreamSize"], len(blob))
        self.assertEqual(
            verified[0]["upstreamSha256"], hashlib.sha256(blob).hexdigest()
        )

    def test_crlf_lf_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            package.verify_license_entries(
                [{"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"}],
                {"LICENSE": b"line1\nline2\n"},
                {"LICENSE": b"line1\r\nline2\r\n"},
            )

    def test_non_license_upstream_path_maps_to_license(self):
        # resolve-matrix.ps1 canonical form: a lone upstreamPath (pgtap's
        # README.md style) is packaged under repositoryPath "LICENSE".
        block = {"verifyAgainstUpstream": True, "upstreamPath": "README.md"}
        verified = package.verify_declaration_licenses(
            block, 17, {"README.md": LICENSE_TEXT}, {"LICENSE": LICENSE_TEXT}
        )
        self.assertEqual(verified[0]["repositoryPath"], "LICENSE")
        self.assertEqual(verified[0]["upstreamPath"], "README.md")

    def test_verify_against_upstream_false_rejected(self):
        block = {"verifyAgainstUpstream": False, "upstreamPath": "LICENSE"}
        with self.assertRaises(ValueError):
            package.verify_declaration_licenses(
                block, 17, {"LICENSE": LICENSE_TEXT}, {"LICENSE": LICENSE_TEXT}
            )

    def test_declaration_per_postgresql_originals(self):
        block = {
            "verifyAgainstUpstream": True,
            "perPostgresql": {
                "17": [{"repositoryPath": "LICENSE", "upstreamPath": "LICENSE"}],
                "18": [{"repositoryPath": "LICENSE", "upstreamPath": "LICENSE18"}],
            },
        }
        upstream = {"LICENSE": LICENSE_TEXT, "LICENSE18": OTHER_LICENSE}
        package.verify_declaration_licenses(
            block, 17, upstream, {"LICENSE": LICENSE_TEXT}
        )
        package.verify_declaration_licenses(
            block, 18, upstream, {"LICENSE": OTHER_LICENSE}
        )
        # The PG17 original must not satisfy the PG18 check and vice versa.
        with self.assertRaises(ValueError):
            package.verify_declaration_licenses(
                block, 18, upstream, {"LICENSE": LICENSE_TEXT}
            )
        with self.assertRaises(ValueError):
            package.verify_declaration_licenses(block, 19, upstream, {})


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args], capture_output=True, text=True
        )

    def test_pin_cli(self):
        ok = self.run_cli("pin", "--declared", DECLARED, "--actual", DECLARED)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        bad = self.run_cli("pin", "--declared", DECLARED, "--actual", "b" * 40)
        self.assertEqual(bad.returncode, 1)

    def make_git_repo(self, root, files):
        root.mkdir(parents=True)

        def git(*args):
            return subprocess.run(
                ["git", "-C", str(root), *args],
                check=True, capture_output=True, text=True,
            )

        subprocess.run(
            ["git", "init", "-q", str(root)], check=True, capture_output=True, text=True
        )
        git("config", "user.email", "central-package-test@example.invalid")
        git("config", "user.name", "central-package-test")
        for rel, data in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        git("add", "-A")
        git("commit", "-qm", "fixture")
        return root

    def git_head(self, repo):
        return subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def git_commit_files(self, repo, files, message):
        def git(*args):
            return subprocess.run(
                ["git", "-C", str(repo), *args],
                check=True, capture_output=True, text=True,
            )

        for rel, data in files.items():
            target = repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        git("add", "-A")
        git("commit", "-qm", message)
        return self.git_head(repo)

    def write_declaration(self, root, upstream, license_block, name="declaration.json"):
        path = root / name
        path.write_text(json.dumps({
            "name": "sample",
            "upstream": upstream,
            "license": license_block,
        }), encoding="utf-8")
        return path

    def git_checkout(self, repo, ref):
        subprocess.run(
            ["git", "-C", str(repo), "checkout", "-q", ref],
            check=True, capture_output=True, text=True,
        )

    def verify_args(self, declaration, major, up, pkg, packaging_commit):
        return (
            "verify-licenses", "--declaration-json", str(declaration),
            "--major", str(major),
            "--upstream-dir", str(up), "--packaging-dir", str(pkg),
            "--packaging-commit", packaging_commit,
        )

    def test_verify_licenses_cli(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": LICENSE_TEXT})
            declaration = self.write_declaration(
                root,
                {"repository": "https://example.invalid/up", "commit": self.git_head(up)},
                {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"},
            )
            args = self.verify_args(declaration, 17, up, pkg, self.git_head(pkg))
            ok = self.run_cli(*args)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            document = json.loads(ok.stdout)
            self.assertEqual(document["upstreamCommit"], self.git_head(up))
            self.assertEqual(document["packagingCommit"], self.git_head(pkg))
            # The document shape is the verify-license-bytes.py contract
            # that windows-package.ps1 consumes: "licenses", not
            # "verified" (B1R2-N3).
            self.assertEqual(len(document["licenses"]), 1)
            self.assertNotIn("verified", document)
            # The CLI reads the fixed commit blobs: a worktree-only edit
            # is not a comparison input and cannot change the outcome.
            (pkg / "LICENSE").write_bytes(OTHER_LICENSE)
            still_ok = self.run_cli(*args)
            self.assertEqual(still_ok.returncode, 0, still_ok.stderr)

    def test_verify_licenses_cli_pin_binding(self):
        # SOL-B1-05: the comparison is bound to the declaration pin and
        # to the trusted packaging expectation, checked before any blob
        # is read, and blobs are read at the resolved SHA.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": LICENSE_TEXT})
            pkg_head = self.git_head(pkg)
            license_block = {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"}

            # A packaging expectation that does not match the resolved
            # packaging HEAD is rejected at the entrance.
            declaration = self.write_declaration(
                root,
                {"repository": "https://example.invalid/up", "commit": self.git_head(up)},
                license_block,
            )
            wrong_pkg = self.verify_args(declaration, 17, up, pkg, "a" * 40)
            self.assertEqual(self.run_cli(*wrong_pkg).returncode, 1)

            # Once the upstream HEAD moves past the declared pin, the
            # entrance rejects it before any blob is read: the
            # comparison is bound to the resolved SHA, and every blob
            # afterwards is read at that SHA, so a reference moving
            # during the comparison cannot change the outcome.
            first_pin = self.git_head(up)
            self.git_commit_files(up, {"LICENSE": OTHER_LICENSE}, "second")
            self.assertNotEqual(self.git_head(up), first_pin)
            moved = self.run_cli(*self.verify_args(declaration, 17, up, pkg, pkg_head))
            self.assertEqual(moved.returncode, 1)
            self.assertIn("commit mismatch", moved.stderr)

            # Re-pinning to the second commit makes the same packaging
            # bytes fail on the byte comparison: bytes that happen to
            # be equal at a different commit do not satisfy the pin.
            declaration2 = self.write_declaration(
                root,
                {"repository": "https://example.invalid/up", "commit": self.git_head(up)},
                license_block,
                name="declaration2.json",
            )
            bad = self.run_cli(*self.verify_args(declaration2, 17, up, pkg, pkg_head))
            self.assertEqual(bad.returncode, 1)

            # A packaging-side byte change committed on top is a byte
            # mismatch once the (new) packaging expectation is supplied
            # and the upstream checkout is back at the declared pin.
            new_pkg_head = self.git_commit_files(pkg, {"LICENSE": OTHER_LICENSE}, "tamper")
            self.git_checkout(up, first_pin)
            bad2 = self.run_cli(
                *self.verify_args(declaration, 17, up, pkg, new_pkg_head)
            )
            self.assertEqual(bad2.returncode, 1)

    def test_verify_licenses_cli_per_postgresql_pin(self):
        # The per-major pin is selected from the declaration's
        # upstream.perPostgresql for the requested major.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pin17 = self.git_head(up)
            self.git_commit_files(up, {"LICENSE": OTHER_LICENSE}, "for-18")
            pin18 = self.git_head(up)
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": LICENSE_TEXT})
            declaration = self.write_declaration(
                root,
                {
                    "repository": "https://example.invalid/up",
                    "perPostgresql": {
                        "17": {"commit": pin17},
                        "18": {"commit": pin18},
                    },
                },
                {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"},
            )
            pkg_head = self.git_head(pkg)
            # Per-major verification runs against a checkout of that
            # major's pin (the fixed-checkout step of the existing
            # route): check out pin17, verify 17; check out pin18,
            # verify 18.
            self.git_checkout(up, pin17)
            ok = self.run_cli(*self.verify_args(declaration, 17, up, pkg, pkg_head))
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(json.loads(ok.stdout)["upstreamCommit"], pin17)
            # PG18's original is OTHER_LICENSE, which the packaging
            # bytes do not match.
            self.git_checkout(up, pin18)
            bad = self.run_cli(*self.verify_args(declaration, 18, up, pkg, pkg_head))
            self.assertEqual(bad.returncode, 1)
            # An undeclared major is rejected before any Git access.
            missing = self.run_cli(*self.verify_args(declaration, 19, up, pkg, pkg_head))
            self.assertEqual(missing.returncode, 1)
            self.assertIn("No upstream pin declared", missing.stderr)

    def test_verify_licenses_cli_malformed_entry_rejected_before_git(self):
        # Entry shapes are validated before any Git call, with the same
        # diagnostics as the byte-comparison path (B1R2-N3).
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": LICENSE_TEXT})
            declaration = self.write_declaration(
                root,
                {"repository": "https://example.invalid/up", "commit": self.git_head(up)},
                {
                    "verifyAgainstUpstream": True,
                    "files": [{"upstreamPath": "LICENSE"}],
                },
            )
            result = self.run_cli(
                *self.verify_args(declaration, 17, up, pkg, self.git_head(pkg))
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("repositoryPath", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_verify_licenses_cli_symlink_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pkg = root / "pkg"
            pkg.mkdir()
            subprocess.run(
                ["git", "init", "-q", str(pkg)], check=True, capture_output=True, text=True
            )

            def git(*args):
                return subprocess.run(
                    ["git", "-C", str(pkg), *args],
                    check=True, capture_output=True, text=True,
                )

            git("config", "user.email", "central-package-test@example.invalid")
            git("config", "user.name", "central-package-test")
            (pkg / "REAL-LICENSE").write_bytes(LICENSE_TEXT)
            try:
                os.symlink("REAL-LICENSE", pkg / "LICENSE")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            git("add", "-A")
            git("commit", "-qm", "fixture")
            declaration = self.write_declaration(
                root,
                {"repository": "https://example.invalid/up", "commit": self.git_head(up)},
                {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"},
            )
            result = self.run_cli(
                *self.verify_args(declaration, 17, up, pkg, self.git_head(pkg))
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("symbolic link", result.stderr)


if __name__ == "__main__":
    unittest.main()
