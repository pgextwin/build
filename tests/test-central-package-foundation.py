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
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

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
            "dir/file[1].dll", "dir/file].dll",
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

    def test_windows_reserved_names_with_spaces_and_zero_rejected(self):
        # Neon B1R6-M3 (SOL-B1-R3-01 residual): Win32 trims
        # trailing spaces from the base name before the
        # reserved-device check (RtlIsDosDeviceName_U), so
        # "aux .txt" is the AUX device, and COM0 / LPT0 are
        # reserved in the Microsoft naming specification. The
        # packaging entrance rejects both forms; lookalike names
        # that merely start with a reserved word, or carry a
        # two-digit COM number, stay valid.
        bad = (
            "tests/aux .txt", "tests/NUL   .json",
            "tests/COM0.txt", "tests/LPT0.txt", "dir/COM0",
        )
        with TemporaryDirectory() as tmp:
            for arcname in bad:
                with self.subTest(arcname=arcname):
                    with self.assertRaises(ValueError):
                        package.write_deterministic_zip(
                            {arcname: b"x"}, Path(tmp) / "evil.zip"
                        )
            good = package.write_deterministic_zip(
                {"dir/com10.txt": b"x", "dir/console.txt": b"y"},
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

    def test_prefix_colliding_entries_rejected(self):
        # A file-versus-directory prefix pair (lib/sample as a file
        # and lib/sample/a.dll beneath it) cannot coexist on disk;
        # windows-package.ps1 rejects the same conflict for install
        # destinations, so the packaging entrance rejects it too
        # (B1R3-N1), in either order and across case differences.
        with TemporaryDirectory() as tmp:
            for entries in (
                {"lib/sample": b"x", "lib/sample/a.dll": b"y"},
                {"lib/sample/a.dll": b"y", "lib/sample": b"x"},
                {"Lib/Sample": b"x", "lib/sample/a.dll": b"y"},
            ):
                with self.subTest(entries=sorted(entries)):
                    with self.assertRaises(ValueError):
                        package.write_deterministic_zip(
                            entries, Path(tmp) / "evil.zip"
                        )


    def test_unicode_prefix_pair_follows_windows_package_contract(self):
        # SOL-B1-R2-N1: windows-package.ps1 compares install
        # destinations with [StringComparison]::OrdinalIgnoreCase,
        # a simple per-character case mapping under which ß does
        # not expand to SS. The Python entrance shares that contract:
        # the straße / STRASSE pair is not a collision there, while
        # an ASCII case-variant prefix pair still is.
        with TemporaryDirectory() as tmp:
            info = package.write_deterministic_zip(
                {"docs/straße": b"x", "docs/STRASSE/a.txt": b"y"},
                Path(tmp) / "ok.zip",
            )
            self.assertEqual(info["fileName"], "ok.zip")
            with self.assertRaises(ValueError):
                package.write_deterministic_zip(
                    {"docs/strassE": b"x", "docs/STRASSE/a.txt": b"y"},
                    Path(tmp) / "evil.zip",
                )

    def test_zip_ordinal_ignore_case_measured_pairs(self):
        # SOL-B1-R3-04: the fold is the measured OrdinalIgnoreCase
        # one, not str.upper(). The Greek ypogegrammeni letters fold
        # to their single-character simple uppercase forms, so the
        # U+1F80 / U+1F88 pairs collide exactly as the existing
        # entrance judges them; U+0131 (dotless i) and U+017F (long
        # s) do NOT fold to I / S under OrdinalIgnoreCase, so those
        # pairs stay accepted; cased astral letters (Deseret) fold
        # like any other cased character.
        rejected = (
            {"docs/\u1f80": b"x", "docs/\u1f88/b.txt": b"y"},
            {"lib/\u1f80.dll": b"x", "lib/\u1f88.dll": b"y"},
            {"docs/\u1fb3": b"x", "docs/\u1fbc/b.txt": b"y"},
            {"docs/\U00010428": b"x", "docs/\U00010400/b.txt": b"y"},
        )
        accepted = (
            {"docs/\u0131": b"x", "docs/I/b.txt": b"y"},
            {"docs/\u017f": b"x", "docs/S/b.txt": b"y"},
        )
        with TemporaryDirectory() as tmp:
            for entries in rejected:
                with self.subTest(entries=sorted(entries)):
                    with self.assertRaises(ValueError):
                        package.write_deterministic_zip(
                            entries, Path(tmp) / "evil.zip"
                        )
            for entries in accepted:
                with self.subTest(entries=sorted(entries)):
                    info = package.write_deterministic_zip(
                        entries, Path(tmp) / "ok.zip"
                    )
                    self.assertEqual(info["fileName"], "ok.zip")

    def test_zip_fold_matches_powershell_ordinal_ignore_case(self):
        # SOL-B1-R3-04 differential check: the Python conflict
        # predicate must agree with the reference implementation
        # (PowerShell's [StringComparer]::OrdinalIgnoreCase, the
        # comparison windows-package.ps1's destination check uses)
        # on every candidate pair -- fold-group members, upper /
        # lower neighbours, and the pairs the audits raised.
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("PowerShell 7 host not available")
        chars = set("ßẞKKıIſS")
        for code, target in package._ORDINAL_IGNORE_CASE_OVERRIDES.items():
            chars.add(chr(code))
            chars.add(chr(target))
        for code in range(0x1F00, 0x2000):
            chars.add(chr(code))
        for code in range(0x10400, 0x10450):
            chars.add(chr(code))
        by_fold = {}
        for char in chars:
            by_fold.setdefault(package._ordinal_ignore_case_key(char), set()).add(char)
        pairs = set()

        def conflict(a, b):
            ka = package._ordinal_ignore_case_key(a)
            kb = package._ordinal_ignore_case_key(b)
            return ka == kb or ka.startswith(kb + "/") or kb.startswith(ka + "/")

        for char in chars:
            candidates = set(by_fold[package._ordinal_ignore_case_key(char)])
            for form in (char.upper(), char.lower()):
                if len(form) == 1:
                    candidates.add(form)
            candidates.add(char)
            for other in candidates:
                pairs.add((f"d/{char}", f"d/{other}"))
                pairs.add((f"d/{char}", f"d/{other}/f.txt"))
        pairs = sorted(pairs)
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "pairs.json").write_text(
                json.dumps(pairs), encoding="utf-8"
            )
            script = tmp_path / "probe.ps1"
            script.write_text(
                "$pairs = [System.IO.File]::ReadAllText('"
                + str(tmp_path / "pairs.json").replace("'", "''")
                + "') | ConvertFrom-Json\n"
                "$out = New-Object System.Collections.Generic.List[string]\n"
                "foreach ($pair in $pairs) {\n"
                "    $a = [string]$pair[0]; $b = [string]$pair[1]\n"
                "    $c = [string]::Equals($a, $b, [System.StringComparison]::OrdinalIgnoreCase) -or\n"
                "        $a.StartsWith(\"$b/\", [System.StringComparison]::OrdinalIgnoreCase) -or\n"
                "        $b.StartsWith(\"$a/\", [System.StringComparison]::OrdinalIgnoreCase)\n"
                "    $out.Add([int]$c)\n"
                "}\n"
                "[System.IO.File]::WriteAllLines('"
                + str(tmp_path / "result.txt").replace("'", "''")
                + "', $out)\n",
                encoding="utf-8",
            )
            subprocess.run(
                [pwsh, "-NoProfile", "-File", str(script)],
                check=True,
                capture_output=True,
                text=True,
            )
            reference = [
                int(line)
                for line in (tmp_path / "result.txt").read_text().split()
            ]
        self.assertEqual(len(reference), len(pairs))
        mismatches = [
            (a, b)
            for (a, b), ref in zip(pairs, reference)
            if conflict(a, b) != bool(ref)
        ]
        self.assertEqual(mismatches, [])


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
            # Bare and infix forms: "PUBLISHER" as a substring and
            # "KEY" as a whole word must not slip past a prefix /
            # marker list (B1R3-M2).
            "PUBLISHER", "MY_PUBLISHER", "KEY", "KEY_PEM",
        ):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    package.build_adapter_environment(
                        self.base_env(), extra_values={key: "x"}
                    )

    def test_managed_persistent_config_names_rejected_as_extras(self):
        # Persistent-configuration names are owned by the boundary:
        # a caller may not point the child at the parent account's
        # home or tool config through an extra value (B1R3-M2).
        for key in (
            "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
            "XDG_CONFIG_HOME", "GH_CONFIG_DIR", "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
        ):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    package.build_adapter_environment(
                        self.base_env(), extra_values={key: "C:\\parent"}
                    )

    def test_persistent_config_not_copied_from_parent(self):
        base = self.base_env()
        base.update({
            "HOME": "/parent/home",
            "USERPROFILE": "C:\\Users\\parent",
            "APPDATA": "C:\\Users\\parent\\AppData\\Roaming",
            "LOCALAPPDATA": "C:\\Users\\parent\\AppData\\Local",
            "GH_CONFIG_DIR": "/parent/gh",
        })
        env = package.build_adapter_environment(base)
        for key in (
            "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
            "APPDATA", "LOCALAPPDATA", "GH_CONFIG_DIR",
        ):
            self.assertNotIn(key, env)

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

    def test_relative_extension_root_executes(self):
        # CI calls with relative paths are standard: the inspected
        # file, the executed file, and the child's working directory
        # must still be one and the same resolved location (B1R3-M2).
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ext = self.make_tree(root)
            probe = ext / "tests" / "probe.ps1"
            probe.write_text(
                "import json\n"
                "from pathlib import Path\n"
                "print(json.dumps({'cwd': str(Path.cwd())}))\n",
                encoding="utf-8",
            )
            previous = Path.cwd()
            os.chdir(root)
            try:
                result = package.run_adapter_script(
                    Path("extensions/sample/tests/probe.ps1"),
                    extension_root=Path("extensions/sample"),
                    executable=sys.executable,
                )
            finally:
                os.chdir(previous)
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(result.stdout)
            self.assertEqual(Path(observed["cwd"]), ext.resolve())

    def test_intermediate_symlink_rejected(self):
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            (ext / "packaging" / "real.ps1").write_text(
                "payload\n", encoding="utf-8"
            )
            try:
                os.symlink(
                    ext / "packaging", ext / "tests" / "sub",
                    target_is_directory=True,
                )
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaises(ValueError):
                package.run_adapter_script(
                    ext / "tests" / "sub" / "real.ps1",
                    extension_root=ext, executable=sys.executable,
                )

    def test_missing_script_rejected(self):
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            with self.assertRaises(ValueError):
                package.run_adapter_script(
                    ext / "tests" / "missing.ps1",
                    extension_root=ext, executable=sys.executable,
                )

    def test_entry_rejects_script_with_unsupported_encoding(self):
        # SOL-B1-R2-02: the common entry enforces the same encoding
        # contract as the static scan. BOM-less bytes that are not
        # valid UTF-8 have no single PowerShell interpretation
        # (5.1 reads ANSI, 7 reads UTF-8), so they never execute
        # through the entry.
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            script = ext / "tests" / "legacy.ps1"
            script.write_bytes(b"# \x93\x94 legacy quotes\nWrite-Host 'x'\n")
            with self.assertRaises(ValueError):
                package.run_adapter_script(
                    script, extension_root=ext, executable=sys.executable
                )

    def test_entry_accepts_bom_encoded_script(self):
        # A UTF-16 (BOM) script is inside the encoding contract: the
        # entry's gate passes it to the host instead of rejecting it.
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            script = ext / "tests" / "bom.ps1"
            script.write_bytes("Write-Host 'ok'\n".encode("utf-16"))
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            with mock.patch.object(package.subprocess, "run", return_value=completed) as run:
                result = package.run_adapter_script(
                    script, extension_root=ext, executable=sys.executable
                )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(run.called)

    def test_pwsh_required_no_windows_powershell_fallback(self):
        # SOL-B1-R3-02: the common entry requires PowerShell 7.
        # Windows PowerShell 5.1 decodes BOM-less sources with the
        # legacy ANSI code page, so under 5.1 the executed text
        # would differ from the text the static scan inspected; the
        # entry fails closed instead of falling back to it.
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            script = ext / "tests" / "plain.ps1"
            script.write_text("Write-Host 'x'\n", encoding="utf-8")
            with mock.patch.object(package.shutil, "which", return_value=None):
                with self.assertRaises(RuntimeError):
                    package.run_adapter_script(script, extension_root=ext)
            with mock.patch.object(
                package.shutil,
                "which",
                side_effect=lambda name: (
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    if name == "powershell"
                    else None
                ),
            ):
                with self.assertRaises(RuntimeError):
                    package.run_adapter_script(script, extension_root=ext)

    def test_entry_rejects_double_bom_and_nul_scripts(self):
        # SOL-B1-R3-03: the byte forms under which the host reports
        # an error yet exits 0 never reach the host through the
        # common entry -- the encoding gate refuses them first.
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            for data in (
                b"\xef\xbb\xbf\xef\xbb\xbfWrite-Host 'x'\n",
                b"# comment\x00\nWrite-Host 'x'\n",
            ):
                script = ext / "tests" / "bad.ps1"
                script.write_bytes(data)
                with self.subTest(data=data[:8]):
                    with self.assertRaises(ValueError):
                        package.run_adapter_script(
                            script,
                            extension_root=ext,
                            executable=sys.executable,
                        )

    def test_entry_rejects_nonleading_feff_scripts(self):
        # Neon B1R6-M1 (SOL-B1-R3-03 residual): a U+FEFF anywhere
        # beyond the leading signature -- after blanks, after a
        # newline, or as a second mark -- is outside the encoding
        # contract, so the entry's gate refuses it before the host
        # can report an error yet exit 0 (the audit's four
        # reproductions).
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            for data in (
                b" \xef\xbb\xbf# comment\n",
                b"\n\xef\xbb\xbf# comment\n",
                b"\xef\xbb\xbf\n\xef\xbb\xbf# comment\n",
                " \ufeff# comment\n".encode("utf-16"),
            ):
                script = ext / "tests" / "bad.ps1"
                script.write_bytes(data)
                with self.subTest(data=data[:8]):
                    with self.assertRaises(ValueError):
                        package.run_adapter_script(
                            script,
                            extension_root=ext,
                            executable=sys.executable,
                        )

    def test_utf16_bom_script_executes_through_default_entry(self):
        # Neon B1R6-N2: the production default branch of
        # run_adapter_script (executable=None -> pwsh resolved
        # from PATH, invoked with -NoProfile -File) also executes
        # a BOM-coded script, not only the explicit-executable
        # seam used by the neighbouring test.
        if shutil.which("pwsh") is None:
            self.skipTest("PowerShell 7 host not available")
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            script = ext / "tests" / "bom.ps1"
            script.write_bytes("Write-Output 'bom-ok'\n".encode("utf-16"))
            result = package.run_adapter_script(script, extension_root=ext)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("bom-ok", result.stdout)

    def test_utf16_bom_script_executes_under_real_powershell(self):
        # The permitted form really executes: a substantive UTF-16
        # (BOM) script runs under the PowerShell host through the
        # common entry and produces its output.
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("PowerShell 7 host not available")
        with TemporaryDirectory() as tmp:
            ext = self.make_tree(Path(tmp))
            script = ext / "tests" / "bom.ps1"
            script.write_bytes("Write-Output 'bom-ok'\n".encode("utf-16"))
            result = package.run_adapter_script(
                script, extension_root=ext, executable=pwsh
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("bom-ok", result.stdout)

    def test_persistent_config_isolated_from_parent_home(self):
        # The parent account's home holds dummy persistent credential
        # stores; through the common entry the child must not reach
        # them: every persistent-configuration name is rebound to a
        # fresh clean home for the run (B1R3-M2).
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ext = self.make_tree(root)
            parent_home = root / "parent-home"
            gh_dir = parent_home / ".config" / "gh"
            gh_dir.mkdir(parents=True)
            (gh_dir / "hosts.yml").write_text(
                "github.com:\n  oauth_token: dummy\n", encoding="utf-8"
            )
            (parent_home / ".git-credentials").write_text(
                "https://dummy.invalid\n", encoding="utf-8"
            )
            probe = ext / "tests" / "probe.ps1"
            probe.write_text(
                "import json, os\n"
                "from pathlib import Path\n"
                "home = Path(os.environ['HOME'])\n"
                "gh_config = Path(os.environ['GH_CONFIG_DIR'])\n"
                "print(json.dumps({\n"
                "    'home_is_parent': home == Path("
                f"{str(parent_home)!r}),\n"
                "    'gh_hosts_via_home': (home / '.config' / 'gh' / 'hosts.yml').exists(),\n"
                "    'git_credentials_via_home': (home / '.git-credentials').exists(),\n"
                "    'gh_hosts_via_config_dir': (gh_config / 'hosts.yml').exists(),\n"
                "    'git_config_nosystem': os.environ.get('GIT_CONFIG_NOSYSTEM'),\n"
                "    'appdata_is_parent': os.environ.get('APPDATA', '').startswith("
                f"{str(parent_home)!r}),\n"
                "}))\n",
                encoding="utf-8",
            )
            base_env = dict(os.environ)
            base_env.update({
                "HOME": str(parent_home),
                "USERPROFILE": str(parent_home),
                "APPDATA": str(parent_home / "AppData" / "Roaming"),
                "LOCALAPPDATA": str(parent_home / "AppData" / "Local"),
            })
            result = package.run_adapter_script(
                probe, extension_root=ext, base_env=base_env,
                executable=sys.executable,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = json.loads(result.stdout)
            self.assertFalse(observed["home_is_parent"])
            self.assertFalse(observed["gh_hosts_via_home"])
            self.assertFalse(observed["git_credentials_via_home"])
            self.assertFalse(observed["gh_hosts_via_config_dir"])
            self.assertEqual(observed["git_config_nosystem"], "1")
            self.assertFalse(observed["appdata_is_parent"])


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

    def test_license_per_postgresql_non_object_rejected(self):
        # A non-object perPostgresql block is a declaration defect and
        # must surface as ValueError, not a raw TypeError (B1R3-N3).
        block = {"verifyAgainstUpstream": True, "perPostgresql": "17"}
        with self.assertRaises(ValueError):
            package.verify_declaration_licenses(
                block, 17, {"LICENSE": LICENSE_TEXT}, {"LICENSE": LICENSE_TEXT}
            )

    def test_declared_upstream_commit_major_binding(self):
        # The pin selection is bound to postgresql.majors: the major
        # must be a positive integer and one of the declared majors,
        # in single and per-major form alike (B1R3-M1).
        single = {
            "postgresql": {"majors": [15, 16, 17, 18, 19]},
            "upstream": {"commit": DECLARED},
        }
        self.assertEqual(package.declared_upstream_commit(single, 17), DECLARED)
        for bad_major in (14, 99, 0, -1, True, "17", 17.0):
            with self.subTest(major=bad_major):
                with self.assertRaises(ValueError):
                    package.declared_upstream_commit(single, bad_major)
        # A declaration without a postgresql block cannot bind a pin.
        with self.assertRaises(ValueError):
            package.declared_upstream_commit({"upstream": {"commit": DECLARED}}, 17)
        # The single and per-major forms are exclusive.
        mixed = {
            "postgresql": {"majors": [17]},
            "upstream": {
                "commit": DECLARED,
                "perPostgresql": {"17": {"commit": DECLARED}},
            },
        }
        with self.assertRaises(ValueError):
            package.declared_upstream_commit(mixed, 17)
        # A per-major pin for a major outside postgresql.majors makes
        # the declaration itself inconsistent and is rejected.
        outside = {
            "postgresql": {"majors": [17]},
            "upstream": {
                "perPostgresql": {
                    "17": {"commit": DECLARED},
                    "18": {"commit": DECLARED},
                },
            },
        }
        with self.assertRaises(ValueError):
            package.declared_upstream_commit(outside, 17)


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

    def write_declaration(self, root, upstream, license_block, name="declaration.json",
                          majors=(15, 16, 17, 18, 19)):
        declaration = {
            "name": "sample",
            "upstream": upstream,
            "license": license_block,
        }
        if majors is not None:
            declaration["postgresql"] = {"majors": list(majors)}
        path = root / name
        path.write_text(json.dumps(declaration), encoding="utf-8")
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

    def test_verify_licenses_cli_undeclared_major_rejected(self):
        # B1R3-M1: the single-form pin must not cover majors the
        # declaration does not declare. Undeclared majors (14 / 99)
        # and non-positive majors (0 / -1) are rejected at the
        # entrance, before any Git access, with no traceback.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": LICENSE_TEXT})
            declaration = self.write_declaration(
                root,
                {"repository": "https://example.invalid/up", "commit": self.git_head(up)},
                {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"},
            )
            pkg_head = self.git_head(pkg)
            for major in (14, 99):
                with self.subTest(major=major):
                    result = self.run_cli(
                        *self.verify_args(declaration, major, up, pkg, pkg_head)
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("not declared in postgresql.majors", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
            for major in (0, -1):
                with self.subTest(major=major):
                    result = self.run_cli(
                        *self.verify_args(declaration, major, up, pkg, pkg_head)
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("positive integer", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
            # The declared majors still verify.
            ok = self.run_cli(*self.verify_args(declaration, 17, up, pkg, pkg_head))
            self.assertEqual(ok.returncode, 0, ok.stderr)

    def test_verify_licenses_cli_per_postgresql_major_outside_majors_rejected(self):
        # B1R3-M1: a per-major pin for a major outside
        # postgresql.majors does not make that major verifiable.
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
                majors=(17,),
            )
            self.git_checkout(up, pin18)
            result = self.run_cli(
                *self.verify_args(declaration, 18, up, pkg, self.git_head(pkg))
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("postgresql.majors", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_verify_licenses_cli_same_bytes_other_commit_rejected(self):
        # B1R3-M1: equal bytes at a different commit do not satisfy
        # the pin. The second commit changes only an unrelated file,
        # so the LICENSE bytes are identical; the entrance still
        # rejects it because the resolved HEAD is not the declared
        # commit.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pin = self.git_head(up)
            self.git_commit_files(up, {"README": b"unrelated\n"}, "unrelated")
            self.assertNotEqual(self.git_head(up), pin)
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": LICENSE_TEXT})
            declaration = self.write_declaration(
                root,
                {"repository": "https://example.invalid/up", "commit": pin},
                {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"},
            )
            result = self.run_cli(
                *self.verify_args(declaration, 17, up, pkg, self.git_head(pkg))
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("commit mismatch", result.stderr)

    def test_verify_licenses_blobs_read_at_resolved_sha(self):
        # B1R3-M1: once the entrance has resolved HEAD to the declared
        # pin, a HEAD that moves afterwards cannot change the
        # comparison -- every blob is read at the resolved SHA.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": LICENSE_TEXT})
            pin = self.git_head(up)
            license_block = {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"}
            original_resolve = package._git_resolve_head
            moved = []

            def resolve_then_move(repo):
                resolved = original_resolve(repo)
                if Path(repo) == up and not moved:
                    moved.append(True)
                    self.git_commit_files(up, {"LICENSE": OTHER_LICENSE}, "moved")
                return resolved

            with mock.patch.object(
                package, "_git_resolve_head", side_effect=resolve_then_move
            ):
                document = package.verify_declaration_licenses_from_git(
                    license_block, 17, up, pkg,
                    expected_upstream_commit=pin,
                    expected_packaging_commit=self.git_head(pkg),
                )
            self.assertEqual(document["upstreamCommit"], pin)
            self.assertEqual(len(document["licenses"]), 1)
            self.assertNotEqual(self.git_head(up), pin)

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

    def add_replace_ref(self, repo, original_bytes, replacement_bytes):
        """Point the repo's LICENSE blob at replacement bytes via git replace.

        Returns once a plain (unguarded) git read of HEAD:LICENSE
        demonstrably returns the replacement bytes, so the negative
        control is part of the fixture, not an assumption.
        """
        def git(*args, **kwargs):
            return subprocess.run(
                ["git", "-C", str(repo), *args],
                check=True, capture_output=True, **kwargs,
            )

        head = self.git_head(repo)
        original_blob = git(
            "rev-parse", f"{head}:LICENSE", text=True
        ).stdout.strip()
        replacement_blob = git(
            "hash-object", "-w", "--stdin", input=replacement_bytes
        ).stdout.decode().strip()
        git("replace", original_blob, replacement_blob)
        masked = git("cat-file", "blob", f"{head}:LICENSE").stdout
        self.assertEqual(masked, replacement_bytes)
        return head

    def test_verify_licenses_cli_git_replace_cannot_mask_bytes(self):
        # SOL-B1-R2-03: a local git replace ref must not change
        # what the K4 comparison reads. The pinned upstream blob is
        # replaced by different bytes in the local repository; the
        # CLI still compares the original object at the pinned SHA,
        # so the genuine match passes and the emitted document
        # records the pinned commit.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": LICENSE_TEXT})
            pin = self.add_replace_ref(up, LICENSE_TEXT, OTHER_LICENSE)
            self.assertEqual(pin, self.git_head(up))
            declaration = self.write_declaration(
                root,
                {"repository": "https://example.invalid/up", "commit": pin},
                {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"},
            )
            result = self.run_cli(
                *self.verify_args(declaration, 17, up, pkg, self.git_head(pkg))
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(result.stdout)
            self.assertEqual(document["upstreamCommit"], pin)
            self.assertEqual(len(document["licenses"]), 1)

    def test_verify_licenses_cli_git_replace_cannot_create_match(self):
        # The replace ref must not manufacture a match either: the
        # packaging side carries different bytes, and replacing the
        # upstream blob with those bytes would make an unguarded
        # comparison pass. The CLI compares the original objects,
        # rejects the mismatch, and emits no evidence document.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": OTHER_LICENSE})
            pin = self.add_replace_ref(up, LICENSE_TEXT, OTHER_LICENSE)
            declaration = self.write_declaration(
                root,
                {"repository": "https://example.invalid/up", "commit": pin},
                {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"},
            )
            result = self.run_cli(
                *self.verify_args(declaration, 17, up, pkg, self.git_head(pkg))
            )
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("licenses", result.stdout)

    def test_verify_licenses_cli_git_replace_on_packaging_side_ignored(self):
        # The packaging repository is held to the same rule: a
        # replace ref there cannot substitute the bytes compared
        # against the trusted packaging commit.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": LICENSE_TEXT})
            pkg_head = self.add_replace_ref(pkg, LICENSE_TEXT, OTHER_LICENSE)
            declaration = self.write_declaration(
                root,
                {"repository": "https://example.invalid/up", "commit": self.git_head(up)},
                {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"},
            )
            result = self.run_cli(
                *self.verify_args(declaration, 17, up, pkg, pkg_head)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(result.stdout)
            self.assertEqual(document["packagingCommit"], pkg_head)


if __name__ == "__main__":
    unittest.main()
