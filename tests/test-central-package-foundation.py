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
        return records

    def test_complete_chain_passes(self):
        with TemporaryDirectory() as tmp:
            package.verify_handoff_chain(self.make_chain(tmp))

    def test_tampering_rejected_at_every_stage(self):
        for stage in package.STAGES:
            with self.subTest(stage=stage), TemporaryDirectory() as tmp:
                records = self.make_chain(tmp, tamper_stage=stage)
                if stage == "T0":
                    # Tampering before T0 is the packaged truth; the chain
                    # itself stays consistent. Tamper evidence appears when
                    # the T0 record is compared with the pre-packaging
                    # digest, covered by test_record_digest_edit_rejected.
                    continue
                with self.assertRaises(ValueError):
                    package.verify_handoff_chain(records)

    def test_record_digest_edit_rejected(self):
        with TemporaryDirectory() as tmp:
            records = self.make_chain(tmp)
            records[2]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                package.verify_handoff_chain(records)

    def test_missing_stage_rejected(self):
        with TemporaryDirectory() as tmp:
            records = self.make_chain(tmp)[:3]
            with self.assertRaises(ValueError):
                package.verify_handoff_chain(records)

    def test_extension_mismatch_rejected(self):
        with TemporaryDirectory() as tmp:
            records = self.make_chain(tmp)
            records[1]["extension"] = "other"
            with self.assertRaises(ValueError):
                package.verify_handoff_chain(records)

    def test_major_mismatch_rejected(self):
        with TemporaryDirectory() as tmp:
            records = self.make_chain(tmp)
            records[3]["pgMajor"] = 18
            with self.assertRaises(ValueError):
                package.verify_handoff_chain(records)

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
            "empty extension": ("extension", ""),
        }
        for case, (key, value) in variants.items():
            with self.subTest(case=case), TemporaryDirectory() as tmp:
                records = self.make_chain(tmp)
                for record in records:
                    record[key] = value
                with self.assertRaises(ValueError):
                    package.verify_handoff_chain(records)

    def test_same_size_tamper_rejected(self):
        with TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "sample-pg17-windows-x64.zip"
            build_sample_zip(tmp)
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
                package.verify_handoff_chain(records)

    def test_t0_baseline_mismatch_rejected(self):
        with TemporaryDirectory() as tmp:
            records = self.make_chain(tmp)
            zip_path = Path(tmp) / "sample-pg17-windows-x64.zip"
            baseline_sha = package.sha256_file(zip_path)
            baseline_size = zip_path.stat().st_size
            package.verify_handoff_chain(
                records, expected_sha256=baseline_sha, expected_size=baseline_size
            )
            with self.assertRaises(ValueError):
                package.verify_handoff_chain(records, expected_sha256="0" * 64)
            with self.assertRaises(ValueError):
                package.verify_handoff_chain(records, expected_size=baseline_size + 1)


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
            self.base_env(), extra_allowed=["PG_BUILD_FLAG"]
        )
        for key in self.SECRET_ENV:
            self.assertNotIn(key, env)
        self.assertEqual(env["PG_BUILD_FLAG"], "1")
        self.assertIn("PATH", env)

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

    def test_forbidden_extra_allowed_rejected(self):
        for key in (
            "GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN",
            "PUBLISHER_TOKEN", "LOCAL_AUTH_SECRET", "APP_PRIVATE_KEY", "SOME_API_KEY",
        ):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    package.build_adapter_environment(
                        self.base_env(), extra_allowed=[key]
                    )


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

    def test_verify_licenses_cli(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            up = self.make_git_repo(root / "up", {"LICENSE": LICENSE_TEXT})
            pkg = self.make_git_repo(root / "pkg", {"LICENSE": LICENSE_TEXT})
            block = root / "license.json"
            block.write_text(json.dumps(
                {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"}
            ), encoding="utf-8")
            args = (
                "verify-licenses", "--license-json", str(block), "--major", "17",
                "--upstream-dir", str(up), "--packaging-dir", str(pkg),
            )
            ok = self.run_cli(*args)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            document = json.loads(ok.stdout)
            self.assertEqual(len(document["upstreamCommit"]), 40)
            self.assertEqual(len(document["packagingCommit"]), 40)
            self.assertEqual(len(document["verified"]), 1)
            # The CLI reads the fixed HEAD blobs: a worktree-only edit is
            # not a comparison input and cannot change the outcome.
            (pkg / "LICENSE").write_bytes(OTHER_LICENSE)
            still_ok = self.run_cli(*args)
            self.assertEqual(still_ok.returncode, 0, still_ok.stderr)
            # Committing the tampered bytes changes the fixed blob.
            subprocess.run(
                ["git", "-C", str(pkg), "add", "-A"],
                check=True, capture_output=True, text=True,
            )
            subprocess.run(
                ["git", "-C", str(pkg), "commit", "-qm", "tamper"],
                check=True, capture_output=True, text=True,
            )
            bad = self.run_cli(*args)
            self.assertEqual(bad.returncode, 1)

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
            block = root / "license.json"
            block.write_text(json.dumps(
                {"verifyAgainstUpstream": True, "upstreamPath": "LICENSE"}
            ), encoding="utf-8")
            result = self.run_cli(
                "verify-licenses", "--license-json", str(block), "--major", "17",
                "--upstream-dir", str(up), "--packaging-dir", str(pkg),
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("symbolic link", result.stderr)


if __name__ == "__main__":
    unittest.main()
