#!/usr/bin/env python3
"""Fail-closed offline contract for parallel PG14-18 portable ZIP CI trial."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "metadata/postgresql-portable-zip-pins.json").read_text(encoding="utf-8"))
FLEET = json.loads((ROOT / "metadata/postgresql.json").read_text(encoding="utf-8"))
SCRIPT = (ROOT / "scripts/install-postgresql-portable.ps1").read_text(encoding="utf-8")
WF = (ROOT / ".github/workflows/postgresql-portable-benchmark.yml").read_text(encoding="utf-8")
EXPECTED = {
    "14": ("14.24", "469f628e5740ea4aa22053fff4ef89334232b68a453691e329374b3eed2e8127"),
    "15": ("15.19", "3b1365016bb381b8e37a38337d9187c72e61696e473256fc24a6b2ed9ca4b255"),
    "16": ("16.15", "43bb45f173a6f08cf1d29a97a6d8deb119e8e8093a24c00d2d1001a0ccaa8281"),
    "17": ("17.11", "b9424ee7bc60b52450ff910a3630225df32e633f3cb29c1d126d9299d59aea28"),
    "18": ("18.6", "e2246ba91d22345bc3d017586c09ede52d9df180b1eeb480f050445f1cad84e2"),
}


def check_pins(pins, fleet):
    assert pins["schemaVersion"] == 1
    assert pins["purpose"] == "READ_ONLY_PR_BENCHMARK_NOT_RELEASE"
    assert set(pins["files"]) == set(EXPECTED)
    versions = {str(e["major"]): e["minor"] for e in fleet["postgresql"]}
    for major, entry in pins["files"].items():
        minor, digest = EXPECTED[major]
        assert versions[major] == minor == entry["minor"]
        assert digest == entry["sha256"]
        assert re.fullmatch(rf"postgresql-{re.escape(minor)}-[1-9][0-9]*-windows-x64-binaries\.zip", entry["file"])
        assert entry["evidence"].startswith("https://")
        assert len(entry["sha256"]) == 64


class FastPGPortableContract(unittest.TestCase):
    def test_five_exact_minor_and_full_sha256_pins(self):
        check_pins(MANIFEST, FLEET)

    def test_forged_major_missing_archive_digest_and_minor_denied(self):
        for mode in ("delete", "wrong_minor", "wrong_digest", "extra_major", "wrong_filename", "bad_purpose"):
            data = json.loads(json.dumps(MANIFEST))
            if mode == "delete":
                del data["files"]["15"]
            elif mode == "wrong_minor":
                data["files"]["14"]["minor"] = "14.23"
            elif mode == "wrong_digest":
                data["files"]["18"]["sha256"] = "f" * 64
            elif mode == "extra_major":
                data["files"]["19"] = dict(data["files"]["18"])
            elif mode == "wrong_filename":
                data["files"]["16"]["file"] = "../evil.zip"
            else:
                data["purpose"] = "PUBLISH"
            with self.subTest(mode=mode), self.assertRaises(AssertionError):
                check_pins(data, FLEET)

    def test_read_only_five_parallel_jobs_are_exact(self):
        self.assertIn("major: [14, 15, 16, 17, 18]", WF)
        self.assertIn("max-parallel: 5", WF)
        self.assertIn("fail-fast: false", WF)
        self.assertIn("pull_request:", WF)
        self.assertIn("github.event_name == 'pull_request'", WF)
        self.assertIn("permissions:\n  contents: read", WF)
        self.assertIn("persist-credentials: false", WF)
        self.assertIn("timeout-minutes: 30", WF)
        self.assertIn("PINNED_PORTABLE_ZIP_REAL_BUILD_SQL_SMOKE=PASS", WF)
        for step in (
            "SHA256-verify and extract official EDB",
            "Verify full 48-export",
            "Install extension DLL, SQL and control",
            "Real PostgreSQL CREATE EXTENSION and invalid-record-field SQL smoke",
        ):
            self.assertIn(step, WF)
        for forbidden in (
            "contents: write", "id-token: write", "attestations: write",
            "pull-requests: write", "gh release create", "gh workflow run",
            "continue-on-error:", "|| true", "cancel-in-progress: true",
        ):
            self.assertNotIn(forbidden, WF)

    def test_installer_checksum_precedes_unzip_and_binary_execution(self):
        ordered = (
            "Get-FileHash -LiteralPath $archive",
            "SHA256 mismatch",
            "[IO.Compression.ZipFile]::OpenRead($archive)",
            "& $unzip x",
            "pg_config.exe') --version",
        )
        positions = [SCRIPT.index(x) for x in ordered]
        self.assertEqual(positions, sorted(positions))
        for required in (
            "https://get.enterprisedb.com/postgresql/",
            "include\\server\\postgres.h",
            "lib\\postgres.lib", "bin\\postgres.exe", "bin\\initdb.exe",
            "share\\extension\\plpgsql.control",
            "GITHUB_STEP_SUMMARY", "READ_ONLY_PR_BENCHMARK_NOT_RELEASE",
        ):
            self.assertIn(required, SCRIPT)
        for forbidden in ("choco install", "gh release", "gh api", "secrets.", "Set-Acl", "Start-Service", "git push"):
            self.assertNotIn(forbidden, SCRIPT)


if __name__ == "__main__":
    unittest.main()
