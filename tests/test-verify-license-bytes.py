#!/usr/bin/env python3
"""Exercise license verification against real Git blobs."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify-license-bytes.py"
LICENSE = b"Copyright Example\nRedistribution permitted.\n"


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def commit_files(repo, files):
    repo.mkdir()
    git(repo, "init", "--quiet")
    git(repo, "config", "core.autocrlf", "false")
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    git(repo, "add", "--all")
    git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com",
        "commit", "--quiet", "--no-gpg-sign", "--allow-empty", "-m", "Add licenses")


class LicenseBytesTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        self.upstream = root / "upstream"
        self.packaging = root / "packaging"
        self.stage = root / "verified licenses"
        self.config = root / "license-files.json"
        self.source_stage = root / "verified sources"
        self.verified = root / "verified.json"

    def verify_entries(self, entries, restore=False):
        self.config.write_text(json.dumps(entries), encoding="utf-8")
        command = [
            sys.executable, str(SCRIPT),
            "--license-files", str(self.config),
            "--upstream-dir", str(self.upstream),
            "--packaging-dir", str(self.packaging),
            "--stage-dir", str(self.stage),
            "--source-stage-dir", str(self.source_stage),
            "--verified-list", str(self.verified),
        ]
        if restore:
            command.append("--restore-worktrees")
        return subprocess.run(command, capture_output=True, text=True)

    def verify(self, *pairs, restore=False, marker=None):
        return self.verify_entries([
            {"repositoryPath": repository, "upstreamPath": upstream,
             **({"upstreamStartMarker": marker} if marker is not None else {})}
            for repository, upstream in pairs
        ], restore=restore)

    def assert_failed(self, result, message):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertFalse(self.stage.exists())
        self.assertFalse(self.source_stage.exists())
        self.assertFalse(self.verified.exists())

    def test_identical_lf_bytes_pass(self):
        commit_files(self.upstream, {"LICENSE": LICENSE})
        commit_files(self.packaging, {"LICENSE": LICENSE})
        result = self.verify(("LICENSE", "LICENSE"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.stage / "LICENSE").read_bytes(), LICENSE)
        self.assertEqual(result.stdout.splitlines(), [f"{hashlib.sha256(LICENSE).hexdigest()}  LICENSE"])

    def test_packaging_crlf_fails_against_upstream_lf(self):
        commit_files(self.upstream, {"LICENSE": LICENSE})
        commit_files(self.packaging, {"LICENSE": LICENSE.replace(b"\n", b"\r\n")})
        self.assert_failed(self.verify(("LICENSE", "LICENSE")), "License file 'LICENSE' differs from upstream 'LICENSE'.")

    def test_upstream_crlf_fails_against_packaging_lf(self):
        commit_files(self.upstream, {"LICENSE": LICENSE.replace(b"\n", b"\r\n")})
        commit_files(self.packaging, {"LICENSE": LICENSE})
        self.assert_failed(self.verify(("LICENSE", "LICENSE")), "License file 'LICENSE' differs from upstream 'LICENSE'.")

    def test_missing_upstream_blob_fails(self):
        commit_files(self.upstream, {})
        commit_files(self.packaging, {"LICENSE": LICENSE})
        (self.upstream / "COPYRIGHT").write_bytes(LICENSE)
        self.assert_failed(self.verify(("LICENSE", "COPYRIGHT")), "Configured upstream license file was not found: COPYRIGHT")

    def test_missing_packaging_blob_fails(self):
        commit_files(self.upstream, {"LICENSE": LICENSE})
        commit_files(self.packaging, {})
        (self.packaging / "COPYRIGHT").write_bytes(LICENSE)
        self.assert_failed(self.verify(("COPYRIGHT", "LICENSE")), "Configured packaging-repository license file was not found: COPYRIGHT")

    def test_multiple_files_preserve_non_utf8_and_mixed_line_endings(self):
        notice = b"\xef\xbb\xbfCopyright \xff\r\nExample\nEnd"
        commit_files(self.upstream, {"COPYRIGHT": LICENSE, "NOTICE": notice})
        commit_files(self.packaging, {"licenses/pg16/LICENSE": LICENSE, "licenses/pg16/NOTICE": notice})
        result = self.verify(("licenses/pg16/LICENSE", "COPYRIGHT"), ("licenses/pg16/NOTICE", "NOTICE"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.stage / "licenses/pg16/LICENSE").read_bytes(), LICENSE)
        self.assertEqual((self.stage / "licenses/pg16/NOTICE").read_bytes(), notice)
        self.assertEqual(len(result.stdout.splitlines()), 2)

    def test_duplicate_repository_path_with_equal_bytes_is_staged_once(self):
        commit_files(self.upstream, {"LICENSE": LICENSE, "COPYRIGHT": LICENSE})
        commit_files(self.packaging, {"LICENSE": LICENSE})
        result = self.verify(("LICENSE", "LICENSE"), ("LICENSE", "COPYRIGHT"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.stage / "LICENSE").read_bytes(), LICENSE)
        self.assertEqual(len(result.stdout.splitlines()), 1)

    def test_duplicate_repository_path_with_different_bytes_fails(self):
        commit_files(self.upstream, {"LICENSE": LICENSE, "COPYRIGHT": b"Different"})
        commit_files(self.packaging, {"LICENSE": LICENSE})
        self.assert_failed(
            self.verify(("LICENSE", "LICENSE"), ("LICENSE", "COPYRIGHT")),
            "License file 'LICENSE' differs from upstream 'COPYRIGHT'.",
        )

    def test_restore_worktrees_preserves_bytes_for_existing_hooks(self):
        commit_files(self.upstream, {"NOTICE": LICENSE})
        commit_files(self.packaging, {"licenses/LICENSE": LICENSE})
        upstream = self.upstream / "NOTICE"
        packaging = self.packaging / "licenses/LICENSE"
        crlf = LICENSE.replace(b"\n", b"\r\n")
        upstream.write_bytes(crlf)
        packaging.write_bytes(crlf)
        git(self.packaging, "add", "licenses/LICENSE")

        result = self.verify(("licenses/LICENSE", "NOTICE"), restore=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(upstream.read_bytes(), LICENSE)
        self.assertEqual(packaging.read_bytes(), LICENSE)
        self.assertEqual((self.stage / "licenses/LICENSE").read_bytes(), LICENSE)

    def test_readme_suffix_stages_license_and_full_source_separately(self):
        readme = b"Upstream README.\n\n" + LICENSE
        commit_files(self.upstream, {"README.md": readme})
        commit_files(self.packaging, {"LICENSE": LICENSE})
        path = self.upstream / "README.md"
        checkout = readme.replace(b"\n", b"\r\n")
        path.write_bytes(checkout)

        result = self.verify(("LICENSE", "README.md"), marker="Copyright")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.read_bytes(), checkout)
        self.assertEqual((self.source_stage / "README.md").read_bytes(), readme)
        self.assertEqual((self.stage / "LICENSE").read_bytes(), LICENSE)
        verified, = json.loads(self.verified.read_bytes())["licenses"]
        self.assertEqual(verified["upstreamOffset"], readme.index(b"Copyright"))
        self.assertEqual(verified["upstreamSize"], len(readme))
        self.assertEqual(verified["upstreamSha256"], hashlib.sha256(readme).hexdigest())
        self.assertEqual(verified["sha256"], hashlib.sha256(LICENSE).hexdigest())

        result = self.verify(("LICENSE", "README.md"), marker="Copyright", restore=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.read_bytes(), readme)

    def test_readme_suffix_rejects_missing_start(self):
        commit_files(self.upstream, {"README.md": b"README without a license"})
        commit_files(self.packaging, {"LICENSE": LICENSE})
        self.assert_failed(self.verify(("LICENSE", "README.md"), marker="Copyright"), "range start not found")

    def test_readme_suffix_rejects_altered_packaging_license(self):
        commit_files(self.upstream, {"README.md": b"README\n" + LICENSE})
        commit_files(self.packaging, {"LICENSE": LICENSE.replace(b"\n", b"\r\n")})
        self.assert_failed(self.verify(("LICENSE", "README.md"), marker="Copyright"), "differs from upstream")

    def test_packaging_origin_license_verified_and_restored(self):
        pkg_license = b"Artistic License 2.0\nLine 2\n"
        commit_files(self.upstream, {"README-ext.md": LICENSE})
        commit_files(self.packaging, {"README-ext.md": LICENSE, "LICENSE": pkg_license})
        (self.packaging / "LICENSE").write_bytes(pkg_license.replace(b"\n", b"\r\n"))

        pkg_sha = hashlib.sha256(pkg_license).hexdigest()
        result = self.verify_entries([
            {"repositoryPath": "README-ext.md", "upstreamPath": "README-ext.md"},
            {"origin": "packaging", "repositoryPath": "LICENSE", "sha256": pkg_sha},
        ], restore=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.stage / "README-ext.md").read_bytes(), LICENSE)
        self.assertEqual((self.stage / "LICENSE").read_bytes(), pkg_license)
        self.assertEqual((self.packaging / "LICENSE").read_bytes(), pkg_license)
        verified = json.loads(self.verified.read_bytes())
        self.assertIn("packagingCommit", verified)
        self.assertEqual(len(verified["licenses"]), 2)
        self.assertEqual(verified["licenses"][1], {
            "origin": "packaging",
            "repositoryPath": "LICENSE",
            "size": len(pkg_license),
            "sha256": pkg_sha,
        })

    def test_packaging_origin_rejects_mismatched_missing_and_malformed_sha256(self):
        pkg_license = b"Artistic License 2.0\n"
        commit_files(self.upstream, {"README-ext.md": LICENSE})
        commit_files(self.packaging, {"README-ext.md": LICENSE, "LICENSE": pkg_license.replace(b"\n", b"\r\n")})

        lf_sha = hashlib.sha256(pkg_license).hexdigest()
        self.assert_failed(
            self.verify_entries([
                {"repositoryPath": "README-ext.md", "upstreamPath": "README-ext.md"},
                {"origin": "packaging", "repositoryPath": "LICENSE", "sha256": lf_sha},
            ]),
            "does not match pinned",
        )
        self.assert_failed(
            self.verify_entries([
                {"repositoryPath": "README-ext.md", "upstreamPath": "README-ext.md"},
                {"origin": "packaging", "repositoryPath": "LICENSE"},
            ]),
            "Invalid fields",
        )
        self.assert_failed(
            self.verify_entries([
                {"repositoryPath": "README-ext.md", "upstreamPath": "README-ext.md"},
                {"origin": "packaging", "repositoryPath": "LICENSE", "sha256": lf_sha.upper()},
            ]),
            "Invalid pinned license sha256",
        )

    def test_packaging_only_without_upstream_entry_is_rejected(self):
        pkg_license = b"Artistic License 2.0\n"
        commit_files(self.upstream, {})
        commit_files(self.packaging, {"LICENSE": pkg_license})
        self.assert_failed(
            self.verify_entries([
                {"origin": "packaging", "repositoryPath": "LICENSE",
                 "sha256": hashlib.sha256(pkg_license).hexdigest()},
            ]),
            "at least one upstream-verified license file",
        )

    def test_build_origin_license_verified_and_restored_without_writing_upstream(self):
        pg_notice = b"PostgreSQL Database Management System\nPortions Copyright\n"
        commit_files(self.upstream, {"README-ext.md": LICENSE})
        commit_files(self.packaging, {
            "README-ext.md": LICENSE,
            "licenses/COPYRIGHT.postgresql": pg_notice,
        })
        (self.packaging / "licenses/COPYRIGHT.postgresql").write_bytes(pg_notice.replace(b"\n", b"\r\n"))

        pg_sha = hashlib.sha256(pg_notice).hexdigest()
        result = self.verify_entries([
            {"repositoryPath": "README-ext.md", "upstreamPath": "README-ext.md"},
            {
                "origin": "build",
                "repositoryPath": "licenses/COPYRIGHT.postgresql",
                "generatedSource": "upstream",
                "generatedPath": "POSTGRESQL-COPYRIGHT",
                "sha256": pg_sha,
            },
        ], restore=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.stage / "licenses/COPYRIGHT.postgresql").read_bytes(), pg_notice)
        self.assertEqual((self.packaging / "licenses/COPYRIGHT.postgresql").read_bytes(), pg_notice)
        self.assertFalse((self.upstream / "POSTGRESQL-COPYRIGHT").exists())
        verified = json.loads(self.verified.read_bytes())
        self.assertEqual(verified["licenses"][1], {
            "origin": "build",
            "repositoryPath": "licenses/COPYRIGHT.postgresql",
            "size": len(pg_notice),
            "sha256": pg_sha,
            "generatedSource": "upstream",
            "generatedPath": "POSTGRESQL-COPYRIGHT",
        })

    def test_build_origin_rejects_invalid_generated_source_and_path_traversal(self):
        pg_notice = b"PostgreSQL Notice\n"
        pg_sha = hashlib.sha256(pg_notice).hexdigest()
        commit_files(self.upstream, {"README-ext.md": LICENSE})
        commit_files(self.packaging, {"README-ext.md": LICENSE, "licenses/COPYRIGHT.postgresql": pg_notice})

        self.assert_failed(
            self.verify_entries([
                {"repositoryPath": "README-ext.md", "upstreamPath": "README-ext.md"},
                {
                    "origin": "build",
                    "repositoryPath": "licenses/COPYRIGHT.postgresql",
                    "generatedSource": "packaging",
                    "generatedPath": "POSTGRESQL-COPYRIGHT",
                    "sha256": pg_sha,
                },
            ]),
            "Invalid generatedSource",
        )
        self.assert_failed(
            self.verify_entries([
                {"repositoryPath": "README-ext.md", "upstreamPath": "README-ext.md"},
                {
                    "origin": "build",
                    "repositoryPath": "licenses/COPYRIGHT.postgresql",
                    "generatedSource": "upstream",
                    "generatedPath": "../POSTGRESQL-COPYRIGHT",
                    "sha256": pg_sha,
                },
            ]),
            "Invalid generatedPath",
        )

    def test_duplicate_repository_path_across_upstream_and_packaging_rejected(self):
        commit_files(self.upstream, {"README.md": LICENSE})
        commit_files(self.packaging, {"LICENSE": LICENSE})
        sha = hashlib.sha256(LICENSE).hexdigest()

        self.assert_failed(
            self.verify_entries([
                {"repositoryPath": "LICENSE", "upstreamPath": "README.md"},
                {"origin": "packaging", "repositoryPath": "LICENSE", "sha256": sha},
            ]),
            "Duplicate license staging path",
        )
        self.assert_failed(
            self.verify_entries([
                {"origin": "packaging", "repositoryPath": "LICENSE", "sha256": sha},
                {"repositoryPath": "LICENSE", "upstreamPath": "README.md"},
            ]),
            "Duplicate license staging path",
        )


if __name__ == "__main__":
    unittest.main()
