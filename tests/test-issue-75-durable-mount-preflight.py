#!/usr/bin/env python3
"""Negative tests for nonpublishing Issue #75 mount preflight."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

p = Path(__file__).resolve().parents[1] / "scripts" / "issue-75-durable-mount-preflight.py"
spec = importlib.util.spec_from_file_location("mount_preflight", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class PreflightTests(unittest.TestCase):
    def assert_denied(self, path):
        result = m.inspect_mount(path)
        self.assertFalse(result["publicationAuthorized"])
        self.assertFalse(result["mutationAuthorized"])
        self.assertFalse(result["retryAuthorized"])
        self.assertEqual(result["goB"], "NO_GO")
        self.assertEqual(result["g4"], "NO_GO")
        self.assertEqual(result["g5"], "NO_GO")

    def test_missing_and_relative(self):
        self.assert_denied("")
        self.assert_denied("relative")
        self.assertEqual(m.inspect_mount("relative")["classification"], "NOT_PROVEN")

    def test_ephemeral_and_workspace(self):
        self.assert_denied("/tmp")
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": root}):
                self.assertEqual(m.inspect_mount(root)["classification"], "NOT_PROVEN")

    def test_symlink_and_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "private"
            target.mkdir(mode=0o700)
            link = Path(root) / "alias"
            link.symlink_to(target, target_is_directory=True)
            self.assertEqual(m.inspect_mount(str(link))["classification"], "NOT_PROVEN")
            target.chmod(0o755)
            self.assertEqual(m.inspect_mount(str(target))["classification"], "NOT_PROVEN")

    def test_custody_does_not_prove_durability(self):
        with tempfile.TemporaryDirectory() as root:
            private = Path(root) / "private"
            private.mkdir(mode=0o700)
            with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": "/unrelated"}):
                result = m.inspect_mount(str(private))
            self.assertEqual(result["classification"], "LOCAL_CUSTODY_ONLY_NOT_DURABILITY_PROOF")
            self.assert_denied(str(private))

if __name__ == "__main__":
    unittest.main()
