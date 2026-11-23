import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/compare-windows-packages.py"


class ComparePackagesTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.before = self.root / "before" / "example.zip"
        self.after = self.root / "after" / "example.zip"
        self.before.parent.mkdir()
        self.after.parent.mkdir()
        self.original = [("LICENSE", b"A\n"), ("share/extension/example.sql", b"SELECT 1;")]
        self.make_zip(self.before, self.original)
        self.licenses = self.root / "verified-license-list.json"
        self.licenses.write_text(json.dumps({
            "schemaVersion": 1,
            "upstreamCommit": "a" * 40,
            "licenses": [{"upstreamPath": "LICENSE", "repositoryPath": "LICENSE", "zipPath": "LICENSE",
                          "size": 2, "sha256": hashlib.sha256(b"A\n").hexdigest()}],
        }))
        self.report = self.root / "report.json"

    @staticmethod
    def make_zip(path, files, compression=zipfile.ZIP_STORED):
        with zipfile.ZipFile(path, "w", compression) as archive:
            for name, data in files:
                archive.writestr(name, data)

    def run_comparison(self):
        result = subprocess.run([
            sys.executable, str(SCRIPT), "--before", str(self.before), "--after", str(self.after),
            "--licenses", str(self.licenses), "--output", str(self.report),
        ], capture_output=True, text=True)
        return result.returncode, json.loads(self.report.read_text())

    def test_container_format_does_not_affect_parity(self):
        self.make_zip(self.after, self.original[::-1], zipfile.ZIP_DEFLATED)
        code, report = self.run_comparison()
        self.assertEqual(code, 0, report["differences"])
        self.assertTrue(report["equivalent"])
        self.assertNotEqual(report["before"]["sha256"], report["after"]["sha256"])

    def test_changed_sql_and_license_reported(self):
        self.make_zip(self.after, [("LICENSE", b"A\r\n"), ("share/extension/example.sql", b"SELECT 2;")])
        code, report = self.run_comparison()
        self.assertEqual(code, 1)
        self.assertIn("Changed entry bytes: share/extension/example.sql", report["differences"])
        self.assertIn("after: license LICENSE differs from verified upstream blob.", report["differences"])

    def test_duplicate_path_denied(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            self.make_zip(self.after, [*self.original, self.original[0]])
        code, report = self.run_comparison()
        self.assertEqual(code, 1)
        self.assertIn("duplicate ZIP path", report["differences"][0])

    def test_equal_modified_license_denied(self):
        files = [("LICENSE", b"B\n"), self.original[1]]
        self.make_zip(self.before, files)
        self.make_zip(self.after, files)
        code, report = self.run_comparison()
        self.assertEqual(code, 1)
        self.assertEqual(len(report["differences"]), 2)


if __name__ == "__main__":
    unittest.main()
