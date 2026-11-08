#!/usr/bin/env python3
"""Offline fault injection for private exact-byte provider GET (no network, no publisher)."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scripts/external-direct-get-originals.sh").read_text("utf-8")
# Test the exact production shell function, not a reimplementation of its policy.
BODY = SCRIPT.split("get_exact() {", 1)[1].split("\n}\ncase \"$extension\" in", 1)[0]
MOCK = r"""#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv
dest = pathlib.Path(args[args.index("--output") + 1])
counter = pathlib.Path(os.environ["MOCK_COUNTER"])
i = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(i + 1))
sequence = os.environ["MOCK_SEQUENCE"].split(",")
kind = sequence[min(i, len(sequence) - 1)]
if kind in ("502", "503", "504", "401", "403"):
    print(kind, end="")
    sys.exit(22)
if kind in ("7", "18", "28", "56"):
    print("000", end="")
    sys.exit(int(kind))
if kind == "json":
    dest.write_bytes(b'{"message":"Not Found"}')
elif kind == "truncated":
    dest.write_bytes(b"PK\x03\x04")
else:
    shutil.copyfile(os.environ["MOCK_ZIP"], dest)
print("200", end="")
"""

class PrivateGetTests(unittest.TestCase):
    def test_shell_parses_and_fixed_original_pins_are_retained(self):
        result = subprocess.run(["bash", "-n", str(ROOT / "scripts/external-direct-get-originals.sh")],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for pinned in ("164673161", "164673166", "164673171",
                       "ac1114d1392494e688b5b6b6f151aebe6ccab2d8ae1a004ec510669c47ef3634",
                       "d23ea9ba7d064ee08e431b12ade50bed4b19a725b5f4df1e088e79e4af8d08ec",
                       "7afd7cda50050829787d4e901fc8292cf1eb2bc5ad59c996a92e414a1bead1f7"):
            self.assertIn(pinned, SCRIPT)
        self.assertNotIn("api.github.com/repos/", SCRIPT)
        self.assertIn("MIRROR=DENY", SCRIPT)

    def exercise(self, sequence, fixture="zip", bad_hash=False, bad_length=False):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            z = folder / "fixture.zip"
            if fixture == "corrupt":
                z.write_bytes(b"PK\x03\x04this-is-not-a-valid-zip-archive")
            else:
                with zipfile.ZipFile(z, "w") as f:
                    f.writestr("hypopg.control", "comment='offline fixture'\n")
            actual = z.read_bytes()
            sha = hashlib.sha256(actual).hexdigest()
            if bad_hash:
                sha = "0" * 64
            size = len(actual) + (1 if bad_length else 0)
            mocks = folder / "bin"
            mocks.mkdir()
            curl = mocks / "curl"
            curl.write_text(MOCK)
            curl.chmod(0o755)
            sleep = mocks / "sleep"
            sleep.write_text("#!/bin/sh\nexit 0\n")
            sleep.chmod(0o755)
            dest = folder / "private.zip"
            bash = ('set -euo pipefail\nget_exact() {' + BODY +
                    '\n}\nget_exact "$URL" "$OUT" "$SIZE" "$SHA" "hypopg PG14 asset=164673161"\n')
            env = {**os.environ, "PATH": str(mocks) + ":" + os.environ["PATH"],
                   "URL": "https://github.com/HypoPG/hypopg/releases/download/1.4.1/fake.zip",
                   "OUT": str(dest), "SIZE": str(size), "SHA": sha,
                   "MOCK_ZIP": str(z), "MOCK_COUNTER": str(folder / "count"),
                   "MOCK_SEQUENCE": sequence}
            res = subprocess.run(["bash", "-c", bash], env=env, capture_output=True, text=True)
            count = int((folder / "count").read_text())
            return res, count, dest.exists(), dest.read_bytes() == actual if dest.exists() else False

    def test_gateway_then_success_exact_zip(self):
        for seq, count in (("503,200", 2), ("504,7,200", 3), ("28,200", 2)):
            with self.subTest(seq=seq):
                r, n, exists, exact = self.exercise(seq)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(n, count)
                self.assertTrue(exists and exact)
                self.assertIn("ORIGINAL_GET_PASS source=hypopg PG14 asset=164673161", r.stdout)

    def test_exhausted_retries_fail_closed(self):
        r, n, exists, _ = self.exercise("502,503,504")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(n, 3)
        self.assertFalse(exists)
        self.assertIn("RETRY_EXHAUSTED", r.stderr)

    def test_denied_auth_never_retried(self):
        for seq in ("401,200", "403,200"):
            r, n, exists, _ = self.exercise(seq)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(n, 1)
            self.assertFalse(exists)
            self.assertIn("NON_RETRYABLE", r.stderr)

    def test_untrusted_or_invalid_bytes_never_accepted(self):
        for kw in ({"sequence": "json"}, {"sequence": "truncated"},
                   {"sequence": "200", "bad_hash": True},
                   {"sequence": "200", "bad_length": True},
                   {"sequence": "200", "fixture": "corrupt"}):
            with self.subTest(kw=kw):
                r, n, exists, _ = self.exercise(**kw)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(n, 1)
                self.assertFalse(exists)
                self.assertIn("BYTE_OR_ZIP_MISMATCH", r.stderr)

if __name__ == "__main__":
    unittest.main()
