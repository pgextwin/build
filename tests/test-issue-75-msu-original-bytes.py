#!/usr/bin/env python3
"""Non-network hostile fixtures for a bounded KB/MSU SHA256 witness."""
from __future__ import annotations

import hashlib
import importlib.util
import io
from pathlib import Path
from unittest import TestCase, main, mock
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "issue75_msu_original", ROOT / "scripts/issue-75-msu-original-bytes.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def fake_script(url=p.URL, sha="a" * 64):
    return ("Url64 = '" + url + "'\nChecksum64 = '" + sha + "'\n").encode()


def fake_archive(script):
    b = io.BytesIO()
    with ZipFile(b, "w") as z:
        z.writestr("KB3033929.nuspec",
                   '<package><metadata><id>KB3033929</id>'
                   '<version>1.0.3</version></metadata></package>')
        z.writestr(p.SCRIPT, script)
    return b.getvalue()


class HostileMSUProbe(TestCase):
    def test_pins_are_original_and_explicitly_historical(self):
        self.assertEqual(p.PKG[2], "51d28a163e4c9cfab2ea94c47d7308a88d578e18f6d4e0ac5c8286ee4ae9c91b")
        self.assertEqual(p.SCRIPT_SHA256, "88f28af10bb556009d17a42cc42ae7d50f8b83c55d172cb3764e23a6a9420ecb")
        self.assertEqual(p.SHA256, "5318587007edb6c8b29310ff18da479a162b486b9101a7de735f94a70dbc3b31")
        self.assertTrue(p.URL.endswith("Windows6.1-KB3033929-x64.msu"))

    def test_exact_adjacent_pair_only_not_runtime_approval(self):
        script = fake_script(sha=p.SHA256)
        with mock.patch.object(p, "SCRIPT_SHA256", hashlib.sha256(script).hexdigest()):
            got = p.source_pair(script)
            self.assertTrue(got["lexicalAdjacentPair"])
            self.assertFalse(got["osBranchReachabilityProven"])

    def test_url_and_checksum_split_or_duplicated_fail(self):
        for script in (
            fake_script(sha="b" * 64),
            fake_script(sha=p.SHA256) + fake_script(sha=p.SHA256),
            ("Url64 = '" + p.URL + "'\n# intermediary\nChecksum64 = '" + p.SHA256 + "'\n").encode(),
            ("# Url64 = '" + p.URL + "'\nChecksum64 = '" + p.SHA256 + "'\n").encode(),
        ):
            with self.subTest(script=script[:30]):
                with mock.patch.object(p, "SCRIPT_SHA256", hashlib.sha256(script).hexdigest()):
                    with self.assertRaises(p.Deny):
                        p.source_pair(script)

    def test_untrusted_redirect_and_insecure_urls_denied(self):
        for url in ("http://download.microsoft.com/a.msu",
                    "https://evil.example/a.msu",
                    "https://user:pass@download.microsoft.com/a.msu",
                    "https://download.microsoft.com:444/a.msu",
                    "https://download.microsoft.com/a.msu#fragment"):
            with self.subTest(url=url):
                with self.assertRaises(p.Deny):
                    p.verify_url(url)
        self.assertEqual(p.verify_url(p.URL), p.URL)

    def test_payload_byte_magic_limits_and_hash_fail_closed(self):
        good = b"MSCF" + b"x" * 150_000
        digest = hashlib.sha256(good).hexdigest()
        self.assertEqual(p.verified_payload(good, digest)["sha256"], digest)
        for bad in (b"MZ" + good, b"MSCF", b"X" * 150_100):
            with self.subTest(prefix=bad[:4]):
                with self.assertRaises(p.Deny):
                    p.verified_payload(bad, digest)
        with self.assertRaisesRegex(p.Deny, "SHA256 mismatch"):
            p.verified_payload(good, "f" * 64)

    def test_modified_package_refused_before_network_msu(self):
        calls = []
        with self.assertRaisesRegex(p.Deny, "nupkg double GET"):
            p.observe(download_package=lambda *x: b"forgery",
                      download_msu=lambda *x: calls.append(x))
        self.assertEqual(calls, [])

    def test_double_get_disagreement_and_inert_positive_fixture(self):
        good = b"MSCF" + b"m" * 150_000
        script = fake_script(sha=hashlib.sha256(good).hexdigest())
        archive = fake_archive(script)
        with (mock.patch.object(p, "SCRIPT_SHA256", hashlib.sha256(script).hexdigest()),
              mock.patch.object(p, "SHA256", hashlib.sha256(good).hexdigest()),
              mock.patch.object(p, "PKG", ("KB3033929", "1.0.3", hashlib.sha256(archive).hexdigest()))):
            approved = p.observe(download_package=lambda *a: archive,
                                 download_msu=lambda *a: good)
            self.assertEqual(approved["payload"]["getCount"], 2)
            self.assertFalse(approved["payload"]["executed"])
            self.assertEqual(approved["goB"], "NO_GO")
            self.assertFalse(approved["signerWriterIsolationProven"])
            count = iter((good, good + b"extra"))
            with self.assertRaisesRegex(p.Deny, "GET byte disagreement"):
                p.observe(download_package=lambda *a: archive,
                          download_msu=lambda *a: next(count))

    def test_workflow_resolver_and_pr_job_have_no_publish_or_auth(self):
        wf = (ROOT / ".github/workflows/validate.yml").read_text(encoding="utf-8")
        self.assertIn("python tests/test-issue-75-msu-original-bytes.py", wf)
        self.assertIn("python scripts/issue-75-msu-original-bytes.py --mode static", wf)
        sec = wf.split("  issue75_msu_original:", 1)[1].split(
            "\n  existing_signed_release_readonly:", 1)[0]
        for required in ("github.event_name == 'pull_request'",
                         "github.head_ref == 'issue-75-msu-original-bytes'",
                         "contents: read", "persist-credentials: false",
                         "python scripts/issue-75-msu-original-bytes.py --mode observe"):
            self.assertIn(required, sec)
        for forbidden in ("contents: write", "id-token: write", "secrets.",
                          "GH_TOKEN:", "GITHUB_TOKEN:", "upload-artifact",
                          "gh release", "choco install", "Start-Process"):
            self.assertNotIn(forbidden, sec)


if __name__ == "__main__":
    main()
